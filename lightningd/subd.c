#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/status.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/subd.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

static bool move_fd(int from, int to)
{
	if (dup2(from, to) == -1)
		return false;
	close(from);
	return true;
}

struct subd_req {
	struct list_node list;

	/* Callback for a reply. */
	int type;
	bool (*replycb)(struct subd *, const u8 *, const int *, void *);
	void *replycb_data;

	size_t num_reply_fds;
	/* If non-NULL, this is here to disable replycb */
	void *disabler;
};

static void free_subd_req(struct subd_req *sr)
{
	list_del(&sr->list);
	/* Don't disable once we're freed! */
	if (sr->disabler)
		tal_free(sr->disabler);
}

/* Called when the callback is disabled because caller was freed. */
static bool ignore_reply(struct subd *sd, const u8 *msg, const int *fds,
			 void *arg)
{
	size_t i;

	log_debug(sd->log, "IGNORING REPLY");
	for (i = 0; i < tal_count(fds); i++)
		close(fds[i]);
	return true;
}

static void disable_cb(void *disabler, struct subd_req *sr)
{
	sr->replycb = ignore_reply;
	sr->disabler = NULL;
}

static void add_req(const tal_t *ctx,
		    struct subd *sd, int type, size_t num_fds_in,
		    bool (*replycb)(struct subd *, const u8 *, const int *,
				    void *),
		    void *replycb_data)
{
	struct subd_req *sr = tal(sd, struct subd_req);

	sr->type = type;
	sr->replycb = replycb;
	sr->replycb_data = replycb_data;
	sr->num_reply_fds = num_fds_in;

	/* We don't allocate sr off ctx, because we still have to handle the
	 * case where ctx is freed between request and reply.  Hence this
	 * trick. */
	if (ctx) {
		sr->disabler = tal(ctx, char);
		tal_add_destructor2(sr->disabler, disable_cb, sr);
	} else
		sr->disabler = NULL;
	assert(strends(sd->msgname(sr->type + SUBD_REPLY_OFFSET), "_REPLY"));

	/* Keep in FIFO order: we sent in order, so replies will be too. */
	list_add_tail(&sd->reqs, &sr->list);
	tal_add_destructor(sr, free_subd_req);
}

/* Caller must free. */
static struct subd_req *get_req(struct subd *sd, int reply_type)
{
	struct subd_req *sr;

	list_for_each(&sd->reqs, sr, list) {
		if (sr->type + SUBD_REPLY_OFFSET == reply_type)
			return sr;
		/* If it's a fail, and that's a valid type. */
		if (sr->type + SUBD_REPLYFAIL_OFFSET == reply_type
		    && strends(sd->msgname(reply_type), "_REPLYFAIL")) {
			sr->num_reply_fds = 0;
			return sr;
		}
	}
	return NULL;
}

/* We use sockets, not pipes, because fds are bidir. */
static int subd(const char *dir, const char *name, const char *debug_subdaemon,
		int *msgfd, int dev_disconnect_fd, va_list *ap)
{
	int childmsg[2], execfail[2];
	pid_t childpid;
	int err, *fd;
	bool debug = debug_subdaemon && strends(name, debug_subdaemon);

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, childmsg) != 0)
		goto fail;

	if (pipe(execfail) != 0)
		goto close_msgfd_fail;

	if (fcntl(execfail[1], F_SETFD, fcntl(execfail[1], F_GETFD)
		  | FD_CLOEXEC) < 0)
		goto close_execfail_fail;

	childpid = fork();
	if (childpid < 0)
		goto close_execfail_fail;

	if (childpid == 0) {
		int fdnum = 3, i;
		long max;
		const char *debug_arg[2] = { NULL, NULL };

		close(childmsg[0]);
		close(execfail[0]);

		// msg = STDIN
		if (childmsg[1] != STDIN_FILENO) {
			if (!move_fd(childmsg[1], STDIN_FILENO))
				goto child_errno_fail;
		}

		// Move dev_disconnect_fd out the way.
		if (dev_disconnect_fd != -1) {
			if (!move_fd(dev_disconnect_fd, 101))
				goto child_errno_fail;
			dev_disconnect_fd = 101;
		}

		/* Dup any extra fds up first. */
		if (ap) {
			while ((fd = va_arg(*ap, int *)) != NULL) {
				/* If this were stdin, dup2 closed! */
				assert(*fd != STDIN_FILENO);
				if (!move_fd(*fd, fdnum))
					goto child_errno_fail;
				fdnum++;
			}
		}

		/* Make (fairly!) sure all other fds are closed. */
		max = sysconf(_SC_OPEN_MAX);
		for (i = fdnum; i < max; i++)
			if (i != dev_disconnect_fd)
				close(i);

		if (dev_disconnect_fd != -1)
			debug_arg[0] = tal_fmt(NULL, "--dev-disconnect=%i", dev_disconnect_fd);
		if (debug)
			debug_arg[debug_arg[0] ? 1 : 0] = "--debugger";
		execl(path_join(NULL, dir, name), name, debug_arg[0], debug_arg[1], NULL);

	child_errno_fail:
		err = errno;
		/* Gcc's warn-unused-result fail. */
		if (write(execfail[1], &err, sizeof(err))) {
			;
		}
		exit(127);
	}

	close(childmsg[1]);
	close(execfail[1]);

	if (ap) {
		while ((fd = va_arg(*ap, int *)) != NULL) {
			if (taken(fd)) {
				close(*fd);
				*fd = -1;
			}
		}
	}

	/* Child will close this without writing on successful exec. */
	if (read(execfail[0], &err, sizeof(err)) == sizeof(err)) {
		close(execfail[0]);
		waitpid(childpid, NULL, 0);
		errno = err;
		return -1;
	}
	close(execfail[0]);
	*msgfd = childmsg[0];
	return childpid;

close_execfail_fail:
	close_noerr(execfail[0]);
	close_noerr(execfail[1]);
close_msgfd_fail:
	close_noerr(childmsg[0]);
	close_noerr(childmsg[1]);
fail:
	return -1;
}

int subd_raw(struct lightningd *ld, const char *name)
{
	pid_t pid;
	int msg_fd;

	pid = subd(ld->daemon_dir, name, ld->dev_debug_subdaemon,
		   &msg_fd, ld->dev_disconnect_fd, NULL);
	if (pid == (pid_t)-1) {
		log_unusual(ld->log, "subd %s failed: %s",
			    name, strerror(errno));
		return -1;
	}

	return msg_fd;
}

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd);

static struct io_plan *sd_msg_reply(struct io_conn *conn, struct subd *sd,
				    struct subd_req *sr)
{
	int type = fromwire_peektype(sd->msg_in);
	bool keep_open;
	const tal_t *tmpctx = tal_tmpctx(conn);

	log_info(sd->log, "REPLY %s with %zu fds",
		 sd->msgname(type), tal_count(sd->fds_in));

	/* Callback could free sd!  Make sure destroy_subd() won't free conn */
	sd->conn = NULL;

	/* We want to free the msg_in, unless they tal_steal() it. */
	tal_steal(tmpctx, sd->msg_in);

	/* And we need to free sr after this too (unless they free via sd!). */
	tal_steal(tmpctx, sr);

	keep_open = sr->replycb(sd, sd->msg_in, sd->fds_in, sr->replycb_data);
	tal_free(tmpctx);

	if (!keep_open)
		return io_close(conn);

	/* Restore conn ptr. */
	sd->conn = conn;
	/* Free any fd array. */
	sd->fds_in = tal_free(sd->fds_in);
	return io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd);
}

static struct io_plan *read_fds(struct io_conn *conn, struct subd *sd)
{
	if (sd->num_fds_in_read == tal_count(sd->fds_in)) {
		size_t i;

		/* Don't trust subd to set it blocking. */
		for (i = 0; i < tal_count(sd->fds_in); i++)
			io_fd_block(sd->fds_in[i], true);
		return sd_msg_read(conn, sd);
	}
	return io_recv_fd(conn, &sd->fds_in[sd->num_fds_in_read++],
			  read_fds, sd);
}

static struct io_plan *sd_collect_fds(struct io_conn *conn, struct subd *sd,
				      size_t num_fds)
{
	assert(!sd->fds_in);
	sd->fds_in = tal_arr(sd, int, num_fds);
	sd->num_fds_in_read = 0;
	return read_fds(conn, sd);
}

/* Don't trust, verify.  Returns NULL if contains weird stuff. */
static const char *string_from_msg(const u8 *msg, int *str_len)
{
	size_t len = tal_count(msg) - sizeof(be16), i;

	for (i = 0; i < len; i++) {
		if (!cisprint((char)msg[sizeof(be16) + i])) {
			*str_len = 0;
			return NULL;
		}
	}
	*str_len = len;
	return (const char *)(msg + sizeof(be16));
}

static void subdaemon_malformed_msg(struct subd *sd, const u8 *msg)
{
	log_broken(sd->log, "%i: malformed string '%.s'",
		   fromwire_peektype(msg),
		   tal_hexstr(msg,
			      msg + sizeof(be16),
			      tal_count(msg) - sizeof(be16)));

	if (sd->ld->dev_subdaemon_fail)
		fatal("Subdaemon %s sent malformed message", sd->name);
}

/* Returns true if logged, false if malformed. */
static bool log_status_fail(struct subd *sd,
			    enum status_fail type, const char *str, int str_len)
{
	const char *name;

	/* No 'default:' here so gcc gives warning if a new type added */
	switch (type) {
	case STATUS_FAIL_MASTER_IO:
		name = "STATUS_FAIL_MASTER_IO";
		goto log_str_broken;
	case STATUS_FAIL_HSM_IO:
		name = "STATUS_FAIL_HSM_IO";
		goto log_str_broken;
	case STATUS_FAIL_GOSSIP_IO:
		name = "STATUS_FAIL_GOSSIP_IO";
		goto log_str_broken;
	case STATUS_FAIL_INTERNAL_ERROR:
		name = "STATUS_FAIL_INTERNAL_ERROR";
		goto log_str_broken;

	/*
	 * These errors happen when the other peer misbehaves:
	 */
	case STATUS_FAIL_PEER_IO:
		name = "STATUS_FAIL_PEER_IO";
		goto log_str_peer;
	case STATUS_FAIL_PEER_BAD:
		name = "STATUS_FAIL_PEER_BAD";
		goto log_str_peer;
	}
	return false;

	/* Peers misbehaving is expected. */
log_str_peer:
	log_info(sd->log, "%s: %.*s", name, str_len, str);
	return true;

/* Shouldn't happen. */
log_str_broken:
	log_broken(sd->log, "%s: %.*s", name, str_len, str);

	if (sd->ld->dev_subdaemon_fail)
		fatal("Subdaemon %s hit error", sd->name);

	return true;
}

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd)
{
	int type = fromwire_peektype(sd->msg_in);
	const tal_t *tmpctx;
	struct subd_req *sr;

	if (type == -1) {
		subdaemon_malformed_msg(sd, sd->msg_in);
		return io_close(conn);
	}

	/* First, check for replies. */
	sr = get_req(sd, type);
	if (sr) {
		if (sr->num_reply_fds && sd->fds_in == NULL)
			return sd_collect_fds(conn, sd, sr->num_reply_fds);

		assert(sr->num_reply_fds == tal_count(sd->fds_in));
		return sd_msg_reply(conn, sd, sr);
	}

	/* If not stolen, we'll free this below. */
	tmpctx = tal_tmpctx(sd);
	tal_steal(tmpctx, sd->msg_in);

	if (type == STATUS_TRACE) {
		int str_len;
		const char *str = string_from_msg(sd->msg_in, &str_len);
		if (!str) {
			subdaemon_malformed_msg(sd, sd->msg_in);
			return io_close(conn);
		}
		log_debug(sd->log, "TRACE: %.*s", str_len, str);
		goto next;
	} else if (type & STATUS_FAIL) {
		int str_len;
		const char *str = string_from_msg(sd->msg_in, &str_len);
		if (!str) {
			subdaemon_malformed_msg(sd, sd->msg_in);
			return io_close(conn);
		}

		if (!log_status_fail(sd, type, str, str_len)) {
			subdaemon_malformed_msg(sd, sd->msg_in);
			return io_close(conn);
		}

		/* If they care, tell them about invalid peer behavior */
		if (sd->peerbadcb && type == STATUS_FAIL_PEER_BAD) {
			const char *errmsg = tal_fmt(sd, "%.*s", str_len, str);
			sd->peerbadcb(sd, errmsg);
		}
		return io_close(conn);
	}

	log_info(sd->log, "UPDATE %s", sd->msgname(type));
	if (sd->msgcb) {
		int i = sd->msgcb(sd, sd->msg_in, sd->fds_in);
		if (i < 0)
			return io_close(conn);
		if (i != 0) {
			/* Don't ask for fds twice! */
			assert(!sd->fds_in);
			/* Don't free msg_in: we go around again. */
			tal_steal(sd, sd->msg_in);
			tal_free(tmpctx);
			return sd_collect_fds(conn, sd, i);
		}
	}

next:
	sd->msg_in = NULL;
	sd->fds_in = tal_free(sd->fds_in);
	tal_free(tmpctx);
	return io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd);
}

static void destroy_subd(struct subd *sd)
{
	int status;
	bool fail_if_subd_fails = sd->ld->dev_subdaemon_fail;

	switch (waitpid(sd->pid, &status, WNOHANG)) {
	case 0:
		log_debug(sd->log, "Status closed, but not exited. Killing");
		kill(sd->pid, SIGKILL);
		waitpid(sd->pid, &status, 0);
		fail_if_subd_fails = false;
		break;
	case -1:
		log_unusual(sd->log, "Status closed, but waitpid %i says %s",
			    sd->pid, strerror(errno));
		status = -1;
		break;
	}

	if (fail_if_subd_fails && WIFSIGNALED(status))
		fatal("Subdaemon %s killed with signal %i",
		      sd->name, WTERMSIG(status));

	/* In case we're freed manually, such as peer_fail_permanent */
	if (sd->conn)
		sd->conn = tal_free(sd->conn);

	log_debug(sd->log, "finishing: %p", sd->finished);
	if (sd->finished)
		sd->finished(sd, status);
}

static struct io_plan *msg_send_next(struct io_conn *conn, struct subd *sd)
{
	const u8 *msg = msg_dequeue(&sd->outq);
	int fd;

	/* Nothing to do?  Wait for msg_enqueue. */
	if (!msg)
		return msg_queue_wait(conn, &sd->outq, msg_send_next, sd);

	fd = msg_extract_fd(msg);
	if (fd >= 0) {
		tal_free(msg);
		return io_send_fd(conn, fd, true, msg_send_next, sd);
	}
	return io_write_wire(conn, take(msg), msg_send_next, sd);
}

static struct io_plan *msg_setup(struct io_conn *conn, struct subd *sd)
{
	return io_duplex(conn,
			 io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd),
			 msg_send_next(conn, sd));
}

struct subd *new_subd(struct lightningd *ld,
		      const char *name,
		      struct peer *peer,
		      const char *(*msgname)(int msgtype),
		      int (*msgcb)(struct subd *, const u8 *, const int *fds),
		      void (*peerbadcb)(struct subd *, const char *),
		      void (*finished)(struct subd *, int),
		      ...)
{
	va_list ap;
	struct subd *sd = tal(ld, struct subd);
	int msg_fd;

	va_start(ap, finished);
	sd->pid = subd(ld->daemon_dir, name, ld->dev_debug_subdaemon,
		       &msg_fd, ld->dev_disconnect_fd, &ap);
	va_end(ap);
	if (sd->pid == (pid_t)-1) {
		log_unusual(ld->log, "subd %s failed: %s",
			    name, strerror(errno));
		return tal_free(sd);
	}
	sd->ld = ld;
	sd->log = new_log(sd, ld->log_book, "%s(%u):", name, sd->pid);
	sd->name = name;
	sd->finished = finished;
	sd->msgname = msgname;
	sd->msgcb = msgcb;
	sd->peerbadcb = peerbadcb;
	sd->fds_in = NULL;
	msg_queue_init(&sd->outq, sd);
	tal_add_destructor(sd, destroy_subd);
	list_head_init(&sd->reqs);
	sd->peer = peer;

	/* conn actually owns daemon: we die when it does. */
	sd->conn = io_new_conn(ld, msg_fd, msg_setup, sd);
	tal_steal(sd->conn, sd);

	log_info(sd->log, "pid %u, msgfd %i", sd->pid, msg_fd);

	return sd;
}

void subd_send_msg(struct subd *sd, const u8 *msg_out)
{
	/* FIXME: We should use unique upper bits for each daemon, then
	 * have generate-wire.py add them, just assert here. */
	assert(!strstarts(sd->msgname(fromwire_peektype(msg_out)), "INVALID"));
	msg_enqueue(&sd->outq, msg_out);
}

void subd_send_fd(struct subd *sd, int fd)
{
	msg_enqueue_fd(&sd->outq, fd);
}

void subd_req_(const tal_t *ctx,
	       struct subd *sd,
	       const u8 *msg_out,
	       int fd_out, size_t num_fds_in,
	       bool (*replycb)(struct subd *, const u8 *, const int *, void *),
	       void *replycb_data)
{
	/* Grab type now in case msg_out is taken() */
	int type = fromwire_peektype(msg_out);

	subd_send_msg(sd, msg_out);
	if (fd_out >= 0)
		subd_send_fd(sd, fd_out);

	add_req(ctx, sd, type, num_fds_in, replycb, replycb_data);
}

void subd_shutdown(struct subd *sd, unsigned int seconds)
{
	/* Idempotent. */
	if (!sd->conn)
		return;

	log_debug(sd->log, "Shutting down");

	/* No finished callback any more. */
	sd->finished = NULL;
	/* Don't free sd when we close connection manually. */
	tal_steal(sd->ld, sd);
	/* Close connection: should begin shutdown now. */
	sd->conn = tal_free(sd->conn);

	/* Do we actually want to wait? */
	while (seconds) {
		if (waitpid(sd->pid, NULL, WNOHANG) > 0) {
			tal_del_destructor(sd, destroy_subd);
			return;
		}
		sleep(1);
		seconds--;
	}
}

char *opt_subd_debug(const char *optarg, struct lightningd *ld)
{
	ld->dev_debug_subdaemon = optarg;
	return NULL;
}

char *opt_subd_dev_disconnect(const char *optarg, struct lightningd *ld)
{
	ld->dev_disconnect_fd = open(optarg, O_RDONLY);
	if (ld->dev_disconnect_fd < 0)
		return tal_fmt(ld, "Could not open --dev-disconnect=%s: %s",
			       optarg, strerror(errno));
	return NULL;
}

/* If test specified that this disconnection should cause permanent failure */
bool dev_disconnect_permanent(struct lightningd *ld)
{
	char permfail[strlen("PERMFAIL")];
	int r;

	if (ld->dev_disconnect_fd == -1)
		return false;

	r = read(ld->dev_disconnect_fd, permfail, sizeof(permfail));
	if (r < 0)
		fatal("Reading dev_disconnect file: %s", strerror(errno));
	lseek(ld->dev_disconnect_fd, -r, SEEK_CUR);

	return memeq(permfail, r, "permfail", strlen("permfail"));
}
