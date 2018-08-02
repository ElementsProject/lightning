#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/crypto_state.h>
#include <common/gen_peer_status_wire.h>
#include <common/gen_status_wire.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/log_status.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wallet/db.h>
#include <wire/wire_io.h>

static bool move_fd(int from, int to)
{
	assert(from >= 0);
	if (dup2(from, to) == -1)
		return false;
	close(from);
	return true;
}

struct subd_req {
	struct list_node list;

	/* Callback for a reply. */
	int type;
	void (*replycb)(struct subd *, const u8 *, const int *, void *);
	void *replycb_data;

	size_t num_reply_fds;
	/* If non-NULL, this is here to disable replycb */
	void *disabler;
};

static void destroy_subd_req(struct subd_req *sr)
{
	list_del(&sr->list);
	/* Don't disable once we're freed! */
	if (sr->disabler)
		tal_free(sr->disabler);
}

/* Called when the callback is disabled because caller was freed. */
static void ignore_reply(struct subd *sd, const u8 *msg UNUSED, const int *fds,
			 void *arg UNUSED)
{
	size_t i;

	log_debug(sd->log, "IGNORING REPLY");
	for (i = 0; i < tal_count(fds); i++)
		close(fds[i]);
}

static void disable_cb(void *disabler UNUSED, struct subd_req *sr)
{
	sr->replycb = ignore_reply;
	sr->disabler = NULL;
}

static void add_req(const tal_t *ctx,
		    struct subd *sd, int type, size_t num_fds_in,
		    void (*replycb)(struct subd *, const u8 *, const int *,
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
	tal_add_destructor(sr, destroy_subd_req);
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

static void close_taken_fds(va_list *ap)
{
	int *fd;

	while ((fd = va_arg(*ap, int *)) != NULL) {
		if (taken(fd) && *fd >= 0) {
			close(*fd);
			*fd = -1;
		}
	}
}

/* We use sockets, not pipes, because fds are bidir. */
static int subd(const char *dir, const char *name,
		const char *debug_subdaemon,
		int *msgfd, int dev_disconnect_fd, va_list *ap)
{
	int childmsg[2], execfail[2];
	pid_t childpid;
	int err, *fd;

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
		int fdnum = 3, i, stdin_is_now = STDIN_FILENO;
		long max;
		size_t num_args;
		char *args[] = { NULL, NULL, NULL, NULL };

		close(childmsg[0]);
		close(execfail[0]);

		// msg = STDIN
		if (childmsg[1] != STDIN_FILENO) {
			/* Do we need to move STDIN out the way? */
			stdin_is_now = dup(STDIN_FILENO);
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
		while ((fd = va_arg(*ap, int *)) != NULL) {
			int actual_fd = *fd;
			/* If this were stdin, we moved it above! */
			if (actual_fd == STDIN_FILENO)
				actual_fd = stdin_is_now;
			if (!move_fd(actual_fd, fdnum))
				goto child_errno_fail;
			fdnum++;
		}

		/* Make (fairly!) sure all other fds are closed. */
		max = sysconf(_SC_OPEN_MAX);
		for (i = fdnum; i < max; i++)
			if (i != dev_disconnect_fd)
				close(i);

		num_args = 0;
		args[num_args++] = path_join(NULL, dir, name);
#if DEVELOPER
		if (dev_disconnect_fd != -1)
			args[num_args++] = tal_fmt(NULL, "--dev-disconnect=%i", dev_disconnect_fd);
		if (debug_subdaemon && strends(name, debug_subdaemon))
			args[num_args++] = "--debugger";
#endif
		execv(args[0], args);

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

	if (ap)
		close_taken_fds(ap);

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
	if (ap)
		close_taken_fds(ap);
	return -1;
}

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd);

static void mark_freed(struct subd *unused UNUSED, bool *freed)
{
	*freed = true;
}

static struct io_plan *sd_msg_reply(struct io_conn *conn, struct subd *sd,
				    struct subd_req *sr)
{
	int type = fromwire_peektype(sd->msg_in);
	bool freed = false;
	int *fds_in;

	log_debug(sd->log, "REPLY %s with %zu fds",
		  sd->msgname(type), tal_count(sd->fds_in));

	/* Callback could free sd!  Make sure destroy_subd() won't free conn */
	sd->conn = NULL;

	/* We want to free the msg_in, unless they tal_steal() it. */
	tal_steal(tmpctx, sd->msg_in);

	/* And we need to free sr after this too. */
	tal_steal(tmpctx, sr);
	/* In case they free sd, don't deref. */
	list_del_init(&sr->list);

	/* Free this array after, too. */
	fds_in = tal_steal(tmpctx, sd->fds_in);
	sd->fds_in = NULL;

	/* Find out if they freed it. */
	tal_add_destructor2(sd, mark_freed, &freed);
	sr->replycb(sd, sd->msg_in, fds_in, sr->replycb_data);

	if (freed)
		return io_close(conn);

	tal_del_destructor2(sd, mark_freed, &freed);

	/* Restore conn ptr. */
	sd->conn = conn;
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

static void subdaemon_malformed_msg(struct subd *sd, const u8 *msg)
{
	log_broken(sd->log, "%i: malformed message '%.s'",
		   fromwire_peektype(msg),
		   tal_hex(msg, msg));

#if DEVELOPER
	if (sd->ld->dev_subdaemon_fail)
		exit(1);
#endif
}

static bool log_status_fail(struct subd *sd, const u8 *msg)
{
	const char *name = NULL;
	enum status_failreason failreason;
	char *desc;

	if (!fromwire_status_fail(msg, msg, &failreason, &desc))
		return false;

	/* No 'default:' here so gcc gives warning if a new type added */
	switch (failreason) {
	case STATUS_FAIL_MASTER_IO:
		name = "STATUS_FAIL_MASTER_IO";
		break;
	case STATUS_FAIL_HSM_IO:
		name = "STATUS_FAIL_HSM_IO";
		break;
	case STATUS_FAIL_GOSSIP_IO:
		name = "STATUS_FAIL_GOSSIP_IO";
		break;
	case STATUS_FAIL_INTERNAL_ERROR:
		name = "STATUS_FAIL_INTERNAL_ERROR";
		break;
	}
	/* fromwire_status_fail() guarantees it's one of those... */
	assert(name);

	log_broken(sd->log, "%s: %s", name, desc);

#if DEVELOPER
	if (sd->ld->dev_subdaemon_fail)
		exit(1);
#endif
	return true;
}

static bool handle_peer_error(struct subd *sd, const u8 *msg, int fds[2])
{
	void *channel = sd->channel;
	struct channel_id channel_id;
	char *desc;
	struct crypto_state cs;
	u8 *err_for_them;

	if (!fromwire_status_peer_error(msg, msg,
					&channel_id, &desc,
					&cs, &err_for_them))
		return false;

	/* Don't free sd; we're may be about to free channel. */
	sd->channel = NULL;
	sd->errcb(channel, fds[0], fds[1], &cs,
		  &channel_id, desc, err_for_them);
	return true;
}

static bool handle_set_billboard(struct subd *sd, const u8 *msg)
{
	bool perm;
	char *happenings;

	if (!fromwire_status_peer_billboard(msg, msg, &perm, &happenings))
		return false;

	sd->billboardcb(sd->channel, perm, happenings);
	return true;
}

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd)
{
	int type = fromwire_peektype(sd->msg_in);
	struct subd_req *sr;
	struct db *db = sd->ld->wallet->db;
	struct io_plan *plan;

	/* Everything we do, we wrap in a database transaction */
	db_begin_transaction(db);

	if (type == -1)
		goto malformed;

	/* First, check for replies. */
	sr = get_req(sd, type);
	if (sr) {
		if (sr->num_reply_fds && sd->fds_in == NULL) {
			plan = sd_collect_fds(conn, sd, sr->num_reply_fds);
			goto out;
		}

		assert(sr->num_reply_fds == tal_count(sd->fds_in));
		plan = sd_msg_reply(conn, sd, sr);
		goto out;
	}

	/* If not stolen, we'll free this later. */
	tal_steal(tmpctx, sd->msg_in);

	/* We handle status messages ourselves. */
	switch ((enum status)type) {
	case WIRE_STATUS_LOG:
	case WIRE_STATUS_IO:
		if (!log_status_msg(sd->log, sd->msg_in))
			goto malformed;
		goto next;
	case WIRE_STATUS_FAIL:
		if (!log_status_fail(sd, sd->msg_in))
			goto malformed;
		goto close;
	case WIRE_STATUS_PEER_CONNECTION_LOST:
		if (!sd->channel)
			goto malformed;
		log_info(sd->log, "Peer connection lost");
		goto close;
	case WIRE_STATUS_PEER_BILLBOARD:
		if (!sd->channel)
			goto malformed;
		if (!handle_set_billboard(sd, sd->msg_in))
			goto malformed;
		goto next;
	}

	if (sd->channel) {
		switch ((enum peer_status)type) {
		case WIRE_STATUS_PEER_ERROR:
			/* We expect 2 fds after this */
			if (!sd->fds_in) {
				/* Don't free msg_in: we go around again. */
				tal_steal(sd, sd->msg_in);
				plan = sd_collect_fds(conn, sd, 2);
				goto out;
			}
			if (!handle_peer_error(sd, sd->msg_in, sd->fds_in))
				goto malformed;
			goto close;
		}
	}

	log_debug(sd->log, "UPDATE %s", sd->msgname(type));
	if (sd->msgcb) {
		unsigned int i;
		bool freed = false;

		/* Might free sd (if returns negative); save/restore sd->conn */
		sd->conn = NULL;
		tal_add_destructor2(sd, mark_freed, &freed);

		i = sd->msgcb(sd, sd->msg_in, sd->fds_in);
		if (freed)
			goto close;
		tal_del_destructor2(sd, mark_freed, &freed);

		sd->conn = conn;

		if (i != 0) {
			/* Don't ask for fds twice! */
			assert(!sd->fds_in);
			/* Don't free msg_in: we go around again. */
			tal_steal(sd, sd->msg_in);
			plan = sd_collect_fds(conn, sd, i);
			goto out;
		}
	}

next:
	sd->msg_in = NULL;
	sd->fds_in = tal_free(sd->fds_in);

	plan = io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd);
	goto out;

malformed:
	subdaemon_malformed_msg(sd, sd->msg_in);
close:
	plan = io_close(conn);
out:
	db_commit_transaction(db);
	return plan;
}


static void destroy_subd(struct subd *sd)
{
	int status;
	bool fail_if_subd_fails = false;

#if DEVELOPER
	fail_if_subd_fails = sd->ld->dev_subdaemon_fail;
#endif

	switch (waitpid(sd->pid, &status, WNOHANG)) {
	case 0:
		/* If it's an essential daemon, don't kill: we want the
		 * exit status */
		if (!sd->must_not_exit) {
			log_debug(sd->log,
				  "Status closed, but not exited. Killing");
			kill(sd->pid, SIGKILL);
		}
		waitpid(sd->pid, &status, 0);
		fail_if_subd_fails = false;
		break;
	case -1:
		log_unusual(sd->log, "Status closed, but waitpid %i says %s",
			    sd->pid, strerror(errno));
		status = -1;
		break;
	}

	if (fail_if_subd_fails && WIFSIGNALED(status)) {
		log_broken(sd->log, "Subdaemon %s killed with signal %i",
			   sd->name, WTERMSIG(status));
		exit(1);
	}

	/* In case we're freed manually, such as channel_fail_permanent */
	if (sd->conn)
		sd->conn = tal_free(sd->conn);

	/* Peer still attached? */
	if (sd->channel) {
		/* Don't loop back when we fail it. */
		void *channel = sd->channel;
		struct db *db = sd->ld->wallet->db;
		bool outer_transaction;

		/* Clear any transient messages in billboard */
		sd->billboardcb(channel, false, NULL);
		sd->channel = NULL;

		/* We can be freed both inside msg handling, or spontaneously. */
		outer_transaction = db->in_transaction;
		if (!outer_transaction)
			db_begin_transaction(db);
		if (sd->errcb)
			sd->errcb(channel, -1, -1, NULL, NULL,
				  tal_fmt(sd, "Owning subdaemon %s died (%i)",
					  sd->name, status),
				  NULL);
		if (!outer_transaction)
			db_commit_transaction(db);
	}

	if (sd->must_not_exit) {
		if (WIFEXITED(status))
			errx(1, "%s failed (exit status %i), exiting.",
			     sd->name, WEXITSTATUS(status));
		errx(1, "%s failed (signal %u), exiting.",
		     sd->name, WTERMSIG(status));
	}
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

static struct subd *new_subd(struct lightningd *ld,
			     const char *name,
			     void *channel,
			     struct log *base_log,
			     bool talks_to_peer,
			     const char *(*msgname)(int msgtype),
			     unsigned int (*msgcb)(struct subd *,
						   const u8 *, const int *fds),
			     void (*errcb)(void *channel,
					   int peer_fd, int gossip_fd,
					   const struct crypto_state *cs,
					   const struct channel_id *channel_id,
					   const char *desc,
					   const u8 *err_for_them),
			     void (*billboardcb)(void *channel,
						 bool perm,
						 const char *happenings),
			     va_list *ap)
{
	struct subd *sd = tal(ld, struct subd);
	int msg_fd;
	const char *debug_subd = NULL;
	int disconnect_fd = -1;

	assert(name != NULL);

#if DEVELOPER
	debug_subd = ld->dev_debug_subdaemon;
	disconnect_fd = ld->dev_disconnect_fd;
#endif /* DEVELOPER */

	sd->pid = subd(ld->daemon_dir, name, debug_subd,
		       &msg_fd, disconnect_fd, ap);
	if (sd->pid == (pid_t)-1) {
		log_unusual(ld->log, "subd %s failed: %s",
			    name, strerror(errno));
		return tal_free(sd);
	}
	sd->ld = ld;
	if (base_log) {
		sd->log = new_log(sd, get_log_book(base_log), "%s-%s", name,
				  log_prefix(base_log));
	} else {
		sd->log = new_log(sd, ld->log_book, "%s(%u):", name, sd->pid);
	}

	sd->name = name;
	sd->must_not_exit = false;
	sd->talks_to_peer = talks_to_peer;
	sd->msgname = msgname;
	sd->msgcb = msgcb;
	sd->errcb = errcb;
	sd->billboardcb = billboardcb;
	sd->fds_in = NULL;
	msg_queue_init(&sd->outq, sd);
	tal_add_destructor(sd, destroy_subd);
	list_head_init(&sd->reqs);
	sd->channel = channel;

	/* conn actually owns daemon: we die when it does. */
	sd->conn = io_new_conn(ld, msg_fd, msg_setup, sd);
	tal_steal(sd->conn, sd);

	log_debug(sd->log, "pid %u, msgfd %i", sd->pid, msg_fd);

	/* Clear any old transient message. */
	if (billboardcb)
		billboardcb(sd->channel, false, NULL);
	return sd;
}

struct subd *new_global_subd(struct lightningd *ld,
			     const char *name,
			     const char *(*msgname)(int msgtype),
			     unsigned int (*msgcb)(struct subd *, const u8 *,
						   const int *fds),
			     ...)
{
	va_list ap;
	struct subd *sd;

	va_start(ap, msgcb);
	sd = new_subd(ld, name, NULL, NULL, false, msgname, msgcb, NULL, NULL, &ap);
	va_end(ap);

	sd->must_not_exit = true;
	return sd;
}

struct subd *new_channel_subd_(struct lightningd *ld,
			       const char *name,
			       void *channel,
			       struct log *base_log,
			       bool talks_to_peer,
			       const char *(*msgname)(int msgtype),
			       unsigned int (*msgcb)(struct subd *, const u8 *,
						     const int *fds),
			       void (*errcb)(void *channel,
					     int peer_fd, int gossip_fd,
					     const struct crypto_state *cs,
					     const struct channel_id *channel_id,
					     const char *desc,
					     const u8 *err_for_them),
			       void (*billboardcb)(void *channel, bool perm,
						   const char *happenings),
			       ...)
{
	va_list ap;
	struct subd *sd;

	va_start(ap, billboardcb);
	sd = new_subd(ld, name, channel, base_log, talks_to_peer, msgname,
		      msgcb, errcb, billboardcb, &ap);
	va_end(ap);
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
	       void (*replycb)(struct subd *, const u8 *, const int *, void *),
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
	log_debug(sd->log, "Shutting down");

	tal_del_destructor(sd, destroy_subd);

	/* This should make it exit; steal so it stays around. */
	tal_steal(sd->ld, sd);
	sd->conn = tal_free(sd->conn);

	/* Wait for a while. */
	while (seconds) {
		if (waitpid(sd->pid, NULL, WNOHANG) > 0) {
			return;
		}
		sleep(1);
		seconds--;
	}

	/* Didn't die?  This will kill it harder */
	sd->must_not_exit = false;
	destroy_subd(sd);
	tal_free(sd);
}

void subd_release_channel(struct subd *owner, void *channel)
{
	/* If owner is a per-peer-daemon, and not already freeing itself... */
	if (owner->channel) {
		assert(owner->channel == channel);
		owner->channel = NULL;
		tal_free(owner);
	}
}

#if DEVELOPER
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

	if (memeq(permfail, r, "permfail", strlen("permfail")))
		return true;

	/* Nope, restore. */
	if (lseek(ld->dev_disconnect_fd, -r, SEEK_CUR) < 0) {
		fatal("lseek failure");
	}
	return false;
}
#endif /* DEVELOPER */
