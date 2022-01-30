#include "config.h"
#include <ccan/closefrom/closefrom.h>
#include <ccan/err/err.h>
#include <ccan/io/fdpass/fdpass.h>
#include <ccan/mem/mem.h>
#include <ccan/noerr/noerr.h>
#include <ccan/tal/path/path.h>
#include <ccan/tal/str/str.h>
#include <common/memleak.h>
#include <common/peer_status_wiregen.h>
#include <common/status_wiregen.h>
#include <common/version.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/lightningd.h>
#include <lightningd/log_status.h>
#include <lightningd/peer_fd.h>
#include <lightningd/subd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <wire/wire_io.h>

void maybe_subd_child(struct lightningd *ld, int childpid, int wstatus)
{
	struct subd *sd;

	list_for_each(&ld->subds, sd, list) {
		if (sd->pid == childpid)
			sd->wstatus = tal_dup(sd, int, &wstatus);
	}
}

/* Carefully move fd *@from to @to: on success *from set to to */
static bool move_fd(int *from, int to)
{
	assert(*from >= 0);

	/* dup2 with same arguments may be a no-op, but
	 * the later close would make the fd invalid.
	 * Handle this edge case.
	 */
	if (*from == to)
		return true;

	if (dup2(*from, to) == -1)
		return false;

	/* dup2 does not duplicate flags, copy it here.
	 * This should be benign; the only POSIX-defined
	 * flag is FD_CLOEXEC, and we only use it rarely.
	 */
	if (fcntl(to, F_SETFD, fcntl(*from, F_GETFD)) < 0)
		return false;

	close(*from);
	*from = to;
	return true;
}

/* Returns index of fds which is == this fd, or -1 */
static int fd_used(int **fds, size_t num_fds, int fd)
{
	for (size_t i = 0; i < num_fds; i++) {
		if (*fds[i] == fd)
			return i;
	}
	return -1;
}

/* Move an series of fd pointers into 0, 1, ... */
static bool shuffle_fds(int **fds, size_t num_fds)
{
	/* If we need to move an fd out the way, this is a good place to start
	 * looking */
	size_t next_free_fd = num_fds;
	for (size_t i = 0; i < num_fds; i++) {
		int in_the_way;

		/* Already in the right place?  Great! */
		if (*fds[i] == i)
			continue;
		/* Is something we care about in the way? */
		in_the_way = fd_used(fds + i, num_fds - i, i);
		if (in_the_way != -1) {
			/* Find a high-numbered unused fd. */
			while (fd_used(fds + i, num_fds - i, next_free_fd) != -1)
				next_free_fd++;
			/* Trick: in_the_way is offset by i! */
			if (!move_fd(fds[i + in_the_way], next_free_fd))
				return false;
			next_free_fd++;
		}

		/* Now there should be nothing in the way. */
		assert(fd_used(fds, num_fds, i) == -1);
		if (!move_fd(fds[i], i))
			return false;
	}
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
		sr->disabler = notleak(tal(ctx, char));
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
static int subd(const char *path, const char *name,
		const char *debug_subdaemon,
		int *msgfd,
		bool io_logging,
		va_list *ap)
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
		size_t num_args;
		char *args[] = { NULL, NULL, NULL, NULL };
		int **fds = tal_arr(tmpctx, int *, 3);
		int stdoutfd = STDOUT_FILENO, stderrfd = STDERR_FILENO;

		close(childmsg[0]);
		close(execfail[0]);

		/* msg = STDIN (0) */
		fds[0] = &childmsg[1];
		/* These are untouched */
		fds[1] = &stdoutfd;
		fds[2] = &stderrfd;

		while ((fd = va_arg(*ap, int *)) != NULL) {
			assert(*fd != -1);
			tal_arr_expand(&fds, fd);
		}

		/* Finally, the fd to report exec errors on */
		tal_arr_expand(&fds, &execfail[1]);

		if (!shuffle_fds(fds, tal_count(fds)))
			goto child_errno_fail;

		/* Make (fairly!) sure all other fds are closed. */
		closefrom(tal_count(fds));

		num_args = 0;
		args[num_args++] = tal_strdup(NULL, path);
		if (io_logging)
			args[num_args++] = "--log-io";
#if DEVELOPER
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

static bool handle_peer_error(struct subd *sd, const u8 *msg, int fds[1])
{
	void *channel = sd->channel;
	struct channel_id channel_id;
	char *desc;
	struct peer_fd *peer_fd;
	u8 *err_for_them;
	bool warning;

	if (!fromwire_status_peer_error(msg, msg,
					&channel_id, &desc, &warning,
					&err_for_them))
		return false;

	peer_fd = new_peer_fd_arr(msg, fds);

	/* Don't free sd; we may be about to free channel. */
	sd->channel = NULL;
	sd->errcb(channel, peer_fd, &channel_id, desc, warning, err_for_them);
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

static bool handle_version(struct subd *sd, const u8 *msg)
{
	char *ver;

	if (!fromwire_status_version(msg, msg, &ver))
		return false;

	if (!streq(ver, version())) {
		log_broken(sd->log, "version '%s' not '%s': restarting",
			   ver, version());
		sd->ld->try_reexec = true;
		/* Return us to toplevel lightningd.c */
		io_break(sd->ld);
		return false;
	}

	sd->rcvd_version = true;
	/* In case there are outgoing msgs, we can send now. */
	msg_wake(sd->outq);

	return true;
}

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd)
{
	int type = fromwire_peektype(sd->msg_in);
	struct subd_req *sr;
	struct db *db = sd->ld->wallet->db;
	struct io_plan *plan;
	unsigned int i;
	bool freed = false;

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
	switch ((enum status_wire)type) {
	case WIRE_STATUS_LOG:
	case WIRE_STATUS_IO:
		if (!log_status_msg(sd->log, sd->node_id, sd->msg_in))
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
	case WIRE_STATUS_VERSION:
		if (!handle_version(sd, sd->msg_in))
			goto close;
		goto next;
	}

	if (sd->channel) {
		switch ((enum peer_status_wire)type) {
		case WIRE_STATUS_PEER_ERROR:
			/* We expect 1 fd after this */
			if (!sd->fds_in) {
				/* Don't free msg_in: we go around again. */
				tal_steal(sd, sd->msg_in);
				plan = sd_collect_fds(conn, sd, 1);
				goto out;
			}
			if (!handle_peer_error(sd, sd->msg_in, sd->fds_in))
				goto malformed;
			goto close;
		}
	}

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
	bool fail_if_subd_fails;

	fail_if_subd_fails = IFDEV(sd->ld->dev_subdaemon_fail, false);
	list_del_from(&sd->ld->subds, &sd->list);

	/* lightningd may have already done waitpid() */
	if (sd->wstatus != NULL) {
		status = *sd->wstatus;
	} else {
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
			log_broken(sd->log, "Status closed, but waitpid %i says %s",
				   sd->pid, strerror(errno));
			status = -1;
			break;
		}
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
		outer_transaction = db_in_transaction(db);
		if (!outer_transaction)
			db_begin_transaction(db);
		if (sd->errcb)
			sd->errcb(channel, NULL, NULL,
				  tal_fmt(sd, "Owning subdaemon %s died (%i)",
					  sd->name, status),
				  false, NULL);
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
	const u8 *msg;
	int fd;

	/* Don't send if we haven't read version! */
	if (!sd->rcvd_version)
		return msg_queue_wait(conn, sd->outq, msg_send_next, sd);

	/* Nothing to do?  Wait for msg_enqueue. */
	msg = msg_dequeue(sd->outq);
	if (!msg)
		return msg_queue_wait(conn, sd->outq, msg_send_next, sd);

	fd = msg_extract_fd(sd->outq, msg);
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
			     const struct node_id *node_id,
			     struct log *base_log,
			     bool talks_to_peer,
			     const char *(*msgname)(int msgtype),
			     unsigned int (*msgcb)(struct subd *,
						   const u8 *, const int *fds),
			     void (*errcb)(void *channel,
					   struct peer_fd *peer_fd,
					   const struct channel_id *channel_id,
					   const char *desc,
					   bool warning,
					   const u8 *err_for_them),
			     void (*billboardcb)(void *channel,
						 bool perm,
						 const char *happenings),
			     va_list *ap)
{
	struct subd *sd = tal(ld, struct subd);
	int msg_fd;
	const char *debug_subd = NULL;
	const char *shortname;

	assert(name != NULL);

	/* This part of the name is a bit redundant for logging */
	if (strstarts(name, "lightning_"))
		shortname = name + strlen("lightning_");
	else
		shortname = name;

	if (base_log) {
		sd->log = new_log(sd, ld->log_book, node_id,
				  "%s-%s", shortname, log_prefix(base_log));
	} else {
		sd->log = new_log(sd, ld->log_book, node_id, "%s", shortname);
	}

#if DEVELOPER
	debug_subd = ld->dev_debug_subprocess;
#endif /* DEVELOPER */

	const char *path = subdaemon_path(tmpctx, ld, name);

	sd->pid = subd(path, name, debug_subd,
		       &msg_fd,
		       /* We only turn on subdaemon io logging if we're going
			* to print it: too stressful otherwise! */
		       log_print_level(sd->log) < LOG_DBG,
		       ap);
	if (sd->pid == (pid_t)-1) {
		log_unusual(ld->log, "subd %s failed: %s",
			    name, strerror(errno));
		return tal_free(sd);
	}
	sd->ld = ld;

	sd->name = shortname;
	sd->must_not_exit = false;
	sd->talks_to_peer = talks_to_peer;
	sd->msgname = msgname;
	assert(msgname);
	sd->msgcb = msgcb;
	assert(msgcb);
	sd->errcb = errcb;
	sd->billboardcb = billboardcb;
	sd->fds_in = NULL;
	sd->outq = msg_queue_new(sd, true);
	sd->wstatus = NULL;
	list_add(&ld->subds, &sd->list);
	tal_add_destructor(sd, destroy_subd);
	list_head_init(&sd->reqs);
	sd->channel = channel;
	sd->rcvd_version = false;
	sd->node_id = tal_dup_or_null(sd, struct node_id, node_id);

	/* conn actually owns daemon: we die when it does. */
	sd->conn = io_new_conn(ld, msg_fd, msg_setup, sd);
	tal_steal(sd->conn, sd);

	log_peer_debug(sd->log, node_id, "pid %u, msgfd %i", sd->pid, msg_fd);

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
	sd = new_subd(ld, name, NULL, NULL, NULL, false,
		      msgname, msgcb, NULL, NULL, &ap);
	va_end(ap);

	sd->must_not_exit = true;
	return sd;
}

struct subd *new_channel_subd_(struct lightningd *ld,
			       const char *name,
			       void *channel,
			       const struct node_id *node_id,
			       struct log *base_log,
			       bool talks_to_peer,
			       const char *(*msgname)(int msgtype),
			       unsigned int (*msgcb)(struct subd *, const u8 *,
						     const int *fds),
			       void (*errcb)(void *channel,
					     struct peer_fd *peer_fd,
					     const struct channel_id *channel_id,
					     const char *desc,
					     bool warning,
					     const u8 *err_for_them),
			       void (*billboardcb)(void *channel, bool perm,
						   const char *happenings),
			       ...)
{
	va_list ap;
	struct subd *sd;

	va_start(ap, billboardcb);
	sd = new_subd(ld, name, channel, node_id, base_log,
		      talks_to_peer, msgname, msgcb, errcb, billboardcb, &ap);
	va_end(ap);
	return sd;
}

void subd_send_msg(struct subd *sd, const u8 *msg_out)
{
	u16 type = fromwire_peektype(msg_out);
	/* FIXME: We should use unique upper bits for each daemon, then
	 * have generate-wire.py add them, just assert here. */
	assert(!strstarts(sd->msgname(type), "INVALID"));
	msg_enqueue(sd->outq, msg_out);
}

void subd_send_fd(struct subd *sd, int fd)
{
	msg_enqueue_fd(sd->outq, fd);
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

/* SIGALRM terminates by default: we just want it to interrupt waitpid(),
 * which is implied by "handling" it. */
static void discard_alarm(int sig UNNEEDED)
{
}

struct subd *subd_shutdown(struct subd *sd, unsigned int seconds)
{
	struct sigaction sa, old;

	log_debug(sd->log, "Shutting down");

	tal_del_destructor(sd, destroy_subd);

	/* This should make it exit; steal so it stays around. */
	tal_steal(sd->ld, sd);
	sd->conn = tal_free(sd->conn);

	/* Set up alarm to wake us up if child doesn't exit. */
	sa.sa_handler = discard_alarm;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, &old);
	alarm(seconds);

	if (waitpid(sd->pid, NULL, 0) > 0) {
		alarm(0);
		sigaction(SIGALRM, &old, NULL);
		list_del_from(&sd->ld->subds, &sd->list);
		return tal_free(sd);
	}

	sigaction(SIGALRM, &old, NULL);
	/* Didn't die?  This will kill it harder */
	sd->must_not_exit = false;
	destroy_subd(sd);
	return tal_free(sd);
}

void subd_shutdown_remaining(struct lightningd *ld)
{
	struct subd *subd;

	/* We give them a second to finish exiting, before we kill
	 * them in destroy_subd() */
	sleep(1);

	while ((subd = list_top(&ld->subds, struct subd, list)) != NULL) {
		/* Destructor removes from list */
		io_close(subd->conn);
	}
}

void subd_release_channel(struct subd *owner, const void *channel)
{
	/* If owner is a per-peer-daemon, and not already freeing itself... */
	if (owner->channel) {
		assert(owner->channel == channel);
		owner->channel = NULL;
		tal_free(owner);
	}
}

#if DEVELOPER
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

/* Ugly helper to get full pathname of the current binary. */
const char *find_my_abspath(const tal_t *ctx, const char *argv0)
{
	char *me;

	/* A command containing / is run relative to the current directory,
	 * not searched through the path.  The shell sets argv0 to the command
	 * run, though something else could set it to a arbitrary value and
	 * this logic would be wrong. */
	if (strchr(argv0, PATH_SEP)) {
		const char *path;
		/* Absolute paths are easy. */
		if (strstarts(argv0, PATH_SEP_STR))
			path = argv0;
		/* It contains a '/', it's relative to current dir. */
		else
			path = path_join(tmpctx, path_cwd(tmpctx), argv0);

		me = path_canon(ctx, path);
		if (!me || access(me, X_OK) != 0)
			errx(1, "I cannot find myself at %s based on my name %s",
			     path, argv0);
	} else {
		/* No /, search path */
		char **pathdirs;
		const char *pathenv = getenv("PATH");
		size_t i;

		/* This replicates the standard shell path search algorithm */
		if (!pathenv)
			errx(1, "Cannot find myself: no $PATH set");

		pathdirs = tal_strsplit(tmpctx, pathenv, ":", STR_NO_EMPTY);
		me = NULL;
		for (i = 0; pathdirs[i]; i++) {
			/* This returns NULL if it doesn't exist. */
			me = path_canon(ctx,
					path_join(tmpctx, pathdirs[i], argv0));
			if (me && access(me, X_OK) == 0)
				break;
			/* Nope, try again. */
			me = tal_free(me);
		}
		if (!me)
			errx(1, "Cannot find %s in $PATH", argv0);
	}

	return me;
}
