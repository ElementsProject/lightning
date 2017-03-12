#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/path/path.h>
#include <daemon/log.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/gen_subd_wire.h>
#include <lightningd/lightningd.h>
#include <lightningd/subd.h>
#include <status.h>
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

/* FIXME: Expose the ccan/io version? */
static void set_blocking(int fd, bool block)
{
	int flags = fcntl(fd, F_GETFL);

	if (block)
		flags &= ~O_NONBLOCK;
	else
		flags |= O_NONBLOCK;

	fcntl(fd, F_SETFL, flags);
}

struct subd_req {
	struct list_node list;

	/* Callback for a reply. */
	int reply_type;
	bool (*replycb)(struct subd *, const u8 *msg_in, void *reply_data);
	void *replycb_data;
	int *fd_in;
	u32 request_id;
};

static void free_subd_req(struct subd_req *sr)
{
	list_del(&sr->list);
}

static struct subd_req *add_req(struct subd *sd, int type,
		    bool (*replycb)(struct subd *, const u8 *, void *),
		    void *replycb_data,
		    int *reply_fd_in)
{
	struct subd_req *sr = tal(sd, struct subd_req);
	static u32 request_num = 0;

	sr->reply_type = type + SUBD_REPLY_OFFSET;
	sr->replycb = replycb;
	sr->replycb_data = replycb_data;
	sr->fd_in = reply_fd_in;
	sr->request_id = request_num;
	request_num++;

	if (sr->fd_in)
		*sr->fd_in = -1;
	assert(strends(sd->msgname(sr->reply_type), "_REPLY"));

	/* Keep in FIFO order: we sent in order, so replies will be too. */
	list_add_tail(&sd->reqs, &sr->list);
	tal_add_destructor(sr, free_subd_req);
	return sr;
}

/* Caller must free. */
static struct subd_req *get_req_by_id(struct subd *sd, u32 request_id)
{
	struct subd_req *sr;

	list_for_each(&sd->reqs, sr, list) {
		if (sr->request_id == request_id)
			return sr;
	}
	return NULL;
}

/* We use sockets, not pipes, because fds are bidir. */
static int subd(const char *dir, const char *name, bool debug,
		     int *msgfd, va_list ap)
{
	int childmsg[2], execfail[2];
	pid_t childpid;
	int err, fd;

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
		int fdnum = 3;
		long max;
		const char *debug_arg = NULL;

		close(childmsg[0]);
		close(execfail[0]);

		// msg = STDIN
		if (childmsg[1] != STDIN_FILENO) {
			if (!move_fd(childmsg[1], STDIN_FILENO))
				goto child_errno_fail;
		}

		/* Dup any extra fds up first. */
		while ((fd = va_arg(ap, int)) != -1) {
			/* If this were stdin, dup2 closed! */
			assert(fd != STDIN_FILENO);
			if (!move_fd(fd, fdnum))
				goto child_errno_fail;
			fdnum++;
		}
		close(STDOUT_FILENO);

		/* Make (fairly!) sure all other fds are closed. */
		max = sysconf(_SC_OPEN_MAX);
		for (fd = fdnum; fd < max; fd++)
			close(fd);

		if (debug)
			debug_arg = "--debugger";
		execl(path_join(NULL, dir, name), name, debug_arg, NULL);

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

	while ((fd = va_arg(ap, int)) != -1)
		close(fd);

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

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd);

static struct io_plan *sd_msg_reply(struct io_conn *conn, struct subd *sd,
				    struct subd_req *sr, u8 flags)
{
	int type = fromwire_peektype(sd->msg_in);
	bool keep_open;

	if (sr->fd_in) {
		/* Don't trust subd to set it blocking. */
		set_blocking(*sr->fd_in, true);
		log_info(sd->log, "REPLY %s with fd %i", sd->msgname(type),
			 *sr->fd_in);
	} else
		log_info(sd->log, "REPLY %s", sd->msgname(type));

	/* If not stolen, we'll free this below. */
	tal_steal(sr, sd->msg_in);
	keep_open = sr->replycb(sd, sd->msg_in, sr->replycb_data);

	/* If this was the last reply in the stream discard the stored request. */
	if (flags & SUBD_FINAL_REPLY)
		tal_free(sr);

	if (!keep_open)
		return io_close(conn);

	return io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd);
}

static struct io_plan *sd_msg_read(struct io_conn *conn, struct subd *sd)
{
	int type = fromwire_peektype(sd->msg_in);
	const char *str;
	int str_len;
	const tal_t *tmpctx;
	struct subd_req *sr;
	u32 request_id;
	u8 *reply;
	u8 reply_flags;

	if (type == -1) {
		log_unusual(sd->log, "ERROR: Invalid msg output");
		return io_close(conn);
	}

	if (type == WIRE_SUBD_REPLY) {
		/* Unwrap to get to the reply metadata */
		fromwire_subd_reply(sd, sd->msg_in, NULL, &request_id, &reply_flags, &reply);
		sr = get_req_by_id(sd, request_id);

		/* If we need fd, read it and call us again. */
		if (sr->fd_in && *sr->fd_in == -1) {
			/* Don't leave junk around, we'll reparse it
			 * on the next pass */
			tal_free(reply);
			return io_recv_fd(conn, sr->fd_in, sd_msg_read, sd);
		}

		/* No need to keep the wrapped message around, and
		 * callees expect the sd to hold a pointer to the
		 * message. */
		tal_free(sd->msg_in);
		sd->msg_in = reply;

		return sd_msg_reply(conn, sd, sr, reply_flags);
	}
	/* If not stolen, we'll free this below. */
	tmpctx = tal_tmpctx(sd);
	tal_steal(tmpctx, sd->msg_in);

	/* If it's a string. */
	str_len = tal_count(sd->msg_in) - sizeof(be16);
	str = (const char *)sd->msg_in + sizeof(be16);

	if (type == STATUS_TRACE)
		log_debug(sd->log, "TRACE: %.*s", str_len, str);
	else if (type & STATUS_FAIL)
		log_unusual(sd->log, "FAILURE %s: %.*s",
			    sd->msgname(type), str_len, str);
	else {
		log_info(sd->log, "UPDATE %s", sd->msgname(type));
		if (sd->msgcb) {
			enum subd_msg_ret r;

			/* If received from subd, set blocking. */
			if (sd->fd_in != -1)
				set_blocking(sd->fd_in, true);
			r = sd->msgcb(sd, sd->msg_in, sd->fd_in);
			switch (r) {
			case SUBD_NEED_FD:
				/* Don't free msg_in: we go around again. */
				tal_steal(sd, sd->msg_in);
				tal_free(tmpctx);
				return io_recv_fd(conn, &sd->fd_in,
						  sd_msg_read, sd);
			case SUBD_COMPLETE:
				break;
			default:
				fatal("Unknown msgcb return for %s:%s: %u",
				      sd->name, sd->msgname(type), r);
			}
		}
	}
	sd->msg_in = NULL;
	sd->fd_in = -1;
	tal_free(tmpctx);
	return io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd);
}

static void destroy_subd(struct subd *sd)
{
	int status;

	switch (waitpid(sd->pid, &status, WNOHANG)) {
	case 0:
		log_debug(sd->log, "Status closed, but not exited. Killing");
		kill(sd->pid, SIGKILL);
		waitpid(sd->pid, &status, 0);
		break;
	case -1:
		log_unusual(sd->log, "Status closed, but waitpid %i says %s",
			    sd->pid, strerror(errno));
		status = -1;
		break;
	}
	if (sd->finished)
		sd->finished(sd, status);
}

static struct io_plan *msg_send_next(struct io_conn *conn, struct subd *sd)
{
	const u8 *msg = msg_dequeue(&sd->outq);

	if (sd->fd_to_close != -1) {
		close(sd->fd_to_close);
		sd->fd_to_close = -1;
	}

	/* Nothing to do?  Wait for msg_enqueue. */
	if (!msg)
		return msg_queue_wait(conn, &sd->outq, msg_send_next, sd);

	/* We overload STATUS_TRACE for outgoing to mean "send an fd" */
	if (fromwire_peektype(msg) == STATUS_TRACE) {
		const u8 *p = msg + sizeof(be16);
		size_t len = tal_count(msg) - sizeof(be16);
		sd->fd_to_close = fromwire_u32(&p, &len);
		tal_free(msg);
		return io_send_fd(conn, sd->fd_to_close, msg_send_next, sd);
	}
	return io_write_wire(conn, take(msg), msg_send_next, sd);
}

static struct io_plan *msg_setup(struct io_conn *conn, struct subd *sd)
{
	return io_duplex(conn,
			 io_read_wire(conn, sd, &sd->msg_in, sd_msg_read, sd),
			 msg_send_next(conn, sd));
}

struct subd *new_subd(const tal_t *ctx,
				struct lightningd *ld,
				const char *name,
				struct peer *peer,
				const char *(*msgname)(int msgtype),
				enum subd_msg_ret (*msgcb)
				(struct subd *, const u8 *, int fd),
				void (*finished)(struct subd *, int),
				...)
{
	va_list ap;
	struct subd *sd = tal(ctx, struct subd);
	int msg_fd;
	bool debug;

	debug = ld->dev_debug_subdaemon
		&& strends(name, ld->dev_debug_subdaemon);
	va_start(ap, finished);
	sd->pid = subd(ld->daemon_dir, name, debug, &msg_fd, ap);
	va_end(ap);
	if (sd->pid == (pid_t)-1) {
		log_unusual(ld->log, "subd %s failed: %s",
			    name, strerror(errno));
		return tal_free(sd);
	}
	sd->ld = ld;
	sd->log = new_log(sd, ld->dstate.log_book, "%s(%u):", name, sd->pid);
	sd->name = name;
	sd->finished = finished;
	sd->msgname = msgname;
	sd->msgcb = msgcb;
	sd->fd_in = -1;
	msg_queue_init(&sd->outq, sd);
	sd->fd_to_close = -1;
	tal_add_destructor(sd, destroy_subd);
	list_head_init(&sd->reqs);

	/* conn actually owns daemon: we die when it does. */
	sd->conn = io_new_conn(ctx, msg_fd, msg_setup, sd);
	tal_steal(sd->conn, sd);

	log_info(sd->log, "pid %u, msgfd %i", sd->pid, msg_fd);

	sd->peer = tal_steal(sd, peer);
	return sd;
}

void subd_send_msg(struct subd *sd, const u8 *msg_out)
{
	/* We overload STATUS_TRACE for outgoing to mean "send an fd" */
	assert(fromwire_peektype(msg_out) != STATUS_TRACE);
	if (!taken(msg_out))
		msg_out = tal_dup_arr(sd, u8, msg_out, tal_len(msg_out), 0);
	msg_enqueue(&sd->outq, msg_out);
}

void subd_send_fd(struct subd *sd, int fd)
{
	/* We overload STATUS_TRACE for outgoing to mean "send an fd" */
	u8 *fdmsg = tal_arr(sd, u8, 0);
	towire_u16(&fdmsg, STATUS_TRACE);
	towire_u32(&fdmsg, fd);
	msg_enqueue(&sd->outq, fdmsg);
}

void subd_req_(struct subd *sd,
	       const u8 *msg_out,
	       int fd_out, int *fd_in,
	       bool (*replycb)(struct subd *, const u8 *, void *),
	       void *replycb_data)
{
	/* Wrap the message in a request so we can keep track of it */
	struct subd_req *sr = add_req(sd, fromwire_peektype(msg_out), replycb, replycb_data, fd_in);
	u8 *request = towire_subd_request(sr, sr->request_id, msg_out);

	subd_send_msg(sd, request);
	if (fd_out >= 0)
		subd_send_fd(sd, fd_out);

}

char *opt_subd_debug(const char *optarg, struct lightningd *ld)
{
	ld->dev_debug_subdaemon = optarg;
	return NULL;
}
