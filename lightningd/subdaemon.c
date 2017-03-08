#include <ccan/io/fdpass/fdpass.h>
#include <ccan/io/io.h>
#include <ccan/noerr/noerr.h>
#include <ccan/take/take.h>
#include <ccan/tal/path/path.h>
#include <daemon/log.h>
#include <errno.h>
#include <fcntl.h>
#include <lightningd/gen_common_wire.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subdaemon.h>
#include <status.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

/* A single request/response for subdaemon. */
struct subdaemon_req {
	struct subdaemon *sd;

	/* In sd->reqs */
	struct list_node list;

	/* Request message. */
	const u8 *msg_out;
	int fd_out;

	/* Response */
	u8 *req_in;
	int *fd_in;

	/* Callback when response comes in. */
	void (*req)(struct subdaemon *, const u8 *msg_in, void *req_data);
	void *req_data;
};

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

/* We use sockets, not pipes, because fds are bidir. */
static int subdaemon(const char *dir, const char *name, bool debug,
		     int *statusfd, int *reqfd, va_list ap)
{
	int childreq[2], childstatus[2], execfail[2];
	pid_t childpid;
	int err, fd;

	if (socketpair(AF_LOCAL, SOCK_STREAM, 0, childstatus) != 0)
		goto fail;

	if (reqfd) {
		if (socketpair(AF_LOCAL, SOCK_STREAM, 0, childreq) != 0)
			goto close_childstatus_fail;
	} else {
		childreq[0] = open("/dev/null", O_RDONLY);
		if (childreq[0] < 0)
			goto close_childstatus_fail;
	}

	if (pipe(execfail) != 0)
		goto close_reqfd_fail;

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

		if (reqfd)
			close(childreq[0]);
		close(childstatus[0]);
		close(execfail[0]);

		// Status = STDOUT
		if (childstatus[1] != STDOUT_FILENO) {
			if (!move_fd(childstatus[1], STDOUT_FILENO))
				goto child_errno_fail;
		}
		// Req = STDIN.
		if (childreq[1] != STDIN_FILENO) {
			if (!move_fd(childreq[1], STDIN_FILENO))
				goto child_errno_fail;
		}
		/* Dup any extra fds up first. */
		while ((fd = va_arg(ap, int)) != -1) {
			/* If these were stdin or stdout, dup2 closed! */
			assert(fd != STDIN_FILENO);
			assert(fd != STDOUT_FILENO);
			if (!move_fd(fd, fdnum))
				goto child_errno_fail;
			fdnum++;
		}

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

	if (reqfd)
		close(childreq[1]);
	close(childstatus[1]);
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
	*statusfd = childstatus[0];
	if (reqfd)
		*reqfd = childreq[0];
	return childpid;

close_execfail_fail:
	close_noerr(execfail[0]);
	close_noerr(execfail[1]);
close_reqfd_fail:
	if (reqfd)
		close_noerr(childreq[1]);
	close_noerr(childreq[0]);
close_childstatus_fail:
	close_noerr(childstatus[0]);
	close_noerr(childstatus[1]);
fail:
	return -1;
}

static struct io_plan *status_read(struct io_conn *conn, struct subdaemon *sd);

static struct io_plan *status_process_fd(struct io_conn *conn,
					 struct subdaemon *sd)
{
	const tal_t *tmpctx = tal_tmpctx(sd);

	/* Don't trust subdaemon to set it blocking. */
	set_blocking(sd->status_fd_in, true);

	/* Ensure we free it iff callback doesn't tal_steal it. */
	tal_steal(tmpctx, sd->status_in);
	sd->statuscb(sd, sd->status_in, sd->status_fd_in);
	tal_free(tmpctx);
	sd->status_in = NULL;
	return status_read(conn, sd);
}

/**
 * forward_peer_msg - Got a forward request from a subdaemon, find owner and forward.
 */
static void forward_peer_msg(struct subdaemon *sd, u8 *msg)
{
	u64 peer_id;
	u8 *wrapped;
	struct peer *peer;
	size_t msglen = tal_count(msg);
	fromwire_forward_peer_msg(msg, msg, &msglen, &peer_id, &wrapped);
	peer = find_peer_by_unique_id(sd->ld, peer_id);
	if (!peer) {
		log_unusual(sd->log, "Unable to locate peer with ID %lu, "
				     "dropping forwarded message",
			    peer_id);
		return;
	} else {
		subdaemon_send_msg(peer->owner, take(msg));
	}
}

static struct io_plan *status_process(struct io_conn *conn, struct subdaemon *sd)
{
	int type = fromwire_peektype(sd->status_in);
	const char *str;
	int str_len;
	const tal_t *tmpctx = tal_tmpctx(sd);

	if (type == -1) {
		log_unusual(sd->log, "ERROR: Invalid status output");
		return io_close(conn);
	}

	/* If not stolen, we'll free this below. */
	tal_steal(tmpctx, sd->status_in);

	/* If it's a string. */
	str_len = tal_count(sd->status_in) - sizeof(be16);
	str = (const char *)sd->status_in + sizeof(be16);

	if (type == STATUS_TRACE)
		log_debug(sd->log, "TRACE: %.*s", str_len, str);
	else if (type == WIRE_FORWARD_PEER_MSG){
		log_info(sd->log, "Got a message to forward to peer");
		forward_peer_msg(sd, sd->status_in);

	} else if (type == WIRE_FORWARD_GOSSIP_MSG){
		log_info(sd->log, "Forwarding %s", common_wire_type_name(type));
		subdaemon_send_msg(sd->ld->gossip, take(sd->status_in));
	} else if (type & STATUS_FAIL)
		log_unusual(sd->log, "FAILURE %s: %.*s",
			    sd->statusname(type), str_len, str);
	else {
		log_info(sd->log, "UPDATE %s", sd->statusname(type));
		if (sd->statuscb) {
			enum subdaemon_status s = sd->statuscb(sd,
							       sd->status_in,
							       -1);
			switch (s) {
			case STATUS_NEED_FD:
				tal_steal(sd, sd->status_in);
				tal_free(tmpctx);
				return io_recv_fd(conn, &sd->status_fd_in,
						  status_process_fd, sd);
			case STATUS_COMPLETE:
				break;
			default:
				fatal("Unknown statuscb return for %s:%s: %u",
				      sd->name, sd->statusname(type), s);
			}
		}
	}
	sd->status_in = NULL;
	tal_free(tmpctx);
	return status_read(conn, sd);
}

static struct io_plan *status_read(struct io_conn *conn, struct subdaemon *sd)
{
	return io_read_wire(conn, sd, &sd->status_in, status_process, sd);
}

static struct io_plan *req_next(struct io_conn *conn, struct subdaemon *sd);

static void destroy_subdaemon(struct subdaemon *sd)
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

struct subdaemon *new_subdaemon(const tal_t *ctx,
				struct lightningd *ld,
				const char *name,
				struct peer *peer,
				const char *(*statusname)(int status),
				const char *(*reqname)(int req),
				enum subdaemon_status (*statuscb)
				(struct subdaemon *, const u8 *, int fd),
				void (*finished)(struct subdaemon *, int),
				...)
{
	va_list ap;
	struct subdaemon *sd = tal(ctx, struct subdaemon);
	int req_fd, status_fd;
	bool debug;

	debug = ld->dev_debug_subdaemon && strends(name,ld->dev_debug_subdaemon);
	va_start(ap, finished);
	sd->pid = subdaemon(ld->daemon_dir, name, debug, &status_fd,
			    reqname ? &req_fd : NULL, ap);
	va_end(ap);
	if (sd->pid == (pid_t)-1) {
		log_unusual(ld->log, "subdaemon %s failed: %s",
			    name, strerror(errno));
		return tal_free(sd);
	}
	sd->ld = ld;
	sd->log = new_log(sd, ld->dstate.log_book, "%s(%u):", name, sd->pid);
	sd->name = name;
	sd->finished = finished;
	sd->statusname = statusname;
	sd->statuscb = statuscb;
	list_head_init(&sd->reqs);
	tal_add_destructor(sd, destroy_subdaemon);

	/* Status conn actually owns daemon: we die when it does. */
	sd->status_conn = io_new_conn(ctx, status_fd, status_read, sd);
	tal_steal(sd->status_conn, sd);

	sd->reqname = reqname;
	if (reqname)
		sd->req_conn = io_new_conn(sd, req_fd, req_next, sd);
	else
		sd->req_conn = NULL;
	log_info(sd->log, "pid %u, statusfd %i, reqfd %i",
		 sd->pid, status_fd, req_fd);

	sd->peer = tal_steal(sd, peer);
	return sd;
}

static struct io_plan *req_finished_reply(struct io_conn *conn,
					  struct subdaemon_req *sr)
{
	struct subdaemon *sd = sr->sd;

	/* Don't trust subdaemon to set it blocking. */
	if (sr->fd_in)
		set_blocking(*sr->fd_in, true);

	sr->req(sd, sr->req_in, sr->req_data);
	tal_free(sr);
	return req_next(conn, sd);
}

static struct io_plan *req_process_replymsg(struct io_conn *conn,
					    struct subdaemon_req *sr)
{
	int type = fromwire_peektype(sr->req_in);

	if (type == -1) {
		log_unusual(sr->sd->log, "ERROR: Invalid request output");
		return io_close(conn);
	}
	log_debug(sr->sd->log, "Received req response %s len %zu%s",
		  sr->sd->reqname(type), tal_count(sr->req_in),
		  sr->fd_in ? " (now getting fd)" : "");

	/* If we're supposed to recv an fd, do it now. */
	if (sr->fd_in)
		return io_recv_fd(conn, sr->fd_in, req_finished_reply, sr);
	return req_finished_reply(conn, sr);
}

static struct io_plan *req_read_reply(struct io_conn *conn,
				      struct subdaemon_req *sr)
{
	/* No callback?  Don't expect reply. */
	if (!sr->req) {
		struct subdaemon *sd = sr->sd;
		tal_free(sr);
		return req_next(conn, sd);
	}
	return io_read_wire(conn, sr, &sr->req_in, req_process_replymsg, sr);
}

static struct io_plan *req_close_fd_out(struct io_conn *conn,
					struct subdaemon_req *sr)
{
	close(sr->fd_out);
	return req_read_reply(conn, sr);
}

static struct io_plan *req_sent_msg(struct io_conn *conn,
				    struct subdaemon_req *sr)
{
	/* If we're supposed to pass an fd, do it now. */
	if (sr->fd_out >= 0)
		return io_send_fd(conn, sr->fd_out, req_close_fd_out, sr);
	return req_read_reply(conn, sr);
}

static struct io_plan *req_next(struct io_conn *conn, struct subdaemon *sd)
{
	struct subdaemon_req *sr;

	sr = list_pop(&sd->reqs, struct subdaemon_req, list);
	if (!sr)
		return io_wait(conn, sd, req_next, sd);
	log_debug(sd->log, "Sending req %s len %zu",
		  sd->reqname(fromwire_peektype(sr->msg_out)),
		  tal_count(sr->msg_out));

	return io_write_wire(conn, sr->msg_out, req_sent_msg, sr);
}

void subdaemon_req_(struct subdaemon *sd,
		    const u8 *msg_out, int fd_out, int *fd_in,
		    void (*reqcb)(struct subdaemon *, const u8 *, void *),
		    void *reqcb_data)
{
	struct subdaemon_req *sr = tal(sd, struct subdaemon_req);

	assert(sd->req_conn);

	sr->sd = sd;
	if (msg_out)
		sr->msg_out = tal_dup_arr(sr, u8, msg_out, tal_count(msg_out), 0);
	else
		sr->msg_out = NULL;
	sr->fd_out = fd_out;
	sr->fd_in = fd_in;
	sr->req = reqcb;
	sr->req_data = reqcb_data;
	list_add_tail(&sd->reqs, &sr->list);
	io_wake(sd);
}

char *opt_subdaemon_debug(const char *optarg, struct lightningd *ld)
{
	ld->dev_debug_subdaemon = optarg;
	return NULL;
}
