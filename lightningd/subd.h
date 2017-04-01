#ifndef LIGHTNING_LIGHTNINGD_SUBD_H
#define LIGHTNING_LIGHTNINGD_SUBD_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <lightningd/msg_queue.h>

struct io_conn;

/* By convention, replies are requests + 100 */
#define SUBD_REPLY_OFFSET 100

/* One of our subds. */
struct subd {
	/* Name, like John, or "lightningd_hsm" */
	const char *name;
	/* The Big Cheese. */
	struct lightningd *ld;
	/* pid, for waiting for status when it dies. */
	int pid;
	/* Connection. */
	struct io_conn *conn;

	/* If we are associated with a single peer, this points to it. */
	struct peer *peer;

	/* For logging */
	struct log *log;

	/* Callback when non-reply message comes in. */
	int (*msgcb)(struct subd *, const u8 *, const int *);
	const char *(*msgname)(int msgtype);
	void (*finished)(struct subd *sd, int status);

	/* Buffer for input. */
	u8 *msg_in;

	/* While we're reading fds in. */
	size_t num_fds_in_read;
	int *fds_in;

	/* Messages queue up here. */
	struct msg_queue outq;

	/* Callbacks for replies. */
	struct list_head reqs;
};

/**
 * new_subd - create a new subdaemon.
 * @ctx: context to allocate from
 * @ld: global state
 * @name: basename of daemon
 * @peer: peer to take ownership of if non-NULL
 * @msgname: function to get name from messages
 * @msgcb: function to call when non-fatal message received (or NULL)
 * @finished: function to call when it's finished (with exit status).
 * @...: the fds to hand as fd 3, 4... terminated with -1.
 *
 * @msgcb gets called with @fds set to NULL: if it returns a positive number,
 * that many @fds are received before calling again.  If it returns -1, the
 * subdaemon is shutdown.
 *
 * If this succeeds subd owns @peer.
 */
struct subd *new_subd(const tal_t *ctx,
		      struct lightningd *ld,
		      const char *name,
		      struct peer *peer,
		      const char *(*msgname)(int msgtype),
		      int (*msgcb)(struct subd *, const u8 *, const int *fds),
		      void (*finished)(struct subd *, int), ...);

/**
 * subd_send_msg - queue a message to the subdaemon.
 * @sd: subdaemon to request
 * @msg_out: message (can be take)
 */
void subd_send_msg(struct subd *sd, const u8 *msg_out);

/**
 * subd_send_msg - queue a file descriptor to pass to the subdaemon.
 * @sd: subdaemon to request
 * @fd: the file descriptor (closed after passing).
 */
void subd_send_fd(struct subd *sd, int fd);

/**
 * subd_req - queue a request to the subdaemon.
 * @ctx: lifetime for the callback: if this is freed, don't call replycb.
 * @sd: subdaemon to request
 * @msg_out: request message (can be take)
 * @fd_out: if >=0 fd to pass at the end of the message (closed after)
 * @num_fds_in: how many fds to read in to hand to @replycb.
 * @replycb: callback when reply comes in, returns false to shutdown daemon.
 * @replycb_data: final arg to hand to @replycb
 *
 * @replycb cannot free @sd, so it returns false to remove it.
 */
#define subd_req(ctx, sd, msg_out, fd_out, num_fds_in, replycb, replycb_data) \
	subd_req_((ctx), (sd), (msg_out), (fd_out), (num_fds_in),	\
		  typesafe_cb_preargs(bool, void *,			\
				      (replycb), (replycb_data),	\
				      struct subd *,			\
				      const u8 *, const int *),		\
		       (replycb_data))
void subd_req_(const tal_t *ctx,
	       struct subd *sd,
	       const u8 *msg_out,
	       int fd_out, size_t num_fds_in,
	       bool (*replycb)(struct subd *, const u8 *, const int *, void *),
	       void *replycb_data);

char *opt_subd_debug(const char *optarg, struct lightningd *ld);

#endif /* LIGHTNING_LIGHTNINGD_SUBD_H */
