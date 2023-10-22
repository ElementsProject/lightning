#ifndef LIGHTNING_LIGHTNINGD_SUBD_H
#define LIGHTNING_LIGHTNINGD_SUBD_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <common/msg_queue.h>
#include <wire/wire.h>

struct crypto_state;
struct io_conn;
struct peer_fd;

/* By convention, replies are requests + 100 */
#define SUBD_REPLY_OFFSET 100
/* And reply failures are requests + 200 */
#define SUBD_REPLYFAIL_OFFSET 200

/* One of our subds. */
struct subd {
	/* Inside ld->subds */
	struct list_node list;

	/* Name, like John, or "lightning_hsmd" */
	const char *name;
	/* The Big Cheese. */
	struct lightningd *ld;
	/* pid, for waiting for status when it dies. */
	int pid;
	/* Connection. */
	struct io_conn *conn;

	/* If we are associated with a single channel, this points to it. */
	void *channel;

	/* Have we received the version msg yet?  Don't send until we do. */
	bool rcvd_version;

	/* For logging */
	struct logger *log;
	const struct node_id *node_id;

	/* Callback when non-reply message comes in (inside db transaction) */
	unsigned (*msgcb)(struct subd *, const u8 *, const int *);
	const char *(*msgname)(int msgtype);

	/* If peer_fd == NULL, it was a disconnect/crash.  Otherwise,
	 * sufficient information to hand back to gossipd, including the
	 * error message we sent them if any. */
	void (*errcb)(void *channel,
		      struct peer_fd *peer_fd,
		      const char *desc,
		      const u8 *err_for_them,
		      bool disconnect,
		      bool warning);

	/* Callback to display information for listpeers RPC */
	void (*billboardcb)(void *channel, bool perm, const char *happenings);

	/* Buffer for input. */
	u8 *msg_in;

	/* While we're reading fds in. */
	size_t num_fds_in_read;
	int *fds_in;

	/* For global daemons: we fail if they fail. */
	bool must_not_exit;

	/* Do we talk to a peer?  ie. not onchaind */
	bool talks_to_peer;

	/* Messages queue up here. */
	struct msg_queue *outq;

	/* Callbacks for replies. */
	struct list_head reqs;

	/* Did lightningd already wait for this pid? */
	int *wstatus;
};

/**
 * new_global_subd - create a new global subdaemon.
 * @ld: global state
 * @name: basename of daemon
 * @msgname: function to get name from messages
 * @msgcb: function to call (inside db transaction) when non-fatal message received
 * @...: NULL-terminated list of pointers to  fds to hand as fd 3, 4...
 *	(can be take, if so, set to -1)
 *
 * @msgcb gets called with @fds set to NULL: if it returns a positive number,
 * that many @fds are received before calling again.  @msgcb can free subd
 * to shut it down.
 */
struct subd *new_global_subd(struct lightningd *ld,
			     const char *name,
			     const char *(*msgname)(int msgtype),
			     unsigned int (*msgcb)(struct subd *, const u8 *,
						   const int *fds),
			     ...);

/**
 * new_channel_subd - create a new subdaemon for a specific channel.
 * @ctx: context to allocate from (usually peer or channel)
 * @ld: global state
 * @name: basename of daemon
 * @channel: channel to associate.
 * @node_id: node_id of peer, for logging.
 * @base_log: log to use (actually makes a copy so it has name in prefix)
 * @msgname: function to get name from messages
 * @msgcb: function to call (inside db transaction) when non-fatal message received (or NULL)
 * @errcb: function to call on errors.
 * @billboardcb: function to call for billboard updates.
 * @...: NULL-terminated list of pointers to  fds to hand as fd 3, 4...
 *	(can be take, if so, set to -1)
 *
 * @msgcb gets called with @fds set to NULL: if it returns a positive number,
 * that many @fds are received before calling again.  If it returns -1, the
 * subdaemon is shutdown.
 */
struct subd *new_channel_subd_(const tal_t *ctx,
			       struct lightningd *ld,
			       const char *name,
			       void *channel,
			       const struct node_id *node_id,
			       struct logger *base_log,
			       bool talks_to_peer,
			       const char *(*msgname)(int msgtype),
			       unsigned int (*msgcb)(struct subd *, const u8 *,
						     const int *fds),
			       void (*errcb)(void *channel,
					     struct peer_fd *peer_fd,
					     const char *desc,
					     const u8 *err_for_them,
					     bool disconnect,
					     bool warning),
			       void (*billboardcb)(void *channel, bool perm,
						   const char *happenings),
			       ...);

#define new_channel_subd(ctx, ld, name, channel, node_id, log, 		\
			 talks_to_peer, msgname, msgcb, errcb, 		\
			 billboardcb, ...)				\
	new_channel_subd_((ctx), (ld), (name), (channel), (node_id),	\
			  (log), (talks_to_peer),			\
			  (msgname), (msgcb),				\
			  typesafe_cb_postargs(void, void *, (errcb),	\
					       (channel),		\
					       struct peer_fd *,	\
					       const char *, const u8 *, bool, bool), \
			  typesafe_cb_postargs(void, void *, (billboardcb), \
					       (channel), bool,		\
					       const char *),		\
			  __VA_ARGS__)

/**
 * subd_send_msg - queue a message to the subdaemon.
 * @sd: subdaemon to request
 * @msg_out: message (can be take)
 */
void subd_send_msg(struct subd *sd, const u8 *msg_out);

/**
 * subd_send_fd - queue a file descriptor to pass to the subdaemon.
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
 * @num_fds_in: how many fds to read in to hand to @replycb if it's a reply.
 * @replycb: callback (inside db transaction) when reply comes in (can free subd)
 * @replycb_data: final arg to hand to @replycb
 *
 * @replycb cannot free @sd, so it returns false to remove it.
 * Note that @replycb is called for replies of type @msg_out + SUBD_REPLY_OFFSET
 * with @num_fds_in fds, or type @msg_out + SUBD_REPLYFAIL_OFFSET with no fds.
 */
#define subd_req(ctx, sd, msg_out, fd_out, num_fds_in, replycb, replycb_data) \
	subd_req_((ctx), (sd), (msg_out), (fd_out), (num_fds_in),	\
		  typesafe_cb_preargs(void, void *,			\
				      (replycb), (replycb_data),	\
				      struct subd *,			\
				      const u8 *, const int *),		\
		       (replycb_data))
struct subd_req *subd_req_(const tal_t *ctx,
	       struct subd *sd,
	       const u8 *msg_out,
	       int fd_out, size_t num_fds_in,
	       void (*replycb)(struct subd *, const u8 *, const int *, void *),
	       void *replycb_data);

/**
 * subd_release_channel - shut down a subdaemon which no longer owns the channel.
 * @owner: subd which owned channel.
 * @channel: channel to release.
 *
 * If the subdaemon is not already shutting down, and it is a per-channel
 * subdaemon, this shuts it down.  Don't call this directly, use
 * channel_set_owner() or uncommitted_channel_release_subd().
 */
void subd_release_channel(struct subd *owner, const void *channel);

/**
 * subd_shutdown - try to politely shut down a (global) subdaemon.
 * @subd: subd to shutdown.
 * @seconds: maximum seconds to wait for it to exit.
 *
 * This closes the fd to the subdaemon, and gives it a little while to exit.
 * The @finished callback will never be called.
 *
 * Return value is null, so pattern should be:
 *
 * sd = subd_shutdown(sd, 10);
 */
struct subd *subd_shutdown(struct subd *subd, unsigned int seconds);

/**
 * subd_shutdown_nonglobals - kill all per-peer subds
 * @ld: lightningd
 */
void subd_shutdown_nonglobals(struct lightningd *ld);

/* Ugly helper to get full pathname of the current binary. */
const char *find_my_abspath(const tal_t *ctx, const char *argv0);

/* lightningd captures SIGCHLD and waits, but so does subd. */
void maybe_subd_child(struct lightningd *ld, int childpid, int wstatus);

char *opt_subd_dev_disconnect(const char *optarg, struct lightningd *ld);

bool dev_disconnect_permanent(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_SUBD_H */
