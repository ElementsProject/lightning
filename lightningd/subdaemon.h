#ifndef LIGHTNING_LIGHTNINGD_SUBDAEMON_H
#define LIGHTNING_LIGHTNINGD_SUBDAEMON_H
#include "config.h"
#include <ccan/endian/endian.h>
#include <ccan/list/list.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct io_conn;

enum subdaemon_status {
	STATUS_NEED_FD,
	STATUS_COMPLETE
};

/* One of our subdaemons. */
struct subdaemon {
	/* Name, like John, or "lightningd_hsm" */
	const char *name;
	/* The Big Cheese. */
	struct lightningd *ld;
	/* pid, for waiting for status when it dies. */
	int pid;
	/* Connection for status (read, then write) */
	struct io_conn *status_conn;
	/* Connection for requests if any (write, then read) */
	struct io_conn *req_conn;

	/* For logging */
	struct log *log;

	/* Callback when status comes in. */
	enum subdaemon_status (*statuscb)(struct subdaemon *, const u8 *, int);
	const char *(*statusname)(int status);
	const char *(*reqname)(int req);
	void (*finished)(struct subdaemon *sd, int status);

	/* Buffer for input. */
	u8 *status_in;
	int status_fd_in;

	/* Requests queue up here. */
	struct list_head reqs;
};

/**
 * new_subdaemon - create a new subdaemon.
 * @ctx: context to allocate from
 * @ld: global state
 * @name: basename of daemon
 * @statusname: function to get name from status messages
 * @reqname: function to get name from request messages, or NULL if no requests.
 * @statuscb: function to call when status message received (or NULL)
 * @finished: function to call when it's finished (with exit status).
 * @...: the fds to hand as fd 3, 4... terminated with -1.
 *
 * @statuscb is called with fd == -1 when a status message is
 * received; if it returns STATUS_NEED_FD, we read an fd from the
 * daemon and call it again with that as the third arg.
 */
struct subdaemon *new_subdaemon(const tal_t *ctx,
				struct lightningd *ld,
				const char *name,
				const char *(*statusname)(int status),
				const char *(*reqname)(int req),
				enum subdaemon_status (*statuscb)
				(struct subdaemon *, const u8 *, int fd),
				void (*finished)(struct subdaemon *, int), ...);

/**
 * subdaemon_req - add a request to the subdaemon.
 * @sd: subdaemon to request
 * @msg_out: request message (can be take, can be NULL for fd passing only)
 * @fd_out: if >=0 fd to pass at the end of the message (closed after)
 * @fd_in: if not NULL, where to put fd read in at end of reply.
 * @reqcb: callback when reply comes in
 * @reqcb_data: final arg to hand to @reqcb
 *
 * The subdaemon must take requests.
 */
#define subdaemon_req(sd, msg_out, fd_out, fd_in, reqcb, reqcb_data)	\
	subdaemon_req_((sd), (msg_out), (fd_out), (fd_in),		\
		       typesafe_cb_preargs(void, void *,		\
					   (reqcb), (reqcb_data),	\
					   struct subdaemon *,		\
					   const u8 *),			\
		       (reqcb_data))
void subdaemon_req_(struct subdaemon *sd,
		    const u8 *msg_out,
		    int fd_out, int *fd_in,
		    void (*reqcb)(struct subdaemon *, const u8 *, void *),
		    void *reqcb_data);
#endif /* LIGHTNING_LIGHTNINGD_SUBDAEMON_H */
