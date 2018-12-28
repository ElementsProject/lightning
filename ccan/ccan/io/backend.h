/* Licensed under LGPLv2.1+ - see LICENSE file for details */
#ifndef CCAN_IO_BACKEND_H
#define CCAN_IO_BACKEND_H
#include <stdbool.h>
#include "io_plan.h"
#include <ccan/list/list.h>

struct fd {
	int fd;
	bool listener;
	size_t backend_info;
};

/* Listeners create connections. */
struct io_listener {
	struct fd fd;

	const tal_t *ctx;

	/* These are for connections we create. */
	struct io_plan *(*init)(struct io_conn *conn, void *arg);
	void *arg;
};

enum io_plan_status {
	/* As before calling next function. */
	IO_UNSET,
	/* Normal, but haven't started yet. */
	IO_POLLING_NOTSTARTED,
	IO_POLLING_STARTED,
	/* Waiting for io_wake */
	IO_WAITING,
	/* Always do this. */
	IO_ALWAYS
};

/**
 * struct io_plan - one half of I/O to do
 * @status: the status of this plan.
 * @io: function to call when fd becomes read/writable, returns 0 to be
 *      called again, 1 if it's finished, and -1 on error (fd will be closed)
 * @next: the next function which is called if io returns 1.
 * @next_arg: the argument to @next
 * @u1, @u2: scratch space for @io.
 */
struct io_plan {
	enum io_plan_status status;

	int (*io)(int fd, struct io_plan_arg *arg);

	struct io_plan *(*next)(struct io_conn *, void *next_arg);
	void *next_arg;

	struct io_plan_arg arg;
};

/* One connection per client. */
struct io_conn {
	struct fd fd;

	/* always list. */
	struct list_node always;

	void (*finish)(struct io_conn *, void *arg);
	void *finish_arg;

	struct io_plan plan[2];
};

extern void *io_loop_return;

bool add_listener(struct io_listener *l);
bool add_conn(struct io_conn *c);
bool add_duplex(struct io_conn *c);
void del_listener(struct io_listener *l);
void cleanup_conn_without_close(struct io_conn *c);
void backend_new_always(struct io_conn *conn);
void backend_new_plan(struct io_conn *conn);
void remove_from_always(struct io_conn *conn);
void backend_plan_done(struct io_conn *conn);

void backend_wake(const void *wait);

void io_ready(struct io_conn *conn, int pollflags);
void io_do_always(struct io_conn *conn);
void io_do_wakeup(struct io_conn *conn, enum io_direction dir);
void *do_io_loop(struct io_conn **ready);
#endif /* CCAN_IO_BACKEND_H */
