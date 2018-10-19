#ifndef LIGHTNING_COMMON_IO_LOCK_H
#define LIGHTNING_COMMON_IO_LOCK_H

#include "config.h"
#include <ccan/io/io.h>
#include <ccan/tal/tal.h>
struct io_lock;

/**
 * Create a new lock
 */
struct io_lock *io_lock_new(const tal_t *ctx);

/**
 * Acquire lock @lock before proceeding to @next
 *
 * Attempts to acquire the lock before proceeding with next. If the
 * lock is free this reduces to `io_always`, otherwise we put @conn in
 * wait until we get notified about the lock being released.
 */
#define io_lock_acquire_out(conn, lock, next, arg)                             \
	io_lock_acquire_out_((conn), (lock),                                   \
			     typesafe_cb_preargs(struct io_plan *, void *,     \
						 (next), (arg),                \
						 struct io_conn *),            \
			     (arg))

struct io_plan *io_lock_acquire_out_(struct io_conn *conn, struct io_lock *lock,
				     struct io_plan *(*next)(struct io_conn *,
							     void *),
				     void *arg);

#define io_lock_acquire_in(conn, lock, next, arg)                             \
	io_lock_acquire_in_((conn), (lock),                                   \
			    typesafe_cb_preargs(struct io_plan *, void *, \
						(next), (arg),		\
						struct io_conn *),	\
			    (arg))

struct io_plan *io_lock_acquire_in_(struct io_conn *conn, struct io_lock *lock,
				    struct io_plan *(*next)(struct io_conn *,
							    void *),
				    void *arg);

/**
 * Release the lock and notify waiters so they can proceed.
 */
void io_lock_release(struct io_lock *lock);

/**
 * Is this lock acquired?
 */
bool io_lock_taken(const struct io_lock *lock);

#endif /* LIGHTNING_COMMON_IO_LOCK_H */
