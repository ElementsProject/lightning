#include "io_lock.h"
#include <assert.h>
#include <ccan/io/io_plan.h>

struct io_lock {
	bool locked;
};

/* Struct to hold information while we wait for the lock to be freed */
struct io_lock_waiter {
	struct io_plan *(*next)(struct io_conn *conn, void *next_arg);
	void *arg;
	struct io_lock *lock;
	enum io_direction dir;
};

struct io_lock *io_lock_new(const tal_t *ctx)
{
	struct io_lock *lock = tal(ctx, struct io_lock);
	lock->locked = false;
	return lock;
}

static struct io_plan *io_lock_try_acquire(struct io_conn *conn,
					   struct io_lock_waiter *waiter)
{
	/* Destructure waiter, since we might be freeing it below */
	struct io_plan *(*next)(struct io_conn *, void *) = waiter->next;
	void *next_arg = waiter->arg;

	if (!waiter->lock->locked) {
		waiter->lock->locked = true;
		tal_free(waiter);
		return next(conn, next_arg);
	} else {
		switch (waiter->dir) {
		case IO_IN:
			return io_wait(conn, waiter->lock, io_lock_try_acquire,
				       waiter);
		case IO_OUT:
			return io_out_wait(conn, waiter->lock,
					   io_lock_try_acquire, waiter);
		}
		/* Should not happen if waiter->dir is a valid enum
		 * value */
		abort();
	}
}

static struct io_plan *io_lock_acquire_dir(
    struct io_conn *conn, struct io_lock *lock, enum io_direction dir,
    struct io_plan *(*next)(struct io_conn *, void *), void *arg)
{
	/* FIXME: We can avoid one allocation if we lock and call next here directly */
	struct io_lock_waiter *waiter = tal(lock, struct io_lock_waiter);
	waiter->next = next;
	waiter->arg = arg;
	waiter->lock = lock;
	waiter->dir = dir;
	return io_lock_try_acquire(conn, waiter);
}

struct io_plan *
io_lock_acquire_out_(struct io_conn *conn, struct io_lock *lock,
		 struct io_plan *(*next)(struct io_conn *, void *), void *arg)
{
	return io_lock_acquire_dir(conn, lock, IO_OUT, next, arg);
}

struct io_plan *
io_lock_acquire_in_(struct io_conn *conn, struct io_lock *lock,
		    struct io_plan *(*next)(struct io_conn *, void *), void *arg)
{
	return io_lock_acquire_dir(conn, lock, IO_IN, next, arg);
}

void io_lock_release(struct io_lock *lock)
{
	assert(lock->locked);
	lock->locked = false;
	io_wake(lock);
}

bool io_lock_taken(const struct io_lock *lock)
{
	return lock->locked;
}
