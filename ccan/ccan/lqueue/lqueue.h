/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_LQUEUE_H
#define CCAN_LQUEUE_H

#include <stdbool.h>
#include <stdio.h>
#include <assert.h>

#include <ccan/tcon/tcon.h>

/**
 * struct lqueue_link - a queue link
 * @next: next entry, or front of queue, if this is the back
 *
 * This is used as a link within a queue entry.
 *
 * Example:
 *	struct waiter {
 *		char *name;
 *		struct lqueue_link ql;
 *	};
 */
struct lqueue_link {
	struct lqueue_link *next;
};

/**
 * struct lqueue_ - a queue (internal type)
 * @b: the back of the queue (NULL if empty)
 */
struct lqueue_ {
	struct lqueue_link *back;
};

/**
 * LQUEUE - declare a queue
 * @type: the type of elements in the queue
 * @link: the field containing the lqueue_link in @type
 *
 * The LQUEUE macro declares an lqueue.  It can be prepended by
 * "static" to define a static lqueue.  The queue begins in undefined
 * state, you must either initialize with LQUEUE_INIT, or call
 * lqueue_init() before using it.
 *
 * See also:
 *	lqueue_init()
 *
 * Example:
 *	struct element {
 *		int value;
 *		struct lqueue_link link;
 *	};
 *	LQUEUE(struct element, link) my_queue;
 */
#define LQUEUE(etype, link)						\
	TCON_WRAP(struct lqueue_,					\
		  TCON_CONTAINER(canary, etype, link))

/**
 * LQUEUE_INIT - initializer for an empty queue
 *
 * The LQUEUE_INIT macro returns a suitable initializer for a queue
 * defined with LQUEUE.
 *
 * Example:
 *	struct element {
 *		int value;
 *		struct lqueue_link link;
 *	};
 *	LQUEUE(struct element, link) my_queue = LQUEUE_INIT;
 *
 *	assert(lqueue_empty(&my_queue));
 */
#define LQUEUE_INIT				\
	TCON_WRAP_INIT({ NULL, })

/**
 * lqueue_entry - convert an lqueue_link back into the structure containing it.
 * @q: the queue
 * @l: the lqueue_link
 *
 * Example:
 *	struct waiter {
 *		char *name;
 *		struct lqueue_link ql;
 *	} w;
 *	LQUEUE(struct waiter, ql) my_queue;
 *	assert(lqueue_entry(&my_queue, &w.ql) == &w);
 */
#define lqueue_entry(q_, l_) tcon_container_of((q_), canary, (l_))

/**
 * lqueue_init_from_back - initialize a queue with a specific back element
 * @s: the lqueue to initialize
 * @e: pointer to the back element of the new queue
 *
 * USE WITH CAUTION: This is for handling unusual cases where you have
 * a pointer to an element in a previously constructed queue but can't
 * conveniently pass around a normal struct lqueue.  Usually you
 * should use lqueue_init().
 *
 * Example:
 *	struct element {
 *		int value;
 *		struct lqueue_link link;
 *	} el;
 *	LQUEUE(struct element, link) queue1;
 *	LQUEUE(struct element, link) queue2;
 *
 *	lqueue_enqueue(&queue1, &el);
 *
 *	lqueue_init_from_back(&queue2, lqueue_back(&queue1));
 */
#define lqueue_init_from_back(q_, e_)					\
	(lqueue_init_(tcon_unwrap(q_), tcon_member_of((q_), canary, (e_))))

/**
 * lqueue_init - initialize a queue
 * @h: the lqueue to set to an empty queue
 *
 * Example:
 *	struct element {
 *		int value;
 *		struct lqueue_link link;
 *	};
 *	LQUEUE(struct element, link) *qp = malloc(sizeof(*qp));
 *	lqueue_init(qp);
 */
#define lqueue_init(q_) \
	(lqueue_init_(tcon_unwrap(q_), NULL))
static inline void lqueue_init_(struct lqueue_ *q, struct lqueue_link *back)
{
	q->back = back;
}

/**
 * lqueue_empty - is a queue empty?
 * @q: the queue
 *
 * If the queue is empty, returns true.
 */
#define lqueue_empty(q_) \
	lqueue_empty_(tcon_unwrap(q_))
static inline bool lqueue_empty_(const struct lqueue_ *q)
{
	return (q->back == NULL);
}

/**
 * lqueue_front - get front entry in a queue
 * @q: the queue
 *
 * If the queue is empty, returns NULL.
 *
 * Example:
 *	struct element *f;
 *
 *	f = lqueue_front(qp);
 *	assert(lqueue_dequeue(qp) == f);
 */
#define lqueue_front(q_) \
	lqueue_entry((q_), lqueue_front_(tcon_unwrap(q_)))
static inline struct lqueue_link *lqueue_front_(const struct lqueue_ *q)
{
	if (!q->back)
		return NULL;
	else
		return q->back->next;
}

/**
 * lqueue_back - get back entry in a queue
 * @q: the queue
 *
 * If the queue is empty, returns NULL.
 *
 * Example:
 *	struct element b;
 *
 *	lqueue_enqueue(qp, &b);
 *	assert(lqueue_back(qp) == &b);
 */
#define lqueue_back(q_) \
	lqueue_entry((q_), lqueue_back_(tcon_unwrap(q_)))
static inline struct lqueue_link *lqueue_back_(const struct lqueue_ *q)
{
	return q->back;
}

/**
 * lqueue_enqueue - add an entry to the back of a queue
 * @q: the queue to add the node to
 * @e: the item to enqueue
 *
 * The lqueue_link does not need to be initialized; it will be overwritten.
 */
#define lqueue_enqueue(q_, e_)			\
	lqueue_enqueue_(tcon_unwrap(q_), tcon_member_of((q_), canary, (e_)))
static inline void lqueue_enqueue_(struct lqueue_ *q, struct lqueue_link *e)
{
	if (lqueue_empty_(q)) {
		/* New entry will be both front and back of queue */
		e->next = e;
		q->back = e;
	} else {
		e->next = lqueue_front_(q);
		q->back->next = e;
		q->back = e;
	}
}

/**
 * lqueue_dequeue - remove and return the entry from the front of the queue
 * @q: the queue
 *
 * Note that this leaves the returned entry's link in an undefined
 * state; it can be added to another queue, but not deleted again.
 */
#define lqueue_dequeue(q_) \
	lqueue_entry((q_), lqueue_dequeue_(tcon_unwrap(q_)))
static inline struct lqueue_link *lqueue_dequeue_(struct lqueue_ *q)
{
	struct lqueue_link *front;

	if (lqueue_empty_(q))
		return NULL;

	front = lqueue_front_(q);
	if (front == lqueue_back_(q)) {
		assert(front->next == front);
		q->back = NULL;
	} else {
		q->back->next = front->next;
	}
	return front;
}

#endif /* CCAN_LQUEUE_H */
