#include "config.h"

#include <ccan/lqueue/lqueue.h>
#include <ccan/tap/tap.h>

struct waiter {
	const char *name;
	struct lqueue_link ql;
};

int main(void)
{
	LQUEUE(struct waiter, ql) q = LQUEUE_INIT;
	struct waiter a = { "Alice" };
	struct waiter b = { "Bob" };
	struct waiter c = { "Carol" };
	struct waiter *waiter;

	/* This is how many tests you plan to run */
	plan_tests(25);

	ok1(lqueue_empty(&q));
	ok1(lqueue_front(&q) == NULL);
	ok1(lqueue_back(&q) == NULL);

	lqueue_enqueue(&q, &a);

	ok1(!lqueue_empty(&q));
	ok1(lqueue_front(&q) == &a);
	ok1(lqueue_back(&q) == &a);

	lqueue_enqueue(&q, &b);

	ok1(!lqueue_empty(&q));
	ok1(lqueue_front(&q) == &a);
	ok1(lqueue_back(&q) == &b);

	lqueue_enqueue(&q, &c);

	ok1(!lqueue_empty(&q));
	ok1(lqueue_front(&q) == &a);
	ok1(lqueue_back(&q) == &c);

	waiter = lqueue_dequeue(&q);
	ok1(waiter == &a);

	ok1(!lqueue_empty(&q));
	ok1(lqueue_front(&q) == &b);
	ok1(lqueue_back(&q) == &c);

	waiter = lqueue_dequeue(&q);
	ok1(waiter == &b);

	ok1(!lqueue_empty(&q));
	ok1(lqueue_front(&q) == &c);
	ok1(lqueue_back(&q) == &c);

	waiter = lqueue_dequeue(&q);
	ok1(waiter == &c);

	ok1(lqueue_empty(&q));
	ok1(lqueue_front(&q) == NULL);
	ok1(lqueue_back(&q) == NULL);

	ok1(lqueue_dequeue(&q) == NULL);

	/* This exits depending on whether all tests passed */
	return exit_status();
}
