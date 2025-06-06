#include "config.h"
#include <common/setup.h>
#include <stdlib.h>

#include "../queue.h"

/* a queue for int */
QUEUE_DEFINE_TYPE(int, iqueue);

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	int x;
	struct iqueue q;
	iqueue_init(&q, NULL);

	iqueue_insert(&q, 1);
	x = iqueue_pop(&q);
	assert(x == 1);

	iqueue_insert(&q, 2);
	x = iqueue_pop(&q);
	assert(x == 2);

	iqueue_insert(&q, 3);
	iqueue_insert(&q, 4);
	x = iqueue_pop(&q);
	assert(x == 3);
	x = iqueue_pop(&q);
	assert(x == 4);

	iqueue_insert(&q, 5);
	iqueue_insert(&q, 6);
	x = iqueue_pop(&q);
	assert(x == 5);
	iqueue_insert(&q, 7);
	x = iqueue_pop(&q);
	assert(x == 6);
	x = iqueue_pop(&q);
	assert(x == 7);

	for (int i = 1; i <= 10000; i++)
		iqueue_insert(&q, i);
	for (int i = 1; i <= 10000; i++) {
		x = iqueue_pop(&q);
		assert(x == i);
	}

	const int MAX_ITEM = 1000000;
	int expected_front = 1, next_insert = 1;

	do {
		if (iqueue_empty(&q) && next_insert > MAX_ITEM)
			break;

		if (iqueue_empty(&q)) {
			/* we can only insert */
			iqueue_insert(&q, next_insert++);
		} else if (next_insert > MAX_ITEM) {
			/* we can only pop */
			x = iqueue_pop(&q);
			assert(x == expected_front);
			expected_front++;
		} else {
			/* we can both insert and pop, throw a coin */
			if (rand() % 2) {
				iqueue_insert(&q, next_insert++);
			} else {
				x = iqueue_pop(&q);
				assert(x == expected_front);
				expected_front++;
			}
		}
	} while (1);

	common_shutdown();
	return 0;
}
