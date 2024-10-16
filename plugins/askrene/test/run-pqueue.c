#include "config.h"
#include <assert.h>
#include <ccan/tal/tal.h>
#include <common/setup.h>
#include <inttypes.h>
#include <stdio.h>


#include "../priorityqueue.c"

#define CHECK(arg) if(!(arg)){fprintf(stderr, "failed CHECK at line %d: %s\n", __LINE__, #arg); abort();}

static void priorityqueue_show(struct priorityqueue *q)
{
	printf("size of queue: %zu\n", priorityqueue_size(q));
	printf("empty?: %s\n", priorityqueue_empty(q) ? "true" : "false");
	if (!priorityqueue_empty(q))
		printf("top of the queue: %" PRIu32 "\n", priorityqueue_top(q));
	const s64 *value = priorityqueue_value(q);
	for (u32 i = 0; i < priorityqueue_maxsize(q); i++) {
		printf("(%" PRIu32 ", %" PRIi64 ")", i, value[i]);
	}

	printf("\n\n");
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);
	printf("Hello world!\n");

	printf("Allocating a memory context\n");
	tal_t *ctx = tal(NULL, tal_t);
	CHECK(ctx);

	printf("Allocating a priorityqueue\n");
	struct priorityqueue *q;
	q = priorityqueue_new(ctx, 5);
	CHECK(q);

	/* reset all values */
	priorityqueue_init(q);
	priorityqueue_show(q);
	CHECK(priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==0);

	priorityqueue_update(q, 0, 10);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==1);
	CHECK(priorityqueue_top(q)==0);

	priorityqueue_update(q, 0, 3);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==1);
	CHECK(priorityqueue_top(q)==0);

	priorityqueue_update(q, 1, 3);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==2);
	// CHECK(priorityqueue_top(q)==0);

	priorityqueue_update(q, 1, 5);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==2);
	CHECK(priorityqueue_top(q)==0);

	priorityqueue_update(q, 1, -1);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==2);
	CHECK(priorityqueue_top(q)==1);

	priorityqueue_pop(q);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==1);
	CHECK(priorityqueue_top(q)==0);

	priorityqueue_update(q, 1, 0);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==2);
	CHECK(priorityqueue_top(q)==1);

	priorityqueue_update(q, 4, -10);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==3);
	CHECK(priorityqueue_top(q)==4);

	priorityqueue_pop(q);
	priorityqueue_show(q);
	CHECK(!priorityqueue_empty(q));
	CHECK(priorityqueue_size(q)==2);
	CHECK(priorityqueue_top(q)==1);

	printf("Freeing memory\n");
	ctx = tal_free(ctx);
	common_shutdown();
	return 0;
}
