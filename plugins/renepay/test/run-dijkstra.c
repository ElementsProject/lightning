#include "config.h"
#include <stdio.h>
#include <assert.h>
#include <common/wireaddr.h>
#include <common/bigsize.h>
#include <common/channel_id.h>
#include <common/setup.h>
#include <common/utils.h>

#include <plugins/renepay/dijkstra.h>

static void insertion_in_increasing_distance(const tal_t *ctx)
{
	dijkstra_malloc(ctx,10);

	for(int i=0;i<dijkstra_maxsize();++i)
	{
		dijkstra_update(i,10+i);
		assert(dijkstra_size()==(i+1));
	}

	dijkstra_update(3,3);
	assert(dijkstra_top()==3);

	dijkstra_update(3,15);
	assert(dijkstra_top()==0);

	dijkstra_update(3,-1);
	assert(dijkstra_top()==3);

	dijkstra_pop();
	assert(dijkstra_size()==9);
	assert(dijkstra_top()==0);

	// Insert again
	dijkstra_update(3,3+10);

	u32 top=0;
	while(!dijkstra_empty())
	{
		assert(top==dijkstra_top());
		top++;
		dijkstra_pop();
	}
}
static void insertion_in_decreasing_distance(const tal_t *ctx)
{
	dijkstra_malloc(ctx,10);

	for(int i=0;i<dijkstra_maxsize();++i)
	{
		dijkstra_update(i,10-i);
		assert(dijkstra_size()==(i+1));
	}

	dijkstra_update(3,-3);
	assert(dijkstra_top()==3);

	dijkstra_update(3,15);
	assert(dijkstra_top()==9);

	dijkstra_update(3,-1);
	assert(dijkstra_top()==3);

	dijkstra_pop();
	assert(dijkstra_size()==9);
	assert(dijkstra_top()==9);

	// Insert again
	dijkstra_update(3,10-3);

	u32 top=9;
	while(!dijkstra_empty())
	{
		assert(top==dijkstra_top());
		top--;
		dijkstra_pop();
	}
}

int main(int argc, char *argv[])
{
	common_setup(argv[0]);

	insertion_in_increasing_distance(NULL);
	insertion_in_decreasing_distance(tmpctx);

	// test dijkstra_free
	dijkstra_free();
	// we can call it twice, no problem
	dijkstra_free();

	// does tal_free() cleansup correctly?
	const tal_t *this_ctx = tal(NULL,tal_t);
	insertion_in_increasing_distance(this_ctx);
	tal_free(this_ctx);
	insertion_in_decreasing_distance(tmpctx);

	common_shutdown();
}
