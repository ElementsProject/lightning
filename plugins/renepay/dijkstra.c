#include "config.h"
#include <plugins/renepay/dijkstra.h>

static const s64 INFINITE = INT64_MAX;

/* Required a global dijkstra for gheap. */
static struct dijkstra *global_dijkstra;

/* The heap comparer for Dijkstra search. Since the top element must be the one
 * with the smallest distance, we use the operator >, rather than <. */
static int dijkstra_less_comparer(
	const void *const ctx UNUSED,
	const void *const a,
	const void *const b)
{
	return global_dijkstra->distance[*(u32*)a]
		> global_dijkstra->distance[*(u32*)b];
}

/* The heap move operator for Dijkstra search. */
static void dijkstra_item_mover(void *const dst, const void *const src)
{
	u32 src_idx = *(u32*)src;
	*(u32*)dst = src_idx;

	// we keep track of the pointer position of each element in the heap,
	// for easy update.
	global_dijkstra->heapptr[src_idx] = dst;
}

/* Destructor for global dijkstra. The valid free state is signalled with a
 * NULL ptr. */
static void dijkstra_destroy(struct dijkstra *ptr UNUSED)
{
	global_dijkstra=NULL;
}

/* Manually release dijkstra resources. */
void dijkstra_free(void)
{
	if(global_dijkstra)
	{
		global_dijkstra = tal_free(global_dijkstra);
	}
}

/* Allocation of resources for the heap. */
void dijkstra_malloc(const tal_t *ctx, const size_t max_num_nodes)
{
	dijkstra_free();

	global_dijkstra = tal(ctx,struct dijkstra);
	tal_add_destructor(global_dijkstra,dijkstra_destroy);

	global_dijkstra->distance = tal_arr(global_dijkstra,s64,max_num_nodes);
	global_dijkstra->base = tal_arr(global_dijkstra,u32,max_num_nodes);
	global_dijkstra->heapptr = tal_arrz(global_dijkstra,u32*,max_num_nodes);

	global_dijkstra->heapsize=0;

	global_dijkstra->gheap_ctx.fanout=2;
	global_dijkstra->gheap_ctx.page_chunks=1024;
	global_dijkstra->gheap_ctx.item_size=sizeof(global_dijkstra->base[0]);
	global_dijkstra->gheap_ctx.less_comparer=dijkstra_less_comparer;
	global_dijkstra->gheap_ctx.less_comparer_ctx=NULL;
	global_dijkstra->gheap_ctx.item_mover=dijkstra_item_mover;
}


void dijkstra_init(void)
{
	const size_t max_num_nodes = tal_count(global_dijkstra->distance);
	global_dijkstra->heapsize=0;
	for(size_t i=0;i<max_num_nodes;++i)
	{
		global_dijkstra->distance[i]=INFINITE;
		global_dijkstra->heapptr[i] = NULL;
	}
}
size_t dijkstra_size(void)
{
	return global_dijkstra->heapsize;
}

size_t dijkstra_maxsize(void)
{
	return tal_count(global_dijkstra->distance);
}

static void dijkstra_append(u32 node_idx, s64 distance)
{
	assert(dijkstra_size() < dijkstra_maxsize());
	assert(node_idx < dijkstra_maxsize());

	const size_t pos = global_dijkstra->heapsize;

	global_dijkstra->base[pos]=node_idx;
	global_dijkstra->distance[node_idx]=distance;
	global_dijkstra->heapptr[node_idx] = &(global_dijkstra->base[pos]);
	global_dijkstra->heapsize++;
}
void dijkstra_update(u32 node_idx, s64 distance)
{
	assert(node_idx < dijkstra_maxsize());

	if(!global_dijkstra->heapptr[node_idx])
	{
		// not in the heap
		dijkstra_append(node_idx,distance);
		gheap_restore_heap_after_item_increase(
			&global_dijkstra->gheap_ctx,
			global_dijkstra->base,
			global_dijkstra->heapsize,
			global_dijkstra->heapptr[node_idx]
				- global_dijkstra->base);
		return;
	}

	if(global_dijkstra->distance[node_idx] > distance)
	{
		// distance decrease
		global_dijkstra->distance[node_idx] = distance;

		gheap_restore_heap_after_item_increase(
			&global_dijkstra->gheap_ctx,
			global_dijkstra->base,
			global_dijkstra->heapsize,
			global_dijkstra->heapptr[node_idx]
				- global_dijkstra->base);
	}else
	{
		// distance increase
		global_dijkstra->distance[node_idx] = distance;

		gheap_restore_heap_after_item_decrease(
			&global_dijkstra->gheap_ctx,
			global_dijkstra->base,
			global_dijkstra->heapsize,
			global_dijkstra->heapptr[node_idx]
				- global_dijkstra->base);

	}
  	// assert(gheap_is_heap(&global_dijkstra->gheap_ctx,
	//                      global_dijkstra->base,
	// 		     dijkstra_size()));
}
u32 dijkstra_top(void)
{
	return global_dijkstra->base[0];
}
bool dijkstra_empty(void)
{
	return global_dijkstra->heapsize==0;
}
void dijkstra_pop(void)
{
	if(global_dijkstra->heapsize==0)
		return;

	const u32 top = dijkstra_top();
	assert(global_dijkstra->heapptr[top]==global_dijkstra->base);

	gheap_pop_heap(
		&global_dijkstra->gheap_ctx,
		global_dijkstra->base,
		global_dijkstra->heapsize--);

	global_dijkstra->heapptr[top]=NULL;
}
const s64* dijkstra_distance_data(void)
{
	return global_dijkstra->distance;
}
