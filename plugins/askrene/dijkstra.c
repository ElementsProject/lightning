#define NDEBUG 1
#include "config.h"
#include <plugins/askrene/dijkstra.h>

/* In the heap we keep node idx, but in this structure we keep the distance
 * value associated to every node, and their position in the heap as a pointer
 * so that we can update the nodes inside the heap when the distance label is
 * changed.
 *
 * Therefore this is no longer a multipurpose heap, the node_idx must be an
 * index between 0 and less than max_num_nodes. */
struct dijkstra {
	//
	s64 *distance;
	u32 *base;
	u32 **heapptr;
	size_t heapsize;
	struct gheap_ctx gheap_ctx;
};

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

/* Allocation of resources for the heap. */
struct dijkstra *dijkstra_new(const tal_t *ctx, size_t max_num_nodes)
{
	struct dijkstra *dijkstra = tal(ctx, struct dijkstra);

	dijkstra->distance = tal_arr(dijkstra,s64,max_num_nodes);
	dijkstra->base = tal_arr(dijkstra,u32,max_num_nodes);
	dijkstra->heapptr = tal_arrz(dijkstra,u32*,max_num_nodes);

	dijkstra->heapsize=0;

	dijkstra->gheap_ctx.fanout=2;
	dijkstra->gheap_ctx.page_chunks=1024;
	dijkstra->gheap_ctx.item_size=sizeof(dijkstra->base[0]);
	dijkstra->gheap_ctx.less_comparer=dijkstra_less_comparer;
	dijkstra->gheap_ctx.less_comparer_ctx=NULL;
	dijkstra->gheap_ctx.item_mover=dijkstra_item_mover;

	return dijkstra;
}


void dijkstra_init(struct dijkstra *dijkstra)
{
	const size_t max_num_nodes = tal_count(dijkstra->distance);
	dijkstra->heapsize=0;
	for(size_t i=0;i<max_num_nodes;++i)
	{
		dijkstra->distance[i]=INFINITE;
		dijkstra->heapptr[i] = NULL;
	}
}
size_t dijkstra_size(const struct dijkstra *dijkstra)
{
	return dijkstra->heapsize;
}

size_t dijkstra_maxsize(const struct dijkstra *dijkstra)
{
	return tal_count(dijkstra->distance);
}

static void dijkstra_append(struct dijkstra *dijkstra, u32 node_idx, s64 distance)
{
	assert(dijkstra_size(dijkstra) < dijkstra_maxsize(dijkstra));
	assert(node_idx < dijkstra_maxsize(dijkstra));

	const size_t pos = dijkstra->heapsize;

	dijkstra->base[pos]=node_idx;
	dijkstra->distance[node_idx]=distance;
	dijkstra->heapptr[node_idx] = &(dijkstra->base[pos]);
	dijkstra->heapsize++;
}

void dijkstra_update(struct dijkstra *dijkstra, u32 node_idx, s64 distance)
{
	assert(node_idx < dijkstra_maxsize(dijkstra));

	if(!dijkstra->heapptr[node_idx])
	{
		// not in the heap
		dijkstra_append(dijkstra, node_idx,distance);
		global_dijkstra = dijkstra;
		gheap_restore_heap_after_item_increase(
			&dijkstra->gheap_ctx,
			dijkstra->base,
			dijkstra->heapsize,
			dijkstra->heapptr[node_idx]
				- dijkstra->base);
		global_dijkstra = NULL;
		return;
	}

	if(dijkstra->distance[node_idx] > distance)
	{
		// distance decrease
		dijkstra->distance[node_idx] = distance;

		global_dijkstra = dijkstra;
		gheap_restore_heap_after_item_increase(
			&dijkstra->gheap_ctx,
			dijkstra->base,
			dijkstra->heapsize,
			dijkstra->heapptr[node_idx]
				- dijkstra->base);
		global_dijkstra = NULL;
	}else
	{
		// distance increase
		dijkstra->distance[node_idx] = distance;

		global_dijkstra = dijkstra;
		gheap_restore_heap_after_item_decrease(
			&dijkstra->gheap_ctx,
			dijkstra->base,
			dijkstra->heapsize,
			dijkstra->heapptr[node_idx]
				- dijkstra->base);
		global_dijkstra = NULL;

	}
  	// assert(gheap_is_heap(&dijkstra->gheap_ctx,
	//                      dijkstra->base,
	// 		     dijkstra_size()));
}

u32 dijkstra_top(const struct dijkstra *dijkstra)
{
	return dijkstra->base[0];
}

bool dijkstra_empty(const struct dijkstra *dijkstra)
{
	return dijkstra->heapsize==0;
}

void dijkstra_pop(struct dijkstra *dijkstra)
{
	if(dijkstra->heapsize==0)
		return;

	const u32 top = dijkstra_top(dijkstra);
	assert(dijkstra->heapptr[top]==dijkstra->base);

	global_dijkstra = dijkstra;
	gheap_pop_heap(
		&dijkstra->gheap_ctx,
		dijkstra->base,
		dijkstra->heapsize--);
	global_dijkstra = NULL;

	dijkstra->heapptr[top]=NULL;
}

const s64* dijkstra_distance_data(const struct dijkstra *dijkstra)
{
	return dijkstra->distance;
}
