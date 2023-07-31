#ifndef LIGHTNING_PLUGINS_RENEPAY_HEAP_H
#define LIGHTNING_PLUGINS_RENEPAY_HEAP_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <gheap.h>
#include <stdint.h>


/* A functionality missing in gheap that can be used to update elements.
 * Input: item
 * Output: the position of the smallest element p, such is greater equal item.
 * Formally:
 * 	Let X={x in heap: !(x<item) }, all the elements that are greater or
 * 	equal item,
 * 	then p in X, and for every x in X: !(x<p), p is the smallest.*/
size_t gheap_upper_bound(const struct gheap_ctx *ctx,
	const void *base, size_t heap_size, void *item);

struct heap_data
{
	u32 idx;
	s64 distance;
};

struct heap
{
	size_t size;
	size_t max_size;
	struct heap_data *data;
	struct gheap_ctx gheap_ctx;
};
struct heap* heap_new(const tal_t *ctx, const size_t max_capacity);
void heap_insert(struct heap* heap, u32 idx, s64 distance);
void heap_update(struct heap* heap, u32 idx, s64 old_distance,s64 new_distance);
bool heap_empty(const struct heap* heap);
void heap_pop(struct heap* heap);
struct heap_data * heap_top(const struct heap * heap);


//------------------------------


static int less_comparer(const void *const ctx UNUSED,
		  const void *const a,
		  const void *const b)
{
	s64 da = ((struct heap_data*)a)->distance,
	    db = ((struct heap_data*)b)->distance;
	u32 ia = ((struct heap_data*)a)->idx,
	    ib = ((struct heap_data*)b)->idx;
	return da==db ? ia > ib : da > db;
}

static void item_mover(void *const dst, const void *const src)
{
	*(struct heap_data*)dst = *(struct heap_data*)src;
}

struct heap* heap_new(const tal_t *ctx, const size_t max_capacity)
{
	struct heap* heap = tal(ctx,struct heap);
	heap->size=0;
	heap->data = tal_arr(heap,struct heap_data,max_capacity);
	heap->max_size = max_capacity;

	heap->gheap_ctx.fanout=2;
	heap->gheap_ctx.page_chunks=1;
	heap->gheap_ctx.item_size= sizeof(struct heap_data);
	heap->gheap_ctx.less_comparer=less_comparer;
	heap->gheap_ctx.less_comparer_ctx=heap;
	heap->gheap_ctx.item_mover=item_mover;

	return heap;
}


void heap_insert(struct heap* heap, u32 idx, s64 distance)
{
	heap->data[heap->size].idx=idx;
	heap->data[heap->size].distance=distance;
	heap->size++;

	assert(heap->size<=heap->max_size);

	gheap_restore_heap_after_item_increase(&heap->gheap_ctx,
					       heap->data,
					       heap->size,
					       heap->size-1);
}
bool heap_empty(const struct heap* heap)
{
	return heap->size==0;
}
struct heap_data * heap_top(const struct heap * heap)
{
	return &heap->data[0];
}
void heap_pop(struct heap* heap)
{
	if(heap->size>0)
		gheap_pop_heap(&heap->gheap_ctx,heap->data,heap->size--);
}

/* Input: item
 * Output: the smallest x such that !(x<item) */
size_t gheap_upper_bound(const struct gheap_ctx *ctx,
	const void *base, size_t heap_size, void *item)
{
	const size_t fanout = ctx->fanout;
	const size_t item_size = ctx->item_size;
	const void*const less_comparer_ctx = ctx->less_comparer_ctx;
	const gheap_less_comparer_t less_comparer = ctx->less_comparer;

	if(less_comparer(less_comparer_ctx,base,item))
	{
		// root<item, so x<=root<item is true for every node
		return heap_size;
	}

	size_t last=0;
	// the root is an upper bound, now let's go down
	while(1)
	{
		// last is an upper bound, seach for a smaller one
		size_t first_child = gheap_get_child_index(ctx,last);
		size_t best_child = last;

		for(size_t i=0;i<fanout;++i)
		{
			size_t child = i+first_child;
			if(child>=heap_size)
				break;
			if(!less_comparer(less_comparer_ctx,
					  ((char*)base) + child*item_size,
					  item))
			{
				// satisfies the condition,
				// is it the smallest one?
				if(!less_comparer(less_comparer_ctx,
				                  ((char*)base) + best_child*item_size,
						  ((char*)base) + child*item_size))
				{
					// child <= best_child, so child is a
					// better upper bound
					best_child = child;
				}
			}
		}

		if(best_child==last)
		{
			// no change, we stop
			break;
		}
		last = best_child;
	}
	return last;
}
void heap_update(struct heap* heap, u32 idx, s64 old_distance, s64 new_distance)
{
	const gheap_less_comparer_t less_comparer = heap->gheap_ctx.less_comparer;
	const void *const less_comparer_ctx = heap->gheap_ctx.less_comparer_ctx;

	struct heap_data old_item = (struct heap_data){.idx=idx, .distance=old_distance};

	size_t pos = gheap_upper_bound(&heap->gheap_ctx,heap->data,heap->size,&old_item);
	if(pos>=heap->size || heap->data[pos].idx!=idx)
	{
		heap_insert(heap,idx,new_distance);
	}
	else
	{
		struct heap_data new_item = (struct heap_data){.idx=idx, .distance=new_distance};

		if(less_comparer(less_comparer_ctx,&new_item,&heap->data[pos]))
		{
			heap->data[pos].distance = new_distance;
			gheap_restore_heap_after_item_decrease(
					&heap->gheap_ctx,
					heap->data,
					heap->size,
					pos);
		}else
		{
			heap->data[pos].distance = new_distance;
			gheap_restore_heap_after_item_increase(
					&heap->gheap_ctx,
					heap->data,
					heap->size,
					pos);
		}
	}
}

#endif /* LIGHTNING_PLUGINS_RENEPAY_HEAP_H */
