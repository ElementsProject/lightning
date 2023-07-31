#ifndef LIGHTNING_PLUGINS_RENEPAY_DIJKSTRA_H
#define LIGHTNING_PLUGINS_RENEPAY_DIJKSTRA_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <gheap.h>

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

/* Allocation of resources for the heap. */
void dijkstra_malloc(const tal_t *ctx, const size_t max_num_nodes);

/* Manually release dijkstra resources. */
void dijkstra_free(void);

/* Initialization of the heap for a new Dijkstra search. */
void dijkstra_init(void);

/* Inserts a new element in the heap. If node_idx was already in the heap then
 * its distance value is updated. */
void dijkstra_update(u32 node_idx, s64 distance);

u32 dijkstra_top(void);
bool dijkstra_empty(void);
void dijkstra_pop(void);

const s64* dijkstra_distance_data(void);

/* Number of elements on the heap. */
size_t dijkstra_size(void);

/* Maximum number of elements the heap can host */
size_t dijkstra_maxsize(void);

#endif /* LIGHTNING_PLUGINS_RENEPAY_DIJKSTRA_H */
