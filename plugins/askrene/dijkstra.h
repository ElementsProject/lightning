#ifndef LIGHTNING_PLUGINS_ASKRENE_DIJKSTRA_H
#define LIGHTNING_PLUGINS_ASKRENE_DIJKSTRA_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <gheap.h>

/* Allocation of resources for the heap. */
struct dijkstra *dijkstra_new(const tal_t *ctx, size_t max_num_nodes);

/* Initialization of the heap for a new Dijkstra search. */
void dijkstra_init(struct dijkstra *dijkstra);

/* Inserts a new element in the heap. If node_idx was already in the heap then
 * its distance value is updated. */
void dijkstra_update(struct dijkstra *dijkstra, u32 node_idx, s64 distance);

u32 dijkstra_top(const struct dijkstra *dijkstra);
bool dijkstra_empty(const struct dijkstra *dijkstra);
void dijkstra_pop(struct dijkstra *dijkstra);

const s64* dijkstra_distance_data(const struct dijkstra *dijkstra);

/* Number of elements on the heap. */
size_t dijkstra_size(const struct dijkstra *dijkstra);

/* Maximum number of elements the heap can host */
size_t dijkstra_maxsize(const struct dijkstra *dijkstra);

#endif /* LIGHTNING_PLUGINS_ASKRENE_DIJKSTRA_H */
