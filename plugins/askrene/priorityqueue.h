#ifndef LIGHTNING_PLUGINS_ASKRENE_PRIORITYQUEUE_H
#define LIGHTNING_PLUGINS_ASKRENE_PRIORITYQUEUE_H

/* Defines a priority queue using gheap. */

#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <gheap.h>

/* Allocation of resources for the heap. */
struct priorityqueue *priorityqueue_new(const tal_t *ctx,
					size_t max_num_elements);

/* Initialization of the heap for a new priorityqueue search. */
void priorityqueue_init(struct priorityqueue *priorityqueue);

/* Inserts a new element in the heap. If node_idx was already in the heap then
 * its value is updated. */
void priorityqueue_update(struct priorityqueue *priorityqueue, u32 key,
			  s64 value);

u32 priorityqueue_top(const struct priorityqueue *priorityqueue);
bool priorityqueue_empty(const struct priorityqueue *priorityqueue);
void priorityqueue_pop(struct priorityqueue *priorityqueue);

const s64 *priorityqueue_value(const struct priorityqueue *priorityqueue);

/* Number of elements on the heap. */
size_t priorityqueue_size(const struct priorityqueue *priorityqueue);

/* Maximum number of elements the heap can host */
size_t priorityqueue_maxsize(const struct priorityqueue *priorityqueue);

#endif /* LIGHTNING_PLUGINS_ASKRENE_PRIORITYQUEUE_H */
