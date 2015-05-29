#ifndef LIGHTNING_ANCHOR_H
#define LIGHTNING_ANCHOR_H
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

/* Create an anchor transaction based on both sides' requests.
 * The scriptSigs are left empty.
 *
 * Allocate an input and output map (if non-NULL); the first
 * o1->anchor->n_inputs of inmap are the location of o1's inputs, the
 * next o2->anchor->n_inputs are o2's.  outmap[0] is the location of
 * output for the commitment tx, then o1's change (if
 * o1->anchor->change), then o2's change if o2->anchor->change.
 */
struct bitcoin_tx *anchor_tx_create(const tal_t *ctx,
				    const OpenChannel *o1,
				    const OpenChannel *o2,
				    size_t **inmap, size_t **outmap);
#endif /* LIGHTNING_ANCHOR_H */
