#ifndef LIGHTNING_ANCHOR_H
#define LIGHTNING_ANCHOR_H
#include <ccan/tal/tal.h>
#include "lightning.pb-c.h"

struct sha256_double;

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

/* Add these scriptsigs to the anchor transaction. */
bool anchor_add_scriptsigs(struct bitcoin_tx *anchor,
			   OpenAnchorScriptsigs *ssigs1,
			   OpenAnchorScriptsigs *ssigs2,
			   const size_t *inmap);

/* We wouldn't need the leak files if we had normalized txids! */
void anchor_txid(struct bitcoin_tx *anchor,
		 const char *leakfile1, const char *leakfile2,
		 const size_t *inmap,
		 struct sha256_double *txid);
#endif /* LIGHTNING_ANCHOR_H */
