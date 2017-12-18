#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "permute_tx.h"
#include <assert.h>

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const u8 *our_script,
				   const u8 *their_script,
				   const struct bitcoin_txid *anchor_txid,
				   unsigned int anchor_index,
				   u64 anchor_satoshis,
				   uint64_t to_us, uint64_t to_them,
				   uint64_t dust_limit)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0;

	assert(to_us + to_them <= anchor_satoshis);

	/* BOLT #3:
	 *
	 * ## Closing Transaction
	 *
	 * Note that there are two possible variants for each node.
	 *
	 * * version: 2
	 * * locktime: 0
	 * * txin count: 1
	 */
	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, 1, 2);

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_index;
	tx->input[0].amount = tal_dup(tx->input, u64, &anchor_satoshis);

	if (to_us >= dust_limit) {
		/* One output is to us. */
		tx->output[num_outputs].amount = to_us;
		tx->output[num_outputs].script = tal_dup_arr(tx, u8,
					   our_script, tal_count(our_script), 0);
		num_outputs++;
	}

	if (to_them >= dust_limit) {
		/* Other output is to them. */
		tx->output[num_outputs].amount = to_them;
		tx->output[num_outputs].script = tal_dup_arr(tx, u8,
					   their_script, tal_count(their_script),
					   0);
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);
	tal_resize(&tx->output, num_outputs);

	permute_outputs(tx->output, num_outputs, NULL);
	return tx;
}
