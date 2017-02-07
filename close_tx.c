#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "close_tx.h"
#include "permute_tx.h"
#include "protobuf_convert.h"

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const u8 *our_script,
				   const u8 *their_script,
				   const struct sha256_double *anchor_txid,
				   unsigned int anchor_index,
				   u64 anchor_satoshis,
				   uint64_t to_us, uint64_t to_them)
{
	struct bitcoin_tx *tx;

	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, 1, 2);

	/* Our input spends the anchor tx output. */
	tx->input[0].txid = *anchor_txid;
	tx->input[0].index = anchor_index;
	tx->input[0].amount = tal_dup(tx->input, u64, &anchor_satoshis);

	/* One output is to us. */
	tx->output[0].amount = to_us;
	tx->output[0].script = tal_dup_arr(tx, u8,
					   our_script, tal_count(our_script), 0);

	/* Other output is to them. */
	tx->output[1].amount = to_them;
	tx->output[1].script = tal_dup_arr(tx, u8,
					   their_script, tal_count(their_script),
					   0);

	assert(tx->output[0].amount + tx->output[1].amount <= anchor_satoshis);

	permute_outputs(tx->output, 2, NULL);
	return tx;
}
