#include "anchor.h"
#include "bitcoin_tx.h"
#include "overflows.h"
#include "pkt.h"
#include "permute_tx.h"
#include "bitcoin_script.h"

struct bitcoin_tx *anchor_tx_create(const tal_t *ctx,
				    const OpenChannel *o1,
				    const OpenChannel *o2,
				    size_t **inmapp, size_t **outmapp)
{
	uint64_t i, n_out;
	struct bitcoin_tx *tx;
	u8 *redeemscript;
	size_t *inmap, *outmap;

	if (add_overflows_size_t(o1->anchor->n_inputs, o2->anchor->n_inputs))
		return tal_free(tx);

	n_out = 1 + !!o1->anchor->change + !!o2->anchor->change;
	tx = bitcoin_tx(ctx, o1->anchor->n_inputs+o2->anchor->n_inputs, n_out);

	/* Override version to use lesser of two versions. */
	if (o1->tx_version < o2->tx_version)
		tx->version = o1->tx_version;
	else
		tx->version = o2->tx_version;
	
	/* Populate inputs. */
	for (i = 0; i < o1->anchor->n_inputs; i++) {
		BitcoinInput *pb = o1->anchor->inputs[i];
		struct bitcoin_tx_input *in = &tx->input[i];
		proto_to_sha256(pb->txid, &in->txid.sha);
		in->index = pb->output;
		/* Leave inputs as stubs for now, for signing. */
	}
	for (i = 0; i < o2->anchor->n_inputs; i++) {
		BitcoinInput *pb = o2->anchor->inputs[i];
		struct bitcoin_tx_input *in
			= &tx->input[o1->anchor->n_inputs + i];
		proto_to_sha256(pb->txid, &in->txid.sha);
		in->index = pb->output;
		/* Leave inputs as stubs for now, for signing. */
	}

	/* Populate outputs. */
	if (add_overflows_u64(o1->anchor->total, o2->anchor->total))
		return tal_free(tx);

	/* Make the 2 of 2 payment for the commitment txs. */
	redeemscript = bitcoin_redeem_2of2(tx, o1->anchor->pubkey,
					   o2->anchor->pubkey);
	tx->output[0].amount = o1->anchor->total + o2->anchor->total;
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Add change transactions (if any) */
	n_out = 1;
	if (o1->anchor->change) {
		struct bitcoin_tx_output *out = &tx->output[n_out++];
		out->amount = o1->anchor->change->amount;
		out->script_length = o1->anchor->change->script.len;
		out->script = o1->anchor->change->script.data;
	}
	if (o2->anchor->change) {
		struct bitcoin_tx_output *out = &tx->output[n_out++];
		out->amount = o2->anchor->change->amount;
		out->script_length = o2->anchor->change->script.len;
		out->script = o2->anchor->change->script.data;
	}
	assert(n_out == tx->output_count);
	
	if (inmapp)
		inmap = *inmapp = tal_arr(ctx, size_t, tx->input_count);
	else
		inmap = NULL;

	if (outmapp)
		outmap = *outmapp = tal_arr(ctx, size_t, tx->output_count);
	else
		outmap = NULL;
		
	permute_inputs(o1->seed, o2->seed, 0, tx->input, tx->input_count,
		       inmap);
	permute_outputs(o1->seed, o2->seed, 0, tx->output, tx->output_count,
			outmap);
	return tx;
}

	
