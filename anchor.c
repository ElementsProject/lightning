#include <ccan/err/err.h>
#include "anchor.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/script.h"
#include "bitcoin/tx.h"
#include "overflows.h"
#include "permute_tx.h"
#include "pkt.h"
#include "protobuf_convert.h"

struct bitcoin_tx *anchor_tx_create(const tal_t *ctx,
				    const OpenChannel *o1,
				    const OpenChannel *o2,
				    size_t **inmapp, size_t **outmapp)
{
	uint64_t i, n_out;
	struct bitcoin_tx *tx;
	u8 *redeemscript;
	size_t *inmap, *outmap;
	struct pubkey key1, key2;
	uint64_t total_in = 0, total_change = 0;

	if (add_overflows_size_t(o1->anchor->n_inputs, o2->anchor->n_inputs))
		return NULL;

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
		in->input_amount = pb->amount;
		if (add_overflows_u64(total_in, in->input_amount))
			return tal_free(tx);
		total_in += in->input_amount;
		/* Leave inputs as stubs for now, for signing. */
	}
	for (i = 0; i < o2->anchor->n_inputs; i++) {
		BitcoinInput *pb = o2->anchor->inputs[i];
		struct bitcoin_tx_input *in
			= &tx->input[o1->anchor->n_inputs + i];
		proto_to_sha256(pb->txid, &in->txid.sha);
		in->index = pb->output;
		in->input_amount = pb->amount;
		if (add_overflows_u64(total_in, in->input_amount))
			return tal_free(tx);
		total_in += in->input_amount;
		/* Leave inputs as stubs for now, for signing. */
	}

	/* Populate outputs. */
	if (add_overflows_u64(o1->anchor->total, o2->anchor->total))
		return tal_free(tx);

	/* Pubkeys both valid, right? */
	if (!proto_to_pubkey(o1->anchor->pubkey, &key1)
	    || !proto_to_pubkey(o2->anchor->pubkey, &key2))
		return tal_free(tx);

	/* Make the 2 of 2 payment for the commitment txs. */
	redeemscript = bitcoin_redeem_2of2(tx, &key1, &key2);
	tx->output[0].amount = o1->anchor->total + o2->anchor->total;
	tx->output[0].script = scriptpubkey_p2sh(tx, redeemscript);
	tx->output[0].script_length = tal_count(tx->output[0].script);

	/* Add change transactions (if any) */
	n_out = 1;
	if (o1->anchor->change) {
		struct bitcoin_tx_output *out = &tx->output[n_out++];
		struct pubkey key;

		if (!proto_to_pubkey(o1->anchor->change->pubkey, &key))
			return tal_free(tx);

		out->amount = o1->anchor->change->amount;
		out->script = scriptpubkey_p2sh(tx,
						bitcoin_redeem_single(tx, &key));
		out->script_length = tal_count(out->script);
		total_change += out->amount;
	}
	if (o2->anchor->change) {
		struct bitcoin_tx_output *out = &tx->output[n_out++];
		struct pubkey key;

		if (!proto_to_pubkey(o2->anchor->change->pubkey, &key))
			return tal_free(tx);

		out->amount = o2->anchor->change->amount;
		out->script = scriptpubkey_p2sh(tx,
						bitcoin_redeem_single(tx, &key));
		out->script_length = tal_count(out->script);
		if (add_overflows_u64(total_change, out->amount))
			return tal_free(tx);
		total_change += out->amount;
	}
	assert(n_out == tx->output_count);

	/* Figure out fee we're paying; check for over and underflow */
	if (add_overflows_u64(total_change, tx->output[0].amount))
		return tal_free(tx);
	if (total_in < total_change + tx->output[0].amount)
		return tal_free(tx);
	tx->fee = total_in - (total_change + tx->output[0].amount);

	/* Check that the fees add up correctly. */
	if (add_overflows_u64(o1->anchor->fee, o2->anchor->fee))
		return tal_free(tx);
	if (tx->fee != o1->anchor->fee + o2->anchor->fee)
		return tal_free(tx);

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

/* This may create an invalid anchor.  That's actually OK, as the bitcoin
 * network won't accept it and we'll ds our way out. */
bool anchor_add_scriptsigs(struct bitcoin_tx *anchor,
			   OpenAnchorScriptsigs *ssigs1,
			   OpenAnchorScriptsigs *ssigs2,
			   const size_t *inmap)
{
	size_t i;

	if (ssigs1->n_script + ssigs2->n_script != anchor->input_count)
		return NULL;

	for (i = 0; i < ssigs1->n_script; i++) {
		size_t n = inmap[i];
		anchor->input[n].script = ssigs1->script[i].data;
		anchor->input[n].script_length = ssigs1->script[i].len;
	}

	for (i = 0; i < ssigs2->n_script; i++) {
		size_t n = inmap[ssigs1->n_script + i];
		anchor->input[n].script	= ssigs2->script[i].data;
		anchor->input[n].script_length = ssigs2->script[i].len;
	}

	return true;
}
	
void anchor_txid(struct bitcoin_tx *anchor, struct sha256_double *txid)
{
	bitcoin_txid(anchor, txid);
}
