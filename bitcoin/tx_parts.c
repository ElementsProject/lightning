#include "config.h"
#include <assert.h>
#include <bitcoin/tx_parts.h>
#include <common/utils.h>
#include <wire/wire.h>

/* This destructor makes it behave like a native tal tree (a little!) */
static void destroy_wally_tx_input(struct wally_tx_input *in)
{
	wally_tx_input_free(in);
}

static void destroy_wally_tx_output(struct wally_tx_output *out)
{
	wally_tx_output_free(out);
}

struct tx_parts *tx_parts_from_wally_tx(const tal_t *ctx,
					const struct wally_tx *wtx,
					int input, int output)
{
	struct tx_parts *txp = tal(ctx, struct tx_parts);

	wally_txid(wtx, &txp->txid);
	txp->inputs = tal_arrz(txp, struct wally_tx_input *, wtx->num_inputs);
	txp->outputs = tal_arrz(txp, struct wally_tx_output *, wtx->num_outputs);

	tal_wally_start();
	for (size_t i = 0; i < wtx->num_inputs; i++) {
		if (input != -1 && input != i)
			continue;
		if (wally_tx_input_clone_alloc(&wtx->inputs[i],
					       &txp->inputs[i]) != WALLY_OK)
			abort();
		tal_add_destructor(txp->inputs[i], destroy_wally_tx_input);
	}

	for (size_t i = 0; i < wtx->num_outputs; i++) {
		if (output != -1 && output != i)
			continue;
		if (wally_tx_output_clone_alloc(&wtx->outputs[i],
						&txp->outputs[i]) != WALLY_OK)
			abort();
		tal_add_destructor(txp->outputs[i], destroy_wally_tx_output);

		/* Cheat a bit by also setting the numeric satoshi
		 * value, otherwise we end up converting a
		 * number of times */
		if (chainparams->is_elements) {
			struct amount_asset asset;
			struct amount_sat sats;
			asset = wally_tx_output_get_amount(txp->outputs[i]);
			/* FIXME: non l-btc assets */
			assert(amount_asset_is_main(&asset));
			sats = amount_asset_to_sat(&asset);
			txp->outputs[i]->satoshi = sats.satoshis; /* Raw: wally conversion */
		}
	}
	tal_wally_end(txp);

	return txp;
}

static void destroy_wally_tx_witness_stack(struct wally_tx_witness_stack *ws)
{
	wally_tx_witness_stack_free(ws);
}

/* FIXME: If libwally exposed their linearization code, we could use it */
static struct wally_tx_witness_stack *
fromwire_wally_tx_witness_stack(const tal_t *ctx,
				const u8 **cursor,
				size_t *max)
{
	struct wally_tx_witness_stack *ws;
	size_t num;
	int ret;

	num = fromwire_u32(cursor, max);
	if (num == 0)
		return NULL;

	tal_wally_start();
	ret = wally_tx_witness_stack_init_alloc(num, &ws);
	if (ret != WALLY_OK) {
		fromwire_fail(cursor, max);
		return NULL;
	}

	for (size_t i = 0; i < num; i++) {
		u8 *w = fromwire_tal_arrn(tmpctx,
					  cursor, max,
					  fromwire_u32(cursor, max));
		ret = wally_tx_witness_stack_add(ws, w, tal_bytelen(w));
		if (ret != WALLY_OK) {
			wally_tx_witness_stack_free(ws);
			fromwire_fail(cursor, max);
			ws = NULL;
			goto out;
		}
	}

	tal_add_destructor(ws, destroy_wally_tx_witness_stack);
out:
	tal_wally_end_onto(ctx, ws, struct wally_tx_witness_stack);
	return ws;
}

static void towire_wally_tx_witness_stack(u8 **pptr,
					  const struct wally_tx_witness_stack *ws)
{
	if (!ws) {
		towire_u32(pptr, 0);
		return;
	}

	towire_u32(pptr, ws->num_items);
	for (size_t i = 0; i < ws->num_items; i++) {
		towire_u32(pptr, ws->items[i].witness_len);
		towire_u8_array(pptr,
				ws->items[i].witness,
				ws->items[i].witness_len);
	}
}

static struct wally_tx_input *fromwire_wally_tx_input(const tal_t *ctx,
						      const u8 **cursor,
						      size_t *max)
{
	struct wally_tx_input *in;
	struct bitcoin_txid txid;
	u32 index, sequence;
	u8 *script;
	struct wally_tx_witness_stack *ws;
	int ret;

	fromwire_bitcoin_txid(cursor, max, &txid);
	index = fromwire_u32(cursor, max);
	sequence = fromwire_u32(cursor, max);
	script = fromwire_tal_arrn(tmpctx,
				   cursor, max, fromwire_u32(cursor, max));
	/* libwally doesn't like non-NULL ptrs with zero lengths. */
	if (tal_bytelen(script) == 0)
		script = tal_free(script);
	ws = fromwire_wally_tx_witness_stack(tmpctx, cursor, max);

	tal_wally_start();
	if (is_elements(chainparams)) {
		u8 *blinding_nonce, *entropy, *issuance_amount,
			*inflation_keys, *issuance_amount_rangeproof,
			*inflation_keys_rangeproof;
		struct wally_tx_witness_stack *pegin_witness;

		blinding_nonce = fromwire_tal_arrn(tmpctx,
						   cursor, max,
						   fromwire_u32(cursor, max));
		entropy = fromwire_tal_arrn(tmpctx,
					    cursor, max,
					    fromwire_u32(cursor, max));
		issuance_amount = fromwire_tal_arrn(tmpctx,
						    cursor, max,
						    fromwire_u32(cursor, max));
		inflation_keys = fromwire_tal_arrn(tmpctx,
						   cursor, max,
						   fromwire_u32(cursor, max));
		issuance_amount_rangeproof = fromwire_tal_arrn(tmpctx,
						   cursor, max,
						   fromwire_u32(cursor, max));
		inflation_keys_rangeproof = fromwire_tal_arrn(tmpctx,
						   cursor, max,
						   fromwire_u32(cursor, max));
		pegin_witness = fromwire_wally_tx_witness_stack(tmpctx,
								cursor, max);
		ret = wally_tx_elements_input_init_alloc
			(txid.shad.sha.u.u8, sizeof(txid.shad.sha.u.u8),
			 index, sequence,
			 script, tal_bytelen(script),
			 ws,
			 blinding_nonce, tal_bytelen(blinding_nonce),
			 entropy, tal_bytelen(entropy),
			 issuance_amount, tal_bytelen(issuance_amount),
			 inflation_keys, tal_bytelen(inflation_keys),
			 issuance_amount_rangeproof,
			 tal_bytelen(issuance_amount_rangeproof),
			 inflation_keys_rangeproof,
			 tal_bytelen(inflation_keys_rangeproof),
			 pegin_witness,
			 &in);
	} else {
		ret = wally_tx_input_init_alloc(txid.shad.sha.u.u8,
						sizeof(txid.shad.sha.u.u8),
						index, sequence,
						script, tal_bytelen(script),
						ws, &in);
	}
	if (ret != WALLY_OK) {
		fromwire_fail(cursor, max);
		in = NULL;
	} else {
		tal_add_destructor(in, destroy_wally_tx_input);
	}

	tal_wally_end_onto(ctx, in, struct wally_tx_input);
	return in;
}

static struct wally_tx_output *fromwire_wally_tx_output(const tal_t *ctx,
							const u8 **cursor,
							size_t *max)
{
	struct wally_tx_output *out;
	unsigned char *script;
	int ret;

	script = fromwire_tal_arrn(tmpctx,
				   cursor, max, fromwire_u32(cursor, max));

	tal_wally_start();
	if (is_elements(chainparams)) {
		u8 *asset, *value, *nonce, *surjectionproof, *rangeproof;

		asset = fromwire_tal_arrn(tmpctx,
					  cursor, max,
					  fromwire_u32(cursor, max));
		value = fromwire_tal_arrn(tmpctx,
					  cursor, max,
					  fromwire_u32(cursor, max));
		nonce = fromwire_tal_arrn(tmpctx,
					  cursor, max,
					  fromwire_u32(cursor, max));
		surjectionproof = fromwire_tal_arrn(tmpctx,
						    cursor, max,
						    fromwire_u32(cursor, max));
		rangeproof = fromwire_tal_arrn(tmpctx,
					       cursor, max,
					       fromwire_u32(cursor, max));
		ret = wally_tx_elements_output_init_alloc
			(script, tal_bytelen(script),
			 asset, tal_bytelen(asset),
			 value, tal_bytelen(value),
			 nonce, tal_bytelen(nonce),
			 surjectionproof, tal_bytelen(surjectionproof),
			 rangeproof, tal_bytelen(rangeproof),
			 &out);

		/* As a convenience, we sent the value over as satoshis */
		out->satoshi = fromwire_u64(cursor, max);
	} else {
		u64 satoshi;
		satoshi = fromwire_u64(cursor, max);
		ret = wally_tx_output_init_alloc(satoshi,
						 script, tal_bytelen(script),
						 &out);
	}
	if (ret != WALLY_OK) {
		fromwire_fail(cursor, max);
		out = NULL;
	} else {
		tal_add_destructor(out, destroy_wally_tx_output);
	}
	tal_wally_end_onto(ctx, out, struct wally_tx_output);

	return out;
}

static void towire_wally_tx_input(u8 **pptr, const struct wally_tx_input *in)
{
	/* Just like a bitcoin_txid */
	towire_u8_array(pptr, in->txhash, sizeof(in->txhash));
	towire_u32(pptr, in->index);
	towire_u32(pptr, in->sequence);
	towire_u32(pptr, in->script_len);
	towire_u8_array(pptr, in->script, in->script_len);
	towire_wally_tx_witness_stack(pptr, in->witness);

	if (is_elements(chainparams)) {
		towire_u32(pptr, sizeof(in->blinding_nonce));
		towire_u8_array(pptr, in->blinding_nonce,
				sizeof(in->blinding_nonce));
		towire_u32(pptr, sizeof(in->entropy));
		towire_u8_array(pptr, in->entropy, sizeof(in->entropy));
		towire_u32(pptr, in->issuance_amount_len);
		towire_u8_array(pptr, in->issuance_amount,
				in->issuance_amount_len);
		towire_u32(pptr, in->inflation_keys_len);
		towire_u8_array(pptr, in->inflation_keys,
				in->inflation_keys_len);
		towire_u32(pptr, in->issuance_amount_rangeproof_len);
		towire_u8_array(pptr, in->issuance_amount_rangeproof,
				in->issuance_amount_rangeproof_len);
		towire_u32(pptr, in->inflation_keys_rangeproof_len);
		towire_u8_array(pptr, in->inflation_keys_rangeproof,
				in->inflation_keys_rangeproof_len);
		towire_wally_tx_witness_stack(pptr, in->pegin_witness);
	}
}

static void towire_wally_tx_output(u8 **pptr, const struct wally_tx_output *out)
{
	towire_u32(pptr, out->script_len);
	towire_u8_array(pptr, out->script, out->script_len);

	if (is_elements(chainparams)) {
		towire_u32(pptr, out->asset_len);
		towire_u8_array(pptr, out->asset, out->asset_len);
		towire_u32(pptr, out->value_len);
		towire_u8_array(pptr, out->value, out->value_len);
		towire_u32(pptr, out->nonce_len);
		towire_u8_array(pptr, out->nonce, out->nonce_len);
		towire_u32(pptr, out->surjectionproof_len);
		towire_u8_array(pptr, out->surjectionproof,
				out->surjectionproof_len);
		towire_u32(pptr, out->rangeproof_len);
		towire_u8_array(pptr, out->rangeproof, out->rangeproof_len);
		/* Copy the value over, as a convenience */
		towire_u64(pptr, out->satoshi);
	} else {
		towire_u64(pptr, out->satoshi);
	}
}

/* Wire marshalling and unmarshalling */
struct tx_parts *fromwire_tx_parts(const tal_t *ctx,
				   const u8 **cursor, size_t *max)
{
	struct tx_parts *txp = tal(ctx, struct tx_parts);
	u32 num_inputs, num_outputs;

	fromwire_bitcoin_txid(cursor, max, &txp->txid);
	num_inputs = fromwire_u32(cursor, max);
	txp->inputs = tal_arr(txp, struct wally_tx_input *, num_inputs);
	for (size_t i = 0; i < num_inputs; i++) {
		if (fromwire_bool(cursor, max)) {
			txp->inputs[i] = fromwire_wally_tx_input(txp->inputs,
								 cursor, max);
		} else {
			txp->inputs[i] = NULL;
		}
	}

	num_outputs = fromwire_u32(cursor, max);
	txp->outputs = tal_arr(txp, struct wally_tx_output *, num_outputs);
	for (size_t i = 0; i < num_outputs; i++) {
		if (fromwire_bool(cursor, max)) {
			txp->outputs[i] = fromwire_wally_tx_output(txp->outputs,
								 cursor, max);
		} else {
			txp->outputs[i] = NULL;
		}
	}

	if (*cursor == NULL)
		return tal_free(txp);

	return txp;
}

void towire_tx_parts(u8 **pptr, const struct tx_parts *txp)
{
	towire_bitcoin_txid(pptr, &txp->txid);

	towire_u32(pptr, tal_count(txp->inputs));
	for (size_t i = 0; i < tal_count(txp->inputs); i++) {
		if (txp->inputs[i]) {
			towire_bool(pptr, true);
			towire_wally_tx_input(pptr, txp->inputs[i]);
		} else {
			towire_bool(pptr, false);
		}
	}

	towire_u32(pptr, tal_count(txp->outputs));
	for (size_t i = 0; i < tal_count(txp->outputs); i++) {
		if (txp->outputs[i]) {
			towire_bool(pptr, true);
			towire_wally_tx_output(pptr, txp->outputs[i]);
		} else {
			towire_bool(pptr, false);
		}
	}
}
