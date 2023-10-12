#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/varint.h>
#include <ccan/ccan/array_size/array_size.h>
#include <ccan/ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <wally_psbt.h>
#include <wire/wire.h>


static void psbt_destroy(struct wally_psbt *psbt)
{
	wally_psbt_free(psbt);
}

struct wally_psbt *create_psbt(const tal_t *ctx, size_t num_inputs, size_t num_outputs, u32 locktime)
{
	const u32 init_flags = is_elements(chainparams) ? WALLY_PSBT_INIT_PSET : 0;
	struct wally_psbt *psbt;
	int wally_err;

	tal_wally_start();
	wally_err = wally_psbt_init_alloc(2, num_inputs, num_outputs, 0, init_flags, &psbt);
	assert(wally_err == WALLY_OK);
	wally_psbt_set_fallback_locktime(psbt, locktime);
	/* By default we are modifying them internally; allow it */
	wally_psbt_set_tx_modifiable_flags(psbt, WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS);
	tal_add_destructor(psbt, psbt_destroy);
	tal_wally_end_onto(ctx, psbt, struct wally_psbt);

	return psbt;
}

struct wally_psbt *clone_psbt(const tal_t *ctx, struct wally_psbt *psbt)
{
	struct wally_psbt *clone;
	tal_wally_start();
	if (wally_psbt_clone_alloc(psbt, 0, &clone) != WALLY_OK)
		abort();
	tal_wally_end_onto(ctx, clone, struct wally_psbt);
	return clone;
}

struct wally_psbt *new_psbt(const tal_t *ctx, const struct wally_tx *wtx)
{
	struct wally_psbt *psbt;
	int wally_err;

	psbt = create_psbt(ctx, wtx->num_inputs, wtx->num_outputs, wtx->locktime);

	tal_wally_start();

	/* locktime and modifiable flags are set in create_psbt */
	wally_psbt_set_tx_version(psbt, wtx->version);

	for (size_t i = 0; i < wtx->num_inputs; i++) {
		wally_err = wally_psbt_add_tx_input_at(psbt, i, 0, &wtx->inputs[i]);
		assert(wally_err == WALLY_OK);

		/* add these scripts + witnesses to the psbt */
		if (wtx->inputs[i].script) {
			wally_err =
				wally_psbt_input_set_final_scriptsig(&psbt->inputs[i],
								     wtx->inputs[i].script,
								     wtx->inputs[i].script_len);
			assert(wally_err == WALLY_OK);
		}
		if (wtx->inputs[i].witness) {
			wally_err =
				wally_psbt_input_set_final_witness(&psbt->inputs[i],
								   wtx->inputs[i].witness);
			assert(wally_err == WALLY_OK);
		}
	}

	for (size_t i = 0; i < wtx->num_outputs; i++) {
		wally_psbt_add_tx_output_at(psbt, i, 0, &wtx->outputs[i]);
	}

	tal_wally_end(psbt);
	return psbt;
}

struct wally_psbt *combine_psbt(const tal_t *ctx,
				const struct wally_psbt *psbt0,
				const struct wally_psbt *psbt1)
{
	struct wally_psbt *combined_psbt;
	tal_wally_start();
	if (wally_psbt_clone_alloc(psbt0, 0, &combined_psbt) != WALLY_OK)
		abort();
	if (wally_psbt_combine(combined_psbt, psbt1) != WALLY_OK) {
		tal_wally_end_onto(ctx, combined_psbt, struct wally_psbt);
		return tal_free(combined_psbt);
	}
	tal_wally_end_onto(ctx, combined_psbt, struct wally_psbt);
	return combined_psbt;
}

bool psbt_is_finalized(const struct wally_psbt *psbt)
{
	size_t is_finalized;
	int wally_err = wally_psbt_is_finalized(psbt, &is_finalized);
	assert(wally_err == WALLY_OK);
	return is_finalized ? true : false;
}

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					const struct wally_tx_input *input,
				       	size_t insert_at)
{
	const u32 flags = WALLY_PSBT_FLAG_NON_FINAL; /* Skip script/witness */
	int wally_err;

	tal_wally_start();
	wally_err = wally_psbt_add_tx_input_at(psbt, insert_at, flags, input);
	assert(wally_err == WALLY_OK);
	tal_wally_end(psbt);
	return &psbt->inputs[insert_at];
}

struct wally_psbt_input *psbt_append_input(struct wally_psbt *psbt,
					   const struct bitcoin_outpoint *outpoint,
					   u32 sequence,
					   const u8 *scriptSig,
					   const u8 *input_wscript,
					   const u8 *redeemscript)
{
	struct wally_tx_input *tx_in;
	size_t input_num = psbt->num_inputs;
	const u32 flags = WALLY_PSBT_FLAG_NON_FINAL; /* Skip script/witness */
	int wally_err;

	tal_wally_start();
	if (chainparams->is_elements) {
		if (wally_tx_elements_input_init_alloc(outpoint->txid.shad.sha.u.u8,
						       sizeof(outpoint->txid.shad.sha.u.u8),
						       outpoint->n,
						       sequence, NULL, 0,
						       NULL,
						       NULL, 0,
						       NULL, 0, NULL, 0,
						       NULL, 0, NULL, 0,
						       NULL, 0, NULL,
						       &tx_in) != WALLY_OK)
			abort();
	} else {
		if (wally_tx_input_init_alloc(outpoint->txid.shad.sha.u.u8,
					      sizeof(outpoint->txid.shad.sha.u.u8),
					      outpoint->n,
					      sequence, NULL, 0, NULL,
					      &tx_in) != WALLY_OK)
			abort();
	}

	wally_err = wally_psbt_add_tx_input_at(psbt, input_num, flags, tx_in);
	assert(wally_err == WALLY_OK);
	wally_tx_input_free(tx_in);
	tal_wally_end(psbt);

	if (input_wscript) {
		/* Add the prev output's data into the PSBT struct */
		psbt_input_set_witscript(psbt, input_num, input_wscript);
	}

	if (redeemscript) {
		tal_wally_start();
		wally_err = wally_psbt_input_set_redeem_script(&psbt->inputs[input_num],
							       redeemscript,
							       tal_bytelen(redeemscript));
		assert(wally_err == WALLY_OK);
		tal_wally_end(psbt);
	}

	return &psbt->inputs[input_num];
}

void psbt_rm_input(struct wally_psbt *psbt,
		   size_t remove_at)
{
	int wally_err = wally_psbt_remove_input(psbt, remove_at);
	assert(wally_err == WALLY_OK);
}

struct wally_psbt_output *psbt_add_output(struct wally_psbt *psbt,
					  struct wally_tx_output *output,
					  size_t insert_at)
{
	int wally_err;

	tal_wally_start();
	wally_err = wally_psbt_add_tx_output_at(psbt, insert_at, 0, output);
	assert(wally_err == WALLY_OK);
	tal_wally_end(psbt);
	return &psbt->outputs[insert_at];
}

struct wally_psbt_output *psbt_append_output(struct wally_psbt *psbt,
					     const u8 *script,
					     struct amount_sat amount)
{
	return psbt_insert_output(psbt, script, amount, psbt->num_outputs);
}

struct wally_psbt_output *psbt_insert_output(struct wally_psbt *psbt,
					     const u8 *script,
					     struct amount_sat amount,
					     size_t insert_at)
{
	struct wally_psbt_output *out;
	struct wally_tx_output *tx_out = wally_tx_output(NULL, script, amount);

	out = psbt_add_output(psbt, tx_out, insert_at);
	wally_tx_output_free(tx_out);
	return out;
}

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at)
{
	int wally_err = wally_psbt_remove_output(psbt, remove_at);
	assert(wally_err == WALLY_OK);
}

void psbt_input_add_pubkey(struct wally_psbt *psbt, size_t in,
			   const struct pubkey *pubkey, bool is_taproot)
{
	int wally_err;
	u32 empty_path[1] = {0};
	unsigned char fingerprint[4];
	struct ripemd160 hash;
	u8 pk_der[PUBKEY_CMPR_LEN];

	assert(in < psbt->num_inputs);

	/* Find the key identifier fingerprint:
	 * the first 32 bits of the identifier, where the identifier
	 * is the hash160 of the ECDSA serialized public key
	 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#key-identifiers
	 * */
	pubkey_to_hash160(pubkey, &hash);
	memcpy(fingerprint, hash.u.u8, sizeof(fingerprint));

	/* we serialize the compressed version of the key, wally likes this */
	pubkey_to_der(pk_der, pubkey);

	tal_wally_start();
	if (is_taproot) {
		wally_err = wally_psbt_input_taproot_keypath_add(&psbt->inputs[in],
								  pk_der + 1, 32,
								  NULL /* tapleaf_hashes */, 0 /* tapleaf_hashes_len */,
								  fingerprint, sizeof(fingerprint),
								  empty_path, ARRAY_SIZE(empty_path));
		assert(wally_err == WALLY_OK);
	} else {
		wally_err = wally_psbt_input_keypath_add(&psbt->inputs[in],
								  pk_der, sizeof(pk_der),
								  fingerprint, sizeof(fingerprint),
								  empty_path, ARRAY_SIZE(empty_path));
		assert(wally_err == WALLY_OK);
	}
	tal_wally_end(psbt);
}

bool psbt_input_set_signature(struct wally_psbt *psbt, size_t in,
			      const struct pubkey *pubkey,
			      const struct bitcoin_signature *sig)
{
	u8 pk_der[PUBKEY_CMPR_LEN];
	u8 sig_der[73];
	size_t sig_len;
	bool ok;

	assert(in < psbt->num_inputs);

	/* we serialize the compressed version of the key, wally likes this */
	pubkey_to_der(pk_der, pubkey);
	sig_len = signature_to_der(sig_der, sig);
	tal_wally_start();
	wally_psbt_input_set_sighash(&psbt->inputs[in], sig->sighash_type);
	ok = wally_psbt_input_add_signature(&psbt->inputs[in],
					    pk_der, sizeof(pk_der),
					    sig_der, sig_len) == WALLY_OK;
	tal_wally_end(psbt);
	return ok;
}

void psbt_input_set_wit_utxo(struct wally_psbt *psbt, size_t in,
			     const u8 *scriptPubkey, struct amount_sat amt)
{
	struct wally_tx_output *tx_out;
	int wally_err;

	assert(in < psbt->num_inputs);
	assert(tal_bytelen(scriptPubkey) > 0);
	tal_wally_start();
	if (is_elements(chainparams)) {
		u8 value[9];
		wally_err =
			wally_tx_confidential_value_from_satoshi(amt.satoshis, /* Raw: wally API */
								 value,
								 sizeof(value));
		assert(wally_err == WALLY_OK);
		wally_err =
			wally_tx_elements_output_init_alloc(scriptPubkey,
						      tal_bytelen(scriptPubkey),
						      chainparams->fee_asset_tag,
						      ELEMENTS_ASSET_LEN,
						      value, sizeof(value),
						      NULL, 0, NULL, 0,
						      NULL, 0, &tx_out);

	} else
		wally_err = wally_tx_output_init_alloc(amt.satoshis, /* Raw: type conv */
						 scriptPubkey,
						 tal_bytelen(scriptPubkey),
						 &tx_out);
	assert(wally_err == WALLY_OK);
	wally_err = wally_psbt_input_set_witness_utxo(&psbt->inputs[in], tx_out);
	wally_tx_output_free(tx_out);
	assert(wally_err == WALLY_OK);
	tal_wally_end(psbt);
}

void psbt_input_set_utxo(struct wally_psbt *psbt, size_t in,
			 const struct wally_tx *prev_tx)
{
	int wally_err;
	tal_wally_start();
	wally_err = wally_psbt_input_set_utxo(&psbt->inputs[in],
					      prev_tx);
	tal_wally_end(psbt);
	assert(wally_err == WALLY_OK);
}

void psbt_input_set_outpoint(struct wally_psbt *psbt, size_t in,
			     struct bitcoin_outpoint outpoint)
{
	assert(in < psbt->num_inputs);
	psbt->inputs[in].index = outpoint.n;
	memcpy(psbt->inputs[in].txhash, &outpoint.txid,
	       sizeof(struct bitcoin_txid));
}

void psbt_input_set_witscript(struct wally_psbt *psbt, size_t in, const u8 *wscript)
{
	int wally_err;

	tal_wally_start();
	wally_err = wally_psbt_input_set_witness_script(&psbt->inputs[in],
							wscript,
							tal_bytelen(wscript));
	assert(wally_err == WALLY_OK);
	tal_wally_end(psbt);
}

void psbt_elements_input_set_asset(struct wally_psbt *psbt, size_t in,
				   struct amount_asset *asset)
{
	tal_wally_start();

	if (asset->value > 0)
		if (wally_psbt_input_set_amount(&psbt->inputs[in],
					       asset->value) != WALLY_OK)
			abort();

	/* PSET expects an asset tag without the prefix */
	if (wally_psbt_input_set_asset(&psbt->inputs[in],
				       asset->asset + 1,
				       ELEMENTS_ASSET_LEN - 1) != WALLY_OK)
		abort();
	tal_wally_end(psbt);
}

void psbt_elements_normalize_fees(struct wally_psbt *psbt)
{
	size_t fee_output_idx = psbt->num_outputs;

	if (!is_elements(chainparams))
		return;

	/* Elements requires that every input value is accounted for,
	 * including the fees */
	struct amount_sat total_fee = AMOUNT_SAT(0), val;
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		val = psbt_input_get_amount(psbt, i);
		if (!amount_sat_add(&total_fee, total_fee, val))
			return;
	}
	for (size_t i = 0; i < psbt->num_outputs; i++) {
		struct amount_asset output_amount = wally_psbt_output_get_amount(&psbt->outputs[i]);
		if (elements_psbt_output_is_fee(psbt, i)) {
			if (fee_output_idx == psbt->num_outputs) {
				fee_output_idx = i;
				continue;
			}
			/* We already have at least one fee output,
			 * remove this one */
			psbt_rm_output(psbt, i--);
			continue;
		}
		if (!amount_asset_is_main(&output_amount))
			continue;

		if (!amount_sat_sub(&total_fee, total_fee,
				    amount_asset_to_sat(&output_amount)))
			return;
	}

	if (amount_sat_eq(total_fee, AMOUNT_SAT(0)))
		return;

	/* We need to add a fee output */
	if (fee_output_idx == psbt->num_outputs) {
		psbt_append_output(psbt, NULL, total_fee);
	} else {
		int ret;
		u64 sats = total_fee.satoshis; /* Raw: wally API */
		struct wally_psbt_output *out = &psbt->outputs[fee_output_idx];
		ret = wally_psbt_output_set_amount(out, sats);
		assert(ret == WALLY_OK);
	}
}

void wally_psbt_input_get_txid(const struct wally_psbt_input *in,
                 struct bitcoin_txid *txid)
{
    BUILD_ASSERT(sizeof(struct bitcoin_txid) == sizeof(in->txhash));
    memcpy(txid, in->txhash, sizeof(struct bitcoin_txid));
}

bool psbt_has_input(const struct wally_psbt *psbt,
		    const struct bitcoin_outpoint *outpoint)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_txid in_txid;
		const struct wally_psbt_input *in = &psbt->inputs[i];

		if (outpoint->n != in->index)
			continue;

		wally_psbt_input_get_txid(in, &in_txid);
		if (bitcoin_txid_eq(&outpoint->txid, &in_txid))
			return true;
	}
	return false;
}

struct amount_sat psbt_input_get_amount(const struct wally_psbt *psbt,
					size_t in)
{
	struct amount_sat val;
	assert(in < psbt->num_inputs);
	if (psbt->inputs[in].witness_utxo) {
		struct amount_asset amt_asset =
			wally_tx_output_get_amount(psbt->inputs[in].witness_utxo);
		assert(amount_asset_is_main(&amt_asset));
		val = amount_asset_to_sat(&amt_asset);
	} else if (psbt->inputs[in].utxo) {
		int idx = psbt->inputs[in].index;
		struct wally_tx *prev_tx = psbt->inputs[in].utxo;
		val = amount_sat(prev_tx->outputs[idx].satoshi);
	} else
		abort();

	return val;
}

size_t psbt_input_get_weight(const struct wally_psbt *psbt,
			     size_t in)
{
	size_t weight;
	const struct wally_map_item *redeem_script;

	redeem_script = wally_map_get_integer(&psbt->inputs[in].psbt_fields, /* PSBT_IN_REDEEM_SCRIPT */ 0x04);

	/* txid + txout + sequence */
	weight = (32 + 4 + 4) * 4;
	if (redeem_script) {
		weight +=
			(redeem_script->value_len +
				varint_size(redeem_script->value_len)) * 4;
	} else {
		/* zero scriptSig length */
		weight += varint_size(0) * 4;
	}

	return weight;
}

struct amount_sat psbt_output_get_amount(const struct wally_psbt *psbt,
					 size_t out)
{
	struct amount_asset asset;
	assert(out < psbt->num_outputs);
	asset = wally_psbt_output_get_amount(&psbt->outputs[out]);
	assert(amount_asset_is_main(&asset));
	return amount_asset_to_sat(&asset);
}

size_t psbt_output_get_weight(const struct wally_psbt *psbt,
			      size_t outnum)
{
	return (8 /* amount*/ + varint_size(psbt->outputs[outnum].script_len) +
		psbt->outputs[outnum].script_len) * 4;
}

static void add(u8 **key, const void *mem, size_t len)
{
	size_t oldlen = tal_count(*key);
	tal_resize(key, oldlen + len);
	memcpy(*key + oldlen, memcheck(mem, len), len);
}

static void add_type(u8 **key, const u8 num)
{
	add(key, &num, 1);
}

void add_varint(u8 **arr, size_t val)
{
	u8 vt[VARINT_MAX_LEN];
	size_t vtlen;
	vtlen = varint_put(vt, val);
	tal_expand(arr, vt, vtlen);
}

#define LIGHTNING_PROPRIETARY_PREFIX "lightning"

u8 *psbt_make_key(const tal_t *ctx, u8 key_subtype, const u8 *key_data)
{
	/**
	 * BIP174:
	 * Type: Proprietary Use Type <tt>PSBT_GLOBAL_PROPRIETARY = 0xFC</tt>
	 ** Key: Variable length identifier prefix, followed
	 *       by a subtype, followed by the key data itself.
	 *** <tt>{0xFC}|<prefix>|{subtype}|{key data}</tt>
	 ** Value: Any value data as defined by the proprietary type user.
	 *** <tt><data></tt>
	 */
	u8 *key = tal_arr(ctx, u8, 0);
	add_type(&key, WALLY_PSBT_PROPRIETARY_TYPE);
	add_varint(&key, strlen(LIGHTNING_PROPRIETARY_PREFIX));
	add(&key, LIGHTNING_PROPRIETARY_PREFIX,
	    strlen(LIGHTNING_PROPRIETARY_PREFIX));
	add_type(&key, key_subtype);
	if (key_data)
		add(&key, key_data, tal_bytelen(key_data));
	return key;
}

static bool wally_map_set_unknown(const tal_t *ctx,
				  struct wally_map *map,
				  const u8 *key,
				  const void *value,
				  size_t value_len)
{
	size_t exists_at;
	struct wally_map_item *item;

	assert(value_len != 0);
	if (wally_map_find(map, key, tal_bytelen(key), &exists_at) != WALLY_OK)
		return false;

	/* If not exists, add */
	if (exists_at == 0) {
		bool ok;
		tal_wally_start();
		ok = wally_map_add(map, key, tal_bytelen(key),
			      (unsigned char *) memcheck(value, value_len), value_len)
			== WALLY_OK;
		tal_wally_end(ctx);
		return ok;
	}

	/* Already in map, update entry */
	item = &map->items[exists_at - 1];
	tal_resize(&item->value, value_len);
	memcpy(item->value, memcheck(value, value_len), value_len);
	item->value_len = value_len;

	return true;
}

void psbt_input_set_unknown(const tal_t *ctx,
			    struct wally_psbt_input *in,
			    const u8 *key,
			    const void *value,
			    size_t value_len)
{
	if (!wally_map_set_unknown(ctx, &in->unknowns, key, value, value_len))
		abort();
}

static void *psbt_get_unknown(const struct wally_map *map,
			      const u8 *key,
			      size_t *val_len)
{
	size_t index;

	if (wally_map_find(map, key, tal_bytelen(key), &index) != WALLY_OK)
		return NULL;

	/* Zero: item not found. */
	if (index == 0)
		return NULL;

	/* ++: item is at this index minus 1 */
	*val_len = map->items[index - 1].value_len;
	return map->items[index - 1].value;
}

void *psbt_get_lightning(const struct wally_map *map,
			 const u8 proprietary_type,
			 size_t *val_len)
{
	void *res;
	u8 *key = psbt_make_key(NULL, proprietary_type, NULL);
	res = psbt_get_unknown(map, key, val_len);
	tal_free(key);
	return res;
}


void psbt_output_set_unknown(const tal_t *ctx,
			     struct wally_psbt_output *out,
			     const u8 *key,
			     const void *value,
			     size_t value_len)
{
	if (!wally_map_set_unknown(ctx, &out->unknowns, key, value, value_len))
		abort();
}

/* Use the destructor to free the wally_tx */
static void wally_tx_destroy(struct wally_tx *wtx)
{
	wally_tx_free(wtx);
}

bool psbt_finalize(struct wally_psbt *psbt)
{
	bool ok;

	tal_wally_start();

	/* Wally doesn't know how to finalize P2WSH; this happens with
	 * option_anchor_outputs, and finalizing those two cases is trivial. */
	/* FIXME: miniscript! miniscript! miniscript! */
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct wally_psbt_input *input = &psbt->inputs[i];
		struct wally_tx_witness_stack *stack;
		const struct wally_map_item *iws;

		iws = wally_map_get_integer(&input->psbt_fields, /* PSBT_IN_WITNESS_SCRIPT */ 0x05);
		if (!iws)
			continue;

		if (!is_to_remote_anchored_witness_script(iws->value,
							  iws->value_len)
		    && !is_anchor_witness_script(iws->value,
						 iws->value_len)) {
			continue;
		}

		if (input->signatures.num_items != 1)
			continue;

		/* BOLT #3:
		 * #### `to_remote` Output
		 *
		 * If `option_anchors` applies to the commitment
		 * transaction, the `to_remote` output is encumbered by a one
		 * block csv lock.
		 *
		 *    <remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
		 *
		 * The output is spent by an input with `nSequence`
		 * field set to `1` and witness:
		 *
		 *    <remote_sig>
		 */
		/* BOLT #3:
		 * #### `to_local_anchor` and `to_remote_anchor` Output (option_anchors)
		 *...
		 *    <local_funding_pubkey/remote_funding_pubkey> OP_CHECKSIG OP_IFDUP
		 *    OP_NOTIF
		 *        OP_16 OP_CHECKSEQUENCEVERIFY
		 *    OP_ENDIF
		 *...
		 * Spending of the output requires the following witness:
		 *     <local_sig/remote_sig>
		 */

		/* i.e. in both cases, this is the same thing */
		wally_tx_witness_stack_init_alloc(2, &stack);
		wally_tx_witness_stack_add(stack,
					   input->signatures.items[0].value,
					   input->signatures.items[0].value_len);
		wally_tx_witness_stack_add(stack,
					   iws->value,
					   iws->value_len);
		wally_psbt_input_set_final_witness(input, stack);
		wally_tx_witness_stack_free(stack);
	}

	ok = (wally_psbt_finalize(psbt, 0 /* flags */) == WALLY_OK);
	tal_wally_end(psbt);

	return ok && psbt_is_finalized(psbt);
}

struct wally_tx *psbt_final_tx(const tal_t *ctx, const struct wally_psbt *psbt)
{
	struct wally_tx *wtx;

	if (!psbt_is_finalized(psbt))
		return NULL;

	tal_wally_start();
	if (wally_psbt_extract(psbt, /* flags */ 0, &wtx) == WALLY_OK)
		tal_add_destructor(wtx, wally_tx_destroy);
	else
		wtx = NULL;

	tal_wally_end_onto(ctx, wtx, struct wally_tx);
	return wtx;
}

struct wally_psbt *psbt_from_b64(const tal_t *ctx,
				 const char *b64,
				 size_t b64len)
{
	struct wally_psbt *psbt;
	char *str = tal_strndup(tmpctx, b64, b64len);

	tal_wally_start();
	if (wally_psbt_from_base64(str, /* flags */ 0, &psbt) == WALLY_OK)
		tal_add_destructor(psbt, psbt_destroy);
	else
		psbt = NULL;
	tal_wally_end_onto(ctx, psbt, struct wally_psbt);

	return psbt;
}

char *psbt_to_b64(const tal_t *ctx, const struct wally_psbt *psbt)
{
	char *serialized_psbt;
	int ret;

	tal_wally_start();
	ret = wally_psbt_to_base64(psbt, 0, &serialized_psbt);
	assert(ret == WALLY_OK);
	tal_wally_end_onto(ctx, serialized_psbt, char);

	return serialized_psbt;
}
REGISTER_TYPE_TO_STRING(wally_psbt, psbt_to_b64);

const u8 *psbt_get_bytes(const tal_t *ctx, const struct wally_psbt *psbt,
			 size_t *bytes_written)
{
	size_t len = 0;
	u8 *bytes;

	if (!psbt) {
		*bytes_written = 0;
		return NULL;
	}

	if (wally_psbt_get_length(psbt, 0, &len) != WALLY_OK) {
		abort();
	}
	bytes = tal_arr(ctx, u8, len);

	if (wally_psbt_to_bytes(psbt, 0, bytes, len, bytes_written) != WALLY_OK ||
	    *bytes_written != len) {
		/* something went wrong. bad libwally ?? */
		abort();
	}
	return bytes;
}

bool validate_psbt(const struct wally_psbt *psbt)
{
	size_t len;
	return wally_psbt_get_length(psbt, 0, &len) == WALLY_OK;
}

struct wally_psbt *psbt_from_bytes(const tal_t *ctx, const u8 *bytes,
				   size_t byte_len)
{
	struct wally_psbt *psbt;

	tal_wally_start();
	if (wally_psbt_from_bytes(bytes, byte_len, /* flags */ 0, &psbt) == WALLY_OK)
		tal_add_destructor(psbt, psbt_destroy);
	else
		psbt = NULL;
	tal_wally_end_onto(ctx, psbt, struct wally_psbt);

	return psbt;
}

void towire_wally_psbt(u8 **pptr, const struct wally_psbt *psbt)
{
	struct wally_psbt *psbt_copy;

	/* Let's include the PSBT bytes */
	size_t bytes_written;
	const u8 *psbt_bytes = psbt_get_bytes(NULL, psbt, &bytes_written);

	/* When sending to other processes, set to v0 for compat */
	psbt_copy = psbt_from_bytes(NULL, psbt_bytes, bytes_written);
	tal_free(psbt_bytes);
    if (!is_elements(chainparams))
		psbt_set_version(psbt_copy, 0);

	const u8 *psbt_bytes_copy = psbt_get_bytes(NULL, psbt_copy, &bytes_written);

	towire_u32(pptr, bytes_written);
	towire_u8_array(pptr, psbt_bytes_copy, bytes_written);
	tal_free(psbt_bytes_copy);
	tal_free(psbt_copy);
}

struct wally_psbt *fromwire_wally_psbt(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct wally_psbt *psbt;
	u32 psbt_byte_len;
	const u8 *psbt_buf;

	psbt_byte_len = fromwire_u32(cursor, max);
	psbt_buf = fromwire(cursor, max, NULL, psbt_byte_len);
	if (!psbt_buf || psbt_byte_len == 0)
		return NULL;

	psbt = psbt_from_bytes(ctx, psbt_buf, psbt_byte_len);
	if (!psbt)
		return fromwire_fail(cursor, max);

	/* Internally we always operate on v2 */
	psbt_set_version(psbt, 2);

	return psbt;
}

void psbt_txid(const tal_t *ctx,
	       const struct wally_psbt *psbt,
		   struct bitcoin_txid *txid,
	       struct wally_tx **wtx)
{
	struct wally_tx *tx;
	int wally_err;
	assert(psbt->version == 2);

	/* We rely on wally extractor to fill out all txid-related fields including scriptSigs */
	tal_wally_start();
	wally_err = wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx);
	assert(wally_err == WALLY_OK);
	wally_err = wally_tx_get_txid(tx, txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
	assert(wally_err == WALLY_OK);
	tal_wally_end(ctx);

	if (wtx)
		*wtx = tx;
	else
		wally_tx_free(tx);
}

struct amount_sat psbt_compute_fee(const struct wally_psbt *psbt)
{
	struct amount_sat fee, input_amt;
	struct amount_asset asset;
	bool ok;

	fee = AMOUNT_SAT(0);
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		input_amt = psbt_input_get_amount(psbt, i);
		ok = amount_sat_add(&fee, fee, input_amt);
		assert(ok);
	}

	for (size_t i = 0; i < psbt->num_outputs; i++) {
		asset = wally_psbt_output_get_amount(&psbt->outputs[i]);
		if (!amount_asset_is_main(&asset)
		    || elements_psbt_output_is_fee(psbt, i))
			continue;

		ok = amount_sat_sub(&fee, fee, amount_asset_to_sat(&asset));
		if (!ok)
			return AMOUNT_SAT(0);
	}

	return fee;
}

bool wally_psbt_input_spends(const struct wally_psbt_input *input,
               const struct bitcoin_outpoint *outpoint)
{
    /* Useful, as tx_part can have some NULL inputs */
    if (!input)
        return false;
    BUILD_ASSERT(sizeof(outpoint->txid) == sizeof(input->txhash));
	if (input->index != outpoint->n)
		return false;
    if (memcmp(&outpoint->txid, input->txhash, sizeof(outpoint->txid)) != 0)
        return false;
    return true;
}

void wally_psbt_input_get_outpoint(const struct wally_psbt_input *in,
                 struct bitcoin_outpoint *outpoint)
{
    BUILD_ASSERT(sizeof(struct bitcoin_txid) == sizeof(in->txhash));
    memcpy(&outpoint->txid, in->txhash, sizeof(struct bitcoin_txid));
    outpoint->n = in->index;
}

const u8 *wally_psbt_output_get_script(const tal_t *ctx,
                     const struct wally_psbt_output *output)
{
    if (output->script == NULL) {
        /* This can happen for coinbase transactions, pegin
         * transactions, and elements fee outputs */
        return NULL;
    }

    return tal_dup_arr(ctx, u8, output->script, output->script_len, 0);
}

/* FIXME(cdecker) Make the caller pass in a reference to amount_asset, and
 * return false if unintelligible/encrypted. (WARN UNUSED). */
struct amount_asset
wally_psbt_output_get_amount(const struct wally_psbt_output *output)
{
    struct amount_asset amount;
	size_t asset_out;

    if (chainparams->is_elements) {
		if (wally_psbt_output_get_asset(output, amount.asset + 1, sizeof(amount.asset) - 1, &asset_out) != WALLY_OK) {
			amount.value = 0;
			return amount;
		}
		assert(asset_out == 32);
		amount.asset[0] = 0x01; /* explicit */
        /* We currently only support explicit value
         * asset tags, others are confidential, so
         * don't even try to assign a value to it. */
        if (output->has_amount == true) {
            amount.value = output->amount;
        } else {
            amount.value = 0;
        }
    } else {
        /* Do not assign amount.asset, we should never touch it in
         * non-elements scenarios. */
		if (output->has_amount) {
        	amount.value = output->amount;
		} else {
			abort();
		}
    }

    return amount;
}

bool elements_psbt_output_is_fee(const struct wally_psbt *psbt, size_t outnum)
{
    assert(outnum < psbt->num_outputs);
    return chainparams->is_elements &&
        psbt->outputs[outnum].script_len == 0;
}

bool psbt_set_version(struct wally_psbt *psbt, u32 version)
{
	bool ok;

	tal_wally_start();
	ok = wally_psbt_set_version(psbt, 0, version) == WALLY_OK;
	if (ok && version == 2) {
		ok &= wally_psbt_set_tx_modifiable_flags(psbt, WALLY_PSBT_TXMOD_INPUTS | WALLY_PSBT_TXMOD_OUTPUTS) == WALLY_OK;
	}
	tal_wally_end(psbt);
	return ok;
}
