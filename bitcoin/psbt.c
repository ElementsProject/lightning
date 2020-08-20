#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <ccan/cast/cast.h>
#include <ccan/ccan/array_size/array_size.h>
#include <ccan/ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <string.h>
#include <wally_psbt.h>
#include <wally_transaction.h>
#include <wire/wire.h>


void psbt_destroy(struct wally_psbt *psbt)
{
	wally_psbt_free(psbt);
}

static struct wally_psbt *init_psbt(const tal_t *ctx, size_t num_inputs, size_t num_outputs)
{
	int wally_err;
	struct wally_psbt *psbt;

	if (is_elements(chainparams))
		wally_err = wally_psbt_elements_init_alloc(0, num_inputs, num_outputs, 0, &psbt);
	else
		wally_err = wally_psbt_init_alloc(0, num_inputs, num_outputs, 0, &psbt);
	assert(wally_err == WALLY_OK);
	tal_add_destructor(psbt, psbt_destroy);
	return tal_steal(ctx, psbt);
}

struct wally_psbt *create_psbt(const tal_t *ctx, size_t num_inputs, size_t num_outputs, u32 locktime)
{
	int wally_err;
	struct wally_tx *wtx;
	struct wally_psbt *psbt;

	if (wally_tx_init_alloc(WALLY_TX_VERSION_2, locktime, num_inputs, num_outputs, &wtx) != WALLY_OK)
		abort();

	psbt = init_psbt(ctx, num_inputs, num_outputs);

	wally_err = wally_psbt_set_global_tx(psbt, wtx);
	assert(wally_err == WALLY_OK);
	return psbt;
}

struct wally_psbt *new_psbt(const tal_t *ctx, const struct wally_tx *wtx)
{
	struct wally_psbt *psbt;
	int wally_err;

	psbt = init_psbt(ctx, wtx->num_inputs, wtx->num_outputs);

	/* Set directly: avoids psbt checks for non-NULL scripts/witnesses */
	wally_err = wally_tx_clone_alloc(wtx, 0, &psbt->tx);
	assert(wally_err == WALLY_OK);
	/* Inputs/outs are pre-allocated above, 'add' them as empty dummies */
	psbt->num_inputs = wtx->num_inputs;
	psbt->num_outputs = wtx->num_outputs;

	for (size_t i = 0; i < wtx->num_inputs; i++) {
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

	return tal_steal(ctx, psbt);
}

bool psbt_is_finalized(const struct wally_psbt *psbt)
{
	size_t is_finalized;
	int wally_err = wally_psbt_is_finalized(psbt, &is_finalized);
	assert(wally_err == WALLY_OK);
	return is_finalized ? true : false;
}

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					struct wally_tx_input *input,
				       	size_t insert_at)
{
	const u32 flags = WALLY_PSBT_FLAG_NON_FINAL; /* Skip script/witness */
	int wally_err;

	wally_err = wally_psbt_add_input_at(psbt, insert_at, flags, input);
	assert(wally_err == WALLY_OK);
	return &psbt->inputs[insert_at];
}

struct wally_psbt_input *psbt_append_input(struct wally_psbt *psbt,
					   const struct bitcoin_txid *txid,
					   u32 outnum, u32 sequence)
{
	struct wally_tx_input *tx_in;
	struct wally_psbt_input *input;

	if (chainparams->is_elements) {
		if (wally_tx_elements_input_init_alloc(txid->shad.sha.u.u8,
						       sizeof(txid->shad.sha.u.u8),
						       outnum, sequence, NULL, 0,
						       NULL,
						       NULL, 0,
						       NULL, 0, NULL, 0,
						       NULL, 0, NULL, 0,
						       NULL, 0, NULL,
						       &tx_in) != WALLY_OK)
			abort();
	} else {
		if (wally_tx_input_init_alloc(txid->shad.sha.u.u8,
					      sizeof(txid->shad.sha.u.u8),
					      outnum, sequence, NULL, 0, NULL,
					      &tx_in) != WALLY_OK)
			abort();
	}

	input = psbt_add_input(psbt, tx_in, psbt->num_inputs);
	wally_tx_input_free(tx_in);
	return input;
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
	int wally_err = wally_psbt_add_output_at(psbt, insert_at, 0, output);
	assert(wally_err == WALLY_OK);
	return &psbt->outputs[insert_at];
}

struct wally_psbt_output *psbt_append_output(struct wally_psbt *psbt,
					     const u8 *script,
					     struct amount_sat amount)
{
	struct wally_psbt_output *out;
	struct wally_tx_output *tx_out = wally_tx_output(script, amount);

	out = psbt_add_output(psbt, tx_out, psbt->tx->num_outputs);
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
			   const struct pubkey *pubkey)
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

	wally_err = wally_psbt_input_add_keypath_item(&psbt->inputs[in],
						      pk_der, sizeof(pk_der),
						      fingerprint, sizeof(fingerprint),
						      empty_path, ARRAY_SIZE(empty_path));
	assert(wally_err == WALLY_OK);
}

bool psbt_input_set_signature(struct wally_psbt *psbt, size_t in,
			      const struct pubkey *pubkey,
			      const struct bitcoin_signature *sig)
{
	u8 pk_der[PUBKEY_CMPR_LEN];

	assert(in < psbt->num_inputs);

	/* we serialize the compressed version of the key, wally likes this */
	pubkey_to_der(pk_der, pubkey);
	wally_psbt_input_set_sighash(&psbt->inputs[in], sig->sighash_type);
	return wally_psbt_input_add_signature(&psbt->inputs[in],
					      pk_der, sizeof(pk_der),
					      sig->s.data,
					      sizeof(sig->s.data)) == WALLY_OK;
}

static void psbt_input_set_witness_utxo(struct wally_psbt *psbt, size_t in,
					const struct wally_tx_output *txout)
{
	int wally_err;
	assert(psbt->num_inputs > in);
	wally_err = wally_psbt_input_set_witness_utxo(&psbt->inputs[in],
						      txout);
	assert(wally_err == WALLY_OK);
}

void psbt_input_set_prev_utxo(struct wally_psbt *psbt, size_t in,
			      const u8 *scriptPubkey, struct amount_sat amt)
{
	struct wally_tx_output prev_out;
	int wally_err;
	u8 *scriptpk;

	if (scriptPubkey) {
		assert(is_p2wsh(scriptPubkey, NULL) || is_p2wpkh(scriptPubkey, NULL)
		       || is_p2sh(scriptPubkey, NULL));
		scriptpk = cast_const(u8 *, scriptPubkey);
	} else {
		/* Adding a NULL scriptpubkey is an error, *however* there is the
		 * possiblity we're spending a UTXO that we didn't save the
		 * scriptpubkey data for. in this case we set it to an 'empty'
		 * or zero-len script */
		scriptpk = tal_arr(psbt, u8, 1);
		scriptpk[0] = 0x00;
	}

	wally_err = wally_tx_output_init(amt.satoshis, /* Raw: type conv */
					 scriptpk,
					 tal_bytelen(scriptpk),
					 &prev_out);
	assert(wally_err == WALLY_OK);
	psbt_input_set_witness_utxo(psbt, in, &prev_out);
}

static void psbt_input_set_elements_prev_utxo(struct wally_psbt *psbt,
					      size_t in,
					      const u8 *scriptPubkey,
					      struct amount_asset *asset,
					      const u8 *nonce)
{
	struct wally_tx_output prev_out;
	int wally_err;

	u8 *prefixed_value = amount_asset_extract_value(psbt, asset);

	wally_err =
		wally_tx_elements_output_init(scriptPubkey,
					      tal_bytelen(scriptPubkey),
					      asset->asset,
					      sizeof(asset->asset),
					      prefixed_value,
					      tal_bytelen(prefixed_value),
					      nonce,
					      tal_bytelen(nonce),
					      NULL, 0,
					      NULL, 0,
					      &prev_out);
	assert(wally_err == WALLY_OK);
	psbt_input_set_witness_utxo(psbt, in, &prev_out);
}

void psbt_input_set_prev_utxo_wscript(struct wally_psbt *psbt, size_t in,
			              const u8 *wscript, struct amount_sat amt)
{
	int wally_err;
	const u8 *scriptPubkey;

	if (wscript) {
		scriptPubkey = scriptpubkey_p2wsh(psbt, wscript);
		wally_err = wally_psbt_input_set_witness_script(&psbt->inputs[in],
								wscript,
								tal_bytelen(wscript));
		assert(wally_err == WALLY_OK);
	} else
		scriptPubkey = NULL;
	psbt_input_set_prev_utxo(psbt, in, scriptPubkey, amt);
}

static void
psbt_input_set_elements_prev_utxo_wscript(struct wally_psbt *psbt,
					  size_t in,
					  const u8 *wscript,
					  struct amount_asset *asset,
					  const u8 *nonce)
{
	int wally_err;
	const u8 *scriptPubkey;

	if (wscript) {
		scriptPubkey = scriptpubkey_p2wsh(psbt, wscript);
		wally_err = wally_psbt_input_set_witness_script(
				&psbt->inputs[in],
				wscript, tal_bytelen(wscript));
		assert(wally_err == WALLY_OK);
	} else
		scriptPubkey = NULL;

	psbt_input_set_elements_prev_utxo(psbt, in, scriptPubkey,
					  asset, nonce);
}

void psbt_elements_input_init_witness(struct wally_psbt *psbt, size_t in,
				      const u8 *witscript,
				      struct amount_asset *asset,
				      const u8 *nonce)
{
	psbt_input_set_elements_prev_utxo_wscript(
			psbt, in, witscript,
			asset, nonce);

	if (asset->value > 0)
		wally_psbt_input_set_value(&psbt->inputs[in], asset->value);

	/* PSET expects an asset tag without the prefix */
	if (wally_psbt_input_set_asset(&psbt->inputs[in],
				       asset->asset + 1,
				       ELEMENTS_ASSET_LEN - 1) != WALLY_OK)
		abort();
}

void psbt_elements_input_init(struct wally_psbt *psbt, size_t in,
			      const u8 *scriptPubkey,
			      struct amount_asset *asset,
			      const u8 *nonce)
{
	psbt_input_set_elements_prev_utxo(psbt, in,
					  scriptPubkey,
					  asset, nonce);

	if (asset->value > 0) {
		if (wally_psbt_input_set_value(
					&psbt->inputs[in],
					asset->value) != WALLY_OK)
			abort();

	}

	/* PSET expects an asset tag without the prefix */
	/* FIXME: Verify that we're sending unblinded asset tag */
	if (wally_psbt_input_set_asset(&psbt->inputs[in],
				       asset->asset + 1,
				       ELEMENTS_ASSET_LEN - 1) != WALLY_OK)
		abort();
}

bool psbt_has_input(struct wally_psbt *psbt,
		    struct bitcoin_txid *txid,
		    u32 outnum)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		struct bitcoin_txid in_txid;
		struct wally_tx_input *in = &psbt->tx->inputs[i];

		if (outnum != in->index)
			continue;

		wally_tx_input_get_txid(in, &in_txid);
		if (bitcoin_txid_eq(txid, &in_txid))
			return true;
	}
	return false;
}

bool psbt_input_set_redeemscript(struct wally_psbt *psbt, size_t in,
				 const u8 *redeemscript)
{
	int wally_err;
	assert(psbt->num_inputs > in);
	wally_err = wally_psbt_input_set_redeem_script(&psbt->inputs[in],
						       redeemscript,
						       tal_bytelen(redeemscript));
	return wally_err == WALLY_OK;
}

struct amount_sat psbt_input_get_amount(struct wally_psbt *psbt,
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
		int idx = psbt->tx->inputs[in].index;
		struct wally_tx *prev_tx = psbt->inputs[in].utxo;
		val = amount_sat(prev_tx->outputs[idx].satoshi);
	} else
		abort();

	return val;
}

struct amount_sat psbt_output_get_amount(struct wally_psbt *psbt,
					 size_t out)
{
	struct amount_asset asset;
	assert(out < psbt->num_outputs);
	asset = wally_tx_output_get_amount(&psbt->tx->outputs[out]);
	assert(amount_asset_is_main(&asset));
	return amount_asset_to_sat(&asset);
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

static void add_varint(u8 **key, size_t val)
{
	u8 vt[VARINT_MAX_LEN];
	size_t vtlen;
	vtlen = varint_put(vt, val);
	add(key, vt, vtlen);
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
	add_type(&key, PSBT_PROPRIETARY_TYPE);
	add_varint(&key, strlen(LIGHTNING_PROPRIETARY_PREFIX));
	add(&key, LIGHTNING_PROPRIETARY_PREFIX,
	    strlen(LIGHTNING_PROPRIETARY_PREFIX));
	add_type(&key, key_subtype);
	if (key_data)
		add(&key, key_data, tal_bytelen(key_data));
	return key;
}

void psbt_input_add_unknown(struct wally_psbt_input *in,
			    const u8 *key,
			    const void *value,
			    size_t value_len)
{
	if (wally_map_add(&in->unknowns,
			  cast_const(unsigned char *, key), tal_bytelen(key),
			  (unsigned char *) memcheck(value, value_len), value_len)
			!= WALLY_OK)
		abort();
}

void *psbt_get_unknown(const struct wally_map *map,
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


void psbt_output_add_unknown(struct wally_psbt_output *out,
			     const u8 *key,
			     const void *value,
			     size_t value_len)
{
	if (wally_map_add(&out->unknowns,
			  cast_const(unsigned char *, key), tal_bytelen(key),
			  (unsigned char *) memcheck(value, value_len), value_len)
			!= WALLY_OK)
		abort();
}

struct wally_tx *psbt_finalize(struct wally_psbt *psbt, bool finalize_in_place)
{
	struct wally_psbt *tmppsbt;
	struct wally_tx *wtx;

	/* We want the 'finalized' tx since that includes any signature
	 * data, not the global tx. But 'finalizing' a tx destroys some fields
	 * so we 'clone' it first and then finalize it */
	if (!finalize_in_place) {
		if (wally_psbt_clone_alloc(psbt, 0, &tmppsbt) != WALLY_OK)
			return NULL;
	} else
		tmppsbt = cast_const(struct wally_psbt *, psbt);

	/* Wally doesn't know how to finalize P2WSH; this happens with
	 * option_anchor_outputs, and finalizing is trivial. */
	/* FIXME: miniscript! miniscript! miniscript! */
	for (size_t i = 0; i < tmppsbt->num_inputs; i++) {
		struct wally_psbt_input *input = &tmppsbt->inputs[i];
		struct wally_tx_witness_stack *stack;

		if (!is_anchor_witness_script(input->witness_script,
					      input->witness_script_len))
			continue;

		if (input->signatures.num_items != 1)
			continue;

		/* BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
		 * #### `to_remote` Output
		 *...
		 *
		 * If `option_anchor_outputs` applies to the commitment
		 * transaction, the `to_remote` output is encumbered by a one
		 * block csv lock.
		 *
		 *    <remote_pubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
		 *
		 * The output is spent by a transaction with `nSequence` field set to `1` and witness:
		 *
		 *    <remote_sig>
		 */
		wally_tx_witness_stack_init_alloc(2, &stack);
		wally_tx_witness_stack_add(stack,
					   input->signatures.items[0].value,
					   input->signatures.items[0].value_len);
		wally_tx_witness_stack_add(stack,
					   input->witness_script,
					   input->witness_script_len);
		input->final_witness = stack;
	}

	if (wally_psbt_finalize(tmppsbt) != WALLY_OK) {
		if (!finalize_in_place)
			wally_psbt_free(tmppsbt);
		return NULL;
	}

	if (psbt_is_finalized(tmppsbt)
		&& wally_psbt_extract(tmppsbt, &wtx) == WALLY_OK) {
		if (!finalize_in_place)
			wally_psbt_free(tmppsbt);
		return wtx;
	}

	if (!finalize_in_place)
		wally_psbt_free(tmppsbt);
	return NULL;
}

struct wally_psbt *psbt_from_b64(const tal_t *ctx,
				 const char *b64,
				 size_t b64len)
{
	struct wally_psbt *psbt;
	char *str = tal_strndup(tmpctx, b64, b64len);

	if (wally_psbt_from_base64(str, &psbt) != WALLY_OK)
		return NULL;

	/* We promised it would be owned by ctx: libwally uses a dummy owner */
	tal_steal(ctx, psbt);
	tal_add_destructor(psbt, psbt_destroy);
	return psbt;
}

char *psbt_to_b64(const tal_t *ctx, const struct wally_psbt *psbt)
{
	char *serialized_psbt, *ret_val;
	int ret;

	ret = wally_psbt_to_base64(psbt, 0, &serialized_psbt);
	assert(ret == WALLY_OK);

	ret_val = tal_strdup(ctx, serialized_psbt);
	wally_free_string(serialized_psbt);
	return ret_val;
}

/* Do not remove this line, it is magic */
REGISTER_TYPE_TO_STRING(wally_psbt, psbt_to_b64);

const u8 *psbt_get_bytes(const tal_t *ctx, const struct wally_psbt *psbt,
			 size_t *bytes_written)
{
	size_t len = 0;
	u8 *bytes;

	wally_psbt_get_length(psbt, 0, &len);
	bytes = tal_arr(ctx, u8, len);

	if (wally_psbt_to_bytes(psbt, 0, bytes, len, bytes_written) != WALLY_OK ||
	    *bytes_written != len) {
		/* something went wrong. bad libwally ?? */
		abort();
	}
	return bytes;
}

struct wally_psbt *psbt_from_bytes(const tal_t *ctx, const u8 *bytes,
				   size_t byte_len)
{
	struct wally_psbt *psbt;

	if (wally_psbt_from_bytes(bytes, byte_len, &psbt) != WALLY_OK)
		return NULL;

	/* We promised it would be owned by ctx: libwally uses a dummy owner */
	tal_steal(ctx, psbt);
	tal_add_destructor(psbt, psbt_destroy);
	return psbt;
}

void towire_wally_psbt(u8 **pptr, const struct wally_psbt *psbt)
{
	/* Let's include the PSBT bytes */
	size_t bytes_written;
	const u8 *pbt_bytes = psbt_get_bytes(NULL, psbt, &bytes_written);
	towire_u32(pptr, bytes_written);
	towire_u8_array(pptr, pbt_bytes, bytes_written);
	tal_free(pbt_bytes);
}

struct wally_psbt *fromwire_wally_psbt(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct wally_psbt *psbt;
	u32 psbt_byte_len;
	const u8 *psbt_buf;

	psbt_byte_len = fromwire_u32(cursor, max);
	psbt_buf = fromwire(cursor, max, NULL, psbt_byte_len);
	if (!psbt_buf)
		return NULL;

	psbt = psbt_from_bytes(ctx, psbt_buf, psbt_byte_len);
	if (!psbt)
		return fromwire_fail(cursor, max);

#if DEVELOPER
	/* Re-marshall for sanity check! */
	u8 *tmpbuf = tal_arr(NULL, u8, psbt_byte_len);
	size_t written;
	if (wally_psbt_to_bytes(psbt, 0, tmpbuf, psbt_byte_len, &written) != WALLY_OK) {
		tal_free(tmpbuf);
		tal_free(psbt);
		return fromwire_fail(cursor, max);
	}
	tal_free(tmpbuf);
#endif

	return psbt;
}

/* This only works on a non-final psbt because we're ALL SEGWIT! */
void psbt_txid(const struct wally_psbt *psbt, struct bitcoin_txid *txid,
	       struct wally_tx **wtx)
{
	struct wally_tx *tx;

	/* You can *almost* take txid of global tx.  But @niftynei thought
	 * about this far more than me and pointed out that P2SH
	 * inputs would not be represented, so here we go. */

	wally_tx_clone_alloc(psbt->tx, 0, &tx);

	for (size_t i = 0; i < tx->num_inputs; i++) {
		u8 *script;
		if (!psbt->inputs[i].redeem_script)
			continue;

		/* P2SH requires push of the redeemscript, from libwally src */
		script = tal_arr(tmpctx, u8, 0);
		script_push_bytes(&script,
				  psbt->inputs[i].redeem_script,
				  psbt->inputs[i].redeem_script_len);
		wally_tx_set_input_script(tx, i, script, tal_bytelen(script));
	}

	wally_txid(tx, txid);
	if (wtx)
		*wtx = tx;
	else
		wally_tx_free(tx);
}
