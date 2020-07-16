#include <assert.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <ccan/cast/cast.h>
#include <ccan/ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/type_to_string.h>
#include <common/utils.h>
/* FIXME: this is ugly! */
#include <external/libwally-core/src/ccan/ccan/base64/base64.h>
#include <string.h>
#include <wally_psbt.h>
#include <wally_transaction.h>
#include <wire/wire.h>

#define MAKE_ROOM(arr, pos, num)				\
	memmove((arr) + (pos) + 1, (arr) + (pos),		\
		sizeof(*(arr)) * ((num) - ((pos) + 1)))

#define REMOVE_ELEM(arr, pos, num)				\
	memmove((arr) + (pos), (arr) + (pos) + 1,		\
		sizeof(*(arr)) * ((num) - ((pos) + 1)))

/* FIXME: someday this will break, because it's been exposed in libwally */
int wally_psbt_clone(const struct wally_psbt *psbt, struct wally_psbt **output)
{
	int ret;
	size_t byte_len;
	const u8 *bytes = psbt_get_bytes(NULL, psbt, &byte_len);

	ret = wally_psbt_from_bytes(bytes, byte_len, output);
	tal_free(bytes);
	return ret;
}

void psbt_destroy(struct wally_psbt *psbt)
{
	wally_psbt_free(psbt);
}

struct wally_psbt *new_psbt(const tal_t *ctx, const struct wally_tx *wtx)
{
	struct wally_psbt *psbt;
	int wally_err;
	u8 **scripts;
	size_t *script_lens;
	struct wally_tx_witness_stack **witnesses;

	if (is_elements(chainparams))
		wally_err = wally_psbt_elements_init_alloc(wtx->num_inputs, wtx->num_outputs, 0, &psbt);
	else
		wally_err = wally_psbt_init_alloc(wtx->num_inputs, wtx->num_outputs, 0, &psbt);
	assert(wally_err == WALLY_OK);
	tal_add_destructor(psbt, psbt_destroy);

	/* we can't have scripts on the psbt's global tx,
	 * so we erase them/stash them until after it's been populated */
	scripts = tal_arr(NULL, u8 *, wtx->num_inputs);
	script_lens = tal_arr(NULL, size_t, wtx->num_inputs);
	witnesses = tal_arr(NULL, struct wally_tx_witness_stack *, wtx->num_inputs);
	for (size_t i = 0; i < wtx->num_inputs; i++) {
		scripts[i] = (u8 *)wtx->inputs[i].script;
		wtx->inputs[i].script = NULL;
		script_lens[i] = wtx->inputs[i].script_len;
		wtx->inputs[i].script_len = 0;
		witnesses[i] = wtx->inputs[i].witness;
		wtx->inputs[i].witness = NULL;
	}

	wally_err = wally_psbt_set_global_tx(psbt, cast_const(struct wally_tx *, wtx));
	assert(wally_err == WALLY_OK);

	/* set the scripts + witnesses back */
	for (size_t i = 0; i < wtx->num_inputs; i++) {
		int wally_err;

		wtx->inputs[i].script = (unsigned char *)scripts[i];
		wtx->inputs[i].script_len = script_lens[i];
		wtx->inputs[i].witness = witnesses[i];

		/* add these scripts + witnesses to the psbt */
		if (scripts[i]) {
			wally_err =
				wally_psbt_input_set_final_script_sig(&psbt->inputs[i],
								      (unsigned char *)scripts[i],
								      script_lens[i]);
			assert(wally_err == WALLY_OK);
		}
		if (witnesses[i]) {
			wally_err =
				wally_psbt_input_set_final_witness(&psbt->inputs[i],
								   witnesses[i]);
			assert(wally_err == WALLY_OK);
		}
	}

	tal_free(witnesses);
	tal_free(scripts);
	tal_free(script_lens);

	return tal_steal(ctx, psbt);
}

bool psbt_is_finalized(struct wally_psbt *psbt)
{
	for (size_t i = 0; i < psbt->num_inputs; i++) {
		if (!psbt->inputs[i].final_script_sig &&
				!psbt->inputs[i].final_witness)
			return false;
	}

	return true;
}

struct wally_psbt_input *psbt_add_input(struct wally_psbt *psbt,
					struct wally_tx_input *input,
				       	size_t insert_at)
{
	struct wally_tx *tx;
	struct wally_tx_input tmp_in;
	u8 *script;
	size_t scriptlen = 0;
	struct wally_tx_witness_stack *witness = NULL;

	tx = psbt->tx;
	assert(insert_at <= tx->num_inputs);

	/* Remove any script sig or witness info before adding it ! */
	if (input->script_len > 0) {
		scriptlen = input->script_len;
		input->script_len = 0;
		script = (u8 *)input->script;
		input->script = NULL;
	}
	if (input->witness) {
		witness = input->witness;
		input->witness = NULL;
	}
	wally_tx_add_input(tx, input);
	/* Put the script + witness info back */
	if (scriptlen > 0) {
		input->script_len = scriptlen;
		input->script = script;
	}
	if (witness)
		input->witness = witness;

	tmp_in = tx->inputs[tx->num_inputs - 1];
	MAKE_ROOM(tx->inputs, insert_at, tx->num_inputs);
	tx->inputs[insert_at] = tmp_in;

    	if (psbt->inputs_allocation_len < tx->num_inputs) {
		struct wally_psbt_input *p = tal_arr(psbt, struct wally_psbt_input, tx->num_inputs);
		memcpy(p, psbt->inputs, sizeof(*psbt->inputs) * psbt->inputs_allocation_len);
		tal_free(psbt->inputs);

		psbt->inputs = p;
		psbt->inputs_allocation_len = tx->num_inputs;
	}

	psbt->num_inputs += 1;
	MAKE_ROOM(psbt->inputs, insert_at, psbt->num_inputs);
	memset(&psbt->inputs[insert_at], 0, sizeof(psbt->inputs[insert_at]));
	return &psbt->inputs[insert_at];
}

void psbt_rm_input(struct wally_psbt *psbt,
		   size_t remove_at)
{
	assert(remove_at < psbt->tx->num_inputs);
	wally_tx_remove_input(psbt->tx, remove_at);
	REMOVE_ELEM(psbt->inputs, remove_at, psbt->num_inputs);
	psbt->num_inputs -= 1;
}

struct wally_psbt_output *psbt_add_output(struct wally_psbt *psbt,
					  struct wally_tx_output *output,
					  size_t insert_at)
{
	struct wally_tx *tx;
	struct wally_tx_output tmp_out;

	tx = psbt->tx;
	assert(insert_at <= tx->num_outputs);
	wally_tx_add_output(tx, output);
	tmp_out = tx->outputs[tx->num_outputs - 1];
	MAKE_ROOM(tx->outputs, insert_at, tx->num_outputs);
	tx->outputs[insert_at] = tmp_out;

    	if (psbt->outputs_allocation_len < tx->num_outputs) {
		struct wally_psbt_output *p = tal_arr(psbt, struct wally_psbt_output, tx->num_outputs);
		memcpy(p, psbt->outputs, sizeof(*psbt->outputs) * psbt->outputs_allocation_len);
		tal_free(psbt->outputs);

		psbt->outputs = p;
		psbt->outputs_allocation_len = tx->num_outputs;
	}

	psbt->num_outputs += 1;
	MAKE_ROOM(psbt->outputs, insert_at, psbt->num_outputs);
	memset(&psbt->outputs[insert_at], 0, sizeof(psbt->outputs[insert_at]));
	return &psbt->outputs[insert_at];
}

void psbt_rm_output(struct wally_psbt *psbt,
		    size_t remove_at)
{
	assert(remove_at < psbt->tx->num_outputs);
	wally_tx_remove_output(psbt->tx, remove_at);
	REMOVE_ELEM(psbt->outputs, remove_at, psbt->num_outputs);
	psbt->num_outputs -= 1;
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

	if (!psbt->inputs[in].keypaths)
		if (wally_keypath_map_init_alloc(1, &psbt->inputs[in].keypaths) != WALLY_OK)
			abort();

	wally_err = wally_add_new_keypath(psbt->inputs[in].keypaths,
					  pk_der, sizeof(pk_der),
					  fingerprint, sizeof(fingerprint),
					  empty_path, ARRAY_SIZE(empty_path));

	assert(wally_err == WALLY_OK);
}

bool psbt_input_set_partial_sig(struct wally_psbt *psbt, size_t in,
				const struct pubkey *pubkey,
				const struct bitcoin_signature *sig)
{
	u8 pk_der[PUBKEY_CMPR_LEN];

	assert(in < psbt->num_inputs);
	if (!psbt->inputs[in].partial_sigs)
		if (wally_partial_sigs_map_init_alloc(1, &psbt->inputs[in].partial_sigs) != WALLY_OK)
			return false;

	/* we serialize the compressed version of the key, wally likes this */
	pubkey_to_der(pk_der, pubkey);
	wally_psbt_input_set_sighash_type(&psbt->inputs[in], sig->sighash_type);
	return wally_add_new_partial_sig(psbt->inputs[in].partial_sigs,
					 pk_der, sizeof(pk_der),
					 cast_const(unsigned char *, sig->s.data),
					 sizeof(sig->s.data)) == WALLY_OK;
}

static void psbt_input_set_witness_utxo(struct wally_psbt *psbt, size_t in,
					struct wally_tx_output *txout)
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
	struct wally_tx_output *prev_out;
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

	wally_err = wally_tx_output_init_alloc(amt.satoshis, /* Raw: type conv */
					       scriptpk,
					       tal_bytelen(scriptpk),
					       &prev_out);
	assert(wally_err == WALLY_OK);
	psbt_input_set_witness_utxo(psbt, in, prev_out);
}

static void psbt_input_set_elements_prev_utxo(struct wally_psbt *psbt,
					      size_t in,
					      const u8 *scriptPubkey,
					      struct amount_asset *asset,
					      const u8 *nonce)
{
	struct wally_tx_output *prev_out;
	int wally_err;

	u8 *prefixed_value = amount_asset_extract_value(psbt, asset);

	wally_err =
		wally_tx_elements_output_init_alloc(scriptPubkey,
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
	psbt_input_set_witness_utxo(psbt, in, prev_out);
}

void psbt_input_set_prev_utxo_wscript(struct wally_psbt *psbt, size_t in,
			              const u8 *wscript, struct amount_sat amt)
{
	int wally_err;
	const u8 *scriptPubkey;

	if (wscript) {
		scriptPubkey = scriptpubkey_p2wsh(psbt, wscript);
		wally_err = wally_psbt_input_set_witness_script(&psbt->inputs[in],
								cast_const(u8 *, wscript),
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
				cast_const(u8 *, wscript),
				tal_bytelen(wscript));
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
		wally_psbt_elements_input_set_value(&psbt->inputs[in],
						    asset->value);

	/* PSET expects an asset tag without the prefix */
	if (wally_psbt_elements_input_set_asset(&psbt->inputs[in],
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
		if (wally_psbt_elements_input_set_value(
					&psbt->inputs[in],
					asset->value) != WALLY_OK)
			abort();

	}

	/* PSET expects an asset tag without the prefix */
	/* FIXME: Verify that we're sending unblinded asset tag */
	if (wally_psbt_elements_input_set_asset(
					&psbt->inputs[in],
					asset->asset + 1,
					ELEMENTS_ASSET_LEN - 1) != WALLY_OK)
		abort();
}

bool psbt_input_set_redeemscript(struct wally_psbt *psbt, size_t in,
				 const u8 *redeemscript)
{
	int wally_err;
	assert(psbt->num_inputs > in);
	wally_err = wally_psbt_input_set_redeem_script(&psbt->inputs[in],
						       cast_const(u8 *, redeemscript),
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
	} else if (psbt->inputs[in].non_witness_utxo) {
		int idx = psbt->tx->inputs[in].index;
		struct wally_tx *prev_tx = psbt->inputs[in].non_witness_utxo;
		val.satoshis = prev_tx->outputs[idx].satoshi; /* Raw: type conversion */
	} else
		abort();

	return val;
}

struct wally_tx *psbt_finalize(struct wally_psbt *psbt, bool finalize_in_place)
{
	struct wally_psbt *tmppsbt;
	struct wally_tx *wtx;

	/* We want the 'finalized' tx since that includes any signature
	 * data, not the global tx. But 'finalizing' a tx destroys some fields
	 * so we 'clone' it first and then finalize it */
	if (!finalize_in_place) {
		if (wally_psbt_clone(psbt, &tmppsbt) != WALLY_OK)
			return NULL;
	} else
		tmppsbt = cast_const(struct wally_psbt *, psbt);

	if (wally_finalize_psbt(tmppsbt) != WALLY_OK) {
		if (!finalize_in_place)
			wally_psbt_free(tmppsbt);
		return NULL;
	}

	if (psbt_is_finalized(tmppsbt)
		&& wally_extract_psbt(tmppsbt, &wtx) == WALLY_OK) {
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
	ssize_t decodelen;
	u8 *bytes = tal_arr(tmpctx, u8, base64_decoded_length(b64len));

	decodelen = base64_decode((char *)bytes, tal_bytelen(bytes),
				  b64, b64len);
	if (decodelen < 0)
		return NULL;

	return psbt_from_bytes(ctx, bytes, decodelen);
}

char *psbt_to_b64(const tal_t *ctx, const struct wally_psbt *psbt)
{
	char *serialized_psbt, *ret_val;
	int ret;

	ret = wally_psbt_to_base64(cast_const(struct wally_psbt *, psbt),
				   &serialized_psbt);
	assert(ret == WALLY_OK);

	ret_val = tal_strdup(ctx, serialized_psbt);
	wally_free_string(serialized_psbt);
	return ret_val;
}
REGISTER_TYPE_TO_STRING(wally_psbt, psbt_to_b64);

const u8 *psbt_get_bytes(const tal_t *ctx, const struct wally_psbt *psbt,
			 size_t *bytes_written)
{
	/* the libwally API doesn't do anything helpful for allocating
	 * things here -- to compensate we do a single shot large alloc
	 */
	size_t room = 1024 * 1000;
	u8 *pbt_bytes = tal_arr(ctx, u8, room);
	if (wally_psbt_to_bytes(psbt, pbt_bytes, room, bytes_written) != WALLY_OK) {
		/* something went wrong. bad libwally ?? */
		abort();
	}
	tal_resize(&pbt_bytes, *bytes_written);
	return pbt_bytes;
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
	if (wally_psbt_to_bytes(psbt, tmpbuf, psbt_byte_len, &written) != WALLY_OK) {
		tal_free(tmpbuf);
		tal_free(psbt);
		return fromwire_fail(cursor, max);
	}
	tal_free(tmpbuf);
#endif

	return psbt;
}

