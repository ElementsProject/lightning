#include <assert.h>
#include <bitcoin/block.h>
#include <bitcoin/chainparams.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pullpush.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/str/hex/hex.h>
#include <common/type_to_string.h>
#include <stdio.h>
#include <wire/wire.h>

#define SEGREGATED_WITNESS_FLAG 0x1

/* FIXME: When wally exposes this, we will clash and can remove this one */
int wally_tx_clone(struct wally_tx *tx, struct wally_tx **output)
{
	u8 *txlin = linearize_wtx(NULL, tx);
	int flags = WALLY_TX_FLAG_USE_WITNESS;
	int ret;

	if (chainparams->is_elements)
		flags |= WALLY_TX_FLAG_USE_ELEMENTS;

	ret = wally_tx_from_bytes(txlin, tal_bytelen(txlin), flags, output);
	tal_free(txlin);
	return ret;
}

int bitcoin_tx_add_output(struct bitcoin_tx *tx, const u8 *script,
			  u8 *wscript, struct amount_sat amount)
{
	size_t i = tx->wtx->num_outputs;
	struct wally_tx_output *output;
	struct wally_psbt_output *psbt_out;
	int ret;
	u64 satoshis = amount.satoshis; /* Raw: low-level helper */
	const struct chainparams *chainparams = tx->chainparams;
	assert(i < tx->wtx->outputs_allocation_len);

	assert(tx->wtx != NULL);
	assert(chainparams);

	if (chainparams->is_elements) {
		u8 value[9];
		ret = wally_tx_confidential_value_from_satoshi(satoshis, value,
							       sizeof(value));
		assert(ret == WALLY_OK);
		ret = wally_tx_elements_output_init_alloc(
		    script, tal_bytelen(script), chainparams->fee_asset_tag, 33,
		    value, sizeof(value), NULL, 0, NULL, 0, NULL, 0, &output);
		assert(ret == WALLY_OK);
		/* Cheat a bit by also setting the numeric satoshi value,
		 * otherwise we end up converting a number of times */
		output->satoshi = satoshis;
	} else {
		ret = wally_tx_output_init_alloc(satoshis, script,
						 tal_bytelen(script), &output);
		assert(ret == WALLY_OK);
	}
	ret = wally_tx_add_output(tx->wtx, output);
	assert(ret == WALLY_OK);

	psbt_out = psbt_add_output(tx->psbt, output, i);
	if (wscript) {
		ret = wally_psbt_output_set_witness_script(psbt_out,
							   wscript,
							   tal_bytelen(wscript));
		assert(ret == WALLY_OK);
	}

	wally_tx_output_free(output);
	bitcoin_tx_output_set_amount(tx, i, amount);

	return i;
}

int bitcoin_tx_add_multi_outputs(struct bitcoin_tx *tx,
				 struct bitcoin_tx_output **outputs)
{
	for (size_t j = 0; j < tal_count(outputs); j++)
		bitcoin_tx_add_output(tx, outputs[j]->script,
				      NULL, outputs[j]->amount);

	return tx->wtx->num_outputs;
}

bool elements_tx_output_is_fee(const struct bitcoin_tx *tx, int outnum)
{
	assert(outnum < tx->wtx->num_outputs);
	return chainparams->is_elements &&
	       tx->wtx->outputs[outnum].script_len == 0;
}

struct amount_sat bitcoin_tx_compute_fee_w_inputs(const struct bitcoin_tx *tx,
						  struct amount_sat input_val)
{
	struct amount_asset asset;
	bool ok;

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		asset = bitcoin_tx_output_get_amount(tx, i);
		if (elements_tx_output_is_fee(tx, i) ||
		    !amount_asset_is_main(&asset))
			continue;

		ok = amount_sat_sub(&input_val, input_val,
				    amount_asset_to_sat(&asset));
		assert(ok);
	}
	return input_val;
}

/**
 * Compute how much fee we are actually sending with this transaction.
 */
struct amount_sat bitcoin_tx_compute_fee(const struct bitcoin_tx *tx)
{
	struct amount_sat input_total = AMOUNT_SAT(0), input_amt;
	bool ok;

	for (size_t i = 0; i < tx->psbt->num_inputs; i++) {
		input_amt = psbt_input_get_amount(tx->psbt, i);
		ok = amount_sat_add(&input_total, input_total, input_amt);
		assert(ok);
	}

	return bitcoin_tx_compute_fee_w_inputs(tx, input_total);
}

/*
 * Add an explicit fee output if necessary.
 *
 * An explicit fee output is only necessary if we are using an elements
 * transaction, and we have a non-zero fee. This method may be called multiple
 * times.
 *
 * Returns the position of the fee output, or -1 in the case of non-elements
 * transactions.
 */
static int elements_tx_add_fee_output(struct bitcoin_tx *tx)
{
	struct amount_sat fee = bitcoin_tx_compute_fee(tx);
	int pos;

	/* If we aren't using elements, we don't add explicit fee outputs */
	if (!chainparams->is_elements || amount_sat_eq(fee, AMOUNT_SAT(0)))
		return -1;

	/* Try to find any existing fee output */
	for (pos = 0; pos < tx->wtx->num_outputs; pos++) {
		if (elements_tx_output_is_fee(tx, pos))
			break;
	}

	if (pos == tx->wtx->num_outputs)
		return bitcoin_tx_add_output(tx, NULL, NULL, fee);
	else {
		bitcoin_tx_output_set_amount(tx, pos, fee);
		return pos;
	}
}

void bitcoin_tx_set_locktime(struct bitcoin_tx *tx, u32 locktime)
{
	tx->wtx->locktime = locktime;
	tx->psbt->tx->locktime = locktime;
}

int bitcoin_tx_add_input(struct bitcoin_tx *tx, const struct bitcoin_txid *txid,
			 u32 outnum, u32 sequence, const u8 *scriptSig,
			 struct amount_sat amount, const u8 *scriptPubkey,
			 const u8 *input_wscript)
{
	struct wally_tx_input *input;
	int wally_err;
	size_t i;

	assert(tx->wtx != NULL);
	i = tx->wtx->num_inputs;
	wally_err = wally_tx_input_init_alloc(txid->shad.sha.u.u8,
					      sizeof(struct bitcoin_txid),
					      outnum, sequence,
					      scriptSig, tal_bytelen(scriptSig),
					      NULL /* Empty witness stack */,
					      &input);
	assert(wally_err == WALLY_OK);
	input->features = chainparams->is_elements ? WALLY_TX_IS_ELEMENTS : 0;
	wally_tx_add_input(tx->wtx, input);
	psbt_add_input(tx->psbt, input, i);

	if (input_wscript) {
		/* Add the prev output's data into the PSBT struct */
		psbt_input_set_prev_utxo_wscript(tx->psbt, i, input_wscript, amount);
	} else if (scriptPubkey) {
		if (is_p2wsh(scriptPubkey, NULL) || is_p2wpkh(scriptPubkey, NULL) ||
			/* FIXME: assert that p2sh inputs are witness/are accompanied by a redeemscript+witnessscript */
			is_p2sh(scriptPubkey, NULL)) {
			/* the only way to get here currently with a p2sh script is via a p2sh-p2wpkh script
			 * that we've created ...*/
			/* Relevant section from bip-0174, emphasis mine:
			 * ** Value: The entire transaction output in network serialization which the current input spends from.
			 * This should only be present for inputs which spend segwit outputs, _including P2SH embedded ones._
			 */
			psbt_input_set_prev_utxo(tx->psbt, i, scriptPubkey, amount);
		}
	}

	wally_tx_input_free(input);

	return i;
}

bool bitcoin_tx_check(const struct bitcoin_tx *tx)
{
	u8 *newtx;
	size_t written;
	int flags = WALLY_TX_FLAG_USE_WITNESS;

	if (wally_tx_get_length(tx->wtx, flags, &written) != WALLY_OK)
		return false;

	newtx = tal_arr(tmpctx, u8, written);
	if (wally_tx_to_bytes(tx->wtx, flags, newtx, written, &written) !=
	    WALLY_OK)
		return false;

	if (written != tal_bytelen(newtx))
		return false;

	return true;
}

void bitcoin_tx_output_set_amount(struct bitcoin_tx *tx, int outnum,
				  struct amount_sat amount)
{
	u64 satoshis = amount.satoshis; /* Raw: low-level helper */
	struct wally_tx_output *output = &tx->wtx->outputs[outnum];
	assert(outnum < tx->wtx->num_outputs);
	if (chainparams->is_elements) {
		int ret = wally_tx_confidential_value_from_satoshi(
		    satoshis, output->value, output->value_len);
		assert(ret == WALLY_OK);
	} else {
		output->satoshi = satoshis;

		/* update the global tx for the psbt also */
		output = &tx->psbt->tx->outputs[outnum];
		output->satoshi = satoshis;
	}
}

const u8 *bitcoin_tx_output_get_script(const tal_t *ctx,
				       const struct bitcoin_tx *tx, int outnum)
{
	const struct wally_tx_output *output;
	u8 *res;
	assert(outnum < tx->wtx->num_outputs);
	output = &tx->wtx->outputs[outnum];

	if (output->script == NULL) {
		/* This can happen for coinbase transactions and pegin
		 * transactions */
		return NULL;
	}

	res = tal_dup_arr(ctx, u8, output->script, output->script_len, 0);
	return res;
}

u8 *bitcoin_tx_output_get_witscript(const tal_t *ctx, const struct bitcoin_tx *tx,
				    int outnum)
{
	struct wally_psbt_output *out;

	assert(outnum < tx->psbt->num_outputs);
	out = &tx->psbt->outputs[outnum];

	if (out->witness_script_len == 0)
		return NULL;

	return tal_dup_arr(ctx, u8, out->witness_script, out->witness_script_len, 0);
}

struct amount_asset bitcoin_tx_output_get_amount(const struct bitcoin_tx *tx,
						 int outnum)
{
	assert(tx->chainparams);
	assert(outnum < tx->wtx->num_outputs);
	return wally_tx_output_get_amount(&tx->wtx->outputs[outnum]);
}

void bitcoin_tx_output_get_amount_sat(struct bitcoin_tx *tx, int outnum,
				      struct amount_sat *amount)
{
	struct amount_asset asset_amt;
	asset_amt = bitcoin_tx_output_get_amount(tx, outnum);
	assert(amount_asset_is_main(&asset_amt));
	*amount = amount_asset_to_sat(&asset_amt);
}

void bitcoin_tx_input_set_witness(struct bitcoin_tx *tx, int innum,
				  u8 **witness)
{
	struct wally_tx_witness_stack *stack = NULL;
	size_t stack_size = tal_count(witness);

	/* Free any lingering witness */
	if (witness) {
		wally_tx_witness_stack_init_alloc(stack_size, &stack);
		for (size_t i = 0; i < stack_size; i++)
			wally_tx_witness_stack_add(stack, witness[i],
						   tal_bytelen(witness[i]));
	}
	wally_tx_set_input_witness(tx->wtx, innum, stack);

	/* Also add to the psbt */
	if (stack)
		wally_psbt_input_set_final_witness(&tx->psbt->inputs[innum], stack);
	else {
		/* FIXME: libwally-psbt doesn't allow 'unsetting' of witness via
		 * the set method at the moment, so we do it manually*/
		struct wally_psbt_input *in = &tx->psbt->inputs[innum];
		if (in->final_witness)
			wally_tx_witness_stack_free(in->final_witness);
		in->final_witness = NULL;
	}

	if (stack)
		wally_tx_witness_stack_free(stack);
	if (taken(witness))
	    tal_free(witness);
}

void bitcoin_tx_input_set_script(struct bitcoin_tx *tx, int innum, u8 *script)
{
	struct wally_psbt_input *in;
	wally_tx_set_input_script(tx->wtx, innum, script, tal_bytelen(script));

	/* Also add to the psbt */
	assert(innum < tx->psbt->num_inputs);
	in = &tx->psbt->inputs[innum];
	wally_psbt_input_set_final_script_sig(in, script, tal_bytelen(script));
}

const u8 *bitcoin_tx_input_get_witness(const tal_t *ctx,
				       const struct bitcoin_tx *tx, int innum,
				       int witnum)
{
	const u8 *witness_item;
	struct wally_tx_witness_item *item;
	assert(innum < tx->wtx->num_inputs);
	assert(witnum < tx->wtx->inputs[innum].witness->num_items);
	item = &tx->wtx->inputs[innum].witness->items[witnum];
	witness_item =
	    tal_dup_arr(ctx, u8, item->witness, item->witness_len, 0);
	return witness_item;
}

void bitcoin_tx_input_get_txid(const struct bitcoin_tx *tx, int innum,
			       struct bitcoin_txid *out)
{
	assert(innum < tx->wtx->num_inputs);
	wally_tx_input_get_txid(&tx->wtx->inputs[innum], out);
}

void wally_tx_input_get_txid(const struct wally_tx_input *in,
			     struct bitcoin_txid *txid)
{
	BUILD_ASSERT(sizeof(struct bitcoin_txid) == sizeof(in->txhash));
	memcpy(txid, in->txhash, sizeof(struct bitcoin_txid));
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
static bool uses_witness(const struct wally_tx *wtx)
{
	size_t i;

	for (i = 0; i < wtx->num_inputs; i++) {
		if (wtx->inputs[i].witness)
			return true;
	}
	return false;
}

u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	return linearize_wtx(ctx, tx->wtx);
}

u8 *linearize_wtx(const tal_t *ctx, const struct wally_tx *wtx)
{
	u8 *arr;
	u32 flag = 0;
	size_t len, written;
	int res;

        if (uses_witness(wtx))
		flag |= WALLY_TX_FLAG_USE_WITNESS;

	res = wally_tx_get_length(wtx, flag, &len);
	assert(res == WALLY_OK);
	arr = tal_arr(ctx, u8, len);
	res = wally_tx_to_bytes(wtx, flag, arr, len, &written);
	assert(len == written);

	return arr;
}

size_t bitcoin_tx_weight(const struct bitcoin_tx *tx)
{
	size_t weight;
	int ret = wally_tx_get_weight(tx->wtx, &weight);
	assert(ret == WALLY_OK);
	return weight;
}

void wally_txid(const struct wally_tx *wtx, struct bitcoin_txid *txid)
{
	u8 *arr;
	size_t len, written;
	int res;

	/* Never use BIP141 form for txid */
	res = wally_tx_get_length(wtx, 0, &len);
	assert(res == WALLY_OK);
	arr = tal_arr(NULL, u8, len);
	res = wally_tx_to_bytes(wtx, 0, arr, len, &written);
	assert(len == written);

	sha256_double(&txid->shad, arr, len);
	tal_free(arr);
}

/* We used to have beautiful, optimal code which fed the tx parts directly
 * into sha256_update().  But that was before libwally; but now we don't have
 * to maintain our own transaction code, so there's that. */
void bitcoin_txid(const struct bitcoin_tx *tx, struct bitcoin_txid *txid)
{
	wally_txid(tx->wtx, txid);
}

/* Use the bitcoin_tx destructor to also free the wally_tx */
static void bitcoin_tx_destroy(struct bitcoin_tx *tx)
{
	wally_tx_free(tx->wtx);
}

struct bitcoin_tx *bitcoin_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      varint_t input_count, varint_t output_count,
			      u32 nlocktime)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	assert(chainparams);

	/* If we are constructing an elements transaction we need to
	 * explicitly add the fee as an extra output. So allocate one more
	 * than the outputs we need internally. */
	if (chainparams->is_elements)
		output_count += 1;

	wally_tx_init_alloc(WALLY_TX_VERSION_2, 0, input_count, output_count,
			    &tx->wtx);
	tal_add_destructor(tx, bitcoin_tx_destroy);

	tx->wtx->locktime = nlocktime;
	tx->wtx->version = 2;
	tx->chainparams = chainparams;
	tx->psbt = new_psbt(tx, tx->wtx);

	return tx;
}

void bitcoin_tx_finalize(struct bitcoin_tx *tx)
{
	elements_tx_add_fee_output(tx);
	assert(bitcoin_tx_check(tx));
}

char *bitcoin_tx_to_psbt_base64(const tal_t *ctx, struct bitcoin_tx *tx)
{
	char *serialized_psbt, *ret_val;
	int ret;

	ret = wally_psbt_to_base64(tx->psbt, &serialized_psbt);
	assert(ret == WALLY_OK);

	ret_val = tal_strdup(ctx, serialized_psbt);
	wally_free_string(serialized_psbt);
	return ret_val;
}

struct bitcoin_tx *bitcoin_tx_with_psbt(const tal_t *ctx, struct wally_psbt *psbt STEALS)
{
	struct wally_psbt *tmppsbt;
	struct bitcoin_tx *tx = bitcoin_tx(ctx, chainparams,
					   psbt->tx->num_inputs,
					   psbt->tx->num_outputs,
					   psbt->tx->locktime);
	wally_tx_free(tx->wtx);

	/* We want the 'finalized' tx since that includes any signature
	 * data, not the global tx. But 'finalizing' a tx destroys some fields
	 * so we 'clone' it first and then finalize it */
	if (wally_psbt_clone(psbt, &tmppsbt) != WALLY_OK)
		abort();

	if (wally_finalize_psbt(tmppsbt) != WALLY_OK)
		abort();

	if (psbt_is_finalized(tmppsbt)) {
		if (wally_extract_psbt(tmppsbt, &tx->wtx) != WALLY_OK)
			abort();
	} else if (wally_tx_clone(psbt->tx, &tx->wtx) != WALLY_OK)
		abort();


	wally_psbt_free(tmppsbt);

	tal_free(tx->psbt);
	tx->psbt = tal_steal(tx, psbt);
	return tx;
}

struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx, const u8 **cursor,
				   size_t *max)
{
	size_t wsize;
	int flags = WALLY_TX_FLAG_USE_WITNESS;
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);

	if (chainparams->is_elements)
		flags |= WALLY_TX_FLAG_USE_ELEMENTS;

	if (wally_tx_from_bytes(*cursor, *max, flags, &tx->wtx) != WALLY_OK) {
		fromwire_fail(cursor, max);
		return tal_free(tx);
	}

	tal_add_destructor(tx, bitcoin_tx_destroy);

	/* For whatever reason the length computation gets upset if we tell it
	 * that we are using elements. It wants to discover it on its own, NO
	 * CLUES! (Ms. Doyle)
	 *
	 * https://github.com/ElementsProject/libwally-core/issues/139
	 */
	wally_tx_get_length(tx->wtx, flags & ~WALLY_TX_FLAG_USE_ELEMENTS,
			    &wsize);

	tx->chainparams = chainparams;

	tx->psbt = new_psbt(tx, tx->wtx);

	*cursor += wsize;
	*max -= wsize;
	return tx;
}

struct bitcoin_tx *bitcoin_tx_from_hex(const tal_t *ctx, const char *hex,
				       size_t hexlen)
{
	const char *end;
	u8 *linear_tx;
	const u8 *p;
	struct bitcoin_tx *tx;
	size_t len;

	end = memchr(hex, '\n', hexlen);
	if (!end)
		end = hex + hexlen;

	len = hex_data_size(end - hex);
	p = linear_tx = tal_arr(ctx, u8, len);
	if (!hex_decode(hex, end - hex, linear_tx, len))
		goto fail;

	tx = pull_bitcoin_tx(ctx, &p, &len);
	if (!tx)
		goto fail;

	if (len)
		goto fail_free_tx;

	tal_free(linear_tx);

	return tx;

fail_free_tx:
	tal_free(tx);
fail:
	tal_free(linear_tx);
	return NULL;
}

/* <sigh>.  Bitcoind represents hashes as little-endian for RPC. */
static void reverse_bytes(u8 *arr, size_t len)
{
	unsigned int i;

	for (i = 0; i < len / 2; i++) {
		unsigned char tmp = arr[i];
		arr[i] = arr[len - 1 - i];
		arr[len - 1 - i] = tmp;
	}
}

bool bitcoin_txid_from_hex(const char *hexstr, size_t hexstr_len,
			   struct bitcoin_txid *txid)
{
	if (!hex_decode(hexstr, hexstr_len, txid, sizeof(*txid)))
		return false;
	reverse_bytes(txid->shad.sha.u.u8, sizeof(txid->shad.sha.u.u8));
	return true;
}

bool bitcoin_txid_to_hex(const struct bitcoin_txid *txid,
			 char *hexstr, size_t hexstr_len)
{
	struct sha256_double rev = txid->shad;
	reverse_bytes(rev.sha.u.u8, sizeof(rev.sha.u.u8));
	return hex_encode(&rev, sizeof(rev), hexstr, hexstr_len);
}

static char *fmt_bitcoin_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *lin = linearize_tx(ctx, tx);
	char *s = tal_hex(ctx, lin);
	tal_free(lin);
	return s;
}

static char *fmt_bitcoin_txid(const tal_t *ctx, const struct bitcoin_txid *txid)
{
	char *hexstr = tal_arr(ctx, char, hex_str_size(sizeof(*txid)));

	bitcoin_txid_to_hex(txid, hexstr, hex_str_size(sizeof(*txid)));
	return hexstr;
}

REGISTER_TYPE_TO_STRING(bitcoin_tx, fmt_bitcoin_tx);
REGISTER_TYPE_TO_STRING(bitcoin_txid, fmt_bitcoin_txid);

void fromwire_bitcoin_txid(const u8 **cursor, size_t *max,
			   struct bitcoin_txid *txid)
{
	fromwire_sha256_double(cursor, max, &txid->shad);
}

struct bitcoin_tx *fromwire_bitcoin_tx(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct bitcoin_tx *tx;

	tx = pull_bitcoin_tx(ctx, cursor, max);
	if (!tx)
		return fromwire_fail(cursor, max);

	/* pull_bitcoin_tx sets the psbt */
	tal_free(tx->psbt);
	tx->psbt = fromwire_psbt(tx, cursor, max);

	return tx;
}

void towire_bitcoin_txid(u8 **pptr, const struct bitcoin_txid *txid)
{
	towire_sha256_double(pptr, &txid->shad);
}

void towire_bitcoin_tx(u8 **pptr, const struct bitcoin_tx *tx)
{
	u8 *lin = linearize_tx(tmpctx, tx);
	towire_u8_array(pptr, lin, tal_count(lin));

	towire_psbt(pptr, tx->psbt);
}

struct bitcoin_tx_output *fromwire_bitcoin_tx_output(const tal_t *ctx,
						     const u8 **cursor, size_t *max)
{
	struct bitcoin_tx_output *output = tal(ctx, struct bitcoin_tx_output);
	output->amount = fromwire_amount_sat(cursor, max);
	u16 script_len = fromwire_u16(cursor, max);
	output->script = fromwire_tal_arrn(output, cursor, max, script_len);
	if (!*cursor)
		return tal_free(output);
	return output;
}

void towire_bitcoin_tx_output(u8 **pptr, const struct bitcoin_tx_output *output)
{
	towire_amount_sat(pptr, output->amount);
	towire_u16(pptr, tal_count(output->script));
	towire_u8_array(pptr, output->script, tal_count(output->script));
}

bool wally_tx_input_spends(const struct wally_tx_input *input,
			   const struct bitcoin_txid *txid,
			   int outnum)
{
	/* Useful, as tx_part can have some NULL inputs */
	if (!input)
		return false;
	BUILD_ASSERT(sizeof(*txid) == sizeof(input->txhash));
	if (memcmp(txid, input->txhash, sizeof(*txid)) != 0)
		return false;
	return input->index == outnum;
}

/* FIXME(cdecker) Make the caller pass in a reference to amount_asset, and
 * return false if unintelligible/encrypted. (WARN UNUSED). */
struct amount_asset
wally_tx_output_get_amount(const struct wally_tx_output *output)
{
	struct amount_asset amount;
	be64 raw;

	if (chainparams->is_elements) {
		assert(output->asset_len == sizeof(amount.asset));
		memcpy(&amount.asset, output->asset, sizeof(amount.asset));

		/* We currently only support explicit value asset tags, others
		 * are confidential, so don't even try to assign a value to
		 * it. */
		if (output->asset[0] == 0x01) {
			memcpy(&raw, output->value + 1, sizeof(raw));
			amount.value = be64_to_cpu(raw);
		} else {
			amount.value = 0;
		}
	} else {
		/* Do not assign amount.asset, we should never touch it in
		 * non-elements scenarios. */
		amount.value = output->satoshi;
	}

	return amount;
}
