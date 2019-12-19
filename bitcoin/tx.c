#include <assert.h>
#include <bitcoin/block.h>
#include <bitcoin/pullpush.h>
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

int bitcoin_tx_add_output(struct bitcoin_tx *tx, const u8 *script,
			  struct amount_sat amount)
{
	size_t i = tx->wtx->num_outputs;
	struct wally_tx_output *output;
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

	wally_tx_output_free(output);
	bitcoin_tx_output_set_amount(tx, i, amount);

	return i;
}

int bitcoin_tx_add_multi_outputs(struct bitcoin_tx *tx,
				 struct bitcoin_tx_output **outputs)
{
	for (size_t j = 0; j < tal_count(outputs); j++)
		bitcoin_tx_add_output(tx, outputs[j]->script,
				      outputs[j]->amount);

	return tx->wtx->num_outputs;
}

static bool elements_tx_output_is_fee(const struct bitcoin_tx *tx, int outnum)
{
	assert(outnum < tx->wtx->num_outputs);
	return chainparams->is_elements &&
	       tx->wtx->outputs[outnum].script_len == 0;
}

/**
 * Compute how much fee we are actually sending with this transaction.
 */
static struct amount_sat bitcoin_tx_compute_fee(const struct bitcoin_tx *tx)
{
	struct amount_sat fee = AMOUNT_SAT(0), value;
	struct amount_asset asset;
	bool ok;

	for (size_t i = 0; i < tal_count(tx->input_amounts); i++) {
		value.satoshis = tx->input_amounts[i]->satoshis; /* Raw: fee computation */
		ok = amount_sat_add(&fee, fee, value);
		assert(ok);
	}

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		asset = bitcoin_tx_output_get_amount(tx, i);
		if (elements_tx_output_is_fee(tx, i) ||
		    !amount_asset_is_main(&asset))
			continue;

		value = amount_asset_to_sat(&asset);
		ok = amount_sat_sub(&fee, fee, value);
		assert(ok);
	}
	return fee;
}

int elements_tx_add_fee_output(struct bitcoin_tx *tx)
{
	struct amount_sat fee = bitcoin_tx_compute_fee(tx);
	int pos = -1;

	/* If we aren't using elements, we don't add explicit fee outputs */
	if (!chainparams->is_elements || amount_sat_eq(fee, AMOUNT_SAT(0)))
		return -1;

	/* Try to find any existing fee output */
	for (int i=0; i<tx->wtx->num_outputs; i++) {
		if (elements_tx_output_is_fee(tx, i)) {
			assert(pos == -1);
			pos = i;
		}
	}

	if (pos == -1) {
		return bitcoin_tx_add_output(tx, NULL, fee);
	} else {
		bitcoin_tx_output_set_amount(tx, pos, fee);
		return pos;
	}
}

int bitcoin_tx_add_input(struct bitcoin_tx *tx, const struct bitcoin_txid *txid,
			 u32 outnum, u32 sequence,
			 struct amount_sat amount, u8 *script)
{
	struct wally_tx_input *input;
	size_t i;

	assert(tx->wtx != NULL);
	i = tx->wtx->num_inputs;
	wally_tx_input_init_alloc(txid->shad.sha.u.u8,
				  sizeof(struct bitcoin_txid), outnum, sequence,
				  script, tal_bytelen(script),
				  NULL /* Empty witness stack */, &input);
	input->features = chainparams->is_elements ? WALLY_TX_IS_ELEMENTS : 0;
	wally_tx_add_input(tx->wtx, input);
	wally_tx_input_free(input);

	/* Now store the input amount if we know it, so we can sign later */
	if (tal_count(tx->input_amounts) < tx->wtx->num_inputs)
		tal_resize(&tx->input_amounts, tx->wtx->num_inputs);

	tx->input_amounts[i] = tal_free(tx->input_amounts[i]);
	tx->input_amounts[i] = tal_dup(tx, struct amount_sat, &amount);

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

	res = tal_arr(ctx, u8, output->script_len);
	memcpy(res, output->script, output->script_len);
	return res;
}

/* FIXME(cdecker) Make the caller pass in a reference to amount_asset, and
 * return false if unintelligible/encrypted. (WARN UNUSED). */
struct amount_asset bitcoin_tx_output_get_amount(const struct bitcoin_tx *tx,
						 int outnum)
{
	struct amount_asset amount;
	struct wally_tx_output *output;
	be64 raw;

	assert(tx->chainparams);
	assert(outnum < tx->wtx->num_outputs);
	output = &tx->wtx->outputs[outnum];

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
		amount.value = tx->wtx->outputs[outnum].satoshi;
	}

	return amount;
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
	if (stack)
		wally_tx_witness_stack_free(stack);
	if (taken(witness))
	    tal_free(witness);
}

void bitcoin_tx_input_set_script(struct bitcoin_tx *tx, int innum, u8 *script)
{
	wally_tx_set_input_script(tx->wtx, innum, script, tal_bytelen(script));
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
	assert(sizeof(struct bitcoin_txid) ==
	       sizeof(tx->wtx->inputs[innum].txhash));
	memcpy(out, tx->wtx->inputs[innum].txhash, sizeof(struct bitcoin_txid));
}

/* BIP144:
 * If the witness is empty, the old serialization format should be used. */
static bool uses_witness(const struct bitcoin_tx *tx)
{
	size_t i;

	for (i = 0; i < tx->wtx->num_inputs; i++) {
		if (tx->wtx->inputs[i].witness)
			return true;
	}
	return false;
}

/* For signing, we ignore input scripts on other inputs, and pretend
 * the current input has a certain script: this is indicated by a
 * non-NULL override_script.
 *
 * For this (and other signing weirdness like SIGHASH_SINGLE), we
 * also need the current input being signed; that's in input_num.
 * We also need sighash_type.
 */
static void push_tx(const struct bitcoin_tx *tx,
		    const u8 *override_script,
		    size_t input_num,
		    void (*push)(const void *, size_t, void *), void *pushp,
		    bool bip144)
{
	int res;
	size_t len, written;
	u8 *serialized;;
	u8 flag = 0;

        if (bip144 && uses_witness(tx))
		flag |= WALLY_TX_FLAG_USE_WITNESS;

	res = wally_tx_get_length(tx->wtx, flag, &len);
	assert(res == WALLY_OK);
	serialized = tal_arr(tmpctx, u8, len);

	res = wally_tx_to_bytes(tx->wtx, flag, serialized, len, &written);
	assert(res == WALLY_OK);
	assert(len == written);
	push(serialized, len, pushp);
	tal_free(serialized);
}

static void push_sha(const void *data, size_t len, void *shactx_)
{
	struct sha256_ctx *ctx = shactx_;
	sha256_update(ctx, memcheck(data, len), len);
}

static void push_linearize(const void *data, size_t len, void *pptr_)
{
	u8 **pptr = pptr_;
	size_t oldsize = tal_count(*pptr);

	tal_resize(pptr, oldsize + len);
	memcpy(*pptr + oldsize, memcheck(data, len), len);
}

u8 *linearize_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *arr = tal_arr(ctx, u8, 0);
	push_tx(tx, NULL, 0, push_linearize, &arr, true);
	return arr;
}

size_t bitcoin_tx_weight(const struct bitcoin_tx *tx)
{
	size_t weight;
	int ret = wally_tx_get_weight(tx->wtx, &weight);
	assert(ret == WALLY_OK);
	return weight;
}

void bitcoin_txid(const struct bitcoin_tx *tx, struct bitcoin_txid *txid)
{
	struct sha256_ctx ctx = SHA256_INIT;

	/* For TXID, we never use extended form. */
	push_tx(tx, NULL, 0, push_sha, &ctx, false);
	sha256_double_done(&ctx, &txid->shad);
}

/* Use the bitcoin_tx destructor to also free the wally_tx */
static void bitcoin_tx_destroy(struct bitcoin_tx *tx)
{
	wally_tx_free(tx->wtx);
}

struct bitcoin_tx *bitcoin_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      varint_t input_count, varint_t output_count)
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

	tx->input_amounts = tal_arrz(tx, struct amount_sat*, input_count);
	tx->wtx->locktime = 0;
	tx->wtx->version = 2;
	tx->output_witscripts = tal_arrz(tx, struct witscript*, output_count);
	tx->chainparams = chainparams;
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

	/* We don't know the input amounts yet, so set them all to NULL */
	tx->input_amounts =
	    tal_arrz(tx, struct amount_sat *, tx->wtx->inputs_allocation_len);
	tx->chainparams = chainparams;

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
