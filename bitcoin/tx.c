#include "config.h"
#include <assert.h>
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <ccan/str/hex/hex.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <wally_psbt.h>
#include <wire/wire.h>

struct bitcoin_tx_output *new_tx_output(const tal_t *ctx,
					struct amount_sat amount,
					const u8 *script)
{
	struct bitcoin_tx_output *output = tal(ctx, struct bitcoin_tx_output);
	output->amount = amount;
	output->script = tal_dup_arr(output, u8, script, tal_count(script), 0);
	return output;
}

struct wally_tx_output *wally_tx_output(const tal_t *ctx,
					const u8 *script,
					struct amount_sat amount)
{
	u64 satoshis = amount.satoshis; /* Raw: wally API */
	struct wally_tx_output *output;
	int ret;

	tal_wally_start();
	if (chainparams->is_elements) {
		u8 value[9];
		ret = wally_tx_confidential_value_from_satoshi(satoshis, value,
							       sizeof(value));
		assert(ret == WALLY_OK);
		ret = wally_tx_elements_output_init_alloc(
		    script, tal_bytelen(script), chainparams->fee_asset_tag, 33,
		    value, sizeof(value), NULL, 0, NULL, 0, NULL, 0, &output);
		if (ret != WALLY_OK) {
			output = NULL;
			goto done;
		}

		/* Cheat a bit by also setting the numeric satoshi value,
		 * otherwise we end up converting a number of times */
		output->satoshi = satoshis;
	} else {
		ret = wally_tx_output_init_alloc(satoshis, script,
						 tal_bytelen(script), &output);
		if (ret != WALLY_OK) {
			output = NULL;
			goto done;
		}
	}

done:
	tal_wally_end_onto(ctx, output, struct wally_tx_output);
	return output;
}

int bitcoin_tx_add_output(struct bitcoin_tx *tx, const u8 *script,
			  const u8 *wscript, struct amount_sat amount)
{
	size_t i = tx->wtx->num_outputs;
	struct wally_tx_output *output;
	struct wally_psbt_output *psbt_out;
	int ret;
	const struct chainparams *chainparams = tx->chainparams;
	assert(i < tx->wtx->outputs_allocation_len);

	assert(tx->wtx != NULL);
	assert(chainparams);

	output = wally_tx_output(NULL, script, amount);
	assert(output);
	tal_wally_start();
	ret = wally_tx_add_output(tx->wtx, output);
	assert(ret == WALLY_OK);
	tal_wally_end(tx->wtx);

	psbt_out = psbt_add_output(tx->psbt, output, i);
	if (wscript) {
		tal_wally_start();
		ret = wally_psbt_output_set_witness_script(psbt_out,
							   wscript,
							   tal_bytelen(wscript));
		assert(ret == WALLY_OK);
		tal_wally_end(tx->psbt);
	}

	wally_tx_output_free(output);
	bitcoin_tx_output_set_amount(tx, i, amount);

	return i;
}

void bitcoin_tx_remove_output(struct bitcoin_tx *tx, size_t outnum)
{
	int ret;
	ret = wally_tx_remove_output(tx->wtx, outnum);
	assert(ret == WALLY_OK);
	ret = wally_psbt_remove_output(tx->psbt, outnum);
	assert(ret == WALLY_OK);
}

bool elements_wtx_output_is_fee(const struct wally_tx *tx, int outnum)
{
	assert(outnum < tx->num_outputs);
	return chainparams->is_elements &&
		tx->outputs[outnum].script_len == 0;
}

bool elements_tx_output_is_fee(const struct bitcoin_tx *tx, int outnum)
{
	return elements_wtx_output_is_fee(tx->wtx, outnum);
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
		if (!ok)
			return AMOUNT_SAT(0);

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
	if (!chainparams->is_elements)
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
	tx->psbt->fallback_locktime = locktime;
	tx->psbt->has_fallback_locktime = true;
}

/* FIXME Stolen from psbt_append_input; export? */
static struct wally_tx_input *wally_tx_input_from_outpoint_sequence(const struct bitcoin_outpoint *outpoint,
			u32 sequence)
{
	struct wally_tx_input *tx_in;
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
	return tx_in;
}

int bitcoin_tx_add_input(struct bitcoin_tx *tx,
			 const struct bitcoin_outpoint *outpoint,
			 u32 sequence, const u8 *scriptSig,
			 struct amount_sat amount, const u8 *scriptPubkey,
			 const u8 *input_wscript)
{
	int wally_err;
	int input_num = tx->wtx->num_inputs;
	struct wally_tx_input *tx_input;

	psbt_append_input(tx->psbt, outpoint,
			  sequence, scriptSig,
			  input_wscript, NULL);

	if (input_wscript) {
		scriptPubkey = scriptpubkey_p2wsh(tmpctx, input_wscript);
	}

	assert(scriptPubkey);
	psbt_input_set_wit_utxo(tx->psbt, input_num,
				scriptPubkey, amount);

	tal_wally_start();
	tx_input = wally_tx_input_from_outpoint_sequence(outpoint, sequence);
	wally_err = wally_tx_add_input(tx->wtx,
			       tx_input);
	assert(wally_err == WALLY_OK);
	wally_tx_input_free(tx_input);

	/* scriptsig isn't actually stored in psbt input, so add that now */
	wally_tx_set_input_script(tx->wtx, input_num,
				  scriptSig, tal_bytelen(scriptSig));
	tal_wally_end(tx->wtx);

	if (is_elements(chainparams)) {
		/* FIXME: persist asset tags */
		amount_sat_to_asset(&amount,
					    chainparams->fee_asset_tag);
		/* FIXME: persist nonces */
	}
	return input_num;
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

	tal_free(newtx);
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
	wally_psbt_output_set_amount(&tx->psbt->outputs[outnum], satoshis);
}

const u8 *cln_wally_tx_output_get_script(const tal_t *ctx,
					 const struct wally_tx_output *output)
{
	if (output->script == NULL) {
		/* This can happen for coinbase transactions and pegin
		 * transactions */
		return NULL;
	}

	return tal_dup_arr(ctx, u8, output->script, output->script_len, 0);
}

const u8 *bitcoin_tx_output_get_script(const tal_t *ctx,
				       const struct bitcoin_tx *tx, int outnum)
{
	const struct wally_tx_output *output;
	assert(outnum < tx->wtx->num_outputs);
	output = &tx->wtx->outputs[outnum];

	return cln_wally_tx_output_get_script(ctx, output);
}

bool bitcoin_tx_output_script_is_p2wsh(const struct bitcoin_tx *tx, int outnum)
{	const struct wally_tx_output *output;
	assert(outnum < tx->wtx->num_outputs);
	output = &tx->wtx->outputs[outnum];

	return output->script_len == BITCOIN_SCRIPTPUBKEY_P2WSH_LEN &&
	       output->script[0] == OP_0 &&
	       output->script[1] == OP_PUSHBYTES(sizeof(struct sha256));
}

u8 *bitcoin_tx_output_get_witscript(const tal_t *ctx, const struct bitcoin_tx *tx,
				    int outnum)
{
	struct wally_psbt_output *out;
	const struct wally_map_item *output_witness_script;

	assert(outnum < tx->psbt->num_outputs);
	out = &tx->psbt->outputs[outnum];

	output_witness_script = wally_map_get_integer(&out->psbt_fields, /* PSBT_OUT_WITNESS_SCRIPT */ 0x01);
	if (output_witness_script->value_len == 0)
		return NULL;

	return tal_dup_arr(ctx, u8, output_witness_script->value, output_witness_script->value_len, 0);
}

struct amount_asset bitcoin_tx_output_get_amount(const struct bitcoin_tx *tx,
						 int outnum)
{
	assert(tx->chainparams);
	assert(outnum < tx->wtx->num_outputs);
	return wally_tx_output_get_amount(&tx->wtx->outputs[outnum]);
}

void bitcoin_tx_output_get_amount_sat(const struct bitcoin_tx *tx, int outnum,
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

	tal_wally_start();
	/* Free any lingering witness */
	if (witness) {
		wally_tx_witness_stack_init_alloc(stack_size, &stack);
		for (size_t i = 0; i < stack_size; i++)
			wally_tx_witness_stack_add(stack, witness[i],
						   tal_bytelen(witness[i]));
	}
	tal_wally_end(tmpctx);

	tal_wally_start();
	wally_tx_set_input_witness(tx->wtx, innum, stack);
	tal_wally_end(tx->wtx);

	/* Also add to the psbt */
	tal_wally_start();
	wally_psbt_input_set_final_witness(&tx->psbt->inputs[innum], stack);
	tal_wally_end(tx->psbt);

	if (taken(witness))
		tal_free(witness);
}

void bitcoin_tx_input_set_script(struct bitcoin_tx *tx, int innum, u8 *script)
{
	struct wally_psbt_input *in;

	tal_wally_start();
	wally_tx_set_input_script(tx->wtx, innum, script, tal_bytelen(script));
	tal_wally_end(tx->wtx);

	/* Also add to the psbt */
	assert(innum < tx->psbt->num_inputs);
	in = &tx->psbt->inputs[innum];
	tal_wally_start();
	wally_psbt_input_set_final_scriptsig(in, script, tal_bytelen(script));
	tal_wally_end(tx->psbt);
}

/* FIXME: remove */
void bitcoin_tx_input_get_txid(const struct bitcoin_tx *tx, int innum,
			       struct bitcoin_txid *out)
{
	assert(innum < tx->wtx->num_inputs);
	wally_tx_input_get_txid(&tx->wtx->inputs[innum], out);
}

void bitcoin_tx_input_get_outpoint(const struct bitcoin_tx *tx,
				   int innum,
				   struct bitcoin_outpoint *outpoint)
{
	assert(innum < tx->wtx->num_inputs);
	wally_tx_input_get_outpoint(&tx->wtx->inputs[innum], outpoint);
}

void bitcoin_tx_input_set_outpoint(struct bitcoin_tx *tx, int innum,
				   const struct bitcoin_outpoint *outpoint)
{
	struct wally_tx_input *in;
	assert(innum < tx->wtx->num_inputs);

	in = &tx->wtx->inputs[innum];
	BUILD_ASSERT(sizeof(struct bitcoin_txid) == sizeof(in->txhash));
	memcpy(in->txhash, &outpoint->txid, sizeof(struct bitcoin_txid));
	in->index = outpoint->n;
}

/* FIXME: remove */
void wally_tx_input_get_txid(const struct wally_tx_input *in,
			     struct bitcoin_txid *txid)
{
	BUILD_ASSERT(sizeof(struct bitcoin_txid) == sizeof(in->txhash));
	memcpy(txid, in->txhash, sizeof(struct bitcoin_txid));
}

void wally_tx_input_get_outpoint(const struct wally_tx_input *in,
				 struct bitcoin_outpoint *outpoint)
{
	BUILD_ASSERT(sizeof(struct bitcoin_txid) == sizeof(in->txhash));
	memcpy(&outpoint->txid, in->txhash, sizeof(struct bitcoin_txid));
	outpoint->n = in->index;
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

size_t wally_tx_weight(const struct wally_tx *wtx)
{
	size_t weight;
	int ret = wally_tx_get_weight(wtx, &weight);
	assert(ret == WALLY_OK);
	return weight;
}

size_t bitcoin_tx_weight(const struct bitcoin_tx *tx)
{
	size_t extra;
	size_t num_witnesses;

	/* If we don't have witnesses *yet*, libwally doesn't encode
	 * in BIP 141 style, omitting the flag and marker bytes */
	wally_tx_get_witness_count(tx->wtx, &num_witnesses);
	if (num_witnesses == 0) {
		if (chainparams->is_elements)
			extra = 7;
		else
			extra = 2;
	} else
		extra = 0;

	return extra + wally_tx_weight(tx->wtx);
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

	tal_wally_start();
	wally_tx_init_alloc(WALLY_TX_VERSION_2, nlocktime, input_count, output_count,
			    &tx->wtx);
	tal_add_destructor(tx, bitcoin_tx_destroy);
	tal_wally_end_onto(tx, tx->wtx, struct wally_tx);

	tx->chainparams = chainparams;
	tx->psbt = new_psbt(tx, tx->wtx);

	return tx;
}

void bitcoin_tx_finalize(struct bitcoin_tx *tx)
{
	elements_tx_add_fee_output(tx);
	assert(bitcoin_tx_check(tx));
}

struct bitcoin_tx *bitcoin_tx_with_psbt(const tal_t *ctx, struct wally_psbt *psbt STEALS)
{
	size_t locktime;
	wally_psbt_get_locktime(psbt, &locktime);
	struct bitcoin_tx *tx = bitcoin_tx(ctx, chainparams,
					   psbt->num_inputs,
					   psbt->num_outputs,
					   locktime);
	wally_tx_free(tx->wtx);

	psbt_finalize(psbt);
	tx->wtx = psbt_final_tx(tx, psbt);
	if (!tx->wtx) {
		tal_wally_start();
		if (wally_psbt_extract(psbt, WALLY_PSBT_EXTRACT_NON_FINAL, &tx->wtx) != WALLY_OK) {
			tx->wtx = NULL;
		}
		tal_wally_end_onto(tx, tx->wtx, struct wally_tx);
		if (!tx->wtx)
			return tal_free(tx);
	}

	tal_free(tx->psbt);
	tx->psbt = tal_steal(tx, psbt);

	return tx;
}

struct bitcoin_tx *clone_bitcoin_tx(const tal_t *ctx,
				    const struct bitcoin_tx *tx)
{
	struct bitcoin_tx *newtx;

	if (taken(tx))
		return cast_const(struct bitcoin_tx *, tal_steal(ctx, tx));

	newtx = tal(ctx, struct bitcoin_tx);

	newtx->chainparams = tx->chainparams;

	tal_wally_start();
	if (wally_tx_clone_alloc(tx->wtx, 0, &newtx->wtx) != WALLY_OK)
		newtx->wtx = NULL;
	tal_wally_end_onto(newtx, newtx->wtx, struct wally_tx);
	if (!newtx->wtx)
		return tal_free(newtx);

	newtx->psbt = clone_psbt(newtx, tx->psbt);
	tal_add_destructor(newtx, bitcoin_tx_destroy);
	return newtx;
}

static struct wally_tx *pull_wtx(const tal_t *ctx,
				 const u8 **cursor,
				 size_t *max)
{
	int flags = WALLY_TX_FLAG_USE_WITNESS;
	struct wally_tx *wtx;

	if (chainparams->is_elements)
		flags |= WALLY_TX_FLAG_USE_ELEMENTS;

	tal_wally_start();
	if (wally_tx_from_bytes(*cursor, *max, flags, &wtx) != WALLY_OK) {
		fromwire_fail(cursor, max);
		wtx = tal_free(wtx);
	}
	tal_wally_end_onto(ctx, wtx, struct wally_tx);

	if (wtx) {
		size_t wsize;
		wally_tx_get_length(wtx, flags, &wsize);
		*cursor += wsize;
		*max -= wsize;
	}

	return wtx;
}

struct bitcoin_tx *pull_bitcoin_tx_only(const tal_t *ctx, const u8 **cursor,
					size_t *max)
{
	struct bitcoin_tx *tx = tal(ctx, struct bitcoin_tx);
	tx->wtx = pull_wtx(tx, cursor, max);
	if (!tx->wtx)
		return tal_free(tx);

	tal_add_destructor(tx, bitcoin_tx_destroy);
	tx->chainparams = chainparams;
	tx->psbt = NULL;

	return tx;
}

struct bitcoin_tx *pull_bitcoin_tx(const tal_t *ctx, const u8 **cursor,
				   size_t *max)
{
	struct bitcoin_tx *tx = pull_bitcoin_tx_only(ctx, cursor, max);
	if (tx) {
		tx->psbt = new_psbt(tx, tx->wtx);
		if (!tx->psbt)
			return tal_free(tx);
        }
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

char *fmt_bitcoin_tx(const tal_t *ctx, const struct bitcoin_tx *tx)
{
	u8 *lin = linearize_tx(ctx, tx);
	char *s = tal_hex(ctx, lin);
	tal_free(lin);
	return s;
}

char *fmt_bitcoin_txid(const tal_t *ctx, const struct bitcoin_txid *txid)
{
	char *hexstr = tal_arr(ctx, char, hex_str_size(sizeof(*txid)));

	bitcoin_txid_to_hex(txid, hexstr, hex_str_size(sizeof(*txid)));
	return hexstr;
}

static char *fmt_bitcoin_outpoint(const tal_t *ctx,
				  const struct bitcoin_outpoint *outpoint)
{
	return tal_fmt(ctx, "%s:%u",
		       fmt_bitcoin_txid(tmpctx, &outpoint->txid),
		       outpoint->n);
}

static char *fmt_wally_tx(const tal_t *ctx, const struct wally_tx *tx)
{
	u8 *lin = linearize_wtx(ctx, tx);
	char *s = tal_hex(ctx, lin);
	tal_free(lin);
	return s;
}

REGISTER_TYPE_TO_STRING(bitcoin_tx, fmt_bitcoin_tx);
REGISTER_TYPE_TO_STRING(bitcoin_txid, fmt_bitcoin_txid);
REGISTER_TYPE_TO_STRING(bitcoin_outpoint, fmt_bitcoin_outpoint);
REGISTER_TYPE_TO_STRING(wally_tx, fmt_wally_tx);

void fromwire_bitcoin_txid(const u8 **cursor, size_t *max,
			   struct bitcoin_txid *txid)
{
	fromwire_sha256_double(cursor, max, &txid->shad);
}

struct bitcoin_tx *fromwire_bitcoin_tx(const tal_t *ctx,
				       const u8 **cursor, size_t *max)
{
	struct bitcoin_tx *tx;

	u32 len = fromwire_u32(cursor, max);
	size_t start = *max;
	tx = pull_bitcoin_tx_only(ctx, cursor, max);
	if (!tx)
		return fromwire_fail(cursor, max);
	// Check that we consumed len bytes
	if (start - *max != len)
		return fromwire_fail(cursor, max);

	tx->psbt = fromwire_wally_psbt(tx, cursor, max);
	if (!tx->psbt)
		return fromwire_fail(cursor, max);

	return tx;
}

void towire_bitcoin_txid(u8 **pptr, const struct bitcoin_txid *txid)
{
	towire_sha256_double(pptr, &txid->shad);
}

void towire_bitcoin_outpoint(u8 **pptr, const struct bitcoin_outpoint *outp)
{
	towire_bitcoin_txid(pptr, &outp->txid);
	towire_u32(pptr, outp->n);
}

void fromwire_bitcoin_outpoint(const u8 **cursor, size_t *max,
			       struct bitcoin_outpoint *outp)
{
	fromwire_bitcoin_txid(cursor, max, &outp->txid);
	outp->n = fromwire_u32(cursor, max);
}

void towire_bitcoin_tx(u8 **pptr, const struct bitcoin_tx *tx)
{
	u8 *lin = linearize_tx(tmpctx, tx);
	towire_u32(pptr, tal_count(lin));
	towire_u8_array(pptr, lin, tal_count(lin));

	towire_wally_psbt(pptr, tx->psbt);
}

bool wally_tx_input_spends(const struct wally_tx_input *input,
			   const struct bitcoin_outpoint *outpoint)
{
	/* Useful, as tx_part can have some NULL inputs */
	if (!input)
		return false;
	BUILD_ASSERT(sizeof(outpoint->txid) == sizeof(input->txhash));
	if (memcmp(&outpoint->txid, input->txhash, sizeof(outpoint->txid)) != 0)
		return false;
	return input->index == outpoint->n;
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
		/* We currently only support explicit value
		 * asset tags, others are confidential, so
		 * don't even try to assign a value to it. */
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

/* Various weights of transaction parts. */
size_t bitcoin_tx_core_weight(size_t num_inputs, size_t num_outputs)
{
	size_t weight;

	/* version, input count, output count, locktime */
	weight = (4 + varint_size(num_inputs) + varint_size(num_outputs) + 4)
		* 4;

	/* Add segwit fields: marker + flag */
	weight += 1 + 1;

	/* A couple of things need to change for elements: */
	if (chainparams->is_elements) {
                /* Each transaction has surjection and rangeproof (both empty
		 * for us as long as we use unblinded L-BTC transactions). */
		weight += 2 * 4;

		/* An elements transaction has 1 additional output for fees */
		weight += bitcoin_tx_output_weight(0);
	}
	return weight;
}

size_t bitcoin_tx_output_weight(size_t outscript_len)
{
	size_t weight;

	/* amount, len, scriptpubkey */
	weight = (8 + varint_size(outscript_len) + outscript_len) * 4;

	if (chainparams->is_elements) {
		/* Each output additionally has an asset_tag (1 + 32), value
		 * is prefixed by a version (1 byte), an empty nonce (1
		 * byte), two empty proofs (2 bytes). */
		weight += (32 + 1 + 1 + 1) * 4;
	}

	return weight;
}

/* We grind signatures to get them down to 71 bytes */
size_t bitcoin_tx_input_sig_weight(void)
{
	return 1 + 71;
}

/* Input weight */
size_t bitcoin_tx_input_weight(bool p2sh, size_t witness_weight)
{
	size_t weight = witness_weight;

	/* Input weight: txid + index + sequence */
	weight += (32 + 4 + 4) * 4;

	/* We always encode the length of the script, even if empty */
	weight += 1 * 4;

	/* P2SH variants include push of <0 <20-byte-key-hash>> */
	if (p2sh)
		weight += 23 * 4;

	/* Elements inputs have 6 bytes of blank proofs attached. */
	if (chainparams->is_elements)
		weight += 6;

	return weight;
}

size_t bitcoin_tx_simple_input_witness_weight(void)
{
	/* Account for witness (1 byte count + sig + key) */
	return 1 + (bitcoin_tx_input_sig_weight() + 1 + 33);
}

/* We only do segwit inputs, and we assume witness is sig + key  */
size_t bitcoin_tx_simple_input_weight(bool p2sh)
{
	return bitcoin_tx_input_weight(p2sh,
				       bitcoin_tx_simple_input_witness_weight());
}

size_t bitcoin_tx_2of2_input_witness_weight(void)
{
        /* BOLT #03:
         * Signatures are 73 bytes long (the maximum length).
         */
	return 1 + /* Prefix: 4 elements to push on stack */
		(1 + 0) + /* [0]: witness-marker-and-flag */
		(1 + 73) + /* [1] Party A signature and length prefix */
		(1 + 73) + /* [2] Party B signature and length prefix */
		(1 + 1 + /* [3] length prefix and numpushes (2) */
		 1 + 33 + /* pubkey A (with prefix) */
		 1 + 33 + /* pubkey B (with prefix) */
		 1 + 1 /* num sigs required and checkmultisig */
		);
}

size_t change_weight(void)
{
	return bitcoin_tx_output_weight(chainparams->is_elements ? BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN : BITCOIN_SCRIPTPUBKEY_P2TR_LEN);
}

struct amount_sat change_fee(u32 feerate_perkw,	size_t total_weight)
{
	struct amount_sat fee;

	/* Must be able to pay for its own additional weight */
	/* Rounding can cause off by one errors, so we do this */
	if (!amount_sat_sub(&fee,
			    amount_tx_fee(feerate_perkw, change_weight() + total_weight),
			    amount_tx_fee(feerate_perkw, total_weight)))
		abort();
	return fee;
}

struct amount_sat change_amount(struct amount_sat excess, u32 feerate_perkw,
				size_t total_weight)
{
	struct amount_sat fee = change_fee(feerate_perkw, total_weight);

	if (!amount_sat_sub(&excess, excess, fee))
		return AMOUNT_SAT(0);

	/* Must be non-dust */
	if (!amount_sat_greater_eq(excess, chainparams->dust_limit))
		return AMOUNT_SAT(0);

	return excess;
}

u32 tx_feerate(const struct bitcoin_tx *tx)
{

	u32 feerate;

	/* Fee should not overflow! */
	if (!amount_feerate(&feerate,
			    bitcoin_tx_compute_fee(tx),
			    bitcoin_tx_weight(tx))) {
		abort();
	}

	return feerate;
}
