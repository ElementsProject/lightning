#include "funding_tx.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <ccan/ptrint/ptrint.h>
#include <common/key_derive.h>
#include <common/permute_tx.h>
#include <common/utils.h>
#include <common/utxo.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct bitcoin_tx *funding_tx(const tal_t *ctx,
			      const struct chainparams *chainparams,
			      u16 *outnum,
			      const struct utxo **utxomap,
			      struct amount_sat funding,
			      const struct pubkey *local_fundingkey,
			      const struct pubkey *remote_fundingkey,
			      struct amount_sat change,
			      const struct pubkey *changekey,
			      const struct ext_key *bip32_base)
{
	u8 *wscript;
	struct bitcoin_tx *tx;
	bool has_change = !amount_sat_eq(change, AMOUNT_SAT(0));

	tx = tx_spending_utxos(ctx, chainparams, utxomap, bip32_base,
			       has_change, 1, 0, BITCOIN_TX_DEFAULT_SEQUENCE);


	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n",
		     tal_hex(wscript, wscript));
	bitcoin_tx_add_output(tx, scriptpubkey_p2wsh(tx, wscript), funding);
	tal_free(wscript);

	if (has_change) {
		const void *map[2];
		map[0] = int2ptr(0);
		map[1] = int2ptr(1);
		bitcoin_tx_add_output(tx, scriptpubkey_p2wpkh(tx, changekey),
				      change);
		permute_outputs(tx, NULL, map);
		*outnum = (map[0] == int2ptr(0) ? 0 : 1);
	} else {
		*outnum = 0;
	}

	permute_inputs(tx, (const void **)utxomap);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

#if EXPERIMENTAL_FEATURES
/* We leave out the change addresses if there's no change left after fees */
/* Returns true if calculated without error, false on overflow */
static bool calculate_input_weights(struct input_info **inputs,
				    struct amount_sat *total,
				    size_t *weight)
{
	u64 scriptlen;
	u32 input_weight;
	size_t i;

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * The *expected weight* of a funding transaction is calculated as follows:
	 * inputs: 40 bytes + var_int + `scriptlen`
	 *   - previous_out_point: 36 bytes
	 *      - hash: 32 bytes
	 *      - index: 4 bytes
	 *   - var_int: ? bytes (dependent on `scriptlen`)
	 *   - script_sig: `scriptlen`
	 *   - witness <----	Cost for "witness" data calculated separately.
	 *   - sequence: 4 bytes
	*/
	*total = AMOUNT_SAT(0);
	for (i = 0; i < tal_count(inputs); i++) {
		/* prev_out hash + index + sequence */
		input_weight = (32 + 4 + 4) * 4;

		if (inputs[i]->script) {
			scriptlen = tal_bytelen(inputs[i]->script);
			input_weight += (scriptlen + varint_size(scriptlen)) * 4;
		} else {
			/* 00 byte script_sig len */
			input_weight += 1 * 4;
		}

		input_weight += inputs[i]->max_witness_len;
		*weight += input_weight;

		if (!amount_sat_add(total, *total, inputs[i]->input_satoshis))
			return false;
	}

	return true;
}

static size_t calculate_output_weights(struct output_info **outputs)
{
	size_t i, output_weights = 0, scriptlen;

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * The *expected weight* of a funding transaction is calculated as follows:
	 * ...
	 * non_funding_outputs: 8 bytes + var_int + `scriptlen`
	 *   - value: 8 bytes
	 *   - var_int: ? bytes (dependent on `scriptlen`)
	 *   - script_sig: `scriptlen`
	*/
	for (i = 0; i < tal_count(outputs); i++) {
		scriptlen = tal_bytelen(outputs[i]->script);
		/* amount field + script + scriptlen varint */
		output_weights += (8 + scriptlen + varint_size(scriptlen)) * 4;
	}

	return output_weights;
}

/* Returns true if calculated without error, false on overflow */
static bool calculate_weight(struct input_info **opener_inputs,
		             struct input_info **accepter_inputs,
		             struct output_info **opener_outputs,
		             struct output_info **accepter_outputs,
			     struct amount_sat *opener_total,
			     struct amount_sat *accepter_total,
			     size_t *weight)

{
	/* version, input count, output count, locktime */
	*weight = (4 + 1 + 1 + 4) * 4;

	/* add segwit fields: marker + flag */
	*weight += 1 + 1;

	if (!calculate_input_weights(opener_inputs, opener_total, weight))
		return false;

	if (!calculate_input_weights(accepter_inputs, accepter_total, weight))
		return false;

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * The *expected weight* of a funding transaction is calculated as follows:
	 * ...
	 * funding_output: 43 bytes
	 *   - value: 8 bytes
	 *   - var_int: 1 byte
	 *   - script: 34 bytes
	*/
	*weight += (8 + 1 + BITCOIN_SCRIPTPUBKEY_P2WSH_LEN) * 4;

	*weight += calculate_output_weights(opener_outputs);
	*weight += calculate_output_weights(accepter_outputs);

	return true;
}

static const struct output_info *find_change_output(struct output_info **outputs)
{
	size_t i = 0;
	for (i = 0; i < tal_count(outputs); i++) {
		if (amount_sat_eq(outputs[i]->output_satoshis, AMOUNT_SAT(0)))
			return outputs[i];
	}
	return NULL;
}

static bool calculate_output_value(struct output_info **outputs,
				   struct amount_sat *total)
{
	size_t i = 0;

	for (i = 0; i < tal_count(outputs); i++) {
		if (!amount_sat_add(total, *total, outputs[i]->output_satoshis))
			return false;
	}
	return true;
}

static void add_inputs(struct bitcoin_tx *tx, struct input_info **inputs)
{
	size_t i = 0;
	for (i = 0; i < tal_count(inputs); i++) {
		bitcoin_tx_add_input(tx, &inputs[i]->prevtx_txid, inputs[i]->prevtx_vout,
				     BITCOIN_TX_DEFAULT_SEQUENCE,
				     inputs[i]->input_satoshis, inputs[i]->script);
	}
}

static void add_outputs(struct bitcoin_tx *tx, struct output_info **outputs,
		        const struct amount_sat *change)
{
	size_t i = 0;
	u8 *script;
	struct amount_sat value;

	for (i = 0; i < tal_count(outputs); i++) {
		/* Is this the change output?? */
		if (change && amount_sat_eq(outputs[i]->output_satoshis, AMOUNT_SAT(0))) {
			/* If there's no change amount, we leave it out */
			if (amount_sat_eq(*change, AMOUNT_SAT(0)))
				continue;
			value = *change;
		} else
			value = outputs[i]->output_satoshis;

		script = tal_dup_arr(tx, u8, outputs[i]->script,
				     tal_count(outputs[i]->script), 0);
		bitcoin_tx_add_output(tx, script, value);
	}
}

struct bitcoin_tx *dual_funding_funding_tx(const tal_t *ctx,
					   const struct chainparams *chainparams,
				           u16 *outnum,
					   u32 feerate_kw_funding,
				           struct amount_sat *opener_funding,
					   struct amount_sat accepter_funding,
				           struct input_info **opener_inputs,
				           struct input_info **accepter_inputs,
					   struct output_info **opener_outputs,
					   struct output_info **accepter_outputs,
				           const struct pubkey *local_fundingkey,
				           const struct pubkey *remote_fundingkey,
					   struct amount_sat *total_funding,
					   struct amount_sat *opener_change,
					   const void **input_map)
{
	size_t weight = 0;
	struct amount_sat est_tx_fee, opener_total_sat,
			  accepter_total_sat, output_val;
	struct bitcoin_tx *tx;
	const struct output_info *change_output;

	size_t i = 0;
	u64 scriptlen;
	u32 input_count, output_count;
	u8 *wscript;

	/* First, we calculate the weight of the transaction, with change outputs */
	if (!calculate_weight(opener_inputs, accepter_inputs,
			      opener_outputs, accepter_outputs,
			      &opener_total_sat, &accepter_total_sat,
			      &weight))
		return NULL;

	/* Does the opener provide enough sats to cover their funding */
	if (!amount_sat_sub(opener_change, opener_total_sat, *opener_funding))
		return NULL;

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * - MUST calculate the `est_tx_fee` as:
	 *   1. Multiply (funding_transaction_weight + witness_weight) by `feerate_per_kw_funding`
	 *   and divide by 1000 (rounding down).
	 */
	est_tx_fee = amount_tx_fee(feerate_kw_funding, weight);

	/* Check that the remaining amount at least covers the other
	 * indicated output values.  We have to cover these other
	 * outputs, as they might be other funding transaction outputs. The
	 * only 'flexible' / change output that's removable etc is indicated
	 * by a zero value. */
	output_val = AMOUNT_SAT(0);
	if (!calculate_output_value(opener_outputs, &output_val))
		return NULL;
	if (!amount_sat_sub(opener_change, *opener_change, output_val))
		return NULL;

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * For channel establishment v2, fees are paid by the opener (the node that
	 * sends the `open_channel` message). Change, if any, is paid to the
	 * opener's change address, a zero value output in their output set.
	 */
	change_output = find_change_output(opener_outputs);

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * - MUST calculate the `est_tx_fee` as:
	 *   ...
	 *   2. Confirm that `change_satoshis` is greater than `dust_limit_satoshis`.
	 */
	if (amount_sat_sub(opener_change, *opener_change, est_tx_fee) &&
			amount_sat_greater(*opener_change, chainparams->dust_limit)) {
		if (!change_output) {
			/*
			 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
			 * - if no change address is provided or `change_satoshis` is less
			 *   than or equal to the negotiated `dust_limit_satoshis`:
			 *   ...
			 *   2. As there is no change_output, any remaining `change_satoshis`
			 *   will be added to the funding output, and credited to the opener's
			 *   initial channel balance. */
			if (!amount_sat_add(opener_funding, *opener_funding,
					    *opener_change))
				return NULL;
			*opener_change = AMOUNT_SAT(0);
		}

		goto build_tx;
	}

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * - if ... `change_satoshis` is less than or equal to the
	 *   negotiated `dust_limit_satoshis`:
	 *   - MUST calculate the `est_tx_fee` without the change output (if provided) as:
	 */
	 if (change_output) {
		scriptlen = tal_count(change_output->script);
		weight -= (8 + scriptlen + varint_size(scriptlen)) * 4;
		est_tx_fee = amount_tx_fee(feerate_kw_funding, weight);

		/*
		 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
		 *   2. As there is no change_output, any remaining `change_satoshis`
		 *   will be added to the funding output, and credited to the opener's
		 *   initial channel balance. */
		if (amount_sat_sub(opener_change, *opener_change, est_tx_fee)) {
			if (!amount_sat_add(opener_funding, *opener_funding, *opener_change))
				return NULL;
			*opener_change = AMOUNT_SAT(0);
			goto build_tx;
		}
	}

	/*
	 * BOLT-343afe6a339617807ced92ab10480188f8e6970e #3
	 * - if the resulting `change_satoshis` is less than zero:
	 *   - sum(`funding_satoshis`) will be decreased by the difference.
	 */
	if (!amount_sat_sub(opener_funding, opener_total_sat, est_tx_fee) ||
		!amount_sat_sub(opener_funding, *opener_funding, output_val))
		return NULL;

	*opener_change = AMOUNT_SAT(0);

build_tx:
	input_count = tal_count(opener_inputs) + tal_count(accepter_inputs);
	/* opener + accepter outputs plus the funding output */
	output_count = tal_count(opener_outputs) +
		tal_count(accepter_outputs) + 1;

	/* If they had supplied a change output, but we removed it because of fees,
	 * remove it from the count */
	if (change_output && amount_sat_eq(AMOUNT_SAT(0), *opener_change)) {
		output_count -= 1;
		/* There should at least be a funding output */
		assert(output_count > 0);
	}

	tx = bitcoin_tx(ctx, chainparams, input_count, output_count, 0);

	/* Add the funding output */
	wscript = bitcoin_redeem_2of2(tx, local_fundingkey, remote_fundingkey);
	SUPERVERBOSE("# funding witness script = %s\n", tal_hex(wscript, wscript));

	*total_funding = *opener_funding;
	if (!amount_sat_add(total_funding, *total_funding, accepter_funding))
		return NULL;

	/*
	 * BOLT-82ccaed20022ddf3eb7927052429f6551e8dac45 #2
	 *
	 * - if the `funding_output` of the resulting transaction is less than
	 *   the `dust_limit` ([BOLT #3: Calculating `est_tx_fee`](03-transactions.md#channel-establishment-v2-funding-transaction-fees)):
	 *   - MUST fail the channel
	 */
	if (!amount_sat_greater(*total_funding, chainparams->dust_limit))
		return NULL;

	const void *o_map[output_count];
	for (i = 0; i < output_count; i++)
		o_map[i] = int2ptr(i);

	bitcoin_tx_add_output(tx, scriptpubkey_p2wsh(tx, wscript), *total_funding);

	/* Add the other outputs */
	add_outputs(tx, opener_outputs, opener_change);
	add_outputs(tx, accepter_outputs, NULL);

	/* Note that hsmd depends on the opener's inputs
	 * being added before the accepter's inputs */
	add_inputs(tx, opener_inputs);
	add_inputs(tx, accepter_inputs);

	/* Sort inputs */
	permute_inputs(tx, input_map);

	/* Sort outputs */
	permute_outputs(tx, NULL, o_map);

	/* Set funding_output index for caller */
	for (i = 0; i < output_count; i++) {
		if (o_map[i] == int2ptr(0)) {
			if (outnum)
				*outnum = i;
			break;
		}
	}

	assert(bitcoin_tx_check(tx));
	return tx;
}
#endif /* EXPERIMENTAL_FEATURES */
