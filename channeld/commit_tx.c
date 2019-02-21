#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/endian/endian.h>
#include <channeld/commit_tx.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/utils.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

static bool trim(const struct htlc *htlc,
		 u32 feerate_per_kw,
		 struct amount_sat dust_limit,
		 enum side side)
{
	struct amount_sat htlc_fee, htlc_min;

	/* BOLT #3:
	 *
	 *   - for every offered HTLC:
	 *    - if the HTLC amount minus the HTLC-timeout fee would be less than
	 *    `dust_limit_satoshis` set by the transaction owner:
	 *      - MUST NOT contain that output.
	 *    - otherwise:
	 *      - MUST be generated as specified in
	 *      [Offered HTLC Outputs](#offered-htlc-outputs).
	 */
	if (htlc_owner(htlc) == side)
		htlc_fee = htlc_timeout_fee(feerate_per_kw);
	/* BOLT #3:
	 *
	 *  - for every received HTLC:
	 *    - if the HTLC amount minus the HTLC-success fee would be less than
	 *    `dust_limit_satoshis` set by the transaction owner:
	 *      - MUST NOT contain that output.
	 *    - otherwise:
	 *      - MUST be generated as specified in
	 */
	else
		htlc_fee = htlc_success_fee(feerate_per_kw);

	/* If these overflow, it implies htlc must be less. */
	if (!amount_sat_add(&htlc_min, dust_limit, htlc_fee))
		return true;
	return amount_msat_less_sat(htlc->amount, htlc_min);
}

size_t commit_tx_num_untrimmed(const struct htlc **htlcs,
			       u32 feerate_per_kw,
			       struct amount_sat dust_limit,
			       enum side side)
{
	size_t i, n;

	for (i = n = 0; i < tal_count(htlcs); i++)
		n += !trim(htlcs[i], feerate_per_kw, dust_limit, side);

	return n;
}

static void add_offered_htlc_out(struct bitcoin_tx *tx, size_t n,
				 const struct htlc *htlc,
				 const struct keyset *keyset)
{
	struct ripemd160 ripemd;
	u8 *wscript;

	ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));
	wscript = htlc_offered_wscript(tx->output, &ripemd, keyset);
	tx->output[n].amount = amount_msat_to_sat_round_down(htlc->amount);
	tx->output[n].script = scriptpubkey_p2wsh(tx, wscript);
	SUPERVERBOSE("# HTLC %"PRIu64" offered %s wscript %s\n",
		     htlc->id,
		     type_to_string(tmpctx, struct amount_sat,
				    &tx->output[n].amount),
		     tal_hex(wscript, wscript));
	tal_free(wscript);
}

static void add_received_htlc_out(struct bitcoin_tx *tx, size_t n,
				  const struct htlc *htlc,
				  const struct keyset *keyset)
{
	struct ripemd160 ripemd;
	u8 *wscript;

	ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));
	wscript = htlc_received_wscript(tx, &ripemd, &htlc->expiry, keyset);
	tx->output[n].amount = amount_msat_to_sat_round_down(htlc->amount);
	tx->output[n].script = scriptpubkey_p2wsh(tx->output, wscript);
	SUPERVERBOSE("# HTLC %"PRIu64" received %s wscript %s\n",
		     htlc->id,
		     type_to_string(tmpctx, struct amount_sat,
				    &tx->output[n].amount),
		     tal_hex(wscript, wscript));
	tal_free(wscript);
}

struct bitcoin_tx *commit_tx(const tal_t *ctx,
			     const struct bitcoin_txid *funding_txid,
			     unsigned int funding_txout,
			     struct amount_sat funding,
			     enum side funder,
			     u16 to_self_delay,
			     const struct keyset *keyset,
			     u32 feerate_per_kw,
			     struct amount_sat dust_limit,
			     struct amount_msat self_pay,
			     struct amount_msat other_pay,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     u64 obscured_commitment_number,
			     enum side side)
{
	struct amount_sat base_fee;
	struct amount_msat total_pay;
	struct bitcoin_tx *tx;
	size_t i, n, untrimmed;
	u32 *cltvs;

	if (!amount_msat_add(&total_pay, self_pay, other_pay))
		abort();
	assert(!amount_msat_greater_sat(total_pay, funding));

	/* BOLT #3:
	 *
	 * 1. Calculate which committed HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	untrimmed = commit_tx_num_untrimmed(htlcs,
					    feerate_per_kw,
					    dust_limit, side);

	/* BOLT #3:
	 *
	 * 2. Calculate the base [commitment transaction
	 * fee](#fee-calculation).
	 */
	base_fee = commit_tx_base_fee(feerate_per_kw, untrimmed);

	SUPERVERBOSE("# base commitment transaction fee = %s\n",
		     type_to_string(tmpctx, struct amount_sat, &base_fee));

	/* BOLT #3:
	 *
	 * 3. Subtract this base fee from the funder (either `to_local` or
	 * `to_remote`), with a floor of 0 (see [Fee Payment](#fee-payment)).
	 */
	try_subtract_fee(funder, side, base_fee, &self_pay, &other_pay);

#ifdef PRINT_ACTUAL_FEE
	{
		struct amount_sat out = AMOUNT_SAT(0);
		bool ok = true;
		for (i = 0; i < tal_count(htlcs); i++) {
			if (!trim(htlcs[i], feerate_per_kw, dust_limit, side))
				ok &= amount_sat_add(&out, out, amount_msat_to_sat_round_down(htlcs[i]->amount));
		}
		if (amount_msat_greater_sat(self_pay, dust_limit))
			ok &= amount_sat_add(&out, out, amount_msat_to_sat_round_down(self_pay));
		if (amount_msat_greater_sat(other_pay, dust_limit))
			ok &= amount_sat_add(&out, out, amount_msat_to_sat_round_down(other_pay));
		assert(ok);
		SUPERVERBOSE("# actual commitment transaction fee = %"PRIu64"\n",
			     funding.satoshis - out.satoshis);  /* Raw: test output */
	}
#endif

	/* Worst-case sizing: both to-local and to-remote outputs. */
	tx = bitcoin_tx(ctx, 1, untrimmed + 2);

	/* We keep track of which outputs have which HTLCs */
	*htlcmap = tal_arr(tx, const struct htlc *, tal_count(tx->output));

	/* We keep cltvs for tie-breaking HTLC outputs; we use the same order
	 * for sending the htlc txs, so it may matter. */
	cltvs = tal_arr(tmpctx, u32, tal_count(tx->output));

	/* This could be done in a single loop, but we follow the BOLT
	 * literally to make comments in test vectors clearer. */

	n = 0;
	/* BOLT #3:
	 *
	 * 3. For every offered HTLC, if it is not trimmed, add an
	 *    [offered HTLC output](#offered-htlc-outputs).
	 */
	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) != side)
			continue;
		if (trim(htlcs[i], feerate_per_kw, dust_limit, side))
			continue;
		add_offered_htlc_out(tx, n, htlcs[i], keyset);
		(*htlcmap)[n] = htlcs[i];
		cltvs[n] = abs_locktime_to_blocks(&htlcs[i]->expiry);
		n++;
	}

	/* BOLT #3:
	 *
	 * 4. For every received HTLC, if it is not trimmed, add an
	 *    [received HTLC output](#received-htlc-outputs).
	 */
	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) == side)
			continue;
		if (trim(htlcs[i], feerate_per_kw, dust_limit, side))
			continue;
		add_received_htlc_out(tx, n, htlcs[i], keyset);
		(*htlcmap)[n] = htlcs[i];
		cltvs[n] = abs_locktime_to_blocks(&htlcs[i]->expiry);
		n++;
	}

	/* BOLT #3:
	 *
	 * 5. If the `to_local` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_local`
	 *    output](#to_local-output).
	 */
	if (amount_msat_greater_eq_sat(self_pay, dust_limit)) {
		u8 *wscript = to_self_wscript(tmpctx, to_self_delay,keyset);
		tx->output[n].amount = amount_msat_to_sat_round_down(self_pay);
		tx->output[n].script = scriptpubkey_p2wsh(tx, wscript);
		(*htlcmap)[n] = NULL;
		/* We don't assign cltvs[n]: if we use it, order doesn't matter.
		 * However, valgrind will warn us something wierd is happening */
		SUPERVERBOSE("# to-local amount %s wscript %s\n",
			     type_to_string(tmpctx, struct amount_sat,
					    &tx->output[n].amount),
			     tal_hex(tmpctx, wscript));
		n++;
	}

	/* BOLT #3:
	 *
	 * 6. If the `to_remote` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_remote`
	 *    output](#to_remote-output).
	 */
	if (amount_msat_greater_eq_sat(other_pay, dust_limit)) {
		/* BOLT #3:
		 *
		 * #### `to_remote` Output
		 *
		 * This output sends funds to the other peer and thus is a simple
		 * P2WPKH to `remotepubkey`.
		 */
		tx->output[n].amount = amount_msat_to_sat_round_down(other_pay);
		tx->output[n].script = scriptpubkey_p2wpkh(tx,
						   &keyset->other_payment_key);
		(*htlcmap)[n] = NULL;
		/* We don't assign cltvs[n]: if we use it, order doesn't matter.
		 * However, valgrind will warn us something wierd is happening */
		SUPERVERBOSE("# to-remote amount %s P2WPKH(%s)\n",
			     type_to_string(tmpctx, struct amount_sat,
					    &tx->output[n].amount),
			     type_to_string(tmpctx, struct pubkey,
					    &keyset->other_payment_key));
		n++;
	}

	assert(n <= tal_count(tx->output));
	tal_resize(&tx->output, n);
	tal_resize(htlcmap, n);

	/* BOLT #3:
	 *
	 * 7. Sort the outputs into [BIP 69
	 *    order](#transaction-input-and-output-ordering)
	 */
	permute_outputs(tx->output, cltvs, (const void **)*htlcmap);

	/* BOLT #3:
	 *
	 * ## Commitment Transaction
	 *
	 * * version: 2
	 */
	assert(tx->version == 2);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
	 */
	tx->lock_time
		= (0x20000000 | (obscured_commitment_number & 0xFFFFFF));

	/* BOLT #3:
	 *
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from
	 *      `funding_created` message
	 */
	tx->input[0].txid = *funding_txid;
	tx->input[0].index = funding_txout;

	/* BOLT #3:
	 *
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 */
	tx->input[0].sequence_number
		= (0x80000000 | ((obscured_commitment_number>>24) & 0xFFFFFF));

	/* Input amount needed for signature code. */
	tx->input[0].amount = tal_dup(tx->input, struct amount_sat, &funding);

	return tx;
}
