#include "config.h"
#include <bitcoin/script.h>
#include <channeld/commit_tx.h>
#include <common/htlc_trim.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

static bool trim(const struct htlc *htlc,
		 u32 feerate_per_kw,
		 struct amount_sat dust_limit,
		 bool option_anchor_outputs,
		 bool option_anchors_zero_fee_htlc_tx,
		 enum side side)
{
	return htlc_is_trimmed(htlc_owner(htlc), htlc->amount,
			       feerate_per_kw, dust_limit, side,
			       option_anchor_outputs,
			       option_anchors_zero_fee_htlc_tx);
}

size_t commit_tx_num_untrimmed(const struct htlc **htlcs,
			       u32 feerate_per_kw,
			       struct amount_sat dust_limit,
			       bool option_anchor_outputs,
			       bool option_anchors_zero_fee_htlc_tx,
			       enum side side)
{
	size_t i, n;

	for (i = n = 0; i < tal_count(htlcs); i++)
		n += !trim(htlcs[i], feerate_per_kw, dust_limit,
			   option_anchor_outputs,
			   option_anchors_zero_fee_htlc_tx,
			   side);

	return n;
}

bool commit_tx_amount_trimmed(const struct htlc **htlcs,
			      u32 feerate_per_kw,
			      struct amount_sat dust_limit,
			      bool option_anchor_outputs,
			      bool option_anchors_zero_fee_htlc_tx,
			      enum side side,
			      struct amount_msat *amt)
{
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		if (trim(htlcs[i], feerate_per_kw, dust_limit,
			 option_anchor_outputs, option_anchors_zero_fee_htlc_tx,
			 side)) {
			if (!amount_msat_add(amt, *amt, htlcs[i]->amount))
				return false;
		}
	}
	return true;
}

static void add_offered_htlc_out(struct bitcoin_tx *tx, size_t n,
				 const struct htlc *htlc,
				 const struct keyset *keyset,
				 bool option_anchor_outputs,
				 bool option_anchors_zero_fee_htlc_tx)
{
	struct ripemd160 ripemd;
	u8 *wscript, *p2wsh;
	struct amount_sat amount = amount_msat_to_sat_round_down(htlc->amount);

	ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));
	wscript = htlc_offered_wscript(tx, &ripemd, keyset,
				       option_anchor_outputs,
				       option_anchors_zero_fee_htlc_tx);
	p2wsh = scriptpubkey_p2wsh(tx, wscript);
	bitcoin_tx_add_output(tx, p2wsh, wscript, amount);
	SUPERVERBOSE("# HTLC #%" PRIu64 " offered amount %"PRIu64" wscript %s\n", htlc->id,
		     amount.satoshis, /* Raw: BOLT 3 output match */
		     tal_hex(wscript, wscript));
	tal_free(wscript);
}

static void add_received_htlc_out(struct bitcoin_tx *tx, size_t n,
				  const struct htlc *htlc,
				  const struct keyset *keyset,
				  bool option_anchor_outputs,
				  bool option_anchors_zero_fee_htlc_tx)
{
	struct ripemd160 ripemd;
	u8 *wscript, *p2wsh;
	struct amount_sat amount;

	ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));
	wscript = htlc_received_wscript(tx, &ripemd, &htlc->expiry, keyset,
					option_anchor_outputs,
					option_anchors_zero_fee_htlc_tx);
	p2wsh = scriptpubkey_p2wsh(tx, wscript);
	amount = amount_msat_to_sat_round_down(htlc->amount);

	bitcoin_tx_add_output(tx, p2wsh, wscript, amount);

	SUPERVERBOSE("# HTLC #%"PRIu64" received amount %"PRIu64" wscript %s\n",
		     htlc->id,
		     amount.satoshis, /* Raw: BOLT 3 output match */
		     tal_hex(wscript, wscript));
	tal_free(wscript);
}

struct bitcoin_tx *commit_tx(const tal_t *ctx,
			     const struct bitcoin_outpoint *funding,
			     struct amount_sat funding_sats,
			     const struct pubkey *local_funding_key,
			     const struct pubkey *remote_funding_key,
			     enum side opener,
			     u16 to_self_delay,
			     u32 lease_expiry,
			     u32 blockheight,
			     const struct keyset *keyset,
			     u32 feerate_per_kw,
			     struct amount_sat dust_limit,
			     struct amount_msat self_pay,
			     struct amount_msat other_pay,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     struct wally_tx_output *direct_outputs[NUM_SIDES],
			     u64 obscured_commitment_number,
			     bool option_anchor_outputs,
			     bool option_anchors_zero_fee_htlc_tx,
			     enum side side,
			     int *anchor_outnum)
{
	struct amount_sat base_fee;
	struct amount_msat total_pay;
	struct bitcoin_tx *tx;
	size_t n, untrimmed;
	/* Is this the lessor ? */
	enum side lessor = !opener;
	u32 *cltvs;
	bool to_local, to_remote;
	struct htlc *dummy_to_local = (struct htlc *)0x01,
		*dummy_to_remote = (struct htlc *)0x02,
		*dummy_other_anchor = (struct htlc *)0x03;
	const u8 *funding_wscript = bitcoin_redeem_2of2(tmpctx,
							local_funding_key,
							remote_funding_key);
	u32 csv_lock = lease_expiry > blockheight ?
		lease_expiry - blockheight : 1;

	if (!amount_msat_add(&total_pay, self_pay, other_pay))
		abort();
	assert(!amount_msat_greater_sat(total_pay, funding_sats));

	/* BOLT #3:
	 *
	 * 1. Calculate which committed HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	untrimmed = commit_tx_num_untrimmed(htlcs,
					    feerate_per_kw,
					    dust_limit,
					    option_anchor_outputs,
					    option_anchors_zero_fee_htlc_tx,
					    side);

	/* BOLT #3:
	 *
	 * 2. Calculate the base [commitment transaction
	 * fee](#fee-calculation).
	 */
	base_fee = commit_tx_base_fee(feerate_per_kw, untrimmed,
				      option_anchor_outputs,
				      option_anchors_zero_fee_htlc_tx);

	SUPERVERBOSE("# base commitment transaction fee = %"PRIu64" for %zu untrimmed\n",
		     base_fee.satoshis /* Raw: spec uses raw numbers */, untrimmed);

	/* BOLT #3:
	 * If `option_anchors` applies to the commitment
	 * transaction, also subtract two times the fixed anchor size
	 * of 330 sats from the funder (either `to_local` or
	 * `to_remote`).
	 */
	if ((option_anchor_outputs || option_anchors_zero_fee_htlc_tx)
	    && !amount_sat_add(&base_fee, base_fee, AMOUNT_SAT(660)))
		/* Can't overflow: feerate is u32. */
		abort();

	/* BOLT #3:
	 *
	 * 3. Subtract this base fee from the funder (either `to_local` or
	 * `to_remote`).
	 */
	try_subtract_fee(opener, side, base_fee, &self_pay, &other_pay);

#ifdef PRINT_ACTUAL_FEE
	{
		struct amount_sat out = AMOUNT_SAT(0);
		bool ok = true;
		for (size_t i = 0; i < tal_count(htlcs); i++) {
			if (!trim(htlcs[i], feerate_per_kw, dust_limit,
				  option_anchor_outputs,
				  option_anchors_zero_fee_htlc_tx,
				  side))
				ok &= amount_sat_add(&out, out, amount_msat_to_sat_round_down(htlcs[i]->amount));
		}
		if (amount_msat_greater_eq_sat(self_pay, dust_limit))
			ok &= amount_sat_add(&out, out, amount_msat_to_sat_round_down(self_pay));
		if (amount_msat_greater_eq_sat(other_pay, dust_limit))
			ok &= amount_sat_add(&out, out, amount_msat_to_sat_round_down(other_pay));
		assert(ok);
		SUPERVERBOSE("# actual commitment transaction fee = %"PRIu64"\n",
			     funding_sats.satoshis - out.satoshis);  /* Raw: test output */
	}
#endif

	/* Worst-case sizing: both to-local and to-remote outputs, and anchors. */
	tx = bitcoin_tx(ctx, chainparams, 1, untrimmed + 2 + 2, 0);

	/* We keep track of which outputs have which HTLCs */
	*htlcmap = tal_arr(tx, const struct htlc *, tx->wtx->outputs_allocation_len);

	/* We keep cltvs for tie-breaking HTLC outputs; we use the same order
	 * for sending the htlc txs, so it may matter. */
	cltvs = tal_arr(tmpctx, u32, tx->wtx->outputs_allocation_len);

	/* This could be done in a single loop, but we follow the BOLT
	 * literally to make comments in test vectors clearer. */

	n = 0;
	/* BOLT #3:
	 *
	 * 4. For every offered HTLC, if it is not trimmed, add an
	 *    [offered HTLC output](#offered-htlc-outputs).
	 */
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) != side)
			continue;
		if (trim(htlcs[i], feerate_per_kw, dust_limit,
			 option_anchor_outputs, option_anchors_zero_fee_htlc_tx,
			 side))
			continue;
		add_offered_htlc_out(tx, n, htlcs[i], keyset,
				     option_anchor_outputs,
				     option_anchors_zero_fee_htlc_tx);
		(*htlcmap)[n] = htlcs[i];
		cltvs[n] = abs_locktime_to_blocks(&htlcs[i]->expiry);
		n++;
	}

	/* BOLT #3:
	 *
	 * 5. For every received HTLC, if it is not trimmed, add an
	 *    [received HTLC output](#received-htlc-outputs).
	 */
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) == side)
			continue;
		if (trim(htlcs[i], feerate_per_kw, dust_limit,
			 option_anchor_outputs, option_anchors_zero_fee_htlc_tx,
			 side))
			continue;
		add_received_htlc_out(tx, n, htlcs[i], keyset,
				      option_anchor_outputs,
				      option_anchors_zero_fee_htlc_tx);
		(*htlcmap)[n] = htlcs[i];
		cltvs[n] = abs_locktime_to_blocks(&htlcs[i]->expiry);
		n++;
	}

	/* BOLT #3:
	 *
	 * 6. If the `to_local` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_local`
	 *    output](#to_local-output).
	 */
	if (amount_msat_greater_eq_sat(self_pay, dust_limit)) {
		/* BOLT- #3:
		 * In a leased channel, the `to_local` output that
		 * pays the `accepter` node is modified so that its
		 * CSV is equal to the greater of the
		 * `to_self_delay` or the `lease_end` - `blockheight`.
		*/
		u8 *wscript = to_self_wscript(tmpctx,
					      to_self_delay,
					      side == lessor ? csv_lock : 0,
					      keyset);
		u8 *p2wsh = scriptpubkey_p2wsh(tx, wscript);
		struct amount_sat amount = amount_msat_to_sat_round_down(self_pay);

		bitcoin_tx_add_output(tx, p2wsh, wscript, amount);
		/* Add a dummy entry to the htlcmap so we can recognize it later */
		(*htlcmap)[n] = direct_outputs ? dummy_to_local : NULL;
		/* We don't assign cltvs[n]: if we use it, order doesn't matter.
		 * However, valgrind will warn us something wierd is happening */
		SUPERVERBOSE("# to_local amount %"PRIu64" wscript %s\n",
			     amount.satoshis, /* Raw: BOLT 3 output match */
			     tal_hex(tmpctx, wscript));
		n++;
		to_local = true;
	} else
		to_local = false;

	/* BOLT #3:
	 *
	 * 7. If the `to_remote` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_remote`
	 *    output](#to_remote-output).
	 */
	u8 *redeem;
	if (amount_msat_greater_eq_sat(other_pay, dust_limit)) {
		struct amount_sat amount = amount_msat_to_sat_round_down(other_pay);
		u8 *scriptpubkey;
		int pos;

		/* BOLT #3:
		 *
		 * #### `to_remote` Output
		 *
		 * If `option_anchors` applies to the commitment
		 * transaction, the `to_remote` output is encumbered by a one
		 * block csv lock.
		 *    <remotepubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
		 *
		 *...
		 * Otherwise, this output is a simple P2WPKH to `remotepubkey`.
		 */
		if (option_anchor_outputs || option_anchors_zero_fee_htlc_tx) {
			redeem = bitcoin_wscript_to_remote_anchored(tmpctx,
							 &keyset->other_payment_key,
							 (!side) == lessor ?
							       csv_lock : 1);
			/* BOLT- #3:
			 * ##### Leased channel (`option_will_fund`)
			 *
			 * If a `lease` applies to the channel, the
			 * `to_remote` output of the `initiator`
			 * ensures the `leasor` funds are not
			 * spendable until the lease expires.
			 *
			 * <remote_pubkey> OP_CHECKSIGVERIFY
			 *       MAX(1, lease_end - blockheight)
			 *       OP_CHECKSEQUENCEVERIFY
			 */
			scriptpubkey = scriptpubkey_p2wsh(tmpctx, redeem);
		} else {
			redeem = NULL;
			scriptpubkey = scriptpubkey_p2wpkh(tmpctx,
							   &keyset->other_payment_key);
		}
		pos = bitcoin_tx_add_output(tx, scriptpubkey, redeem, amount);
		assert(pos == n);
		(*htlcmap)[n] = direct_outputs ? dummy_to_remote : NULL;
		/* We don't assign cltvs[n]: if we use it, order doesn't matter.
		 * However, valgrind will warn us something wierd is happening */
		SUPERVERBOSE("# to_remote amount %"PRIu64" P2WPKH(%s)\n",
			     amount.satoshis, /* Raw: BOLT 3 output match */
			     fmt_pubkey(tmpctx, &keyset->other_payment_key));
		n++;

		to_remote = true;
	} else {
		to_remote = false;
		redeem = NULL;
	}

	/* BOLT #3:
	 *
	 * 8. If `option_anchors` applies to the commitment transaction:
	 *    * if `to_local` exists or there are untrimmed HTLCs, add a
	 *      [`to_local_anchor` output]...
	 *    * if `to_remote` exists or there are untrimmed HTLCs, add a
	 *      [`to_remote_anchor` output]
	 */
	if (option_anchor_outputs || option_anchors_zero_fee_htlc_tx) {
		if (to_local || untrimmed != 0) {
			tx_add_anchor_output(tx, local_funding_key);
			(*htlcmap)[n] = NULL;
			n++;
		}

		/* With anchors, the caller really wants to know what
		 * is the LOCAL anchor for the REMOTE side. */
		if (to_remote || untrimmed != 0) {
			tx_add_anchor_output(tx, remote_funding_key);
			(*htlcmap)[n] = dummy_other_anchor;
			n++;
		}
	}

	/* BOLT #2:
	 *
	 *  - MUST set `channel_reserve_satoshis` greater than or equal to
	 *    `dust_limit_satoshis`.
	 */
	/* This means there must be at least one output. */
	assert(n > 0);

	assert(n <= tx->wtx->outputs_allocation_len);
	tal_resize(htlcmap, n);

	/* BOLT #3:
	 *
	 * 9. Sort the outputs into [BIP 69+CLTV
	 *    order](#transaction-output-ordering)
	 */
	permute_outputs(tx, cltvs, (const void **)*htlcmap);

	/* BOLT #3:
	 *
	 * ## Commitment Transaction
	 *
	 * * version: 2
	 */
	assert(tx->wtx->version == 2);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the lower 24 bits of the obscured commitment number
	 */
	bitcoin_tx_set_locktime(tx,
	    (0x20000000 | (obscured_commitment_number & 0xFFFFFF)));

	/* BOLT #3:
	 *
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from
	 *      `funding_created` message
	 */
	/* BOLT #3:
	 *
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 */
	u32 sequence = (0x80000000 | ((obscured_commitment_number>>24) & 0xFFFFFF));
	bitcoin_tx_add_input(tx, funding,
			     sequence, NULL, funding_sats, NULL, funding_wscript);

	/* Identify the direct outputs (to_us, to_them), and the local anchor */
	if (direct_outputs != NULL)
		direct_outputs[LOCAL] = direct_outputs[REMOTE] = NULL;

	*anchor_outnum = -1;
	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		if ((*htlcmap)[i] == dummy_to_local) {
			(*htlcmap)[i] = NULL;
			direct_outputs[LOCAL] = tx->wtx->outputs + i;
		} else if ((*htlcmap)[i] == dummy_to_remote) {
			(*htlcmap)[i] = NULL;
			direct_outputs[REMOTE] = tx->wtx->outputs + i;
		} else if ((*htlcmap)[i] == dummy_other_anchor) {
			(*htlcmap)[i] = NULL;
			*anchor_outnum = i;
		}
	}

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));

	return tx;
}
