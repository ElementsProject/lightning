#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/endian/endian.h>
#include <lightningd/commit_tx.h>
#include <permute_tx.h>
#include <utils.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* BOLT #3:
 *
 * The 48-bit commitment transaction number is obscured by `XOR` with
 * the lower 48 bits of:
 *
 *     SHA256(payment-basepoint from open_channel || payment-basepoint from accept_channel)
 */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint,
			   const struct pubkey *accepter_payment_basepoint)
{
	u8 ders[PUBKEY_DER_LEN * 2];
	struct sha256 sha;
	be64 obscurer = 0;

	pubkey_to_der(ders, opener_payment_basepoint);
	pubkey_to_der(ders + PUBKEY_DER_LEN, accepter_payment_basepoint);

	sha256(&sha, ders, sizeof(ders));
	/* Lower 48 bits */
	memcpy((u8 *)&obscurer + 2, sha.u.u8 + sizeof(sha.u.u8) - 6, 6);
	return be64_to_cpu(obscurer);
}

static void subtract_fee(enum side funder,
			 u64 base_fee_msat, u64 *local_msat, u64 *remote_msat)
{
	u64 *funder_msat;

	if (funder == LOCAL)
		funder_msat = local_msat;
	else
		funder_msat = remote_msat;

	if (*funder_msat >= base_fee_msat)
		*funder_msat -= base_fee_msat;
	else
		*funder_msat = 0;
}

u64 htlc_timeout_fee(u64 feerate_per_kw)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction MUST BE calculated to match:
	 *
	 * 1. Multiply `feerate-per-kw` by 634 and divide by 1000 (rounding
	 *    down).
	 */
	return feerate_per_kw * 634 / 1000;
}

u64 htlc_success_fee(u64 feerate_per_kw)
{
	/* BOLT #3:
	 *
	 * The fee for an HTLC-success transaction MUST BE calculated to match:
	 *
	 * 1. Multiply `feerate-per-kw` by 671 and divide by 1000 (rounding
	 *    down).
	 */
	return feerate_per_kw * 671 / 1000;
}

static const struct htlc **untrimmed(const tal_t *ctx,
				     const struct htlc **htlcs,
				     enum side side,
				     u64 htlc_fee, u64 dust_limit_satoshis)
{
	const struct htlc **arr;
	size_t i, n;

	/* BOLT #3:
	 *
	 * For every offered HTLC, if the HTLC amount minus the HTLC-timeout
	 * fee would be less than `dust-limit-satoshis` set by the transaction
	 * owner, the commitment transaction MUST NOT contain that output,
	 * otherwise it MUST be generated as specified in [Offered HTLC
	 * Outputs](#offered-htlc-outputs).
	 *
	 * For every received HTLC, if the HTLC amount minus the HTLC-success
	 * fee would be less than `dust-limit-satoshis` set by the transaction
	 * owner, the commitment transaction MUST NOT contain that output,
	 * otherwise it MUST be generated as specified in [Received HTLC
	 * Outputs](#received-htlc-outputs).
	 */
	arr = tal_arr(ctx, const struct htlc *, tal_count(htlcs));
	for (i = n = 0; i < tal_count(htlcs); i++) {
		if  (htlc_owner(htlcs[i]) != side)
			continue;
		if (htlcs[i]->msatoshi / 1000 < dust_limit_satoshis + htlc_fee)
			continue;
		arr[n++] = htlcs[i];
	}

	assert(n <= tal_count(arr));
	tal_resize(&arr, n);

	return arr;
}

static u64 commit_tx_base_fee(u64 feerate_per_kw, size_t num_untrimmed_htlcs)
{
	u64 weight;

	/* BOLT #3:
	 *
	 * The base fee for a commitment transaction MUST BE
	 * calculated to match:
	 *
	 * 1. Start with `weight` = 724.
	 */
	weight = 724;

	/* BOLT #3:
	 *
	 * 2. For each committed HTLC, if that output is not trimmed
	 *    as specified in [Trimmed Outputs](#trimmed-outputs), add
	 *    172 to `weight`.
	 */
	weight += 172 * num_untrimmed_htlcs;

	/* BOLT #3:
	 *
	 * 3. Multiply `feerate-per-kw` by `weight`, divide by 1000
	 *    (rounding down).
	 */
	return feerate_per_kw * weight / 1000;
}

struct bitcoin_tx *commit_tx(const tal_t *ctx,
			     const struct sha256_double *funding_txid,
			     unsigned int funding_txout,
			     u64 funding_satoshis,
			     enum side funder,
			     u16 to_self_delay,
			     const struct pubkey *revocation_pubkey,
			     const struct pubkey *local_delayedkey,
			     const struct pubkey *localkey,
			     const struct pubkey *remotekey,
			     u64 feerate_per_kw,
			     u64 dust_limit_satoshis,
			     u64 local_pay_msat,
			     u64 remote_pay_msat,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     u64 obscured_commitment_number)
{
	const tal_t *tmpctx = tal_tmpctx(ctx);
	const struct htlc **offered, **received;
	u64 base_fee_msat;
	struct bitcoin_tx *tx;
	size_t i, n;

	assert(local_pay_msat + remote_pay_msat <= funding_satoshis * 1000);

	/* BOLT #3:
	 *
	 * 1. Calculate which committed HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	offered = untrimmed(tmpctx, htlcs, LOCAL,
			    htlc_timeout_fee(feerate_per_kw),
			    dust_limit_satoshis);
	received = untrimmed(tmpctx, htlcs, REMOTE,
			     htlc_success_fee(feerate_per_kw),
			     dust_limit_satoshis);

	/* BOLT #3:
	 *
	 * 2. Calculate the base [commitment transaction
	 * fee](#fee-calculation).
	 */
	base_fee_msat = commit_tx_base_fee(feerate_per_kw,
					   tal_count(offered)
					   + tal_count(received))
		* 1000;

	SUPERVERBOSE("# base commitment transaction fee = %"PRIu64"\n",
		     base_fee_msat / 1000);

	/* BOLT #3:
	 *
	 * 3. Subtract this base fee from the funder (either `to-local` or
	 * `to-remote`), with a floor of zero (see [Fee Payment](#fee-payment)).
	 */
	subtract_fee(funder, base_fee_msat, &local_pay_msat, &remote_pay_msat);

	/* Worst-case sizing: both to-local and to-remote outputs. */
	tx = bitcoin_tx(ctx, 1, tal_count(offered) + tal_count(received) + 2);

	/* We keep track of which outputs have which HTLCs */
	*htlcmap = tal_arr(tx, const struct htlc *, tal_count(tx->output));

	/* BOLT #3:
	 *
	 * 3. For every offered HTLC, if it is not trimmed, add an [offered
	 *    HTLC output](#offered-htlc-outputs).
	 */
	n = 0;
	for (i = 0; i < tal_count(offered); i++, n++) {
		u8 *wscript = bitcoin_wscript_htlc_offer(tmpctx,
							 localkey, remotekey,
							 &offered[i]->rhash);
		tx->output[n].amount = offered[i]->msatoshi / 1000;
		tx->output[n].script = scriptpubkey_p2wsh(tx, wscript);
		(*htlcmap)[n] = offered[i];
		SUPERVERBOSE("# HTLC offered amount %"PRIu64" wscript %s\n",
			     tx->output[n].amount,
			     tal_hex(tmpctx, wscript));
	}

	/* BOLT #3:
	 *
	 * 4. For every received HTLC, if it is not trimmed, add an [received
	 *    HTLC output](#received-htlc-outputs).
	 */
	for (i = 0; i < tal_count(received); i++, n++) {
		u8 *wscript = bitcoin_wscript_htlc_receive(tmpctx,
							   &received[i]->expiry,
							   localkey, remotekey,
							   &received[i]->rhash);
		tx->output[n].amount = received[i]->msatoshi / 1000;
		tx->output[n].script = scriptpubkey_p2wsh(tx, wscript);
		(*htlcmap)[n] = received[i];
		SUPERVERBOSE("# HTLC received amount %"PRIu64" wscript %s\n",
			     tx->output[n].amount,
			     tal_hex(tmpctx, wscript));
	}

	/* BOLT #3:
	 *
	 * 5. If the `to-local` amount is greater or equal to
	 *    `dust-limit-satoshis`, add a [To-Local
	 *    Output](#to-local-output).
	 */
	if (local_pay_msat / 1000 >= dust_limit_satoshis) {
		u8 *wscript = bitcoin_wscript_to_local(tmpctx,
						       to_self_delay,
						       revocation_pubkey,
						       local_delayedkey);
		tx->output[n].amount = local_pay_msat / 1000;
		tx->output[n].script = scriptpubkey_p2wsh(tx, wscript);
		(*htlcmap)[n] = NULL;
		SUPERVERBOSE("# to-local amount %"PRIu64" wscript %s\n",
			     tx->output[n].amount,
			     tal_hex(tmpctx, wscript));
		n++;
	}

	/* BOLT #3:
	 *
	 * 6. If the `to-remote` amount is greater or equal to
	 *    `dust-limit-satoshis`, add a [To-Remote
	 *    Output](#to-remote-output).
	 */
	if (remote_pay_msat / 1000 >= dust_limit_satoshis) {
		/* BOLT #3:
		 *
		 * #### To-Remote Output
		 *
		 * This output sends funds to the other peer, thus is a simple
		 * P2WPKH to `remotekey`.
		 */
		tx->output[n].amount = remote_pay_msat / 1000;
		tx->output[n].script = scriptpubkey_p2wpkh(tx, remotekey);
		(*htlcmap)[n] = NULL;
		SUPERVERBOSE("# to-remote amount %"PRIu64" P2WPKH(%s)\n",
			     tx->output[n].amount,
			     type_to_string(tmpctx, struct pubkey, remotekey));
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
	permute_outputs(tx->output, tal_count(tx->output), *htlcmap);

	/* BOLT #3:
	 *
	 * ## Commitment Transaction
	 *
	 * * version: 2
	 */
	assert(tx->version == 2);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the lower
	 *   24 bits of the obscured commitment transaction number.
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
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are
	 *       upper 24 bits of the obscured commitment transaction number.
	 */
	tx->input[0].sequence_number
		= (0x80000000 | ((obscured_commitment_number>>24) & 0xFFFFFF));

	/* Input amount needed for signature code. */
	tx->input[0].amount = tal_dup(tx->input, u64, &funding_satoshis);

	tal_free(tmpctx);
	return tx;
}
