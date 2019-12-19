#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/endian/endian.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <inttypes.h>

/* BOLT #3:
 *
 * The 48-bit commitment number is obscured by `XOR` with the lower 48 bits of:
 *
 *     SHA256(payment_basepoint from open_channel || payment_basepoint from accept_channel)
 */
u64 commit_number_obscurer(const struct pubkey *opener_payment_basepoint,
			   const struct pubkey *accepter_payment_basepoint)
{
	u8 ders[PUBKEY_CMPR_LEN * 2];
	struct sha256 sha;
	be64 obscurer = 0;

	pubkey_to_der(ders, opener_payment_basepoint);
	pubkey_to_der(ders + PUBKEY_CMPR_LEN, accepter_payment_basepoint);

	sha256(&sha, ders, sizeof(ders));
	/* Lower 48 bits */
	memcpy((u8 *)&obscurer + 2, sha.u.u8 + sizeof(sha.u.u8) - 6, 6);
	return be64_to_cpu(obscurer);
}

bool try_subtract_fee(enum side funder, enum side side,
		      struct amount_sat base_fee,
		      struct amount_msat *self,
		      struct amount_msat *other)
{
	struct amount_msat *funder_amount;

	if (funder == side)
		funder_amount = self;
	else
		funder_amount = other;

	if (amount_msat_sub_sat(funder_amount, *funder_amount, base_fee))
		return true;

	*funder_amount = AMOUNT_MSAT(0);
	return false;
}

u8 *to_self_wscript(const tal_t *ctx,
		    u16 to_self_delay,
		    const struct keyset *keyset)
{
	return bitcoin_wscript_to_local(ctx, to_self_delay,
					&keyset->self_revocation_key,
					&keyset->self_delayed_payment_key);
}

struct bitcoin_tx *initial_commit_tx(const tal_t *ctx,
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
				     struct amount_sat self_reserve,
				     u64 obscured_commitment_number,
				     enum side side,
				     char** err_reason)
{
	struct amount_sat base_fee;
	struct bitcoin_tx *tx;
	size_t n, untrimmed;
	struct amount_msat total_pay;
	struct amount_sat amount;
	u32 sequence;

	if (!amount_msat_add(&total_pay, self_pay, other_pay))
		abort();
	assert(!amount_msat_greater_sat(total_pay, funding));

	/* BOLT #3:
	 *
	 * 1. Calculate which committed HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	untrimmed = 0;

	/* BOLT #3:
	 *
	 * 2. Calculate the base [commitment transaction
	 * fee](#fee-calculation).
	 */
	base_fee = commit_tx_base_fee(feerate_per_kw, untrimmed);

	/* BOLT #3:
	 *
	 * 3. Subtract this base fee from the funder (either `to_local` or
	 * `to_remote`), with a floor of 0 (see [Fee Payment](#fee-payment)).
	 */
	if (!try_subtract_fee(funder, side, base_fee, &self_pay, &other_pay)) {
		/* BOLT #2:
		 *
		 * The receiving node MUST fail the channel if:
		 *...
		 *   - it considers `feerate_per_kw` too small for timely
		 *     processing or unreasonably large.
		 */
		*err_reason = "Funder cannot afford fee on initial commitment transaction";
		status_unusual("Funder cannot afford fee"
			       " on initial commitment transaction");
		return NULL;
	}

	/* FIXME, should be in #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - both `to_local` and `to_remote` amounts for the initial
	 *   commitment transaction are less than or equal to
	 *   `channel_reserve_satoshis`.
	 */
	if (!amount_msat_greater_sat(self_pay, self_reserve)
	    && !amount_msat_greater_sat(other_pay, self_reserve)) {
		*err_reason = "Neither self amount nor other amount exceed reserve on "
				   "initial commitment transaction";
		status_unusual("Neither self amount %s"
			       " nor other amount %s"
			       " exceed reserve %s"
			       " on initial commitment transaction",
			       type_to_string(tmpctx, struct amount_msat,
					      &self_pay),
			       type_to_string(tmpctx, struct amount_msat,
					      &other_pay),
			       type_to_string(tmpctx, struct amount_sat,
					      &self_reserve));
		return NULL;
	}


	/* Worst-case sizing: both to-local and to-remote outputs. */
	tx = bitcoin_tx(ctx, chainparams, 1, untrimmed + 2);

	/* This could be done in a single loop, but we follow the BOLT
	 * literally to make comments in test vectors clearer. */

	n = 0;
	/* BOLT #3:
	 *
	 * 3. For every offered HTLC, if it is not trimmed, add an
	 *    [offered HTLC output](#offered-htlc-outputs).
	 */

	/* BOLT #3:
	 *
	 * 4. For every received HTLC, if it is not trimmed, add an
	 *    [received HTLC output](#received-htlc-outputs).
	 */

	/* BOLT #3:
	 *
	 * 5. If the `to_local` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_local`
	 *    output](#to_local-output).
	 */
	if (amount_msat_greater_eq_sat(self_pay, dust_limit)) {
		u8 *wscript = to_self_wscript(tmpctx, to_self_delay, keyset);
		amount = amount_msat_to_sat_round_down(self_pay);
		int pos = bitcoin_tx_add_output(
		    tx, scriptpubkey_p2wsh(tx, wscript), amount);
		assert(pos == n);
		tx->output_witscripts[n] =
			tal(tx->output_witscripts, struct witscript);
		tx->output_witscripts[n]->ptr =
			tal_dup_arr(tx->output_witscripts[n], u8,
				    wscript, tal_count(wscript), 0);
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
		amount = amount_msat_to_sat_round_down(other_pay);
		int pos = bitcoin_tx_add_output(
		    tx, scriptpubkey_p2wpkh(tx, &keyset->other_payment_key),
		    amount);
		assert(pos == n);
		n++;
	}

	assert(n <= tx->wtx->num_outputs);

	tal_resize(&(tx->output_witscripts), n);

	/* BOLT #3:
	 *
	 * 7. Sort the outputs into [BIP 69+CLTV
	 *    order](#transaction-input-and-output-ordering)
	 */
	permute_outputs(tx, NULL, NULL);

	/* BOLT #3:
	 *
	 * ## Commitment Transaction
	 *
	 * * version: 2
	 */
	assert(tx->wtx->version == 2);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the
	 * lower 24 bits of the obscured commitment number
	 */
	tx->wtx->locktime =
	    (0x20000000 | (obscured_commitment_number & 0xFFFFFF));

	/* BOLT #3:
	 *
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from
	 *      `funding_created` message
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 *    * `txin[0]` script bytes: 0
	 */
	sequence = (0x80000000 | ((obscured_commitment_number>>24) & 0xFFFFFF));
	bitcoin_tx_add_input(tx, funding_txid, funding_txout, sequence, funding, NULL);

	elements_tx_add_fee_output(tx);
	assert(bitcoin_tx_check(tx));

	return tx;
}
