#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/endian/endian.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <common/utils.h>
#include <inttypes.h>

/* BOLT #3:
 *
 * The 48-bit commitment transaction number is obscured by `XOR` with
 * the lower 48 bits of:
 *
 *     SHA256(payment_basepoint from open_channel || payment_basepoint from accept_channel)
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

bool try_subtract_fee(enum side funder, enum side side,
		      u64 base_fee_msat, u64 *self_msat, u64 *other_msat)
{
	u64 *funder_msat;

	if (funder == side)
		funder_msat = self_msat;
	else
		funder_msat = other_msat;

	if (*funder_msat >= base_fee_msat) {
		*funder_msat -= base_fee_msat;
		return true;
	} else {
		*funder_msat = 0;
		return false;
	}
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
				     u64 funding_satoshis,
				     enum side funder,
				     u16 to_self_delay,
				     const struct keyset *keyset,
				     u32 feerate_per_kw,
				     u64 dust_limit_satoshis,
				     u64 self_pay_msat,
				     u64 other_pay_msat,
				     u64 self_reserve_msat,
				     u64 obscured_commitment_number,
				     enum side side)
{
	u64 base_fee_msat;
	struct bitcoin_tx *tx;
	size_t n, untrimmed;

	assert(self_pay_msat + other_pay_msat <= funding_satoshis * 1000);

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
	base_fee_msat = commit_tx_base_fee(feerate_per_kw, untrimmed) * 1000;

	/* BOLT #3:
	 *
	 * 3. Subtract this base fee from the funder (either `to_local` or
	 * `to_remote`), with a floor of 0 (see [Fee Payment](#fee-payment)).
	 */
	if (!try_subtract_fee(funder, side, base_fee_msat,
			      &self_pay_msat, &other_pay_msat)) {
		/* BOLT #2:
		 *
		 * The receiving node MUST fail the channel if:
		 *...
		 *   - it considers `feerate_per_kw` too small for timely
		 *     processing or unreasonably large.
		 */
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
	if (self_pay_msat <= self_reserve_msat
	    && other_pay_msat <= self_reserve_msat) {
		status_unusual("Neither self amount %"PRIu64
			       " nor other amount %"PRIu64
			       " exceed reserve %"PRIu64
			       " on initial commitment transaction",
			       self_pay_msat / 1000,
			       other_pay_msat / 1000,
			       self_reserve_msat / 1000);
		return NULL;
	}


	/* Worst-case sizing: both to-local and to-remote outputs. */
	tx = bitcoin_tx(ctx, 1, untrimmed + 2);

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
	 *    output](#to-local-output).
	 */
	if (self_pay_msat / 1000 >= dust_limit_satoshis) {
		u8 *wscript = to_self_wscript(tmpctx, to_self_delay,keyset);
		tx->output[n].amount = self_pay_msat / 1000;
		tx->output[n].script = scriptpubkey_p2wsh(tx, wscript);
		n++;
	}

	/* BOLT #3:
	 *
	 * 6. If the `to_remote` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_remote`
	 *    output](#to-remote-output).
	 */
	if (other_pay_msat / 1000 >= dust_limit_satoshis) {
		/* BOLT #3:
		 *
		 * #### `to_remote` Output
		 *
		 * This output sends funds to the other peer and thus is a simple
		 * P2WPKH to `remotepubkey`.
		 */
		tx->output[n].amount = other_pay_msat / 1000;
		tx->output[n].script = scriptpubkey_p2wpkh(tx,
						   &keyset->other_payment_key);
		n++;
	}

	assert(n <= tal_count(tx->output));
	tal_resize(&tx->output, n);

	/* BOLT #3:
	 *
	 * 7. Sort the outputs into [BIP 69
	 *    order](#transaction-input-and-output-ordering)
	 */
	permute_outputs(tx->output, tal_count(tx->output), NULL);

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
	 *   24 bits of the obscured commitment transaction number
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
	 *       upper 24 bits of the obscured commitment transaction number
	 */
	tx->input[0].sequence_number
		= (0x80000000 | ((obscured_commitment_number>>24) & 0xFFFFFF));

	/* Input amount needed for signature code. */
	tx->input[0].amount = tal_dup(tx->input, u64, &funding_satoshis);

	return tx;
}
