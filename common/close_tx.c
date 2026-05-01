#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <common/close_tx.h>
#include <common/permute_tx.h>
#include <common/psbt_keypath.h>
#include <wally_script.h>

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0;
	struct amount_sat total_out;
	u8 *script;

	assert(amount_sat_add(&total_out, to_us, to_them));
	assert(amount_sat_less_eq(total_out, funding_sats));

	/* BOLT #3:
	 *
	 * ## Legacy Closing Transaction
	 *
	 * This variant is used for `closing_signed` messages (i.e. where
	 * `option_simple_close` is not negotiated).
	 *
	 * Note that there are two possible variants for each node.
	 *
	 * * version: 2
	 * * locktime: 0
	 * * txin count: 1
	 */
	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, chainparams, 1, 2, 0);

	/* Our input spends the anchor tx output. */
	bitcoin_tx_add_input(tx, funding,
			     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
			     funding_sats, NULL, funding_wscript);

	if (amount_sat_greater_eq(to_us, dust_limit)) {
		script = tal_dup_talarr(tx, u8, our_script);
		/* One output is to us. */
		bitcoin_tx_add_output(tx, script, NULL, to_us);
		assert((local_wallet_index == NULL) == (local_wallet_ext_key == NULL));
		if (local_wallet_index) {
			size_t script_len = tal_bytelen(script);
			/* Should not happen! */
			if (!psbt_add_keypath_to_last_output(
				    tx, *local_wallet_index, local_wallet_ext_key,
				    is_p2tr(script, script_len, NULL)))
				return tal_free(tx);
                }
		num_outputs++;
	}

	if (amount_sat_greater_eq(to_them, dust_limit)) {
		script = tal_dup_talarr(tx, u8, their_script);
		/* Other output is to them. */
		bitcoin_tx_add_output(tx, script, NULL, to_them);
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);

	permute_outputs(tx, NULL, NULL);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

/* BOLT #3:
 *
 * ## Closing Transaction
 *
 * This variant is used for `closing_complete` and `closing_sig` messages
 * (i.e. where `option_simple_close` is negotiated).
 * ...
 * - version: 2
 * - locktime: `locktime` from the `closing_complete` message
 * ...
 * - txin count: 1
 * ...
 *   - txin[0] sequence: 0xFFFFFFFD
 */
struct bitcoin_tx *create_simple_close_tx(const tal_t *ctx,
					  const struct chainparams *chainparams,
					  u32 *local_wallet_index,
					  const struct ext_key *local_wallet_ext_key,
					  const u8 *closer_script,
					  const u8 *closee_script,
					  const u8 *funding_wscript,
					  const struct bitcoin_outpoint *funding,
					  struct amount_sat funding_sats,
					  struct amount_sat closer_amount,
					  struct amount_sat closee_amount,
					  u32 locktime)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0;
	u8 *script;

	/* Sequence 0xFFFFFFFD signals RBF and satisfies the nSequence
	 * requirement for nLockTime. */
	tx = bitcoin_tx(ctx, chainparams, 1, 2, locktime);

	bitcoin_tx_add_input(tx, funding,
			     /* RBF-enabled, not final */
			     0xFFFFFFFD,
			     NULL,
			     funding_sats, NULL, funding_wscript);

	/* BOLT #3:
	 * The closer output:
	 *   - `txout` amount: 0 if the `scriptpubkey` starts with `OP_RETURN`,
	 *     otherwise the final balance for the closer, minus `fee_satoshis`
	 */
	if (closer_script) {
		struct amount_sat amt = closer_amount;
		/* OP_RETURN output must have zero value */
		if (tal_count(closer_script) > 0
		    && closer_script[0] == OP_RETURN)
			amt = AMOUNT_SAT(0);

		script = tal_dup_talarr(tx, u8, closer_script);
		bitcoin_tx_add_output(tx, script, NULL, amt);
		assert((local_wallet_index == NULL) == (local_wallet_ext_key == NULL));
		if (local_wallet_index) {
			size_t script_len = tal_bytelen(script);
			if (!psbt_add_keypath_to_last_output(
				    tx, *local_wallet_index, local_wallet_ext_key,
				    is_p2tr(script, script_len, NULL)))
				return tal_free(tx);
		}
		num_outputs++;
	}

	/* BOLT #3:
	 * The closee output:
	 *   - `txout` amount: 0 if the `scriptpubkey` starts with `OP_RETURN`,
	 *     otherwise the final balance for the closee
	 */
	if (closee_script) {
		struct amount_sat amt = closee_amount;
		if (tal_count(closee_script) > 0
		    && closee_script[0] == OP_RETURN)
			amt = AMOUNT_SAT(0);

		script = tal_dup_talarr(tx, u8, closee_script);
		bitcoin_tx_add_output(tx, script, NULL, amt);
		num_outputs++;
	}

	if (num_outputs == 0)
		return tal_free(tx);

	permute_outputs(tx, NULL, NULL);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}
