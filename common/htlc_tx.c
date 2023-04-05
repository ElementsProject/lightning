#include "config.h"
#include <bitcoin/preimage.h>
#include <bitcoin/script.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>

/* Low-level tx creator: used when onchaind has done most of the work! */
struct bitcoin_tx *htlc_tx(const tal_t *ctx,
			   const struct chainparams *chainparams,
			   const struct bitcoin_outpoint *commit,
			   const u8 *commit_wscript,
			   struct amount_sat amount,
			   const u8 *htlc_tx_wscript,
			   struct amount_sat htlc_fee,
			   u32 locktime,
			   bool option_anchor_outputs)
{
	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	struct bitcoin_tx *tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);

	/* BOLT #3:
	 *
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *
	 * These HTLC transactions are almost identical, except the
	 * HTLC-timeout transaction is timelocked.  Both
	 * HTLC-timeout/HTLC-success transactions can be spent by a valid
	 * penalty transaction.
	 */

	/* BOLT #3:
	 * * version: 2
	 */
	assert(tx->wtx->version == 2);

	/* BOLT #3:
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` of the commitment transaction and
	 *      `output_index` of the matching HTLC output for the HTLC
	 *      transaction
	 *    * `txin[0]` sequence: `0` (set to `1` for `option_anchors`)
	 */
	bitcoin_tx_add_input(tx, commit,
			     option_anchor_outputs ? 1 : 0,
			     NULL, amount, NULL, commit_wscript);

	/* BOLT #3:
	 * * txout count: 1
	 *    * `txout[0]` amount: the HTLC `amount_msat` divided by 1000
	 *      (rounding down) minus fees in satoshis (see
	 *      [Fee Calculation](#fee-calculation))
	 *    * `txout[0]` script: version-0 P2WSH with witness script as shown
	 *       below
	 */
	if (!amount_sat_sub(&amount, amount, htlc_fee))
		return tal_free(tx);

	bitcoin_tx_add_output(tx, scriptpubkey_p2wsh(tmpctx, htlc_tx_wscript),
			      htlc_tx_wscript, amount);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));

	return tx;
}

struct bitcoin_tx *htlc_success_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_outpoint *commit,
				   const u8 *commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset,
				   bool option_anchor_outputs)
{
	const u8 *htlc_wscript;

	htlc_wscript = bitcoin_wscript_htlc_tx(tmpctx,
					       to_self_delay,
					       &keyset->self_revocation_key,
					       &keyset->self_delayed_payment_key);
	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	return htlc_tx(ctx, chainparams, commit,
		       commit_wscript,
		       amount_msat_to_sat_round_down(htlc_msatoshi),
		       htlc_wscript,
		       htlc_success_fee(feerate_per_kw,
					option_anchor_outputs),
		       0,
		       option_anchor_outputs);
}

/* Fill in the witness for HTLC-success tx produced above. */
void htlc_success_tx_add_witness(struct bitcoin_tx *htlc_success,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localhtlckey,
				 const struct pubkey *remotehtlckey,
				 const struct bitcoin_signature *localhtlcsig,
				 const struct bitcoin_signature *remotehtlcsig,
				 const struct preimage *payment_preimage,
				 const struct pubkey *revocationkey,
				 bool option_anchor_outputs)
{
	struct sha256 hash;
	u8 *wscript, **witness;

	sha256(&hash, payment_preimage, sizeof(*payment_preimage));
	wscript = bitcoin_wscript_htlc_receive(htlc_success,
					       htlc_abstimeout,
					       localhtlckey, remotehtlckey,
					       &hash, revocationkey,
					       option_anchor_outputs);

	witness = bitcoin_witness_htlc_success_tx(htlc_success,
						  localhtlcsig, remotehtlcsig,
						  payment_preimage, wscript);
	bitcoin_tx_input_set_witness(htlc_success, 0, take(witness));
	tal_free(wscript);
}

struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   const struct bitcoin_outpoint *commit,
				   const u8 *commit_wscript,
				   struct amount_msat htlc_msatoshi,
				   u32 cltv_expiry,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset,
				   bool option_anchor_outputs)
{
	const u8 *htlc_wscript;

	htlc_wscript = bitcoin_wscript_htlc_tx(tmpctx,
					       to_self_delay,
					       &keyset->self_revocation_key,
					       &keyset->self_delayed_payment_key);
	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	return htlc_tx(ctx, chainparams, commit,
		       commit_wscript,
		       amount_msat_to_sat_round_down(htlc_msatoshi),
		       htlc_wscript,
		       htlc_timeout_fee(feerate_per_kw,
					option_anchor_outputs),
		       cltv_expiry,
		       option_anchor_outputs);
}

/* Fill in the witness for HTLC-timeout tx produced above. */
void htlc_timeout_tx_add_witness(struct bitcoin_tx *htlc_timeout,
				 const struct pubkey *localhtlckey,
				 const struct pubkey *remotehtlckey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 const struct bitcoin_signature *localhtlcsig,
				 const struct bitcoin_signature *remotehtlcsig,
				 bool option_anchor_outputs)
{
	u8 **witness;
	u8 *wscript = bitcoin_wscript_htlc_offer(htlc_timeout,
						 localhtlckey, remotehtlckey,
						 payment_hash, revocationkey,
						 option_anchor_outputs);

	witness = bitcoin_witness_htlc_timeout_tx(htlc_timeout, localhtlcsig,
						  remotehtlcsig, wscript);
	bitcoin_tx_input_set_witness(htlc_timeout, 0, take(witness));
	tal_free(wscript);
}

u8 *htlc_offered_wscript(const tal_t *ctx,
			 const struct ripemd160 *ripemd,
			 const struct keyset *keyset,
			 bool option_anchor_outputs)
{
	return bitcoin_wscript_htlc_offer_ripemd160(ctx,
						    &keyset->self_htlc_key,
						    &keyset->other_htlc_key,
						    ripemd,
						    &keyset->self_revocation_key,
						    option_anchor_outputs);
}

u8 *htlc_received_wscript(const tal_t *ctx,
			  const struct ripemd160 *ripemd,
			  const struct abs_locktime *expiry,
			  const struct keyset *keyset,
			  bool option_anchor_outputs)
{
	return bitcoin_wscript_htlc_receive_ripemd(ctx,
						   expiry,
						   &keyset->self_htlc_key,
						   &keyset->other_htlc_key,
						   ripemd,
						   &keyset->self_revocation_key,
						   option_anchor_outputs);
}
