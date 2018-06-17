#include <bitcoin/preimage.h>
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <common/htlc_tx.h>
#include <common/keyset.h>

static struct bitcoin_tx *htlc_tx(const tal_t *ctx,
				  const struct bitcoin_txid *commit_txid,
				  unsigned int commit_output_number,
				  u64 msatoshi,
				  u16 to_self_delay,
				  const struct pubkey *revocation_pubkey,
				  const struct pubkey *local_delayedkey,
				  u64 htlc_fee_satoshi,
				  u32 locktime)
{
	struct bitcoin_tx *tx = bitcoin_tx(ctx, 1, 1);
	u8 *wscript;
	u64 amount;

	/* BOLT #3:
	 *
	 * ## HTLC-Timeout and HTLC-Success Transactions
	 *
	 * These HTLC transactions are almost identical, except the
	 * HTLC-timeout transaction is timelocked.  The HTLC-timeout
	 * transaction is also the transaction that can be spent by a valid
	 * penalty transaction.
	 */

	/* BOLT #3:
	 * * version: 2
	 */
	assert(tx->version == 2);

	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	tx->lock_time = locktime;

	/* BOLT #3:
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` of the commitment transaction and
	 *      `output_index` of the matching HTLC output for the HTLC
	 *      transaction
	 */
	tx->input[0].txid = *commit_txid;
	tx->input[0].index = commit_output_number;

	/* We need amount for signing. */
	amount = msatoshi / 1000;
	tx->input[0].amount = tal_dup(tx, u64, &amount);

	/* BOLT #3:
	 *    * `txin[0]` sequence: `0`
	 */
	tx->input[0].sequence_number = 0;

	/* BOLT #3:
	 * * txout count: 1
	 *    * `txout[0]` amount: the HTLC amount minus fees
	 *       (see [Fee Calculation](#fee-calculation))
	 *    * `txout[0]` script: version-0 P2WSH with witness script as shown
	 *       below
	 */
	tx->output[0].amount = amount - htlc_fee_satoshi;
	wscript = bitcoin_wscript_htlc_tx(tx, to_self_delay,
					  revocation_pubkey, local_delayedkey);
	tx->output[0].script = scriptpubkey_p2wsh(tx, wscript);
	tal_free(wscript);

	return tx;
}

struct bitcoin_tx *htlc_success_tx(const tal_t *ctx,
				   const struct bitcoin_txid *commit_txid,
				   unsigned int commit_output_number,
				   u64 htlc_msatoshi,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset)
{
	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	return htlc_tx(ctx, commit_txid, commit_output_number, htlc_msatoshi,
		       to_self_delay,
		       &keyset->self_revocation_key,
		       &keyset->self_delayed_payment_key,
		       htlc_success_fee(feerate_per_kw), 0);
}

/* Fill in the witness for HTLC-success tx produced above. */
void htlc_success_tx_add_witness(struct bitcoin_tx *htlc_success,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localhtlckey,
				 const struct pubkey *remotehtlckey,
				 const secp256k1_ecdsa_signature *localhtlcsig,
				 const secp256k1_ecdsa_signature *remotehtlcsig,
				 const struct preimage *payment_preimage,
				 const struct pubkey *revocationkey)
{
	struct sha256 hash;
	u8 *wscript;

	sha256(&hash, payment_preimage, sizeof(*payment_preimage));
	wscript = bitcoin_wscript_htlc_receive(htlc_success,
					       htlc_abstimeout,
					       localhtlckey, remotehtlckey,
					       &hash, revocationkey);

	htlc_success->input[0].witness
		= bitcoin_witness_htlc_success_tx(htlc_success->input,
						  localhtlcsig, remotehtlcsig,
						  payment_preimage,
						  wscript);
	tal_free(wscript);
}

struct bitcoin_tx *htlc_timeout_tx(const tal_t *ctx,
				   const struct bitcoin_txid *commit_txid,
				   unsigned int commit_output_number,
				   u64 htlc_msatoshi,
				   u32 cltv_expiry,
				   u16 to_self_delay,
				   u32 feerate_per_kw,
				   const struct keyset *keyset)
{
	/* BOLT #3:
	 * * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
	 */
	return htlc_tx(ctx, commit_txid, commit_output_number, htlc_msatoshi,
		       to_self_delay,
		       &keyset->self_revocation_key,
		       &keyset->self_delayed_payment_key,
		       htlc_timeout_fee(feerate_per_kw),
		       cltv_expiry);
}

/* Fill in the witness for HTLC-timeout tx produced above. */
void htlc_timeout_tx_add_witness(struct bitcoin_tx *htlc_timeout,
				 const struct pubkey *localhtlckey,
				 const struct pubkey *remotehtlckey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 const secp256k1_ecdsa_signature *localhtlcsig,
				 const secp256k1_ecdsa_signature *remotehtlcsig)
{
	u8 *wscript = bitcoin_wscript_htlc_offer(htlc_timeout,
						 localhtlckey, remotehtlckey,
						 payment_hash, revocationkey);

	htlc_timeout->input[0].witness
		= bitcoin_witness_htlc_timeout_tx(htlc_timeout->input,
						  localhtlcsig, remotehtlcsig,
						  wscript);
	tal_free(wscript);
}

u8 *htlc_offered_wscript(const tal_t *ctx,
			 const struct ripemd160 *ripemd,
			 const struct keyset *keyset)
{
	return bitcoin_wscript_htlc_offer_ripemd160(ctx,
						    &keyset->self_htlc_key,
						    &keyset->other_htlc_key,
						    ripemd,
						    &keyset->self_revocation_key);
}

u8 *htlc_received_wscript(const tal_t *ctx,
			  const struct ripemd160 *ripemd,
			  const struct abs_locktime *expiry,
			  const struct keyset *keyset)
{
	return bitcoin_wscript_htlc_receive_ripemd(ctx,
						   expiry,
						   &keyset->self_htlc_key,
						   &keyset->other_htlc_key,
						   ripemd,
						   &keyset->self_revocation_key);
}
