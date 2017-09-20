#include <bitcoin/script.h>
#include <ccan/crypto/shachain/shachain.h>
#include <ccan/mem/mem.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/str/str.h>
#include <common/debug.h>
#include <common/derive_basepoints.h>
#include <common/htlc_tx.h>
#include <common/initial_commit_tx.h>
#include <common/key_derive.h>
#include <common/keyset.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/version.h>
#include <errno.h>
#include <inttypes.h>
#include <lightningd/peer_state.h>
#include <onchaind/gen_onchain_wire.h>
#include <onchaind/onchain_types.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/wire_sync.h>
  #include "gen_onchain_types_names.h"

/* stdin == requests */
#define REQ_FD STDIN_FILENO

/* Required in various places: keys for commitment transaction. */
static const struct keyset *keyset;

/* The feerate to use when we generate transactions. */
static u64 feerate_per_kw;

/* The dust limit to use when we generate transactions. */
static u64 dust_limit_satoshis;

/* The CSV delays for each side. */
static u32 to_self_delay[NUM_SIDES];

/* Where we send money to (our wallet) */
static struct pubkey our_wallet_pubkey;

/* Private keys for spending HTLC outputs via HTLC txs, and directly. */
static struct privkey delayed_payment_privkey, payment_privkey;

/* If we broadcast a tx, or need a delay to resolve the output. */
struct proposed_resolution {
	/* This can be NULL if our proposal is to simply ignore it after depth */
	const struct bitcoin_tx *tx;
	/* Non-zero if this is CSV-delayed. */
	u32 depth_required;
	enum tx_type tx_type;
};

/* How it actually got resolved. */
struct resolution {
	struct sha256_double txid;
	unsigned int depth;
	enum tx_type tx_type;
};

struct tracked_output {
	enum tx_type tx_type;
	struct sha256_double txid;
	u32 tx_blockheight;
	u32 outnum;
	u64 satoshi;
	enum output_type output_type;

	/* If it is an HTLC, these are non-NULL */
	const struct htlc_stub *htlc;
	const u8 *wscript;

	/* If it's an HTLC off our unilateral, this is their sig for htlc_tx */
	const secp256k1_ecdsa_signature *remote_htlc_sig;

	/* Our proposed solution (if any) */
	struct proposed_resolution *proposal;

	/* If it is resolved. */
	struct resolution *resolved;
};

/* We use the same feerate for htlcs and commit transactions; we don't
 * record what it was, so we brute-force it. */
struct {
	u32 min, max;
} feerate_range;

static void init_feerate_range(u64 funding_satoshi,
			       const struct bitcoin_tx *commit_tx)
{
	size_t i, max_untrimmed_htlcs;
	u64 fee = funding_satoshi;

	for (i = 0; i < tal_count(commit_tx->output); i++)
		fee -= commit_tx->output[i].amount;

	/* We don't know how many trimmed HTLCs there are, so they could
	 * be making fee entirely. */
	feerate_range.min = 0;

	/* But we can estimate the maximum fee rate:
	 *
	 * fee = feerate_per_kw * (724 + 172 * num_untrimmed) / 1000;
	 */
	if (tal_count(commit_tx->output) < 2)
		max_untrimmed_htlcs = 0;
	else
		max_untrimmed_htlcs = tal_count(commit_tx->output) - 2;

	feerate_range.max = (fee + 999) * 1000
		/ (724 + 172 * max_untrimmed_htlcs);

	status_trace("Initial feerate %u to %u",
		     feerate_range.min, feerate_range.max);
}

static void narrow_feerate_range(u64 fee, u32 multiplier)
{
	u32 min, max;

	/* fee = feerate_per_kw * multiplier / 1000; */

	max = (fee + 999) * 1000 / multiplier;
	if (fee < 999)
		min = 0;
	else
		min = (fee - 999) * 1000 / multiplier;

	status_trace("Fee %"PRIu64" gives feerate min/max %u/%u",
		     fee, min, max);
	if (max < feerate_range.max)
 		feerate_range.max = max;
	if (min > feerate_range.min)
 		feerate_range.min = min;
	status_trace("Feerate now %u to %u",
		     feerate_range.min, feerate_range.max);
}

/* We vary feerate until signature they offered matches: we're more
 * likely to be near max. */
static bool grind_feerate(struct bitcoin_tx *commit_tx,
			  const secp256k1_ecdsa_signature *remotesig,
			  const u8 *wscript,
			  u64 multiplier)
{
	u64 prev_fee = UINT64_MAX;
	u64 input_amount = *commit_tx->input[0].amount;

	for (s64 i = feerate_range.max; i >= feerate_range.min; i--) {
		u64 fee = feerate_per_kw * multiplier / 1000;

		if (fee > input_amount)
			continue;

		/* Minor optimization: don't check same fee twice */
		if (fee == prev_fee)
			continue;

		prev_fee = fee;
		commit_tx->output[0].amount = input_amount - fee;
		if (!check_tx_sig(commit_tx, 0, NULL, wscript,
				  &keyset->other_payment_key, remotesig))
			continue;

		narrow_feerate_range(fee, multiplier);
		return true;
	}
	return false;
}

static const char *tx_type_name(enum tx_type tx_type)
{
	size_t i;

	for (i = 0; enum_tx_type_names[i].name; i++)
		if (enum_tx_type_names[i].v == tx_type)
			return enum_tx_type_names[i].name;
	return "unknown";
}

static const char *output_type_name(enum output_type output_type)
{
	size_t i;

	for (i = 0; enum_output_type_names[i].name; i++)
		if (enum_output_type_names[i].v == output_type)
			return enum_output_type_names[i].name;
	return "unknown";
}

/*
 * This covers:
 * 1. to-us output spend (`<local_delayedsig> 0`)
 * 2. the their-commitment, our HTLC timeout case (`<remotesig> 0`),
 * 3. the their-commitment, our HTLC redeem case (`<remotesig> <payment_preimage>`)
 */
static struct bitcoin_tx *tx_to_us(const tal_t *ctx,
				   struct tracked_output *out,
				   u32 to_self_delay,
				   u32 locktime,
				   const void *elem, size_t elemsize,
				   const u8 *wscript,
				   const struct privkey *privkey,
				   const struct pubkey *pubkey)
{
	struct bitcoin_tx *tx;
	u64 fee;
	secp256k1_ecdsa_signature sig;

	tx = bitcoin_tx(ctx, 1, 1);
	tx->lock_time = locktime;
	tx->input[0].sequence_number = to_self_delay;
	tx->input[0].txid = out->txid;
	tx->input[0].index = out->outnum;
	tx->input[0].amount = tal_dup(tx->input, u64, &out->satoshi);

	tx->output[0].amount = out->satoshi;
	tx->output[0].script = scriptpubkey_p2wpkh(tx->output,
						   &our_wallet_pubkey);

	/* Worst-case sig is 73 bytes */
	fee = feerate_per_kw * (measure_tx_cost(tx)
			 + 1 + 3 + 73 + 0 + tal_len(wscript))
		/ 1000;

	/* Result is trivial?  Just eliminate output. */
	if (tx->output[0].amount < dust_limit_satoshis + fee)
		tal_resize(&tx->output, 0);
	else
		tx->output[0].amount -= fee;

	sign_tx_input(tx, 0, NULL, wscript, privkey, pubkey, &sig);
	tx->input[0].witness = bitcoin_witness_sig_and_element(tx->input,
							       &sig,
							       elem, elemsize,
							       wscript);
	return tx;
}

static struct tracked_output *
	new_tracked_output(struct tracked_output ***outs,
			   const struct sha256_double *txid,
			   u32 tx_blockheight,
			   enum tx_type tx_type,
			   u32 outnum,
			   u64 satoshi,
			   enum output_type output_type,
			   const struct htlc_stub *htlc,
			   const u8 *wscript,
			   const secp256k1_ecdsa_signature *remote_htlc_sig)
{
	size_t n = tal_count(*outs);
	struct tracked_output *out = tal(*outs, struct tracked_output);

	status_trace("Tracking output %u of %s: %s/%s",
		     outnum,
		     type_to_string(trc, struct sha256_double, txid),
		     tx_type_name(tx_type),
		     output_type_name(output_type));

	out->tx_type = tx_type;
	out->txid = *txid;
	out->tx_blockheight = tx_blockheight;
	out->outnum = outnum;
	out->satoshi = satoshi;
	out->output_type = output_type;
	out->proposal = NULL;
	out->resolved = NULL;
	out->htlc = htlc;
	out->wscript = wscript;
	out->remote_htlc_sig = remote_htlc_sig;

	tal_resize(outs, n+1);
	(*outs)[n] = out;

	return out;
}

static void ignore_output(struct tracked_output *out)
{
	status_trace("Ignoring output %u of %s: %s/%s",
		     out->outnum,
		     type_to_string(trc, struct sha256_double, &out->txid),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = out->txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = SELF;
}

static void propose_resolution(struct tracked_output *out,
			       const struct bitcoin_tx *tx,
			       unsigned int depth_required,
			       enum tx_type tx_type)
{
	status_trace("Propose handling %s/%s by %s (%s) in %u blocks",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(tx_type),
		     tx ? type_to_string(trc, struct bitcoin_tx, tx):"IGNORING",
		     depth_required);

	out->proposal = tal(out, struct proposed_resolution);
	out->proposal->tx = tal_steal(out->proposal, tx);
	out->proposal->depth_required = depth_required;
	out->proposal->tx_type = tx_type;
}

static void propose_resolution_at_block(struct tracked_output *out,
					const struct bitcoin_tx *tx,
					unsigned int block_required,
					enum tx_type tx_type)
{
	u32 depth;

	/* Expiry could be in the past! */
	if (block_required < out->tx_blockheight)
		depth = 0;
	else
		depth = block_required - out->tx_blockheight;
	propose_resolution(out, tx, depth, tx_type);
}

/* This simple case: true if this was resolved by our proposal. */
static bool resolved_by_proposal(struct tracked_output *out,
				 const struct sha256_double *txid)
{
	/* If there's no TX associated, it's not us. */
	if (!out->proposal->tx)
		return false;

	out->resolved = tal(out, struct resolution);
	bitcoin_txid(out->proposal->tx, &out->resolved->txid);

	/* Not the same as what we proposed? */
	if (!structeq(&out->resolved->txid, txid)) {
		out->resolved = tal_free(out->resolved);
		return false;
	}

	status_trace("Resolved %s/%s by our proposal %s (%s)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(out->proposal->tx_type),
		     type_to_string(trc, struct bitcoin_tx, out->proposal->tx));

	out->resolved->depth = 0;
	out->resolved->tx_type = out->proposal->tx_type;
	return true;
}

/* Otherwise, we figure out what happened and then call this. */
static void resolved_by_other(struct tracked_output *out,
			      const struct sha256_double *txid,
			      enum tx_type tx_type)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = *txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = tx_type;

	status_trace("Resolved %s/%s by %s (%s)",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     tx_type_name(tx_type),
		     type_to_string(trc, struct sha256_double, txid));
}

static void unknown_spend(struct tracked_output *out,
			  const struct bitcoin_tx *tx)
{
	out->resolved = tal(out, struct resolution);
	bitcoin_txid(tx, &out->resolved->txid);
	out->resolved->depth = 0;
	out->resolved->tx_type = UNKNOWN_TXTYPE;

	/* FIXME: we need a louder warning! */
	status_trace("Unknown spend of %s/%s by %s",
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(trc, struct bitcoin_tx, tx));
}

static u64 unmask_commit_number(const struct bitcoin_tx *tx,
				enum side funder,
				const struct pubkey *local_payment_basepoint,
				const struct pubkey *remote_payment_basepoint)
{
	u64 obscurer;
	const struct pubkey *keys[NUM_SIDES];
	keys[LOCAL] = local_payment_basepoint;
	keys[REMOTE] = remote_payment_basepoint;

	/* BOLT #3:
	 *
	 * The 48-bit commitment transaction number is obscured by
	 * `XOR` with the lower 48 bits of...
	 */
	obscurer = commit_number_obscurer(keys[funder], keys[!funder]);

	/* BOLT #3:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the
	 *             lower 24 bits of the obscured commitment transaction
	 *             number.
	 *...
	 * * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits
	 *                are upper 24 bits of the obscured commitment
	 *                transaction number.
	 */
	return ((tx->lock_time & 0x00FFFFFF)
		| (tx->input[0].sequence_number & (u64)0x00FFFFFF) << 24)
		^ obscurer;
}

static bool is_mutual_close(const struct bitcoin_tx *tx,
			    const u8 *local_scriptpubkey,
			    const u8 *remote_scriptpubkey)
{
	size_t i;
	bool local_matched = false, remote_matched = false;

	for (i = 0; i < tal_count(tx->output); i++) {
		/* To be paranoid, we only let each one match once. */
		if (scripteq(tx->output[i].script, local_scriptpubkey)
		    && !local_matched)
			local_matched = true;
		else if (scripteq(tx->output[i].script, remote_scriptpubkey)
			 && !remote_matched)
			remote_matched = true;
		else
			return false;
	}

	return true;
}

/* We only ever send out one, so matching it is easy. */
static bool is_local_commitment(const struct sha256_double *txid,
				const struct sha256_double *our_broadcast_txid)
{
	return structeq(txid, our_broadcast_txid);
}

/* BOLT #5:
 *
 * Outputs which are *resolved* are considered *irrevocably resolved*
 * once their *resolving* transaction is included in a block at least 100
 * deep on the most-work blockchain.
 */
static bool all_irrevocably_resolved(struct tracked_output **outs)
{
	size_t i;

	for (i = 0; i < tal_count(outs); i++) {
		if (outs[i]->resolved && outs[i]->resolved->depth < 100)
			return false;
	}
	return true;
}

static void proposal_meets_depth(struct tracked_output *out)
{
	/* If we simply wanted to ignore it after some depth */
	if (!out->proposal->tx) {
		ignore_output(out);
		return;
	}

	status_trace("Broadcasting %s (%s) to resolve %s/%s",
		     tx_type_name(out->proposal->tx_type),
		     type_to_string(trc, struct bitcoin_tx, out->proposal->tx),
		     tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	wire_sync_write(REQ_FD,
			take(towire_onchain_broadcast_tx(NULL,
							 out->proposal->tx)));
	/* We will get a callback when it's in a block. */
}

static void unwatch_tx(const struct bitcoin_tx *tx)
{
	u8 *msg;
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);

	msg = towire_onchain_unwatch_tx(tx, &txid, tal_count(tx->output));
	wire_sync_write(REQ_FD, take(msg));
}

static void handle_htlc_onchain_fulfill(struct tracked_output *out,
				      const struct bitcoin_tx *tx)
{
	status_failed(STATUS_FAIL_INTERNAL_ERROR, "FIXME: %s", __func__);
}

/* An output has been spent: see if it resolves something we care about. */
static void output_spent(struct tracked_output **outs,
			 const struct bitcoin_tx *tx,
			 u32 input_num,
			 u32 tx_blockheight)
{
	struct sha256_double txid;

	bitcoin_txid(tx, &txid);

	for (size_t i = 0; i < tal_count(outs); i++) {
		if (outs[i]->resolved)
			continue;

		if (tx->input[input_num].index != outs[i]->outnum)
			continue;
		if (!structeq(&tx->input[input_num].txid, &outs[i]->txid))
			continue;

		/* Was this our resolution? */
		if (resolved_by_proposal(outs[i], &txid))
			return;

		switch (outs[i]->output_type) {
		case OUTPUT_TO_US:
		case DELAYED_OUTPUT_TO_US:
			unknown_spend(outs[i], tx);
			break;

		case THEIR_HTLC:
			/* We ignore this timeout tx, since we should
			 * resolve by ignoring once we reach depth. */
			break;

		case OUR_HTLC:
			/* The only way	they can spend this: fulfill */
			handle_htlc_onchain_fulfill(outs[i], tx);
			break;

		case FUNDING_OUTPUT:
			/* Master should be restarting us, as this implies
			 * that our old tx was unspent. */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Funding output spent again!");

		/* Um, we don't track these! */
		case OUTPUT_TO_THEM:
		case DELAYED_OUTPUT_TO_THEM:
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tracked spend of %s/%s?",
				      tx_type_name(outs[i]->tx_type),
				      output_type_name(outs[i]->output_type));
		}
		return;
	}

	/* Not interesting to us, so unwatch the tx and all its outputs */
	status_trace("Notified about tx %s output %u spend, but we don't care",
		     type_to_string(trc, struct sha256_double,
				    &tx->input[input_num].txid),
		     tx->input[input_num].index);
	unwatch_tx(tx);
}

static void tx_new_depth(struct tracked_output **outs,
			 const struct sha256_double *txid, u32 depth)
{
	size_t i;

	for (i = 0; i < tal_count(outs); i++) {
		/* Is this tx resolving an output? */
		if (outs[i]->resolved) {
			if (structeq(&outs[i]->resolved->txid, txid)) {
				status_trace("%s depth %u",
					     tx_type_name(outs[i]->resolved->tx_type),
					     depth);
				outs[i]->resolved->depth = depth;
			}
			continue;
		}

		/* Otherwise, is this something we have a pending
		 * resolution for? */
		if (outs[i]->proposal
		    && structeq(&outs[i]->txid, txid)
		    && depth >= outs[i]->proposal->depth_required) {
			proposal_meets_depth(outs[i]);
		}
	}
}

/* BOLT #5:
 *
 * If the node receives (or already knows) a payment preimage for an
 * unresolved HTLC output it was offered, it MUST *resolve* the output by
 * spending it.
 */
static void handle_preimage(struct tracked_output **outs,
			    const struct preimage *preimage)
{
	size_t i;
	struct sha256 sha;
	struct ripemd160 ripemd;

	sha256(&sha, preimage, sizeof(*preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	for (i = 0; i < tal_count(outs); i++) {
		struct bitcoin_tx *tx;
		secp256k1_ecdsa_signature sig;

		if (outs[i]->output_type != THEIR_HTLC)
			continue;

		if (!structeq(&outs[i]->htlc->ripemd, &ripemd))
			continue;

		/* Too late? */
		if (outs[i]->resolved) {
			/* FIXME: We need a better warning method! */
			status_trace("WARNING: HTLC already resolved by %s"
				     " when we found preimage",
				     tx_type_name(outs[i]->resolved->tx_type));
			return;
		}

		/* Discard any previous resolution.  Could be a timeout,
		 * could be due to multiple identical rhashes in tx. */
		outs[i]->proposal = tal_free(outs[i]->proposal);

		/* BOLT #5:
		 *
		 * If the transaction is the nodes' own commitment
		 * transaction, then the it MUST use the HTLC-success
		 * transaction, and the HTLC-success transaction output MUST
		 * be *resolved* as described in "On-chain HTLC Transaction
		 * Handling".
		 */
		if (outs[i]->remote_htlc_sig) {
			tx = htlc_success_tx(outs[i], &outs[i]->txid,
					     outs[i]->outnum,
					     outs[i]->satoshi * 1000,
					     to_self_delay[LOCAL],
					     feerate_per_kw,
					     keyset);
			sign_tx_input(tx, 0, NULL, outs[i]->wscript,
				      &payment_privkey,
				      &keyset->self_payment_key,
				      &sig);
			tx->input[0].witness
				= bitcoin_witness_htlc_success_tx(tx->input,
								  &sig,
								  outs[i]->remote_htlc_sig,
								  preimage,
								  outs[i]->wscript);
			propose_resolution(outs[i], tx, 0, OUR_HTLC_SUCCESS_TX);
		} else {
			/* BOLT #5:
			 *
			 * Otherwise, it MUST *resolve* the output by spending
			 * it to a convenient address.
			 */
			tx = tx_to_us(outs[i], outs[i], 0, 0,
				      preimage, sizeof(*preimage),
				      outs[i]->wscript,
				      &payment_privkey,
				      &keyset->other_payment_key);
			propose_resolution(outs[i], tx, 0,
					   THEIR_HTLC_FULFILL_TO_US);
		}

		/* Broadcast immediately. */
		proposal_meets_depth(outs[i]);
		break;
	}
}

/* BOLT #5:
 *
 * Once a node has broadcast a funding transaction or sent a commitment
 * signature for a commitment transaction which contains an HTLC output,
 * it MUST monitor the blockchain for transactions which spend any output
 * which is not *irrevocably resolved* until all outputs are *irrevocably
 * resolved*.
 */
static void wait_for_resolved(struct tracked_output **outs)
{
	while (!all_irrevocably_resolved(outs)) {
		u8 *msg = wire_sync_read(outs, REQ_FD);
		struct sha256_double txid;
		struct bitcoin_tx *tx = tal(msg, struct bitcoin_tx);
		u32 input_num, depth, tx_blockheight;
		struct preimage preimage;

		status_trace("Got new message %s",
			     onchain_wire_type_name(fromwire_peektype(msg)));

		if (fromwire_onchain_depth(msg, NULL, &txid, &depth))
			tx_new_depth(outs, &txid, depth);
		else if (fromwire_onchain_spent(msg, NULL, tx, &input_num,
						&tx_blockheight))
			output_spent(outs, tx, input_num, tx_blockheight);
		else if (fromwire_onchain_known_preimage(msg, NULL, &preimage))
			handle_preimage(outs, &preimage);
		else
			master_badmsg(-1, msg);
		tal_free(msg);
	}
}

static void set_state(enum peer_state state)
{
	wire_sync_write(REQ_FD, take(towire_onchain_init_reply(NULL, state)));
}

static void handle_mutual_close(const struct bitcoin_tx *tx,
				const struct sha256_double *txid,
				struct tracked_output **outs)
{
	set_state(ONCHAIND_MUTUAL);

	/* BOLT #5:
	 *
	 * A mutual close transaction *resolves* the funding transaction output.
	 *
	 * A node doesn't need to do anything else as it has already agreed to
	 * the output, which is sent to its specified `scriptpubkey`
	 */
	resolved_by_other(outs[0], txid, MUTUAL_CLOSE);

	wait_for_resolved(outs);
}

static u8 **derive_htlc_scripts(const struct htlc_stub *htlcs, enum side side)
{
	size_t i;
	u8 **htlc_scripts = tal_arr(htlcs, u8 *, tal_count(htlcs));

	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlcs[i].owner == side)
			htlc_scripts[i] = htlc_offered_wscript(htlc_scripts,
							       &htlcs[i].ripemd,
							       keyset);
		else {
			/* FIXME: remove abs_locktime */
			struct abs_locktime ltime;
			if (!blocks_to_abs_locktime(htlcs[i].cltv_expiry,
						    &ltime))
				status_failed(STATUS_FAIL_INTERNAL_ERROR,
					      "Could not convert cltv_expiry %u to locktime",
					      htlcs[i].cltv_expiry);
			htlc_scripts[i] = htlc_received_wscript(htlc_scripts,
								&htlcs[i].ripemd,
								&ltime,
								keyset);
		}
	}
	return htlc_scripts;
}

static void resolve_our_htlc_ourcommit(struct tracked_output *out)
{
	struct bitcoin_tx *tx;
	secp256k1_ecdsa_signature localsig;

	/* BOLT #5:
	 *
	 * # On-chain HTLC Output Handling: Our Offers
	 * ...
	 *
	 * If the HTLC output has *timed out* and not been *resolved*, the
	 * node MUST *resolve* the output.  If the transaction is the node's
	 * own commitment transaction, it MUST *resolve* the output by
	 * spending it using the HTLC-timeout transaction, and the
	 * HTLC-timeout transaction output MUST be *resolved* as described in
	 * "On-chain HTLC Transaction Handling".
	 */
	tx = htlc_timeout_tx(out, &out->txid, out->outnum, out->satoshi * 1000,
			     out->htlc->cltv_expiry,
			     to_self_delay[LOCAL], 0, keyset);

	/* BOLT #3:
	 *
	 * The fee for an HTLC-timeout transaction MUST BE calculated to
	 * match:
	 *
	 * 1. Multiply `feerate_per_kw` by 663 and divide by 1000 (rounding
	 *    down).
	 */
	if (!grind_feerate(tx, out->remote_htlc_sig, out->wscript, 663))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not find feerate for signature on"
			      " HTLC timeout between %u and %u",
			      feerate_range.min, feerate_range.max);

	sign_tx_input(tx, 0, NULL, out->wscript, &payment_privkey,
		      &keyset->self_payment_key, &localsig);

	tx->input[0].witness
		= bitcoin_witness_htlc_timeout_tx(tx->input,
						  &localsig,
						  out->remote_htlc_sig,
						  out->wscript);

	propose_resolution_at_block(out, tx, out->htlc->cltv_expiry,
				    OUR_HTLC_TIMEOUT_TO_US);
}

static void resolve_our_htlc_theircommit(struct tracked_output *out)
{
	struct bitcoin_tx *tx;

	/* BOLT #5:
	 *
	 * # On-chain HTLC Output Handling: Our Offers
	 * ...
	 *
	 * If the HTLC output has *timed out* and not been *resolved*, the
	 * node MUST *resolve* the output.  If the transaction is the node's
	 * own commitment transaction, .... Otherwise it MUST resolve the
	 * output by spending it to a convenient address.
	 */
	tx = tx_to_us(out, out, 0, out->htlc->cltv_expiry, NULL, 0,
		      out->wscript,
		      &payment_privkey,
		      &keyset->other_payment_key);

	propose_resolution_at_block(out, tx, out->htlc->cltv_expiry,
				    OUR_HTLC_TIMEOUT_TO_US);
}

static void resolve_their_htlc(struct tracked_output *out)
{
	/* BOLT #5:
	 *
	 * # On-chain HTLC Output Handling: Their Offers
	 *
	 *...
	 * ## Requirements
	 *
	 *
	 * If the node receives (or already knows) a payment preimage for an
	 * unresolved HTLC output it was offered, it MUST *resolve* the output
	 * by spending it.  If the transaction is the nodes' own commitment
	 * transaction, then the it MUST use the HTLC-success transaction, and
	 * the HTLC-success transaction output MUST be *resolved* as described
	 * in "On-chain HTLC Transaction Handling".  Otherwise, it MUST
	 * *resolve* the output by spending it to a convenient address.
	 *
	 * Otherwise, if the HTLC output has expired, it is considered
	 * *irrevocably resolved*.
	 */
	/* If we hit timeout depth, resolve by ignoring. */
	propose_resolution_at_block(out, NULL, out->htlc->cltv_expiry,
				    THEIR_HTLC_TIMEOUT_TO_THEM);
}

static int match_htlc_output(const struct bitcoin_tx *tx,
			     unsigned int outnum,
			     u8 **htlc_scripts)
{
	/* Must be a p2wsh output */
	if (!is_p2wsh(tx->output[outnum].script))
		return -1;

	for (size_t i = 0; i < tal_count(htlc_scripts); i++) {
		struct sha256 sha;
		if (!htlc_scripts[i])
			continue;

		sha256(&sha, htlc_scripts[i], tal_len(htlc_scripts[i]));
		if (memeq(tx->output[outnum].script + 2,
			  tal_len(tx->output[outnum].script) - 2,
			  &sha, sizeof(sha)))
			return i;
	}
	return -1;
}

static void handle_our_unilateral(const struct bitcoin_tx *tx,
				  u32 tx_blockheight,
				  const struct sha256_double *txid,
				  const struct secrets *secrets,
				  const struct sha256 *shaseed,
				  const struct pubkey *remote_revocation_basepoint,
				  const struct pubkey *remote_payment_basepoint,
				  const struct pubkey *local_payment_basepoint,
				  const struct pubkey *local_delayed_payment_basepoint,
				  u64 commit_num,
				  const struct htlc_stub *htlcs,
				  const secp256k1_ecdsa_signature *remote_htlc_sigs,
				  struct tracked_output **outs)
{
	const tal_t *tmpctx = tal_tmpctx(NULL);
	u8 **htlc_scripts;
	u8 *local_wscript, *script[NUM_SIDES];
	struct pubkey local_per_commitment_point;
	struct keyset *ks;
	size_t i;

	set_state(ONCHAIND_OUR_UNILATERAL);

	init_feerate_range(outs[0]->satoshi, tx);

	/* BOLT #5:
	 *
	 * There are two cases to consider here: in the first case, node A
	 * sees its own *commitment transaction*, in the second, it sees the
	 * node B's unrevoked *commitment transaction*.
	 *
	 * Either transaction *resolves* the funding transaction output.
	 */
	resolved_by_other(outs[0], txid, OUR_UNILATERAL);

	/* Figure out what delayed to-us output looks like */
	if (!per_commit_point(shaseed, &local_per_commitment_point, commit_num))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving local_per_commit_point for %"PRIu64,
			      commit_num);

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(&local_per_commitment_point,
			   local_payment_basepoint,
			   remote_payment_basepoint,
			   local_delayed_payment_basepoint,
			   remote_revocation_basepoint,
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_trace("Deconstructing unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s",
		     commit_num,
		     type_to_string(trc, struct pubkey,
				    &keyset->self_revocation_key),
		     type_to_string(trc, struct pubkey,
				    &keyset->self_delayed_payment_key),
		     type_to_string(trc, struct pubkey,
				    &keyset->self_payment_key),
		     type_to_string(trc, struct pubkey,
				    &keyset->other_payment_key));

	if (!derive_simple_privkey(&secrets->delayed_payment_basepoint_secret,
				   local_delayed_payment_basepoint,
				   &local_per_commitment_point,
				   &delayed_payment_privkey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving delayed_payment_privkey for %"PRIu64,
			      commit_num);

	if (!derive_simple_privkey(&secrets->payment_basepoint_secret,
				   local_payment_basepoint,
				   &local_per_commitment_point,
				   &payment_privkey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving payment_privkey for %"PRIu64,
			      commit_num);

	local_wscript = to_self_wscript(tmpctx, to_self_delay[LOCAL], keyset);

	/* Figure out what to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wsh(tmpctx, local_wscript);

	/* Figure out what direct to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs, LOCAL);

	status_trace("Script to-me: %u: %s (%s)",
		     to_self_delay[LOCAL],
		     tal_hex(trc, script[LOCAL]),
		     tal_hex(trc, local_wscript));
	status_trace("Script to-them: %s",
		     tal_hex(trc, script[REMOTE]));

	for (i = 0; i < tal_count(tx->output); i++) {
		status_trace("Output %zu: %s",
			     i, tal_hex(trc, tx->output[i].script));
	}

	/* BOLT #5:
	 *
	 * When node A sees its own *commitment transaction*:
	 *
	 * 1. _A's main output_:...
	 * 2. _B's main output_:...
	 * 3. _A's offered HTLCs_:...
	 * 4. _B's offered HTLCs_:...
	 */
	for (i = 0; i < tal_count(tx->output); i++) {
		struct tracked_output *out;
		int j;

		if (script[LOCAL]
		    && scripteq(tx->output[i].script, script[LOCAL])) {
			struct bitcoin_tx *to_us;
			/* BOLT #5:
			 *
			 * 1. _A's main output_: A node SHOULD spend this
			 *    output to a convenient address.
			 */
			out = new_tracked_output(&outs, txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 tx->output[i].amount,
						 DELAYED_OUTPUT_TO_US,
						 NULL, NULL, NULL);
			/* BOLT #3:
			 *
			 * It is spent by a transaction with `nSequence` field
			 * set to `to_self_delay` (which can only be valid
			 * after that duration has passed), and witness:
			 *
			 *	<local_delayedsig> 0
			 */
			to_us = tx_to_us(out, out, to_self_delay[LOCAL], 0,
					 NULL, 0,
					 local_wscript,
					 &delayed_payment_privkey,
					 &keyset->self_delayed_payment_key);

			/* BOLT #5:
			 *
			 * If the output is spent (as recommended), the output
			 * is *resolved* by the spending transaction */
			propose_resolution(out, to_us, to_self_delay[LOCAL],
					   OUR_UNILATERAL_TO_US_RETURN_TO_WALLET);

			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && scripteq(tx->output[i].script, script[REMOTE])) {
			/* BOLT #5:
			 *
			 * 2. _B's main output_: No action required, this
			 *    output is considered *resolved* by the
			 *    *commitment transaction* itself. */
			out = new_tracked_output(&outs, txid, tx_blockheight,
						 OUR_UNILATERAL, i,
						 tx->output[i].amount,
						 OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			script[REMOTE] = NULL;
			continue;
		}

		/* FIXME: limp along when this happens! */
		j = match_htlc_output(tx, i, htlc_scripts);
		if (j == -1)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);

		if (htlcs[j].owner == LOCAL) {
			/* BOLT #5:
			 *
			 * 3. _A's offered HTLCs_: See "On-chain HTLC
			 *    Output Handling: Our Offers" below. */
			out = new_tracked_output(&outs, txid,
						 tx_blockheight,
						 OUR_UNILATERAL, i,
						 tx->output[i].amount,
						 OUR_HTLC,
						 &htlcs[j], htlc_scripts[j],
						 remote_htlc_sigs);
			resolve_our_htlc_ourcommit(out);
		} else {
			out = new_tracked_output(&outs, txid,
						 tx_blockheight,
						 OUR_UNILATERAL, i,
						 tx->output[i].amount,
						 THEIR_HTLC,
						 &htlcs[j],
						 htlc_scripts[j],
						 remote_htlc_sigs);
			/* BOLT #5:
			 *
			 * 4. _B's offered HTLCs_: See "On-chain HTLC
			 *    Output Handling: Their Offers" below. */
			resolve_their_htlc(out);
		}
		/* Each of these consumes one HTLC signature */
		remote_htlc_sigs++;
		/* We've matched this HTLC, can't do again. */
		htlc_scripts[j] = NULL;
	}

	wait_for_resolved(outs);
	tal_free(tmpctx);
}

static void handle_their_cheat(const struct bitcoin_tx *tx,
			       u64 commit_index,
			       const struct sha256 *revocation_preimage,
			       const struct htlc_stub *htlcs,
			       struct tracked_output **outs)
{
	status_failed(STATUS_FAIL_INTERNAL_ERROR,
		      "FIXME: Implement penalty transaction");
}

static void handle_their_unilateral(const struct bitcoin_tx *tx,
				    u32 tx_blockheight,
				    const struct sha256_double *txid,
				    const struct secrets *secrets,
				    const struct sha256 *shaseed,
				    const struct pubkey *remote_per_commitment_point,
				    const struct pubkey *local_revocation_basepoint,
				    const struct pubkey *local_payment_basepoint,
				    const struct pubkey *remote_payment_basepoint,
				    const struct pubkey *remote_delayed_payment_basepoint,
				    u64 commit_num,
				    const struct htlc_stub *htlcs,
				    struct tracked_output **outs)
{
	const tal_t *tmpctx = tal_tmpctx(NULL);
	u8 **htlc_scripts;
	u8 *remote_wscript, *script[NUM_SIDES];
	struct keyset *ks;
	size_t i;

	set_state(ONCHAIND_THEIR_UNILATERAL);

	init_feerate_range(outs[0]->satoshi, tx);

	/* BOLT #5:
	 *
	 * There are two cases to consider here: in the first case, node A
	 * sees its own *commitment transaction*, in the second, it sees the
	 * node B's unrevoked *commitment transaction*.
	 *
	 * Either transaction *resolves* the funding transaction output.
	 */
	resolved_by_other(outs[0], txid, THEIR_UNILATERAL);

	status_trace("Deriving keyset %"PRIu64
		     ": per_commit_point=%s"
		     " self_payment_basepoint=%s"
		     " other_payment_basepoint=%s"
		     " self_delayed_basepoint=%s"
		     " other_revocation_basepoint=%s",
		     commit_num,
		     type_to_string(trc, struct pubkey,
				    remote_per_commitment_point),
		     type_to_string(trc, struct pubkey,
				    remote_payment_basepoint),
		     type_to_string(trc, struct pubkey,
				    local_payment_basepoint),
		     type_to_string(trc, struct pubkey,
				    remote_delayed_payment_basepoint),
		     type_to_string(trc, struct pubkey,
				    local_revocation_basepoint));

	/* keyset is const, we need a non-const ptr to set it up */
	keyset = ks = tal(tx, struct keyset);
	if (!derive_keyset(remote_per_commitment_point,
			   remote_payment_basepoint,
			   local_payment_basepoint,
			   remote_delayed_payment_basepoint,
			   local_revocation_basepoint,
			   ks))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving keyset for %"PRIu64, commit_num);

	status_trace("Deconstructing unilateral tx: %"PRIu64
		     " using keyset: "
		     " self_revocation_key: %s"
		     " self_delayed_payment_key: %s"
		     " self_payment_key: %s"
		     " other_payment_key: %s",
		     commit_num,
		     type_to_string(trc, struct pubkey,
				    &keyset->self_revocation_key),
		     type_to_string(trc, struct pubkey,
				    &keyset->self_delayed_payment_key),
		     type_to_string(trc, struct pubkey,
				    &keyset->self_payment_key),
		     type_to_string(trc, struct pubkey,
				    &keyset->other_payment_key));

	if (!derive_simple_privkey(&secrets->payment_basepoint_secret,
				   local_payment_basepoint,
				   remote_per_commitment_point,
				   &payment_privkey))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Deriving local_delayeprivkey for %"PRIu64,
			      commit_num);

	remote_wscript = to_self_wscript(tmpctx, to_self_delay[REMOTE], keyset);

	/* Figure out what to-them output looks like. */
	script[REMOTE] = scriptpubkey_p2wsh(tmpctx, remote_wscript);

	/* Figure out what direct to-us output looks like. */
	script[LOCAL] = scriptpubkey_p2wpkh(tmpctx, &keyset->other_payment_key);

	/* Calculate all the HTLC scripts so we can match them */
	htlc_scripts = derive_htlc_scripts(htlcs, REMOTE);

	status_trace("Script to-them: %u: %s (%s)",
		     to_self_delay[REMOTE],
		     tal_hex(trc, script[REMOTE]),
		     tal_hex(trc, remote_wscript));
	status_trace("Script to-me: %s",
		     tal_hex(trc, script[LOCAL]));

	for (i = 0; i < tal_count(tx->output); i++) {
		status_trace("Output %zu: %s",
			     i, tal_hex(trc, tx->output[i].script));
	}

	/* BOLT #5:
	 *
	 * Similarly, when node A sees a *commitment transaction* from B:
	 *
	 * 1. _A's main output_:...
	 * 2. _B's main output_:...
	 * 3. _A's offered HTLCs_:...
	 * 4. _B's offered HTLCs_:...
	 */
	for (i = 0; i < tal_count(tx->output); i++) {
		struct tracked_output *out;
		int j;

		if (script[LOCAL]
		    && scripteq(tx->output[i].script, script[LOCAL])) {
			/* BOLT #5:
			 *
			 * 1. _A's main output_: No action is required; this
			 *    is a simple P2WPKH output.  This output is
			 *    considered *resolved* by the *commitment
			 *    transaction* itself.
			 */
			out = new_tracked_output(&outs, txid, tx_blockheight,
						 THEIR_UNILATERAL,
						 i, tx->output[i].amount,
						 OUTPUT_TO_US, NULL, NULL, NULL);
			ignore_output(out);
			script[LOCAL] = NULL;
			continue;
		}
		if (script[REMOTE]
		    && scripteq(tx->output[i].script, script[REMOTE])) {
			/* BOLT #5:
			 *
			 * 2. _B's main output_: No action required, this
			 *    output is considered *resolved* by the
			 *    *commitment transaction* itself. */
			out = new_tracked_output(&outs, txid, tx_blockheight,
						 THEIR_UNILATERAL, i,
						 tx->output[i].amount,
						 DELAYED_OUTPUT_TO_THEM,
						 NULL, NULL, NULL);
			ignore_output(out);
			continue;
		}

		j = match_htlc_output(tx, i, htlc_scripts);
		if (j == -1)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not find resolution for output %zu",
				      i);
		if (htlcs[j].owner == LOCAL) {
			/* BOLT #5:
			 *
			 * 3. _A's offered HTLCs_: See "On-chain HTLC Output
			 *    Handling: Our Offers" below. */
			out = new_tracked_output(&outs, txid,
						 tx_blockheight,
						 THEIR_UNILATERAL, i,
						 tx->output[i].amount,
						 OUR_HTLC,
						 &htlcs[j], htlc_scripts[j],
						 NULL);
			resolve_our_htlc_theircommit(out);
		} else {
			out = new_tracked_output(&outs, txid,
						 tx_blockheight,
						 THEIR_UNILATERAL, i,
						 tx->output[i].amount,
						 THEIR_HTLC,
						 &htlcs[j], htlc_scripts[j],
						 NULL);
			/* BOLT #5:
			 *
			 * 4. _B's offered HTLCs_: See "On-chain HTLC Output
			 *    Handling: Their Offers" below. */
			resolve_their_htlc(out);
		}
		htlc_scripts[j] = NULL;
	}

	wait_for_resolved(outs);
	tal_free(tmpctx);
}

int main(int argc, char *argv[])
{
	const tal_t *ctx = tal_tmpctx(NULL);
	u8 *msg;
	struct privkey seed;
	struct pubkey remote_payment_basepoint,
		remote_per_commit_point, old_remote_per_commit_point,
		remote_revocation_basepoint, remote_delayed_payment_basepoint;
	enum side funder;
	struct basepoints basepoints;
	struct shachain shachain;
	struct bitcoin_tx *tx;
	struct secrets secrets;
	struct sha256 shaseed;
	struct tracked_output **outs;
	struct sha256_double our_broadcast_txid, txid;
	secp256k1_ecdsa_signature *remote_htlc_sigs;
	u64 funding_amount_satoshi, num_htlcs;
	u8 *scriptpubkey[NUM_SIDES];
	struct htlc_stub *htlcs;
	u32 tx_blockheight;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);

	/* We handle write returning errors! */
	signal(SIGCHLD, SIG_IGN);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	status_setup_sync(REQ_FD);

	msg = wire_sync_read(ctx, REQ_FD);
	tx = tal(ctx, struct bitcoin_tx);
	if (!fromwire_onchain_init(ctx, msg, NULL,
				   &seed, &shachain,
				   &funding_amount_satoshi,
				   &old_remote_per_commit_point,
				   &remote_per_commit_point,
				   &to_self_delay[LOCAL],
				   &to_self_delay[REMOTE],
				   &feerate_per_kw,
				   &dust_limit_satoshis,
				   &remote_revocation_basepoint,
				   &our_broadcast_txid,
				   &scriptpubkey[LOCAL],
				   &scriptpubkey[REMOTE],
				   &our_wallet_pubkey,
				   &funder,
				   &remote_payment_basepoint,
				   &remote_delayed_payment_basepoint,
				   tx,
				   &tx_blockheight,
				   &remote_htlc_sigs,
				   &num_htlcs)) {
		master_badmsg(WIRE_ONCHAIN_INIT, msg);
	}
	derive_basepoints(&seed, NULL, &basepoints, &secrets, &shaseed);
	bitcoin_txid(tx, &txid);

	/* FIXME: Filter as we go, don't load them all into mem! */
	htlcs = tal_arr(ctx, struct htlc_stub, num_htlcs);
	if (!htlcs)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Can't allocate %"PRIu64" htlcs", num_htlcs);

	for (u64 i = 0; i < num_htlcs; i++) {
		msg = wire_sync_read(ctx, REQ_FD);
		if (!fromwire_onchain_htlc(msg, NULL, &htlcs[i]))
			master_badmsg(WIRE_ONCHAIN_HTLC, msg);
	}

	outs = tal_arr(ctx, struct tracked_output *, 0);
	new_tracked_output(&outs, &tx->input[0].txid,
			   0, /* We don't care about funding blockheight */
			   FUNDING_TRANSACTION,
			   tx->input[0].index,
			   funding_amount_satoshi,
			   FUNDING_OUTPUT, NULL, NULL, NULL);

	status_trace("Remote per-commit point: %s",
		     type_to_string(trc, struct pubkey,
				    &remote_per_commit_point));
	status_trace("Old remote per-commit point: %s",
		     type_to_string(trc, struct pubkey,
				    &old_remote_per_commit_point));

	/* BOLT #5:
	 *
	 * There are three ways a channel can end:
	 *
	 * 1. The good way (*mutual close*): at some point A and B agree on
	 *    closing the channel, they generate a *closing transaction*
	 *    (which is similar to a *commitment transaction* without any
	 *    pending payments), and publish it on the blockchain (see [BOLT
	 *    #2: Channel Close](02-peer-protocol.md#channel-close)).
	 */
	if (is_mutual_close(tx, scriptpubkey[LOCAL], scriptpubkey[REMOTE]))
		handle_mutual_close(tx, &txid, outs);
	else {
		/* BOLT #5:
		 *
		 * 2. The bad way (*unilateral close*): something goes wrong,
		 *    without necessarily any evil intent on either side
		 *    (maybe one party crashed, for instance). Anyway, one
		 *    side publishes its latest *commitment transaction*.
		 */
		struct sha256 revocation_preimage;
		u64 commit_num = unmask_commit_number(tx, funder,
						      &basepoints.payment,
						      &remote_payment_basepoint);

		status_trace("commitnum = %"PRIu64
			     ", revocations_recived = %"PRIu64,
			     commit_num, revocations_received(&shachain));

		if (is_local_commitment(&txid, &our_broadcast_txid))
			handle_our_unilateral(tx, tx_blockheight, &txid,
					      &secrets,
					      &shaseed,
					      &remote_revocation_basepoint,
					      &remote_payment_basepoint,
					      &basepoints.payment,
					      &basepoints.delayed_payment,
					      commit_num,
					      htlcs,
					      remote_htlc_sigs,
					      outs);
		/* BOLT #5:
		 *
		 * 3. The ugly way (*revoked transaction close*): one of the
		 *    parties deliberately tries to cheat by publishing an
		 *    outdated version of its *commitment transaction*
		 *    (presumably one that was more in her favor).
		 */
		else if (shachain_get_hash(&shachain,
					   shachain_index(commit_num),
					   &revocation_preimage)) {
			handle_their_cheat(tx, commit_num,
					   &revocation_preimage,
					   htlcs, outs);
		/* BOLT #5:
		 *
		 * Note that there can be more than one valid,
		 * unrevoked *commitment transaction* after a
		 * signature has been received via `commitment_signed`
		 * and before the corresponding `revoke_and_ack`.
		 * Either commitment can serve as B's *commitment
		 * transaction*, hence the requirement to handle both.
		 */
		} else if (commit_num == revocations_received(&shachain)) {
			status_trace("Their unilateral tx, old commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&txid, &secrets, &shaseed,
						&old_remote_per_commit_point,
						&basepoints.revocation,
						&basepoints.payment,
						&remote_payment_basepoint,
						&remote_delayed_payment_basepoint,
						commit_num,
						htlcs, outs);
		} else if (commit_num == revocations_received(&shachain) + 1) {
			status_trace("Their unilateral tx, new commit point");
			handle_their_unilateral(tx, tx_blockheight,
						&txid, &secrets, &shaseed,
						&remote_per_commit_point,
						&basepoints.revocation,
						&basepoints.payment,
						&remote_payment_basepoint,
						&remote_delayed_payment_basepoint,
						commit_num,
						htlcs, outs);
		} else
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Unknown commitment index %"PRIu64
				      " for tx %s",
				      commit_num,
				      type_to_string(ctx, struct bitcoin_tx,
						     tx));
	}

	/* We're done! */
	tal_free(ctx);

	return 0;
}
