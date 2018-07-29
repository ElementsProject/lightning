#include <bitcoin/script.h>
#include <closingd/gen_closing_wire.h>
#include <common/close_tx.h>
#include <common/initial_commit_tx.h>
#include <common/utils.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/options.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

/* Is this better than the last tx we were holding?  This can happen
 * even without closingd misbehaving, if we have multiple,
 * interrupted, rounds of negotiation. */
static bool better_closing_fee(struct lightningd *ld,
			       struct channel *channel,
			       const struct bitcoin_tx *tx)
{
	u64 weight, fee, last_fee, min_fee;
	size_t i;

	/* Calculate actual fee (adds in eliminated outputs) */
	fee = channel->funding_satoshi;
	for (i = 0; i < tal_count(tx->output); i++)
		fee -= tx->output[i].amount;

	last_fee = channel->funding_satoshi;
	for (i = 0; i < tal_count(channel->last_tx->output); i++)
		last_fee -= channel->last_tx->output[i].amount;

	log_debug(channel->log, "Their actual closing tx fee is %"PRIu64
		 " vs previous %"PRIu64, fee, last_fee);

	/* Weight once we add in sigs. */
	weight = measure_tx_weight(tx) + 74 * 2;

	min_fee = get_feerate(ld->topology, FEERATE_SLOW) * weight / 1000;
	if (fee < min_fee) {
		log_debug(channel->log, "... That's below our min %"PRIu64
			 " for weight %"PRIu64" at feerate %u",
			 min_fee, weight,
			 get_feerate(ld->topology, FEERATE_SLOW));
		return false;
	}

	/* Prefer lower fee: in case of a tie, prefer new over old: this
	 * covers the preference for a mutual close over a unilateral one. */
	return fee <= last_fee;
}

static void peer_received_closing_signature(struct channel *channel,
					    const u8 *msg)
{
	secp256k1_ecdsa_signature sig;
	struct bitcoin_tx *tx;
	struct lightningd *ld = channel->peer->ld;

	if (!fromwire_closing_received_signature(msg, msg, &sig, &tx)) {
		channel_internal_error(channel, "Bad closing_received_signature %s",
				       tal_hex(msg, msg));
		return;
	}

	/* FIXME: Make sure signature is correct! */
	if (better_closing_fee(ld, channel, tx)) {
		channel_set_last_tx(channel, tx, &sig);
		/* TODO(cdecker) Selectively save updated fields to DB */
		wallet_channel_save(ld->wallet, channel);
	}

	/* OK, you can continue now. */
	subd_send_msg(channel->owner,
		      take(towire_closing_received_signature_reply(channel)));
}

static void peer_closing_complete(struct channel *channel, const u8 *msg)
{
	if (!fromwire_closing_complete(msg)) {
		channel_internal_error(channel, "Bad closing_complete %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Don't report spurious failure when closingd exits. */
	channel_set_owner(channel, NULL);
	/* Clear any transient negotiation messages */
	channel_set_billboard(channel, false, NULL);

	/* Retransmission only, ignore closing. */
	if (channel->state == CLOSINGD_COMPLETE)
		return;

	/* Channel gets dropped to chain cooperatively. */
	drop_to_chain(channel->peer->ld, channel, true);
	channel_set_state(channel, CLOSINGD_SIGEXCHANGE, CLOSINGD_COMPLETE);
}

static unsigned closing_msg(struct subd *sd, const u8 *msg, const int *fds UNUSED)
{
	enum closing_wire_type t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CLOSING_RECEIVED_SIGNATURE:
		peer_received_closing_signature(sd->channel, msg);
		break;

	case WIRE_CLOSING_COMPLETE:
		peer_closing_complete(sd->channel, msg);
		break;

	/* We send these, not receive them */
	case WIRE_CLOSING_INIT:
	case WIRE_CLOSING_RECEIVED_SIGNATURE_REPLY:
		break;
	}

	return 0;
}

void peer_start_closingd(struct channel *channel,
			 const struct crypto_state *cs,
			 int peer_fd, int gossip_fd,
			 bool reconnected,
			 const u8 *channel_reestablish)
{
	u8 *initmsg;
	u64 minfee, startfee, feelimit;
	u64 num_revocations;
	u64 funding_msatoshi, our_msatoshi, their_msatoshi;
	int hsmfd;
	struct lightningd *ld = channel->peer->ld;

	if (!channel->remote_shutdown_scriptpubkey) {
		channel_internal_error(channel,
				       "Can't start closing: no remote info");
		return;
	}

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id, channel->dbid,
				  HSM_CAP_SIGN_CLOSING_TX);

	channel_set_owner(channel,
			  new_channel_subd(ld,
					   "lightning_closingd",
					   channel, channel->log, true,
					   closing_wire_type_name, closing_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&peer_fd), take(&gossip_fd),
					   take(&hsmfd),
					   NULL));
	if (!channel->owner) {
		log_unusual(channel->log, "Could not subdaemon closing: %s",
			    strerror(errno));
		channel_fail_transient(channel, "Failed to subdaemon closing");
		return;
	}

	/* BOLT #2:
	 *
	 * The sending node:
	 *  - MUST set `fee_satoshis` less than or equal to the base
	 *    fee of the final commitment transaction, as calculated in
	 *    [BOLT #3](03-transactions.md#fee-calculation).
	 */
	feelimit = commit_tx_base_fee(channel->channel_info.feerate_per_kw[LOCAL],
				      0);

	minfee = commit_tx_base_fee(get_feerate(ld->topology, FEERATE_SLOW), 0);
	startfee = commit_tx_base_fee(get_feerate(ld->topology, FEERATE_NORMAL),
				      0);

	if (startfee > feelimit)
		startfee = feelimit;
	if (minfee > feelimit)
		minfee = feelimit;

	num_revocations
		= revocations_received(&channel->their_shachain.chain);

	/* BOLT #3:
	 *
	 * Each node offering a signature:
	 *  - MUST round each output down to whole satoshis.
	 */
	/* Convert unit */
	funding_msatoshi = channel->funding_satoshi * 1000;
	/* What is not ours is theirs */
	our_msatoshi = channel->our_msatoshi;
	their_msatoshi = funding_msatoshi - our_msatoshi;
	initmsg = towire_closing_init(tmpctx,
				      cs,
				      &channel->funding_txid,
				      channel->funding_outnum,
				      channel->funding_satoshi,
				      &channel->local_funding_pubkey,
				      &channel->channel_info.remote_fundingkey,
				      channel->funder,
				      our_msatoshi / 1000, /* Rounds down */
				      their_msatoshi / 1000, /* Rounds down */
				      channel->our_config.dust_limit_satoshis,
				      minfee, feelimit, startfee,
				      p2wpkh_for_keyidx(tmpctx, ld,
							channel->final_key_idx),
				      channel->remote_shutdown_scriptpubkey,
				      reconnected,
				      channel->next_index[LOCAL],
				      channel->next_index[REMOTE],
				      num_revocations,
				      channel_reestablish);

	/* We don't expect a response: it will give us feedback on
	 * signatures sent and received, then closing_complete. */
	subd_send_msg(channel->owner, take(initmsg));

	/* Now tell gossipd that we're closing and that neither direction should
	 * be used. */
	if (channel->scid)
		subd_send_msg(channel->peer->ld->gossip,
			      take(towire_gossip_local_channel_close(
				  tmpctx, channel->scid)));
}
