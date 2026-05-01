/* Master-side control for the simpleclosed subdaemon (option_simple_close). */
#include "config.h"
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <closingd/simpleclosed_wiregen.h>
#include <common/fee_states.h>
#include <common/shutdown_scriptpubkey.h>
#include <errno.h>
#include <hsmd/permissions.h>
#include <inttypes.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/connect_control.h>
#include <lightningd/feerate.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/peer_fd.h>
#include <lightningd/simple_close_control.h>
#include <lightningd/subd.h>
#include <wally_bip32.h>


/* Master receives simpleclosed_got_sig: store tx and broadcast. */
static void handle_simpleclosed_got_sig(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_tx *tx;
	struct bitcoin_txid txid;

	if (!fromwire_simpleclosed_got_sig(tmpctx, msg, &tx)) {
		channel_internal_error(channel, "bad simpleclosed_got_sig: %s",
				       tal_hex(msg, msg));
		return;
	}
	tx->chainparams = chainparams;

	/* Broadcast it (rebroadcast on restarts as needed). */
	broadcast_tx(channel, ld->topology, channel, tx, NULL, false, 0,
		     NULL, NULL, NULL);

	bitcoin_txid(tx, &txid);
	log_info(channel->log,
		 "Simple close: broadcasting closer tx %s",
		 fmt_bitcoin_txid(tmpctx, &txid));

	subd_send_msg(channel->owner,
		      take(towire_simpleclosed_got_sig_reply(NULL, &txid)));
}

/* Master receives simpleclosed_closee_broadcast: broadcast peer's closing tx
 * that we signed as the closee. */
static void handle_simpleclosed_closee_broadcast(struct channel *channel,
						 const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_tx *tx;
	struct bitcoin_txid txid;

	if (!fromwire_simpleclosed_closee_broadcast(tmpctx, msg, &tx)) {
		channel_internal_error(channel,
				       "bad simpleclosed_closee_broadcast: %s",
				       tal_hex(msg, msg));
		return;
	}
	tx->chainparams = chainparams;

	broadcast_tx(channel, ld->topology, channel, tx, NULL, false, 0,
		     NULL, NULL, NULL);

	bitcoin_txid(tx, &txid);
	log_info(channel->log,
		 "Simple close: broadcasting closee tx %s",
		 fmt_bitcoin_txid(tmpctx, &txid));
}

static void handle_simpleclosed_complete(struct channel *channel, const u8 *msg)
{
	if (!fromwire_simpleclosed_complete(msg)) {
		channel_internal_error(channel,
				       "bad simpleclosed_complete: %s",
				       tal_hex(msg, msg));
		return;
	}

	/* Don't report spurious failure when simpleclosed exits. */
	channel_set_owner(channel, NULL);
	channel_set_billboard(channel, false, NULL);

	/* Retransmission only, ignore. */
	if (channel->state != CLOSINGD_SIGEXCHANGE)
		return;

	channel_set_state(channel,
			  CLOSINGD_SIGEXCHANGE,
			  CLOSINGD_COMPLETE,
			  REASON_UNKNOWN,
			  "Simple close complete");

	/* Watch for the closing tx confirming on-chain and resolve any pending
	 * close command.  We use drop_to_chain_simple_close() rather than
	 * drop_to_chain() to avoid broadcasting the commitment tx: the mutual
	 * close txs have already been submitted by the subdaemon, and
	 * broadcasting the commitment tx would race with them (and potentially
	 * replace them via RBF, causing onchaind to treat the close as
	 * unilateral). */
	drop_to_chain_simple_close(channel->peer->ld, channel);
}

static unsigned int simpleclosed_msg(struct subd *sd, const u8 *msg,
				     const int *fds UNUSED)
{
	enum simpleclosed_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_SIMPLECLOSED_GOT_SIG:
		handle_simpleclosed_got_sig(sd->channel, msg);
		return 0;
	case WIRE_SIMPLECLOSED_CLOSEE_BROADCAST:
		handle_simpleclosed_closee_broadcast(sd->channel, msg);
		return 0;
	case WIRE_SIMPLECLOSED_COMPLETE:
		handle_simpleclosed_complete(sd->channel, msg);
		return 0;

	/* Inbound-only (master→daemon) — should not be received here. */
	case WIRE_SIMPLECLOSED_INIT:
	case WIRE_SIMPLECLOSED_GOT_SIG_REPLY:
		break;
	}

	return 0;
}

void peer_start_simpleclosed(struct channel *channel, struct peer_fd *peer_fd)
{
	u8 *initmsg;
	u32 min_feerate, max_feerate;
	struct amount_msat their_msat;
	int hsmfd;
	struct lightningd *ld = channel->peer->ld;
	u32 *local_wallet_index = NULL;
	struct ext_key *local_wallet_ext_key = NULL;
	u32 index_val;
	struct ext_key ext_key_val;

	if (!channel->shutdown_scriptpubkey[REMOTE]) {
		channel_internal_error(channel,
				       "Can't start simpleclosed: no remote script");
		return;
	}

	hsmfd = hsm_get_client_fd(ld, &channel->peer->id, channel->dbid,
				  HSM_PERM_SIGN_CLOSING_TX
				  | HSM_PERM_COMMITMENT_POINT);
	if (hsmfd < 0) {
		log_broken(channel->log,
			   "Could not get hsm fd for simpleclosed: %s",
			   strerror(errno));
		force_peer_disconnect(ld, channel->peer,
				      "Failed to get hsm fd for simpleclosed");
		return;
	}

	channel_set_owner(channel,
			  new_channel_subd(channel, ld,
					   "lightning_simpleclosed",
					   channel, &channel->peer->id,
					   channel->log, true,
					   simpleclosed_wire_name,
					   simpleclosed_msg,
					   channel_errmsg,
					   channel_set_billboard,
					   take(&peer_fd->fd),
					   take(&hsmfd),
					   NULL));

	if (!channel->owner) {
		log_broken(channel->log,
			   "Could not subdaemon simpleclosed: %s",
			   strerror(errno));
		force_peer_disconnect(ld, channel->peer,
				      "Failed to create simpleclosed");
		return;
	}

	/* Compute their balance. */
	if (!amount_sat_sub_msat(&their_msat,
				 channel->funding_sats, channel->our_msat)) {
		log_broken(channel->log,
			   "our_msat overflow on simple close: %s minus %s",
			   fmt_amount_sat(tmpctx, channel->funding_sats),
			   fmt_amount_msat(tmpctx, channel->our_msat));
		channel_fail_permanent(channel, REASON_LOCAL,
				       "our_msat overflow on simple close");
		return;
	}

	min_feerate = feerate_min(ld, NULL);
	max_feerate = unilateral_feerate(ld->topology, false);
	if (!max_feerate)
		max_feerate = get_feerate(channel->fee_states,
					  channel->opener, LOCAL);

	/* Wallet key for our output. */
	if (wallet_can_spend(ld->wallet,
			     channel->shutdown_scriptpubkey[LOCAL],
			     tal_bytelen(channel->shutdown_scriptpubkey[LOCAL]),
			     &index_val, NULL)) {
		if (bip32_key_from_parent(ld->bip32_base, index_val,
					  BIP32_FLAG_KEY_PUBLIC,
					  &ext_key_val) != WALLY_OK) {
			channel_internal_error(channel,
					       "Could not derive ext public key");
			return;
		}
		local_wallet_index = &index_val;
		local_wallet_ext_key = &ext_key_val;
	}

	initmsg = towire_simpleclosed_init(tmpctx,
					   chainparams,
					   &channel->cid,
					   &channel->funding,
					   channel->funding_sats,
					   &channel->local_funding_pubkey,
					   &channel->channel_info.remote_fundingkey,
					   amount_msat_to_sat_round_down(channel->our_msat),
					   amount_msat_to_sat_round_down(their_msat),
					   channel->our_config.dust_limit,
					   min_feerate,
					   max_feerate,
					   local_wallet_index,
					   local_wallet_ext_key,
					   channel->shutdown_scriptpubkey[LOCAL],
					   channel->shutdown_scriptpubkey[REMOTE],
					   channel->opener);

	subd_send_msg(channel->owner, take(initmsg));
}
