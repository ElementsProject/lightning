/* Master-side control for the simpleclosed subdaemon (option_simple_close). */
#include "config.h"
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
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
#include <wallet/wallet.h>
#include <wally_bip32.h>


/* Check that tx spends exactly our funding outpoint and every output goes
 * to a known shutdown script.  Returns an error string, or NULL on success. */
static const char *close_tx_check(const tal_t *ctx,
				   const struct channel *channel,
				   const struct bitcoin_tx *tx)
{
	if (tx->wtx->num_inputs != 1)
		return tal_fmt(ctx, "expected 1 input, got %zu",
			tx->wtx->num_inputs);

	if (!wally_tx_input_spends(&tx->wtx->inputs[0], &channel->funding))
		return tal_fmt(ctx, "does not spend funding outpoint %s",
			fmt_bitcoin_outpoint(ctx, &channel->funding));

	for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
		const struct wally_tx_output *out = &tx->wtx->outputs[i];
		/* Elements has an explicit fee output with no script. */
		if (out->script_len == 0) {
			if (chainparams->is_elements)
				continue;
			return tal_fmt(ctx, "output %zu has no script", i);
		}
		const u8 *script = tal_dup_arr(ctx, u8,
					       out->script, out->script_len, 0);
		if (!scripteq(script, channel->shutdown_scriptpubkey[LOCAL])
		    && !scripteq(script, channel->shutdown_scriptpubkey[REMOTE]))
			return tal_fmt(ctx,
				"output %zu goes to unknown script %s",
				i, tal_hex(ctx, script));
	}
	return NULL;
}

/* Master receives simpleclosed_got_sig: validate remote sig, store mutual
 * close tx, and reply with txid.  drop_to_chain handles broadcast. */
static void handle_simpleclosed_got_sig(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_tx *tx;
	struct bitcoin_txid txid;
	struct bitcoin_signature sig;
	const u8 *funding_wscript;

	if (!fromwire_simpleclosed_got_sig(tmpctx, msg, &tx, &sig)) {
		channel_internal_error(channel, "bad simpleclosed_got_sig: %s",
			tal_hex(msg, msg));
		return;
	}
	tx->chainparams = chainparams;

	const char *err = close_tx_check(tmpctx, channel, tx);
	if (err) {
		channel_internal_error(channel,
			"bad simpleclosed_got_sig: %s",
			err);
		return;
	}

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
		&channel->local_funding_pubkey,
		&channel->channel_info.remote_fundingkey);
	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
				&channel->channel_info.remote_fundingkey, &sig)) {
		channel_internal_error(channel,
			"bad simpleclosed_got_sig: invalid sig: %s",
			tal_hex(msg, msg));
		return;
	}

	channel_set_last_tx(channel, tx, &sig);
	wallet_channel_save(ld->wallet, channel);

	bitcoin_txid(tx, &txid);
	log_info(channel->log,
		"Simple close: stored closer tx %s",
		fmt_bitcoin_txid(tmpctx, &txid));

	subd_send_msg(channel->owner,
		take(towire_simpleclosed_got_sig_reply(NULL, &txid)));
}

/* Master receives simpleclosed_closee_broadcast: validate remote sig and
 * store the mutual close tx.  drop_to_chain handles broadcast. */
static void handle_simpleclosed_closee_broadcast(struct channel *channel,
						 const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct bitcoin_tx *tx;
	struct bitcoin_txid txid;
	struct bitcoin_signature sig;
	const u8 *funding_wscript;

	if (!fromwire_simpleclosed_closee_broadcast(tmpctx, msg, &tx, &sig)) {
		channel_internal_error(channel,
			"bad simpleclosed_closee_broadcast: %s",
			tal_hex(msg, msg));
		return;
	}
	tx->chainparams = chainparams;

	const char *err = close_tx_check(tmpctx, channel, tx);
	if (err) {
		channel_internal_error(channel,
			"bad simpleclosed_closee_broadcast: %s",
			err);
		return;
	}

	funding_wscript = bitcoin_redeem_2of2(tmpctx,
		&channel->local_funding_pubkey,
		&channel->channel_info.remote_fundingkey);
	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
			&channel->channel_info.remote_fundingkey, &sig)) {
		channel_internal_error(channel,
			"bad simpleclosed_closee_broadcast: invalid sig: %s",
			tal_hex(msg, msg));
		return;
	}

	channel_set_last_tx(channel, tx, &sig);
	wallet_channel_save(ld->wallet, channel);

	bitcoin_txid(tx, &txid);
	log_info(channel->log,
		"Simple close: stored closee tx %s",
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

	drop_to_chain(channel->peer->ld, channel, true, NULL);
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
	u32 feerate_perkw;
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
		HSM_PERM_SIGN_CLOSING_TX | HSM_PERM_COMMITMENT_POINT);
	if (hsmfd < 0) {
		log_broken(channel->log,
			"Could not get hsm fd for simpleclosed: %s",
			strerror(errno));
		force_peer_disconnect(ld, channel->peer,
			"Failed to get hsm fd for simpleclosed");
		return;
	}

	channel_set_owner(channel,
			  new_channel_subd(channel, ld, "lightning_simpleclosed", channel,
					&channel->peer->id, channel->log, true,
					simpleclosed_wire_name, simpleclosed_msg, channel_errmsg,
					channel_set_billboard, take(&peer_fd->fd), take(&hsmfd),
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

	feerate_perkw = mutual_close_feerate(ld->topology);
	if (!feerate_perkw) {
		feerate_perkw = get_feerate(channel->fee_states,
			channel->opener, LOCAL) / 2;
		if (feerate_perkw < get_feerate_floor(ld->topology))
			feerate_perkw = get_feerate_floor(ld->topology);
	}

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

	initmsg = towire_simpleclosed_init(tmpctx, chainparams, &channel->cid,
		&channel->funding, channel->funding_sats,
		&channel->local_funding_pubkey,
		&channel->channel_info.remote_fundingkey,
		amount_msat_to_sat_round_down(channel->our_msat),
		amount_msat_to_sat_round_down(their_msat),
		channel->our_config.dust_limit, feerate_perkw, local_wallet_index,
		local_wallet_ext_key, channel->shutdown_scriptpubkey[LOCAL],
		channel->shutdown_scriptpubkey[REMOTE], channel->opener);

	subd_send_msg(channel->owner, take(initmsg));
}
