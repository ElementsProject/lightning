#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/channel_config.h>
#include <common/funding_tx.h>
#include <common/key_derive.h>
#include <common/wire_error.h>
#include <errno.h>
#include <gossipd/gen_gossip_wire.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <lightningd/build_utxos.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/opening_control.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>
#include <openingd/gen_opening_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

/* Channel we're still opening. */
struct uncommitted_channel {
	/* peer->uncommitted_channel == this */
	struct peer *peer;

	/* openingd which is running now */
	struct subd *openingd;

	/* Reserved dbid for if we become a real struct channel */
	u64 dbid;

	/* For logging */
	struct log *log;

	/* Openingd can tell us stuff. */
	const char *transient_billboard;

	/* If we offered channel, this contains information, otherwise NULL */
	struct funding_channel *fc;

	/* Secret seed (FIXME: Move to hsm!) */
	struct privkey seed;

	/* Blockheight at creation, scans for funding confirmations
	 * will start here */
	u64 first_blocknum;

	/* These are *not* filled in by new_uncommitted_channel: */

	/* Minimum funding depth (if funder == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};

struct funding_channel {
	struct command *cmd; /* Which also owns us. */

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Details of how to make funding. */
	const struct utxo **utxomap;
	u64 change;
	u32 change_keyindex;
	u64 funding_satoshi, push_msat;
	u8 channel_flags;

	/* Channel. */
	struct uncommitted_channel *uc;
};

/* Opening failed: hand back to gossipd (sending errpkt if not NULL) */
static void uncommitted_channel_to_gossipd(struct lightningd *ld,
					   struct uncommitted_channel *uc,
					   const struct crypto_state *cs,
					   u64 gossip_index,
					   int peer_fd, int gossip_fd,
					   const u8 *errorpkt,
					   const char *fmt,
					   ...)
{
	va_list ap;
	char *errstr;
	u8 *msg;

	va_start(ap, fmt);
	errstr = tal_vfmt(uc, fmt, ap);
	va_end(ap);

	log_unusual(uc->log, "Opening channel: %s", errstr);
	if (uc->fc)
		command_fail(uc->fc->cmd, "%s", errstr);

	/* Hand back to gossipd, (maybe) with an error packet to send. */
	msg = towire_gossipctl_hand_back_peer(errstr, &uc->peer->id, cs,
					      gossip_index,
					      errorpkt);
	subd_send_msg(ld->gossip, take(msg));
	subd_send_fd(ld->gossip, peer_fd);
	subd_send_fd(ld->gossip, gossip_fd);
}

void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why)
{
	log_info(uc->log, "Killing openingd: %s", why);

	/* Close openingd. */
	subd_release_channel(uc->openingd, uc);

	if (uc->fc)
		command_fail(uc->fc->cmd, "%s", why);
	tal_free(uc);
}

void json_add_uncommitted_channel(struct json_result *response,
				  const struct uncommitted_channel *uc)
{
	if (!uc)
		return;

	json_object_start(response, NULL);
	json_add_string(response, "state", "OPENINGD");
	json_add_string(response, "owner", "lightning_openingd");
	json_add_string(response, "funder",
			uc->fc ? "LOCAL" : "REMOTE");
	if (uc->transient_billboard) {
		json_array_start(response, "status");
		json_add_string(response, NULL, uc->transient_billboard);
		json_array_end(response);
	}
	if (uc->fc) {
		u64 msatoshi_total, our_msatoshi;

		msatoshi_total = uc->fc->funding_satoshi * 1000;
		our_msatoshi = msatoshi_total - uc->fc->push_msat;
		json_add_u64(response, "msatoshi_to_us", our_msatoshi);
		json_add_u64(response, "msatoshi_total", msatoshi_total);
	}
	json_object_end(response);
}

/* Steals fields from uncommitted_channel: returns NULL if can't generate a
 * key for this channel (shouldn't happen!). */
static struct channel *
wallet_commit_channel(struct lightningd *ld,
		      struct uncommitted_channel *uc,
		      struct bitcoin_tx *remote_commit,
		      secp256k1_ecdsa_signature *remote_commit_sig,
		      const struct bitcoin_txid *funding_txid,
		      u16 funding_outnum,
		      u64 funding_satoshi,
		      u64 push_msat,
		      u8 channel_flags,
		      struct channel_info *channel_info,
		      u32 feerate)
{
	struct channel *channel;
	u64 our_msatoshi;
	s64 final_key_idx;

	/* Get a key to use for closing outputs from this tx */
	final_key_idx = wallet_get_newindex(ld);
	if (final_key_idx == -1) {
		log_broken(uc->log, "Can't get final key index");
		return NULL;
	}

	if (uc->fc)
		our_msatoshi = funding_satoshi * 1000 - push_msat;
	else
		our_msatoshi = push_msat;

	/* Feerates begin identical. */
	channel_info->feerate_per_kw[LOCAL]
		= channel_info->feerate_per_kw[REMOTE]
		= feerate;

	/* old_remote_per_commit not valid yet, copy valid one. */
	channel_info->old_remote_per_commit = channel_info->remote_per_commit;

	channel = new_channel(uc->peer, uc->dbid,
			      NULL, /* No shachain yet */
			      CHANNELD_AWAITING_LOCKIN,
			      uc->fc ? LOCAL : REMOTE,
			      uc->log,
			      take(uc->transient_billboard),
			      channel_flags,
			      &uc->our_config,
			      uc->minimum_depth,
			      1, 1, 0,
			      funding_txid,
			      funding_outnum,
			      funding_satoshi,
			      push_msat,
			      false, /* !remote_funding_locked */
			      NULL, /* no scid yet */
			      our_msatoshi,
			      remote_commit,
			      remote_commit_sig,
			      NULL, /* No HTLC sigs yet */
			      channel_info,
			      NULL, /* No remote_shutdown_scriptpubkey yet */
			      final_key_idx, false,
			      NULL, /* No commit sent yet */
			      uc->first_blocknum,
			      feerate, feerate);

	/* Now we finally put it in the database. */
	wallet_channel_insert(ld->wallet, channel);

	return channel;
}

static void funding_broadcast_failed(struct channel *channel,
				     int exitstatus, const char *err)
{
	channel_internal_error(channel,
			       "Funding broadcast exited with %i: %s",
			       exitstatus, err);
}

static void opening_funder_finished(struct subd *openingd, const u8 *resp,
				    const int *fds,
				    struct funding_channel *fc)
{
	u8 *msg, *linear;
	struct channel_info channel_info;
	struct bitcoin_tx *fundingtx;
	struct bitcoin_txid funding_txid, expected_txid;
	struct pubkey changekey;
	struct pubkey local_fundingkey;
	struct crypto_state cs;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u16 funding_outnum;
	u64 gossip_index;
	u32 feerate;
	u64 change_satoshi;
	struct channel *channel;
	struct json_result *response;
	struct lightningd *ld = openingd->ld;
	struct channel_id cid;

	assert(tal_count(fds) == 2);

	/* This is a new channel_info.their_config so set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_opening_funder_reply(resp, resp,
					   &channel_info.their_config,
					   &remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &gossip_index,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &fc->uc->minimum_depth,
					   &channel_info.remote_fundingkey,
					   &expected_txid,
					   &feerate)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		command_fail(fc->cmd, "bad OPENING_FUNDER_REPLY %s",
			     tal_hex(fc->cmd, resp));
		goto failed;
	}
	log_debug(ld->log,
		  "%s", type_to_string(tmpctx, struct pubkey,
				       &channel_info.remote_per_commit));

	/* Generate the funding tx. */
	if (fc->change
	    && !bip32_pubkey(ld->wallet->bip32_base,
			     &changekey, fc->change_keyindex))
		fatal("Error deriving change key %u", fc->change_keyindex);

	derive_basepoints(&fc->uc->seed, &local_fundingkey, NULL, NULL, NULL);

	fundingtx = funding_tx(tmpctx, &funding_outnum,
			       fc->utxomap, fc->funding_satoshi,
			       &local_fundingkey,
			       &channel_info.remote_fundingkey,
			       fc->change, &changekey,
			       ld->wallet->bip32_base);

	log_debug(fc->uc->log, "Funding tx has %zi inputs, %zu outputs:",
		  tal_count(fundingtx->input),
		  tal_count(fundingtx->output));

	for (size_t i = 0; i < tal_count(fundingtx->input); i++) {
		log_debug(fc->uc->log, "%zi: %"PRIu64" satoshi (%s) %s\n",
			  i, fc->utxomap[i]->amount,
			  fc->utxomap[i]->is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(tmpctx, struct bitcoin_txid,
					 &fundingtx->input[i].txid));
	}

	bitcoin_txid(fundingtx, &funding_txid);

	if (!structeq(&funding_txid, &expected_txid)) {
		log_broken(fc->uc->log,
			   "Funding txid mismatch:"
			   " satoshi %"PRIu64" change %"PRIu64
			   " changeidx %u"
			   " localkey %s remotekey %s",
			   fc->funding_satoshi,
			   fc->change, fc->change_keyindex,
			   type_to_string(fc, struct pubkey,
					  &local_fundingkey),
			   type_to_string(fc, struct pubkey,
					  &channel_info.remote_fundingkey));
		command_fail(fc->cmd,
			     "Funding txid mismatch:"
			     " satoshi %"PRIu64" change %"PRIu64
			     " changeidx %u"
			     " localkey %s remotekey %s",
			     fc->funding_satoshi,
			     fc->change, fc->change_keyindex,
			     type_to_string(fc, struct pubkey,
					    &local_fundingkey),
			     type_to_string(fc, struct pubkey,
					    &channel_info.remote_fundingkey));
		goto failed;
	}

	/* Steals fields from uc */
	channel = wallet_commit_channel(ld, fc->uc,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					fc->funding_satoshi,
					fc->push_msat,
					fc->channel_flags,
					&channel_info,
					feerate);
	if (!channel) {
		command_fail(fc->cmd, "Key generation failure");
		goto failed;
	}

	/* Get HSM to sign the funding tx. */
	log_debug(channel->log, "Getting HSM to sign funding tx");

	msg = towire_hsm_sign_funding(tmpctx, channel->funding_satoshi,
				      fc->change, fc->change_keyindex,
				      &local_fundingkey,
				      &channel_info.remote_fundingkey,
				      fc->utxomap);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = hsm_sync_read(fc, ld);
	if (!fromwire_hsm_sign_funding_reply(tmpctx, msg, &fundingtx))
		fatal("HSM gave bad sign_funding_reply %s",
		      tal_hex(msg, resp));

	/* Extract the change output and add it to the DB */
	wallet_extract_owned_outputs(ld->wallet, fundingtx, NULL, &change_satoshi);

	/* Make sure we recognize our change output by its scriptpubkey in
	 * future. This assumes that we have only two outputs, may not be true
	 * if we add support for multifundchannel */
	if (tal_count(fundingtx->output) == 2)
		txfilter_add_scriptpubkey(ld->owned_txfilter, fundingtx->output[!funding_outnum].script);

	/* Send it out and watch for confirms. */
	broadcast_tx(ld->topology, channel, fundingtx, funding_broadcast_failed);

	channel_watch_funding(ld, channel);

	/* Start normal channel daemon. */
	peer_start_channeld(channel, &cs, gossip_index,
			    fds[0], fds[1], NULL, false);

	wallet_confirm_utxos(ld->wallet, fc->utxomap);

	response = new_json_result(fc->cmd);
	json_object_start(response, NULL);
	linear = linearize_tx(response, fundingtx);
	json_add_hex(response, "tx", linear, tal_len(linear));
	json_add_txid(response, "txid", &channel->funding_txid);
	derive_channel_id(&cid, &channel->funding_txid, funding_outnum);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
	json_object_end(response);
	command_success(fc->cmd, response);

	subd_release_channel(openingd, fc->uc);
	/* Frees fc too, and tmpctx */
	tal_free(fc->uc);
	return;

failed:
	close(fds[0]);
	close(fds[1]);
	subd_release_channel(openingd, fc->uc);
	/* Frees fc too, and tmpctx */
	tal_free(fc->uc);
}

static void opening_fundee_finished(struct subd *openingd,
				    const u8 *reply,
				    const int *fds,
				    struct uncommitted_channel *uc)
{
	u8 *funding_signed;
	struct channel_info channel_info;
	struct crypto_state cs;
	u64 gossip_index;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	struct lightningd *ld = openingd->ld;
	struct bitcoin_txid funding_txid;
	u16 funding_outnum;
	u64 funding_satoshi, push_msat;
	u32 feerate;
	u8 channel_flags;
	struct channel *channel;

	log_debug(uc->log, "Got opening_fundee_finish_response");
	assert(tal_count(fds) == 2);

	/* This is a new channel_info.their_config, set its ID to 0 */
	channel_info.their_config.id = 0;

	if (!fromwire_opening_fundee_reply(tmpctx, reply,
					   &channel_info.their_config,
					   &remote_commit,
					   &remote_commit_sig,
					   &cs,
					   &gossip_index,
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &channel_info.remote_fundingkey,
					   &funding_txid,
					   &funding_outnum,
					   &funding_satoshi,
					   &push_msat,
					   &channel_flags,
					   &feerate,
					   &funding_signed)) {
		log_broken(uc->log, "bad OPENING_FUNDEE_REPLY %s",
			   tal_hex(reply, reply));
		tal_free(uc);
		return;
	}

	/* Consumes uc */
	channel = wallet_commit_channel(ld, uc,
					remote_commit,
					&remote_commit_sig,
					&funding_txid,
					funding_outnum,
					funding_satoshi,
					push_msat,
					channel_flags,
					&channel_info,
					feerate);
	if (!channel) {
		tal_free(uc);
		return;
	}

	log_debug(channel->log, "Watching funding tx %s",
		     type_to_string(reply, struct bitcoin_txid,
				    &channel->funding_txid));

	channel_watch_funding(ld, channel);

	/* On to normal operation! */
	peer_start_channeld(channel, &cs, gossip_index,
			    fds[0], fds[1], funding_signed, false);

	subd_release_channel(openingd, uc);
	tal_free(uc);
}

static void opening_channel_errmsg(struct uncommitted_channel *uc,
				   int peer_fd, int gossip_fd,
				   const struct crypto_state *cs,
				   u64 gossip_index,
				   const struct channel_id *channel_id UNUSED,
				   const char *desc,
				   const u8 *err_for_them)
{
	if (peer_fd == -1) {
		log_info(uc->log, "%s", desc);
		if (uc->fc)
			command_fail(uc->fc->cmd, "%s", desc);
	} else {
		/* An error occurred (presumably negotiation fail). */
		const char *errsrc = err_for_them ? "sent" : "received";

		uncommitted_channel_to_gossipd(uc->peer->ld, uc,
					       cs, gossip_index,
					       peer_fd, gossip_fd,
					       err_for_them,
					       "%s ERROR %s", errsrc, desc);
	}
	tal_free(uc);
}

/* There's nothing permanent in an unconfirmed transaction */
static void opening_channel_set_billboard(struct uncommitted_channel *uc,
					  bool perm UNUSED,
					  const char *happenings TAKES)
{
	uc->transient_billboard = tal_free(uc->transient_billboard);
	if (happenings)
		uc->transient_billboard = tal_strdup(uc, happenings);
}

static void destroy_uncommitted_channel(struct uncommitted_channel *uc)
{
	uc->peer->uncommitted_channel = NULL;

	/* Last one out frees */
	if (list_empty(&uc->peer->channels))
		delete_peer(uc->peer);
}

/* Returns NULL if there's already an opening or active channel for this peer */
static struct uncommitted_channel *
new_uncommitted_channel(struct lightningd *ld,
			struct funding_channel *fc,
			const struct pubkey *peer_id,
			const struct wireaddr *addr)
{
	struct uncommitted_channel *uc = tal(ld, struct uncommitted_channel);
	char *idname;

	/* We make a new peer if necessary. */
	uc->peer = peer_by_id(ld, peer_id);
	if (!uc->peer)
		uc->peer = new_peer(ld, 0, peer_id, addr);

	if (uc->peer->uncommitted_channel)
		return tal_free(uc);

	if (peer_active_channel(uc->peer))
		return tal_free(uc);

	uc->transient_billboard = NULL;
	uc->dbid = wallet_get_channel_dbid(ld->wallet);

	idname = type_to_string(uc, struct pubkey, &uc->peer->id);
	uc->log = new_log(uc, uc->peer->log_book, "%s chan #%"PRIu64":",
			  idname, uc->dbid);
	tal_free(idname);

	uc->fc = fc;
	uc->first_blocknum = get_block_height(ld->topology);
	uc->our_config.id = 0;

	derive_channel_seed(ld, &uc->seed, &uc->peer->id, uc->dbid);
	uc->peer->uncommitted_channel = uc;
	tal_add_destructor(uc, destroy_uncommitted_channel);

	return uc;
}

static void channel_config(struct lightningd *ld,
			   struct channel_config *ours,
			   u32 *max_to_self_delay,
			   u32 *max_minimum_depth,
			   u64 *min_effective_htlc_capacity_msat)
{
	/* FIXME: depend on feerate. */
	*max_to_self_delay = ld->config.locktime_max;
	*max_minimum_depth = ld->config.anchor_confirms_max;
	/* This is 1c at $1000/BTC */
	*min_effective_htlc_capacity_msat = 1000000;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `dust_limit_satoshis` to a sufficient
	 * value to allow commitment transactions to propagate through
	 * the Bitcoin network.
	 */
	ours->dust_limit_satoshis = 546;
	ours->max_htlc_value_in_flight_msat = UINT64_MAX;

	/* Don't care */
	ours->htlc_minimum_msat = 0;

	/* BOLT #2:
	 *
	 * The sender SHOULD set `to_self_delay` sufficient to ensure
	 * the sender can irreversibly spend a commitment transaction
	 * output in case of misbehavior by the receiver.
	 */
	 ours->to_self_delay = ld->config.locktime_blocks;

	 /* BOLT #2:
	  *
	  * It MUST fail the channel if `max_accepted_htlcs` is greater than
	  * 483.
	  */
	 ours->max_accepted_htlcs = 483;

	 /* This is filled in by lightning_openingd, for consistency. */
	 ours->channel_reserve_satoshis = 0;
};

/* Peer has spontaneously exited from gossip due to open msg.  Return
 * NULL if we took over, otherwise hand back to gossipd with this
 * error.
 */
u8 *peer_accept_channel(const tal_t *ctx,
			struct lightningd *ld,
			const struct pubkey *peer_id,
			const struct wireaddr *addr,
			const struct crypto_state *cs,
			u64 gossip_index,
			const u8 *gfeatures UNUSED, const u8 *lfeatures UNUSED,
			int peer_fd, int gossip_fd,
			const struct channel_id *channel_id,
			const u8 *open_msg)
{
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;
	struct uncommitted_channel *uc;

	assert(fromwire_peektype(open_msg) == WIRE_OPEN_CHANNEL);

	/* Fails if there's already one */
	uc = new_uncommitted_channel(ld, NULL, peer_id, addr);
	if (!uc)
		return towire_errorfmt(ctx, channel_id,
				       "Multiple channels unsupported");

	uc->openingd = new_channel_subd(ld, "lightning_openingd", uc, uc->log,
					opening_wire_type_name,	NULL,
					opening_channel_errmsg,
					opening_channel_set_billboard,
					take(&peer_fd), take(&gossip_fd),
					NULL);
	if (!uc->openingd) {
		u8 *errpkt;
		char *errmsg;

		errmsg = tal_fmt(uc, "INTERNAL ERROR:"
				 " Failed to subdaemon opening: %s",
				 strerror(errno));
		errpkt = towire_errorfmt(uc, channel_id, "%s", errmsg);

		uncommitted_channel_to_gossipd(ld, uc,
					       cs, gossip_index,
					       peer_fd, gossip_fd,
					       errpkt, "%s", errmsg);
		tal_free(uc);
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The sender SHOULD set `minimum_depth` to a number of blocks it
	 * considers reasonable to avoid double-spending of the funding
	 * transaction.
	 */
	uc->minimum_depth = ld->config.anchor_confirms;

	channel_config(ld, &uc->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	msg = towire_opening_init(uc, get_chainparams(ld)->index,
				  &uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, gossip_index, &uc->seed);

	subd_send_msg(uc->openingd, take(msg));

	/* BOLT #2:
	 *
	 * Given the variance in fees, and the fact that the transaction may
	 * be spent in the future, it's a good idea for the fee payer to keep
	 * a good margin, say 5x the expected fee requirement */
	msg = towire_opening_fundee(uc, uc->minimum_depth,
				    get_feerate(ld->topology, FEERATE_SLOW),
				    get_feerate(ld->topology, FEERATE_IMMEDIATE)
				    * 5,
				    open_msg);

	subd_req(uc, uc->openingd, take(msg), -1, 2,
		 opening_fundee_finished, uc);
	return NULL;
}

static void peer_offer_channel(struct lightningd *ld,
			       struct funding_channel *fc,
			       const struct wireaddr *addr,
			       const struct crypto_state *cs,
			       u64 gossip_index,
			       const u8 *gfeatures UNUSED, const u8 *lfeatures UNUSED,
			       int peer_fd, int gossip_fd)
{
	u8 *msg;
	u32 max_to_self_delay, max_minimum_depth;
	u64 min_effective_htlc_capacity_msat;

	fc->uc = new_uncommitted_channel(ld, fc, &fc->peerid, addr);

	/* We asked to release this peer, but another raced in?  Corner case,
	 * close this is easiest. */
	if (!fc->uc) {
		command_fail(fc->cmd, "Peer already active");
		close(peer_fd);
		close(gossip_fd);
		return;
	}

	/* Channel now owns fc; if it dies, we free fc. */
	tal_steal(fc->uc, fc);

	fc->uc->openingd = new_channel_subd(ld,
				    "lightning_openingd", fc->uc, fc->uc->log,
				    opening_wire_type_name, NULL,
				    opening_channel_errmsg,
				    opening_channel_set_billboard,
				    take(&peer_fd), take(&gossip_fd),
				    NULL);
	if (!fc->uc->openingd) {
		/* We don't send them an error packet: for them, nothing
		 * happened! */
		uncommitted_channel_to_gossipd(ld, fc->uc, NULL,
					       gossip_index,
					       peer_fd, gossip_fd,
					       NULL,
					       "Failed to launch openingd: %s",
					       strerror(errno));
		tal_free(fc->uc);
		return;
	}

	channel_config(ld, &fc->uc->our_config,
		       &max_to_self_delay, &max_minimum_depth,
		       &min_effective_htlc_capacity_msat);

	msg = towire_opening_init(fc,
				  get_chainparams(ld)->index,
				  &fc->uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, gossip_index, &fc->uc->seed);
	subd_send_msg(fc->uc->openingd, take(msg));

	msg = towire_opening_funder(fc, fc->funding_satoshi,
				    fc->push_msat,
				    get_feerate(ld->topology, FEERATE_NORMAL),
				    max_minimum_depth,
				    fc->change, fc->change_keyindex,
				    fc->channel_flags,
				    fc->utxomap,
				    ld->wallet->bip32_base);

	subd_req(fc, fc->uc->openingd,
		 take(msg), -1, 2, opening_funder_finished, fc);
}

/* Peer has been released from gossip.  Start opening. */
static void gossip_peer_released(struct subd *gossip,
				 const u8 *resp,
				 const int *fds,
				 struct funding_channel *fc)
{
	struct lightningd *ld = gossip->ld;
	struct crypto_state cs;
	u64 gossip_index;
	u8 *gfeatures, *lfeatures;
	struct wireaddr addr;
	struct channel *c;
	struct uncommitted_channel *uc;

	c = active_channel_by_id(ld, &fc->peerid, &uc);

	if (!fromwire_gossipctl_release_peer_reply(fc, resp, &addr, &cs,
						   &gossip_index,
						   &gfeatures, &lfeatures)) {
		if (!fromwire_gossipctl_release_peer_replyfail(resp)) {
			fatal("Gossip daemon gave invalid reply %s",
			      tal_hex(gossip, resp));
		}
		if (uc)
			command_fail(fc->cmd, "Peer already OPENING");
		else if (c)
			command_fail(fc->cmd, "Peer already %s",
				     channel_state_name(c));
		else
			command_fail(fc->cmd, "Peer not connected");
		return;
	}
	assert(tal_count(fds) == 2);

	/* Gossipd should guarantee peer is unique: we would have killed any
	 * old connection when it was told us peer reconnected. */
	assert(!c);
	assert(!uc);

	/* OK, offer peer a channel. */
	peer_offer_channel(ld, fc, &addr, &cs, gossip_index,
			   gfeatures, lfeatures,
			   fds[0], fds[1]);
}

/**
 * json_fund_channel - Entrypoint for funding a channel
 */
static void json_fund_channel(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *desttok, *sattok;
	bool all_funds = false;
	struct funding_channel * fc;
	u32 feerate_per_kw = get_feerate(cmd->ld->topology, FEERATE_NORMAL);
    u64 fee_estimate;
	u8 *msg;

	if (!json_get_params(cmd, buffer, params,
			     "id", &desttok,
			     "satoshi", &sattok,
			     NULL)) {
		return;
	}

	fc = tal(cmd, struct funding_channel);
	fc->cmd = cmd;
	fc->change_keyindex = 0;
	fc->funding_satoshi = 0;

	if (json_tok_streq(buffer, sattok, "all")) {
		all_funds = true;

	} else if (!json_tok_u64(buffer, sattok, &fc->funding_satoshi)) {
		command_fail(cmd, "Invalid satoshis");
		return;
	}

	if (!pubkey_from_hexstr(buffer + desttok->start,
				desttok->end - desttok->start, &fc->peerid)) {
		command_fail(cmd, "Could not parse id");
		return;
	}
	/* FIXME: Support push_msat? */
	fc->push_msat = 0;
	fc->channel_flags = OUR_CHANNEL_FLAGS;

	/* Try to do this now, so we know if insufficient funds. */
	/* FIXME: dustlimit */
    if (all_funds) {
		fc->utxomap = wallet_select_all(cmd, cmd->ld->wallet,
			feerate_per_kw,
			BITCOIN_SCRIPTPUBKEY_P2WSH_LEN,
			&fc->funding_satoshi,
			&fee_estimate);
		if (!fc->utxomap || fc->funding_satoshi < 546) {
			command_fail(cmd, "Cannot afford fee %"PRIu64,
				     fee_estimate);
			return;
		}
		fc->change = 0;
	} else {
		fc->utxomap = build_utxos(fc, cmd->ld, fc->funding_satoshi,
			feerate_per_kw,
			600, BITCOIN_SCRIPTPUBKEY_P2WSH_LEN,
			&fc->change, &fc->change_keyindex);
		if (!fc->utxomap) {
			command_fail(cmd, "Cannot afford funding transaction");
			return;
		}
	}

	if (fc->funding_satoshi > MAX_FUNDING_SATOSHI) {
		command_fail(cmd, "Funding satoshi must be <= %d",
			     MAX_FUNDING_SATOSHI);
		return;
	}

	msg = towire_gossipctl_release_peer(cmd, &fc->peerid);
	subd_req(fc, cmd->ld->gossip, msg, -1, 2, gossip_peer_released, fc);
	command_still_pending(cmd);
}

static const struct json_command fund_channel_command = {
	"fundchannel",
	json_fund_channel,
	"Fund channel with {id} using {satoshi} satoshis"
};
AUTODATA(json_command, &fund_channel_command);
