#include <bitcoin/privkey.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/channel_config.h>
#include <common/funding_tx.h>
#include <common/key_derive.h>
#include <common/wallet_tx.h>
#include <common/wire_error.h>
#include <connectd/gen_connect_wire.h>
#include <errno.h>
#include <hsmd/gen_hsm_client_wire.h>
#include <lightningd/chaintopology.h>
#include <lightningd/channel_control.h>
#include <lightningd/closing_control.h>
#include <lightningd/hsm_control.h>
#include <lightningd/json.h>
#include <lightningd/jsonrpc.h>
#include <lightningd/jsonrpc_errors.h>
#include <lightningd/lightningd.h>
#include <lightningd/log.h>
#include <lightningd/opening_control.h>
#include <lightningd/param.h>
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

	/* Our basepoints for the channel. */
	struct basepoints local_basepoints;

	/* Public key for funding tx. */
	struct pubkey local_funding_pubkey;

	/* These are *not* filled in by new_uncommitted_channel: */

	/* Minimum funding depth (if funder == REMOTE). */
	u32 minimum_depth;

	/* Our channel config. */
	struct channel_config our_config;
};


struct funding_channel {
	/* In lightningd->fundchannels while waiting for connectd reply. */
	struct list_node list;

	struct command *cmd; /* Which also owns us. */
	struct wallet_tx wtx;
	u64 push_msat;
	u8 channel_flags;

	/* Peer we're trying to reach. */
	struct pubkey peerid;

	/* Channel. */
	struct uncommitted_channel *uc;
};

static struct funding_channel *find_funding_channel(struct lightningd *ld,
						    const struct pubkey *id)
{
	struct funding_channel *i;

	list_for_each(&ld->fundchannels, i, list) {
		if (pubkey_eq(&i->peerid, id))
			return i;
	}
	return NULL;
}

static void remove_funding_channel_from_list(struct funding_channel *fc)
{
	list_del_from(&fc->cmd->ld->fundchannels, &fc->list);
}

/* Opening failed: hand back to connectd (sending errpkt if not NULL) */
static void uncommitted_channel_to_connectd(struct lightningd *ld,
					   struct uncommitted_channel *uc,
					   const struct crypto_state *cs,
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
		command_fail(uc->fc->cmd, LIGHTNINGD, "%s", errstr);

	/* Hand back to connectd, (maybe) with an error packet to send. */
	msg = towire_connectctl_hand_back_peer(errstr, &uc->peer->id, cs,
					      errorpkt);
	subd_send_msg(ld->connectd, take(msg));
	subd_send_fd(ld->connectd, peer_fd);
	subd_send_fd(ld->connectd, gossip_fd);
}

static void uncommitted_channel_disconnect(struct uncommitted_channel *uc,
					   const char *desc)
{
	u8 *msg = towire_connectctl_peer_disconnected(tmpctx, &uc->peer->id);
	log_info(uc->log, "%s", desc);
	subd_send_msg(uc->peer->ld->connectd, msg);
	if (uc->fc)
		command_fail(uc->fc->cmd, LIGHTNINGD, "%s", desc);
}

void kill_uncommitted_channel(struct uncommitted_channel *uc,
			      const char *why)
{
	log_info(uc->log, "Killing openingd: %s", why);

	/* Close openingd. */
	subd_release_channel(uc->openingd, uc);
	uc->openingd = NULL;

	uncommitted_channel_disconnect(uc, why);
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

		msatoshi_total = uc->fc->wtx.amount * 1000;
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
			      /* The three arguments below are msatoshi_to_us,
			       * msatoshi_to_us_min, and msatoshi_to_us_max.
			       * Because, this is a newly-funded channel,
			       * all three are same value. */
			      our_msatoshi,
			      our_msatoshi, /* msatoshi_to_us_min */
			      our_msatoshi, /* msatoshi_to_us_max */
			      remote_commit,
			      remote_commit_sig,
			      NULL, /* No HTLC sigs yet */
			      channel_info,
			      NULL, /* No remote_shutdown_scriptpubkey yet */
			      final_key_idx, false,
			      NULL, /* No commit sent yet */
			      /* If we're fundee, could be a little before this
			       * in theory, but it's only used for timing out. */
			      get_block_height(ld->topology),
			      feerate, feerate,
			      /* We are connected */
			      true,
			      &uc->local_basepoints,
			      &uc->local_funding_pubkey);

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

void tell_connectd_peer_is_important(struct lightningd *ld,
				    const struct channel *channel)
{
	u8 *msg;

	/* Tell connectd we need to keep connection to this peer */
	msg = towire_connectctl_peer_important(NULL, &channel->peer->id, true);
	subd_send_msg(ld->connectd, take(msg));
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
	struct crypto_state cs;
	secp256k1_ecdsa_signature remote_commit_sig;
	struct bitcoin_tx *remote_commit;
	u16 funding_outnum;
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
					   &channel_info.theirbase.revocation,
					   &channel_info.theirbase.payment,
					   &channel_info.theirbase.htlc,
					   &channel_info.theirbase.delayed_payment,
					   &channel_info.remote_per_commit,
					   &fc->uc->minimum_depth,
					   &channel_info.remote_fundingkey,
					   &expected_txid,
					   &feerate,
					   &fc->uc->our_config.channel_reserve_satoshis)) {
		log_broken(fc->uc->log,
			   "bad OPENING_FUNDER_REPLY %s",
			   tal_hex(resp, resp));
		command_fail(fc->cmd, LIGHTNINGD, "bad OPENING_FUNDER_REPLY %s",
			     tal_hex(fc->cmd, resp));
		goto failed;
	}
	log_debug(ld->log,
		  "%s", type_to_string(tmpctx, struct pubkey,
				       &channel_info.remote_per_commit));

	/* Generate the funding tx. */
	if (fc->wtx.change
	    && !bip32_pubkey(ld->wallet->bip32_base,
			     &changekey, fc->wtx.change_key_index))
		fatal("Error deriving change key %u", fc->wtx.change_key_index);

	fundingtx = funding_tx(tmpctx, &funding_outnum,
			       fc->wtx.utxos, fc->wtx.amount,
			       &fc->uc->local_funding_pubkey,
			       &channel_info.remote_fundingkey,
			       fc->wtx.change, &changekey,
			       ld->wallet->bip32_base);

	log_debug(fc->uc->log, "Funding tx has %zi inputs, %zu outputs:",
		  tal_count(fundingtx->input),
		  tal_count(fundingtx->output));

	for (size_t i = 0; i < tal_count(fundingtx->input); i++) {
		log_debug(fc->uc->log, "%zi: %"PRIu64" satoshi (%s) %s\n",
			  i, fc->wtx.utxos[i]->amount,
			  fc->wtx.utxos[i]->is_p2sh ? "P2SH" : "SEGWIT",
			  type_to_string(tmpctx, struct bitcoin_txid,
					 &fundingtx->input[i].txid));
	}

	bitcoin_txid(fundingtx, &funding_txid);

	if (!bitcoin_txid_eq(&funding_txid, &expected_txid)) {
		log_broken(fc->uc->log,
			   "Funding txid mismatch:"
			   " satoshi %"PRIu64" change %"PRIu64
			   " changeidx %u"
			   " localkey %s remotekey %s",
			   fc->wtx.amount,
			   fc->wtx.change, fc->wtx.change_key_index,
			   type_to_string(fc, struct pubkey,
					  &fc->uc->local_funding_pubkey),
			   type_to_string(fc, struct pubkey,
					  &channel_info.remote_fundingkey));
		command_fail(fc->cmd, JSONRPC2_INVALID_PARAMS,
			     "Funding txid mismatch:"
			     " satoshi %"PRIu64" change %"PRIu64
			     " changeidx %u"
			     " localkey %s remotekey %s",
			     fc->wtx.amount,
			     fc->wtx.change, fc->wtx.change_key_index,
			     type_to_string(fc, struct pubkey,
					    &fc->uc->local_funding_pubkey),
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
					fc->wtx.amount,
					fc->push_msat,
					fc->channel_flags,
					&channel_info,
					feerate);
	if (!channel) {
		command_fail(fc->cmd, LIGHTNINGD,
			     "Key generation failure");
		goto failed;
	}

	/* Get HSM to sign the funding tx. */
	log_debug(channel->log, "Getting HSM to sign funding tx");

	msg = towire_hsm_sign_funding(tmpctx, channel->funding_satoshi,
				      fc->wtx.change, fc->wtx.change_key_index,
				      &fc->uc->local_funding_pubkey,
				      &channel_info.remote_fundingkey,
				      fc->wtx.utxos);

	if (!wire_sync_write(ld->hsm_fd, take(msg)))
		fatal("Could not write to HSM: %s", strerror(errno));

	msg = wire_sync_read(fc, ld->hsm_fd);
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

	tell_connectd_peer_is_important(ld, channel);

	/* Start normal channel daemon. */
	peer_start_channeld(channel, &cs, fds[0], fds[1], NULL, false);

	wallet_confirm_utxos(ld->wallet, fc->wtx.utxos);

	response = new_json_result(fc->cmd);
	json_object_start(response, NULL);
	linear = linearize_tx(response, fundingtx);
	json_add_hex_talarr(response, "tx", linear);
	json_add_txid(response, "txid", &channel->funding_txid);
	derive_channel_id(&cid, &channel->funding_txid, funding_outnum);
	json_add_string(response, "channel_id",
			type_to_string(tmpctx, struct channel_id, &cid));
	json_object_end(response);
	command_success(fc->cmd, response);

	subd_release_channel(openingd, fc->uc);
	fc->uc->openingd = NULL;

	/* Frees fc too, and tmpctx */
	tal_free(fc->uc);
	return;

failed:
	close(fds[0]);
	close(fds[1]);
	subd_release_channel(openingd, fc->uc);
	fc->uc->openingd = NULL;
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
					   &funding_signed,
					   &uc->our_config.channel_reserve_satoshis)) {
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

	tell_connectd_peer_is_important(ld, channel);

	/* On to normal operation! */
	peer_start_channeld(channel, &cs,
			    fds[0], fds[1], funding_signed, false);

	subd_release_channel(openingd, uc);
	uc->openingd = NULL;
	tal_free(uc);
}

static void opening_channel_errmsg(struct uncommitted_channel *uc,
				   int peer_fd, int gossip_fd,
				   const struct crypto_state *cs,
				   const struct channel_id *channel_id UNUSED,
				   const char *desc,
				   const u8 *err_for_them)
{
	if (peer_fd == -1) {
		uncommitted_channel_disconnect(uc, desc);
	} else {
		/* An error occurred (presumably negotiation fail). */
		const char *errsrc = err_for_them ? "sent" : "received";

		uncommitted_channel_to_connectd(uc->peer->ld, uc,
					       cs,
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
	if (uc->openingd) {
		struct subd *openingd = uc->openingd;
		uc->openingd = NULL;
		subd_release_channel(openingd, uc);
	}

	/* This is how shutdown_subdaemons tells us not to delete from db! */
	if (!uc->peer->uncommitted_channel)
		return;

	uc->peer->uncommitted_channel = NULL;

	maybe_delete_peer(uc->peer);
}

/* Returns NULL if there's already an opening or active channel for this peer */
static struct uncommitted_channel *
new_uncommitted_channel(struct lightningd *ld,
			struct funding_channel *fc,
			const struct pubkey *peer_id,
			const struct wireaddr_internal *addr,
			const u8 *gfeatures, const u8 *lfeatures)
{
	struct uncommitted_channel *uc = tal(ld, struct uncommitted_channel);
	char *idname;

	/* We make a new peer if necessary. */
	uc->peer = peer_by_id(ld, peer_id);
	if (!uc->peer)
		uc->peer = new_peer(ld, 0, peer_id, addr, gfeatures, lfeatures);

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
	uc->our_config.id = 0;

	get_channel_basepoints(ld, &uc->peer->id, uc->dbid,
			       &uc->local_basepoints, &uc->local_funding_pubkey);

	uc->peer->uncommitted_channel = uc;
	tal_add_destructor(uc, destroy_uncommitted_channel);

	return uc;
}

static void channel_config(struct lightningd *ld,
			   struct channel_config *ours,
			   u32 *max_to_self_delay,
			   u64 *min_effective_htlc_capacity_msat)
{
	/* FIXME: depend on feerate. */
	*max_to_self_delay = ld->config.locktime_max;
	/* This is 1c at $1000/BTC */
	*min_effective_htlc_capacity_msat = 1000000;

	/* BOLT #2:
	 *
	 * The sending node SHOULD:
	 *...
	 *   - set `dust_limit_satoshis` to a sufficient value to allow
	 *     commitment transactions to propagate through the Bitcoin network.
	 */
	ours->dust_limit_satoshis = 546;
	ours->max_htlc_value_in_flight_msat = UINT64_MAX;

	/* Don't care */
	ours->htlc_minimum_msat = 0;

	/* BOLT #2:
	 *
	 * The sending node SHOULD:
	 *   - set `to_self_delay` sufficient to ensure the sender can
	 *     irreversibly spend a commitment transaction output, in case of
	 *     misbehavior by the receiver.
	 */
	 ours->to_self_delay = ld->config.locktime_blocks;

	 /* BOLT #2:
	  *
	  * The receiving node MUST fail the channel if:
	  *...
	  *   - `max_accepted_htlcs` is greater than 483.
	  */
	 ours->max_accepted_htlcs = 483;

	 /* This is filled in by lightning_openingd, for consistency. */
	 ours->channel_reserve_satoshis = -1;
}

/* Peer has spontaneously exited from connectd due to open msg.  Return
 * NULL if we took over, otherwise hand back to connectd with this
 * error.
 */
u8 *peer_accept_channel(const tal_t *ctx,
			struct lightningd *ld,
			const struct pubkey *peer_id,
			const struct wireaddr_internal *addr,
			const struct crypto_state *cs,
			const u8 *gfeatures, const u8 *lfeatures,
			int peer_fd, int gossip_fd,
			const struct channel_id *channel_id,
			const u8 *open_msg)
{
	u32 max_to_self_delay;
	u64 min_effective_htlc_capacity_msat;
	u8 *msg;
	struct uncommitted_channel *uc;
	int hsmfd;

	assert(fromwire_peektype(open_msg) == WIRE_OPEN_CHANNEL);

	/* Fails if there's already one */
	uc = new_uncommitted_channel(ld, NULL, peer_id, addr,
				     gfeatures, lfeatures);
	if (!uc)
		return towire_errorfmt(ctx, channel_id,
				       "Multiple channels unsupported");

	hsmfd = hsm_get_client_fd(ld, &uc->peer->id, uc->dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	uc->openingd = new_channel_subd(ld, "lightning_openingd", uc, uc->log,
					true, opening_wire_type_name, NULL,
					opening_channel_errmsg,
					opening_channel_set_billboard,
					take(&peer_fd), take(&gossip_fd),
					take(&hsmfd), NULL);
	if (!uc->openingd) {
		u8 *errpkt;
		char *errmsg;

		errmsg = tal_fmt(uc, "INTERNAL ERROR:"
				 " Failed to subdaemon opening: %s",
				 strerror(errno));
		errpkt = towire_errorfmt(uc, channel_id, "%s", errmsg);

		uncommitted_channel_to_connectd(ld, uc,
					       cs,
					       peer_fd, gossip_fd,
					       errpkt, "%s", errmsg);
		tal_free(uc);
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The sender:
	 *   - SHOULD set `minimum_depth` to a number of blocks it considers
	 *     reasonable to avoid double-spending of the funding transaction.
	 */
	uc->minimum_depth = ld->config.anchor_confirms;

	channel_config(ld, &uc->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity_msat);

	msg = towire_opening_init(uc, get_chainparams(ld)->index,
				  &uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, &uc->local_basepoints,
				  &uc->local_funding_pubkey);

	subd_send_msg(uc->openingd, take(msg));

	msg = towire_opening_fundee(uc, uc->minimum_depth,
				    feerate_min(ld), feerate_max(ld),
				    open_msg);

	subd_req(uc, uc->openingd, take(msg), -1, 2,
		 opening_fundee_finished, uc);
	return NULL;
}

static void peer_offer_channel(struct lightningd *ld,
			       struct funding_channel *fc,
			       const struct wireaddr_internal *addr,
			       const struct crypto_state *cs,
			       const u8 *gfeatures, const u8 *lfeatures,
			       int peer_fd, int gossip_fd)
{
	u8 *msg;
	u32 max_to_self_delay;
	u64 min_effective_htlc_capacity_msat;
	int hsmfd;

	/* Remove from list, it's not pending any more. */
	list_del_from(&ld->fundchannels, &fc->list);
	tal_del_destructor(fc, remove_funding_channel_from_list);

	fc->uc = new_uncommitted_channel(ld, fc, &fc->peerid, addr,
					 gfeatures, lfeatures);

	/* We asked to release this peer, but another raced in?  Corner case,
	 * close this is easiest. */
	if (!fc->uc) {
		command_fail(fc->cmd, LIGHTNINGD, "Peer already active");
		close(peer_fd);
		close(gossip_fd);
		return;
	}

	/* Channel now owns fc; if it dies, we free fc. */
	tal_steal(fc->uc, fc);

	hsmfd = hsm_get_client_fd(ld, &fc->uc->peer->id, fc->uc->dbid,
				  HSM_CAP_COMMITMENT_POINT
				  | HSM_CAP_SIGN_REMOTE_TX);

	fc->uc->openingd = new_channel_subd(ld,
					    "lightning_openingd",
					    fc->uc, fc->uc->log,
					    true, opening_wire_type_name, NULL,
					    opening_channel_errmsg,
					    opening_channel_set_billboard,
					    take(&peer_fd), take(&gossip_fd),
					    take(&hsmfd),
					    NULL);
	if (!fc->uc->openingd) {
		/* We don't send them an error packet: for them, nothing
		 * happened! */
		uncommitted_channel_to_connectd(ld, fc->uc, NULL,
					       peer_fd, gossip_fd,
					       NULL,
					       "Failed to launch openingd: %s",
					       strerror(errno));
		tal_free(fc->uc);
		return;
	}

	channel_config(ld, &fc->uc->our_config,
		       &max_to_self_delay,
		       &min_effective_htlc_capacity_msat);

	msg = towire_opening_init(fc,
				  get_chainparams(ld)->index,
				  &fc->uc->our_config,
				  max_to_self_delay,
				  min_effective_htlc_capacity_msat,
				  cs, &fc->uc->local_basepoints,
				  &fc->uc->local_funding_pubkey);
	subd_send_msg(fc->uc->openingd, take(msg));

	msg = towire_opening_funder(fc, fc->wtx.amount,
				    fc->push_msat,
				    get_feerate(ld->topology, FEERATE_NORMAL),
				    fc->wtx.change, fc->wtx.change_key_index,
				    fc->channel_flags,
				    fc->wtx.utxos,
				    ld->wallet->bip32_base);

	subd_req(fc, fc->uc->openingd,
		 take(msg), -1, 2, opening_funder_finished, fc);
}

/* Peer has been released from connectd.  Start opening. */
static void connectd_peer_released(struct subd *connectd,
				 const u8 *resp,
				 const int *fds,
				 struct funding_channel *fc)
{
	struct lightningd *ld = connectd->ld;
	struct crypto_state cs;
	u8 *gfeatures, *lfeatures;
	struct wireaddr_internal addr;
	struct channel *c;
	struct uncommitted_channel *uc;

	/* handle_opening_channel might have already taken care of this. */
	if (fc->uc)
		return;

	c = active_channel_by_id(ld, &fc->peerid, &uc);

	if (!fromwire_connectctl_release_peer_reply(fc, resp, &addr, &cs,
						   &gfeatures, &lfeatures)) {
		if (!fromwire_connectctl_release_peer_replyfail(resp)) {
			fatal("Connect daemon gave invalid reply %s",
			      tal_hex(connectd, resp));
		}
		if (uc)
			command_fail(fc->cmd, LIGHTNINGD, "Peer already OPENING");
		else if (c)
			command_fail(fc->cmd, LIGHTNINGD, "Peer already %s",
				     channel_state_name(c));
		else
			command_fail(fc->cmd, LIGHTNINGD, "Peer not connected");
		return;
	}
	assert(tal_count(fds) == 2);

	/* Connectd should guarantee peer is unique: we would have killed any
	 * old connection when it was told us peer reconnected. */
	assert(!c);
	assert(!uc);

	/* OK, offer peer a channel. */
	peer_offer_channel(ld, fc, &addr, &cs,
			   gfeatures, lfeatures,
			   fds[0], fds[1]);
}

/* We can race: we're trying to get connectd to release peer just as it
 * reconnects.  If that's happened, treat it as if it were
 * released. */
bool handle_opening_channel(struct lightningd *ld,
			    const struct pubkey *id,
			    const struct wireaddr_internal *addr,
			    const struct crypto_state *cs,
			    const u8 *gfeatures, const u8 *lfeatures,
			    int peer_fd, int gossip_fd)
{
	struct funding_channel *fc = find_funding_channel(ld, id);

	if (!fc)
		return false;

	peer_offer_channel(ld, fc, addr, cs, gfeatures, lfeatures,
			   peer_fd, gossip_fd);
	return true;
}

/**
 * json_fund_channel - Entrypoint for funding a channel
 */
static void json_fund_channel(struct command *cmd,
			      const char *buffer, const jsmntok_t *params)
{
	const jsmntok_t *desttok, *sattok;
	struct funding_channel * fc = tal(cmd, struct funding_channel);
	u32 feerate_per_kw = get_feerate(cmd->ld->topology, FEERATE_NORMAL);
	u8 *msg;

	fc->cmd = cmd;
	fc->uc = NULL;
	wtx_init(cmd, &fc->wtx);
	if (!param(fc->cmd, buffer, params,
		   p_req("id", json_tok_tok, &desttok),
		   p_req("satoshi", json_tok_tok, &sattok),
		   NULL))
		return;

	if (!json_tok_wtx(&fc->wtx, buffer, sattok, MAX_FUNDING_SATOSHI))
		return;
	if (!pubkey_from_hexstr(buffer + desttok->start,
				desttok->end - desttok->start,
				&fc->peerid)) {
		command_fail(cmd, JSONRPC2_INVALID_PARAMS, "Could not parse id");
		return;
	}

	/* FIXME: Support push_msat? */
	fc->push_msat = 0;
	fc->channel_flags = OUR_CHANNEL_FLAGS;

	if (!wtx_select_utxos(&fc->wtx, feerate_per_kw,
			      BITCOIN_SCRIPTPUBKEY_P2WSH_LEN))
		return;

	assert(fc->wtx.amount <= MAX_FUNDING_SATOSHI);

	list_add(&cmd->ld->fundchannels, &fc->list);
	tal_add_destructor(fc, remove_funding_channel_from_list);

	msg = towire_connectctl_release_peer(cmd, &fc->peerid);
	subd_req(fc, cmd->ld->connectd, msg, -1, 2, connectd_peer_released, fc);
	command_still_pending(cmd);
}

static const struct json_command fund_channel_command = {
	"fundchannel",
	json_fund_channel,
	"Fund channel with {id} using {satoshi} (or 'all') satoshis"
};
AUTODATA(json_command, &fund_channel_command);
