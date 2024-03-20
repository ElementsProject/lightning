#include "config.h"
#include <ccan/cast/cast.h>
#include <common/configdir.h>
#include <common/type_to_string.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/notification.h>

bool notifications_topic_is_native(const char *topic)
{
	static const char **notilist = NULL;
	static size_t num_notis;
	if (!notilist)
		notilist = cast_const2(const char **,
				       autodata_get(notifications, &num_notis));

	for (size_t i=0; i<num_notis; i++)
		if (streq(notilist[i], topic))
			return true;
	return false;
}

bool notifications_have_topic(const struct plugins *plugins, const char *topic)
{
	struct plugin *plugin;
	if (notifications_topic_is_native(topic))
		return true;

	/* Some plugin at some point announced it'd be emitting
	 * notifications to this topic. */
	list_for_each(&plugins->plugins, plugin, list) {
		for (size_t i = 0; i < tal_count(plugin->notification_topics); i++)
			if (streq(plugin->notification_topics[i], topic))
				return true;
	}

	return false;
}

/* Modern notifications X contain an object X */
static struct jsonrpc_notification *notify_start(const char *name)
{
	struct jsonrpc_notification *n;

	n = jsonrpc_notification_start(NULL, name);
	json_object_start(n->stream, name);
	return n;
}

static void notify_send(struct lightningd *ld,
			struct jsonrpc_notification *n STEALS)
{
	json_object_end(n->stream);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void json_add_connect_fields(struct json_stream *stream,
				    const struct node_id *nodeid,
				    bool incoming,
				    const struct wireaddr_internal *addr)
{
	json_add_node_id(stream, "id", nodeid);
	json_add_string(stream, "direction", incoming ? "in" : "out");
	json_add_address_internal(stream, "address", addr);
}

static void connect_notification_serialize(struct json_stream *stream,
					   struct lightningd *ld,
					   const struct node_id *nodeid,
					   bool incoming,
					   const struct wireaddr_internal *addr)
{
	/* Old style: Add raw fields without connect key */
	if (lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
					 "connect_notification", "rawfields",
					 "v23.08", "v24.08")) {
		json_add_connect_fields(stream, nodeid, incoming, addr);
	}
	json_object_start(stream, "connect");
	json_add_connect_fields(stream, nodeid, incoming, addr);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(connect);

void notify_connect(struct lightningd *ld,
		    const struct node_id *nodeid,
		    bool incoming,
		    const struct wireaddr_internal *addr)
{
	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, "connect");
	connect_notification_serialize(n->stream, ld, nodeid, incoming, addr);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void json_add_disconnect_fields(struct json_stream *stream,
					   const struct node_id *nodeid)
{
	json_add_node_id(stream, "id", nodeid);
}

static void disconnect_notification_serialize(struct json_stream *stream,
					      struct lightningd *ld,
					      const struct node_id *nodeid)
{
	/* Old style: Add raw fields without disconnect key */
	if (lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
					 "disconnect_notification", "rawfields",
					 "v23.08", "v24.08")) {
		json_add_disconnect_fields(stream, nodeid);
	}
	json_object_start(stream, "disconnect");
	json_add_disconnect_fields(stream, nodeid);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(disconnect);

void notify_disconnect(struct lightningd *ld, struct node_id *nodeid)
{
	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, "disconnect");
	disconnect_notification_serialize(n->stream, ld, nodeid);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

/*'warning' is based on LOG_UNUSUAL/LOG_BROKEN level log
 *(in plugin module, they're 'warn'/'error' level). */
static void warning_notification_serialize(struct json_stream *stream,
					   struct log_entry *l)
{
	/* Choose "BROKEN"/"UNUSUAL" to keep consistent with the habit
	 * of plugin. But this may confuses the users who want to 'getlog'
	 * with the level indicated by notifications. It is the duty of a
	 * plugin to eliminate this misunderstanding.
	 */
	json_add_string(stream, "level",
			l->level == LOG_BROKEN ? "error"
			: "warn");
	/* unsuaul/broken event is rare, plugin pay more attentions on
	 * the absolute time, like when channels failed. */
	json_add_timestr(stream, "time", l->time.ts);
	json_add_timeiso(stream, "timestamp", l->time);
	json_add_string(stream, "source", l->prefix->prefix);
	json_add_string(stream, "log", l->log);
}

REGISTER_NOTIFICATION(warning);

void notify_warning(struct lightningd *ld, struct log_entry *l)
{
	struct jsonrpc_notification *n = notify_start("warning");
	warning_notification_serialize(n->stream, l);
	notify_send(ld, n);
}

static void custommsg_notification_serialize(struct json_stream *stream,
					     const struct node_id *peer_id,
					     const u8 *msg)
{
	json_add_node_id(stream, "peer_id", peer_id);
	json_add_hex_talarr(stream, "payload", msg);
}

REGISTER_NOTIFICATION(custommsg);

void notify_custommsg(struct lightningd *ld,
		      const struct node_id *peer_id,
		      const u8 *msg)
{
	struct jsonrpc_notification *n = notify_start("custommsg");
	custommsg_notification_serialize(n->stream, peer_id, msg);
	notify_send(ld, n);
}

static void invoice_payment_notification_serialize(struct json_stream *stream,
						   struct amount_msat amount,
						   const struct preimage *preimage,
						   const struct json_escape *label,
						   const struct bitcoin_outpoint *outpoint)
{
	json_add_amount_msat(stream, "msat", amount);
	json_add_preimage(stream, "preimage", preimage);
	if (outpoint)
		json_add_outpoint(stream, "outpoint", outpoint);
	json_add_escaped_string(stream, "label", label);
}

REGISTER_NOTIFICATION(invoice_payment)

void notify_invoice_payment(struct lightningd *ld,
			    struct amount_msat amount,
			    const struct preimage *preimage,
			    const struct json_escape *label,
			    const struct bitcoin_outpoint *outpoint)
{
	struct jsonrpc_notification *n = notify_start("invoice_payment");
	invoice_payment_notification_serialize(n->stream, amount, preimage, label, outpoint);
	notify_send(ld, n);
}

static void invoice_creation_notification_serialize(struct json_stream *stream,
						    const struct amount_msat *amount,
						    const struct preimage *preimage,
						    const struct json_escape *label)
{
	if (amount != NULL)
		json_add_amount_msat(stream, "msat", *amount);

	json_add_preimage(stream, "preimage", preimage);
	json_add_escaped_string(stream, "label", label);
}

REGISTER_NOTIFICATION(invoice_creation)

void notify_invoice_creation(struct lightningd *ld,
			     const struct amount_msat *amount,
			     const struct preimage *preimage,
			     const struct json_escape *label)
{
	struct jsonrpc_notification *n = notify_start("invoice_creation");
	invoice_creation_notification_serialize(n->stream, amount, preimage, label);
	notify_send(ld, n);
}

/* FIXME: Use outpoint here! */
static void channel_opened_notification_serialize(struct json_stream *stream,
						  struct lightningd *ld,
						  const struct node_id *node_id,
						  const struct amount_sat *funding_sat,
						  const struct bitcoin_txid *funding_txid,
						  bool channel_ready)
{
	json_add_node_id(stream, "id", node_id);
	json_add_amount_sat_msat(stream, "funding_msat", *funding_sat);
	json_add_txid(stream, "funding_txid", funding_txid);
	if (lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
					 "channel_opened", "funding_locked", "v22.11", "v24.02"))
		json_add_bool(stream, "funding_locked", channel_ready);
	json_add_bool(stream, "channel_ready", channel_ready);
}

REGISTER_NOTIFICATION(channel_opened)

void notify_channel_opened(struct lightningd *ld,
			   const struct node_id *node_id,
			   const struct amount_sat *funding_sat,
			   const struct bitcoin_txid *funding_txid,
			   bool channel_ready)
{
	struct jsonrpc_notification *n = notify_start("channel_opened");
	channel_opened_notification_serialize(n->stream, ld, node_id, funding_sat, funding_txid, channel_ready);
	notify_send(ld, n);
}

static void channel_state_changed_notification_serialize(struct json_stream *stream,
							 const struct node_id *peer_id,
							 const struct channel_id *cid,
							 const struct short_channel_id *scid,
							 struct timeabs timestamp,
							 enum channel_state old_state,
							 enum channel_state new_state,
							 enum state_change cause,
							 const char *message)
{
	json_add_node_id(stream, "peer_id", peer_id);
	json_add_channel_id(stream, "channel_id", cid);
	if (scid)
		json_add_short_channel_id(stream, "short_channel_id", scid);
	else
		json_add_null(stream, "short_channel_id");
	json_add_timeiso(stream, "timestamp", timestamp);
	json_add_string(stream, "old_state", channel_state_str(old_state));
	json_add_string(stream, "new_state", channel_state_str(new_state));
	json_add_string(stream, "cause", channel_change_state_reason_str(cause));
	if (message != NULL)
		json_add_string(stream, "message", message);
	else
		json_add_null(stream, "message");
}

REGISTER_NOTIFICATION(channel_state_changed)

void notify_channel_state_changed(struct lightningd *ld,
				  const struct node_id *peer_id,
				  const struct channel_id *cid,
				  const struct short_channel_id *scid,
				  struct timeabs timestamp,
				  enum channel_state old_state,
				  enum channel_state new_state,
				  enum state_change cause,
				  const char *message)
{
	struct jsonrpc_notification *n = notify_start("channel_state_changed");
	channel_state_changed_notification_serialize(n->stream, peer_id, cid, scid, timestamp, old_state, new_state, cause, message);
	notify_send(ld, n);
}

static void forward_event_notification_serialize(struct json_stream *stream,
						 const struct htlc_in *in,
						 const struct short_channel_id *scid_out,
						 const struct amount_msat *amount_out,
						 enum forward_status state,
						 enum onion_wire failcode,
						 struct timeabs *resolved_time,
						 enum forward_style forward_style,
						 u64 created_index,
						 u64 updated_index)
{
	/* Here is more neat to initial a forwarding structure than
	 * to pass in a bunch of parameters directly*/
	struct forwarding *cur = tal(tmpctx, struct forwarding);

	/* We use the LOCAL alias, not the REMOTE, despite the route
	 * the the sender is using probably using the REMOTE
	 * alias. The LOCAL one is controlled by us, and we keep it
	 * stable. */
	cur->channel_in = *channel_scid_or_local_alias(in->key.channel);

	cur->msat_in = in->msat;
	if (scid_out) {
		cur->channel_out = *scid_out;
		if (amount_out) {
			cur->msat_out = *amount_out;
			if (!amount_msat_sub(&cur->fee,
					     in->msat, *amount_out))
				abort();
		} else {
			cur->msat_out = AMOUNT_MSAT(0);
			cur->fee = AMOUNT_MSAT(0);
		}
	} else {
		cur->channel_out.u64 = 0;
		cur->msat_out = AMOUNT_MSAT(0);
		cur->fee = AMOUNT_MSAT(0);
	}
	cur->htlc_id_out = NULL;
	cur->status = state;
	cur->failcode = failcode;
	cur->received_time = in->received_time;
	cur->resolved_time = tal_steal(cur, resolved_time);
	cur->forward_style = forward_style;
	cur->htlc_id_in = in->key.id;
	cur->created_index = created_index;
	cur->updated_index = updated_index;

	json_add_forwarding_fields(stream, cur, &in->payment_hash);
}

REGISTER_NOTIFICATION(forward_event);

void notify_forward_event(struct lightningd *ld,
			  const struct htlc_in *in,
			  const struct short_channel_id *scid_out,
			  const struct amount_msat *amount_out,
			  enum forward_status state,
			  enum onion_wire failcode,
			  struct timeabs *resolved_time,
			  enum forward_style forward_style,
			  u64 created_index,
			  u64 updated_index)
{
	struct jsonrpc_notification *n = notify_start("forward_event");
	forward_event_notification_serialize(n->stream, in, scid_out, amount_out, state, failcode, resolved_time, forward_style, created_index, updated_index);
	notify_send(ld, n);
}

REGISTER_NOTIFICATION(sendpay_success);

void notify_sendpay_success(struct lightningd *ld,
			    const struct wallet_payment *payment)
{
	struct jsonrpc_notification *n = notify_start("sendpay_success");
	json_add_payment_fields(n->stream, payment);
	notify_send(ld, n);
}

static void sendpay_failure_notification_serialize(struct json_stream *stream,
						   const struct wallet_payment *payment,
						   enum jsonrpc_errcode pay_errcode,
						   const struct onionreply *onionreply,
						   const struct routing_failure *fail,
						   const char *errmsg)
{
	/* In line with the format of json error returned
	 * by sendpay_fail(). */
	json_add_jsonrpc_errcode(stream, "code", pay_errcode);
	json_add_string(stream, "message", errmsg);

	json_object_start(stream, "data");
	json_sendpay_fail_fields(stream,
				 payment,
				 pay_errcode,
				 onionreply,
				 fail);

	json_object_end(stream); /* .data */
}

REGISTER_NOTIFICATION(sendpay_failure);

void notify_sendpay_failure(struct lightningd *ld,
			    const struct wallet_payment *payment,
			    enum jsonrpc_errcode pay_errcode,
			    const struct onionreply *onionreply,
			    const struct routing_failure *fail,
			    const char *errmsg)
{
	struct jsonrpc_notification *n = notify_start("sendpay_failure");
	sendpay_failure_notification_serialize(n->stream, payment, pay_errcode, onionreply, fail, errmsg);
	notify_send(ld, n);
}

static void json_mvt_id(struct json_stream *stream, enum mvt_type mvt_type,
			const struct mvt_id *id)
{
	switch (mvt_type) {
		case CHAIN_MVT:
			/* some 'journal entries' don't have a txid */
			if (id->tx_txid)
				json_add_string(stream, "txid",
						fmt_bitcoin_txid(tmpctx,
								 id->tx_txid));
			/* some chain ledger entries aren't associated with a utxo
			 * e.g. journal updates (due to penalty/state loss) and
			 * chain_fee entries */
			if (id->outpoint) {
				json_add_string(stream, "utxo_txid",
						fmt_bitcoin_txid(tmpctx,
								 &id->outpoint->txid));
				json_add_u32(stream, "vout", id->outpoint->n);
			}

			/* on-chain htlcs include a payment hash */
			if (id->payment_hash)
				json_add_sha256(stream, "payment_hash", id->payment_hash);
			return;
	case CHANNEL_MVT:
		/* push funding / leases don't have a payment_hash */
		if (id->payment_hash)
			json_add_sha256(stream, "payment_hash", id->payment_hash);
		if (id->part_id)
			json_add_u64(stream, "part_id", *id->part_id);
		return;
	}
	abort();
}

static void coin_movement_notification_serialize(struct json_stream *stream,
						 const struct coin_mvt *mvt)
{
	json_add_num(stream, "version", mvt->version);
	json_add_node_id(stream, "node_id", mvt->node_id);
	if (mvt->peer_id)
		json_add_node_id(stream, "peer_id", mvt->peer_id);
	json_add_string(stream, "type", mvt_type_str(mvt->type));
	json_add_string(stream, "account_id", mvt->account_id);
	if (mvt->originating_acct)
		json_add_string(stream, "originating_account",
				mvt->originating_acct);
	json_mvt_id(stream, mvt->type, &mvt->id);
	json_add_amount_msat(stream, "credit_msat", mvt->credit);
	json_add_amount_msat(stream, "debit_msat", mvt->debit);

	/* Only chain movements */
	if (mvt->output_val)
		json_add_amount_sat_msat(stream,
					 "output_msat", *mvt->output_val);
	if (mvt->output_count > 0)
		json_add_num(stream, "output_count",
			     mvt->output_count);

	if (mvt->fees) {
		json_add_amount_msat(stream, "fees_msat", *mvt->fees);
	}

	json_array_start(stream, "tags");
	for (size_t i = 0; i < tal_count(mvt->tags); i++)
		json_add_string(stream, NULL, mvt_tag_str(mvt->tags[i]));
	json_array_end(stream);

	if (mvt->type == CHAIN_MVT)
		json_add_u32(stream, "blockheight", mvt->blockheight);

	json_add_u32(stream, "timestamp", mvt->timestamp);
	json_add_string(stream, "coin_type", mvt->hrp_name);
}

REGISTER_NOTIFICATION(coin_movement);

void notify_coin_mvt(struct lightningd *ld,
		     const struct coin_mvt *mvt)
{
	struct jsonrpc_notification *n = notify_start("coin_movement");
	coin_movement_notification_serialize(n->stream, mvt);
	notify_send(ld, n);
}

static void balance_snapshot_serialize(struct json_stream *stream,
				       const struct balance_snapshot *snap)
{
	json_add_node_id(stream, "node_id", snap->node_id);
	json_add_u32(stream, "blockheight", snap->blockheight);
	json_add_u32(stream, "timestamp", snap->timestamp);

	json_array_start(stream, "accounts");
	for (size_t i = 0; i < tal_count(snap->accts); i++) {
		json_object_start(stream, NULL);
		json_add_string(stream, "account_id",
				snap->accts[i]->acct_id);
		json_add_amount_msat(stream, "balance_msat",
				     snap->accts[i]->balance);
		json_add_string(stream, "coin_type", snap->accts[i]->bip173_name);
		json_object_end(stream);
	}
	json_array_end(stream);
}

REGISTER_NOTIFICATION(balance_snapshot);

void notify_balance_snapshot(struct lightningd *ld,
			     const struct balance_snapshot *snap)
{
	struct jsonrpc_notification *n = notify_start("balance_snapshot");
	balance_snapshot_serialize(n->stream, snap);
	notify_send(ld, n);
}

static void json_add_block_added_fields(struct json_stream *stream,
					const struct block *block)
{
	json_add_string(stream, "hash",
			fmt_bitcoin_blkid(tmpctx, &block->blkid));
	json_add_u32(stream, "height", block->height);
}

static void block_added_notification_serialize(struct json_stream *stream,
					       struct lightningd *ld,
					       const struct block *block)
{
	if (lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
					 "block_added_notification", "block",
					 "v23.08", "v24.08")) {
		json_object_start(stream, "block");
		json_add_block_added_fields(stream, block);
		json_object_end(stream);
	}
	json_object_start(stream, "block_added");
	json_add_block_added_fields(stream, block);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(block_added);

void notify_block_added(struct lightningd *ld,
			const struct block *block)
{
	struct jsonrpc_notification *n =
		jsonrpc_notification_start(NULL, "block_added");
	block_added_notification_serialize(n->stream, ld, block);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void openchannel_peer_sigs_serialize(struct json_stream *stream,
					    const struct channel_id *cid,
					    const struct wally_psbt *psbt)
{
	json_add_channel_id(stream, "channel_id", cid);
	json_add_psbt(stream, "signed_psbt", psbt);
}

REGISTER_NOTIFICATION(openchannel_peer_sigs);

void notify_openchannel_peer_sigs(struct lightningd *ld,
				  const struct channel_id *cid,
				  const struct wally_psbt *psbt)
{
	struct jsonrpc_notification *n = notify_start("openchannel_peer_sigs");
	openchannel_peer_sigs_serialize(n->stream, cid, psbt);
	notify_send(ld, n);
}

static void channel_open_failed_serialize(struct json_stream *stream,
					  const struct channel_id *cid)
{
	json_add_channel_id(stream, "channel_id", cid);
}

REGISTER_NOTIFICATION(channel_open_failed);

void notify_channel_open_failed(struct lightningd *ld,
				const struct channel_id *cid)
{
	struct jsonrpc_notification *n = notify_start("channel_open_failed");
	channel_open_failed_serialize(n->stream, cid);
	notify_send(ld, n);
}

REGISTER_NOTIFICATION(shutdown);

bool notify_plugin_shutdown(struct lightningd *ld, struct plugin *p)
{
	struct jsonrpc_notification *n = notify_start("shutdown");
	json_object_end(n->stream);
	jsonrpc_notification_end(n);
	return plugin_single_notify(p, take(n));
}

bool notify_deprecated_oneshot(struct lightningd *ld,
			       struct plugin *p,
			       bool deprecated_ok)
{
	struct jsonrpc_notification *n = notify_start("deprecated_oneshot");
	json_add_bool(n->stream, "deprecated_ok", deprecated_ok);
	json_object_end(n->stream);
	jsonrpc_notification_end(n);
	return plugin_single_notify(p, take(n));
}
REGISTER_NOTIFICATION(deprecated_oneshot);
