#include "config.h"
#include <ccan/cast/cast.h>
#include <common/configdir.h>
#include <lightningd/channel.h>
#include <lightningd/coin_mvts.h>
#include <lightningd/log.h>
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
static struct jsonrpc_notification *notify_start(struct lightningd *ld,
						 const char *name)
{
	struct jsonrpc_notification *n;

	/* Optimization: does anyone care? */
	if (!plugins_anyone_cares(ld->plugins, name))
		return NULL;

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

static void connect_notification_serialize(struct json_stream *stream,
					   const struct node_id *nodeid,
					   bool incoming,
					   const struct wireaddr_internal *addr)
{
	json_add_node_id(stream, "id", nodeid);
	json_add_string(stream, "direction", incoming ? "in" : "out");
	json_add_address_internal(stream, "address", addr);
}
REGISTER_NOTIFICATION(connect);

void notify_connect(struct lightningd *ld,
		    const struct node_id *nodeid,
		    bool incoming,
		    const struct wireaddr_internal *addr)
{
	struct jsonrpc_notification *n = notify_start(ld, "connect");
	if (!n)
		return;
	connect_notification_serialize(n->stream, nodeid, incoming, addr);
	notify_send(ld, n);
}

static void disconnect_notification_serialize(struct json_stream *stream,
					      const struct node_id *nodeid)
{
	json_add_node_id(stream, "id", nodeid);
}
REGISTER_NOTIFICATION(disconnect);

void notify_disconnect(struct lightningd *ld, struct node_id *nodeid)
{
	struct jsonrpc_notification *n = notify_start(ld, "disconnect");
	if (!n)
		return;
	disconnect_notification_serialize(n->stream, nodeid);
	notify_send(ld, n);
}

/*'warning' is based on LOG_UNUSUAL/LOG_BROKEN level log
 *(in plugin module, they're 'warn'/'error' level). */
static void warning_notification_serialize(struct json_stream *stream,
					   struct log_entry *l)
{
	/* Choose "BROKEN"/"UNUSUAL" to keep consistent with the habit
	 * of plugin. But this may confuses the users who want to 'getlog'
	 * with the level indicated by notifications. It is the duty of a
	 * plugin to eliminate this misunderstanding. */
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
	struct jsonrpc_notification *n = notify_start(ld, "warning");
	if (!n)
		return;
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
	struct jsonrpc_notification *n = notify_start(ld, "custommsg");
	if (!n)
		return;
	custommsg_notification_serialize(n->stream, peer_id, msg);
	notify_send(ld, n);
}

static void onionmessage_forward_fail_serialize(struct json_stream *stream,
						const struct node_id *source,
						const u8 *incoming,
						const struct pubkey *path_key,
						const u8 *outgoing,
						const struct sciddir_or_pubkey *next_node)
{
	json_add_node_id(stream, "source", source);
	json_add_hex_talarr(stream, "incoming", incoming);
	json_add_pubkey(stream, "path_key", path_key);
	if (tal_count(outgoing) != 0) {
		json_add_hex_talarr(stream, "outgoing", outgoing);
		if (next_node->is_pubkey)
			json_add_pubkey(stream, "next_node_id", &next_node->pubkey);
		else
			json_add_short_channel_id_dir(stream, "next_short_channel_id_dir",
						      next_node->scidd);
	}
}

REGISTER_NOTIFICATION(onionmessage_forward_fail);

void notify_onionmessage_forward_fail(struct lightningd *ld,
				      const struct node_id *source,
				      const u8 *incoming,
				      const struct pubkey *path_key,
				      const u8 *outgoing,
				      const struct sciddir_or_pubkey *next_node)
{
	struct jsonrpc_notification *n = notify_start(ld, "onionmessage_forward_fail");
	if (!n)
		return;
	onionmessage_forward_fail_serialize(n->stream,
					    source,
					    incoming,
					    path_key,
					    outgoing,
					    next_node);
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
	struct jsonrpc_notification *n = notify_start(ld, "invoice_payment");
	if (!n)
		return;
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
	struct jsonrpc_notification *n = notify_start(ld, "invoice_creation");
	if (!n)
		return;
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
	json_add_bool(stream, "channel_ready", channel_ready);
}

REGISTER_NOTIFICATION(channel_opened)

void notify_channel_opened(struct lightningd *ld,
			   const struct node_id *node_id,
			   const struct amount_sat *funding_sat,
			   const struct bitcoin_txid *funding_txid,
			   bool channel_ready)
{
	struct jsonrpc_notification *n = notify_start(ld, "channel_opened");
	if (!n)
		return;
	channel_opened_notification_serialize(n->stream, ld, node_id, funding_sat, funding_txid, channel_ready);
	notify_send(ld, n);
}

static void channel_state_changed_notification_serialize(struct json_stream *stream,
							 struct lightningd *ld,
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
		json_add_short_channel_id(stream, "short_channel_id", *scid);
	else if (lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
					      "channel_state_changed",
					      "null_scid",
					      "v25.09", "v26.09"))
		json_add_null(stream, "short_channel_id");
	json_add_timeiso(stream, "timestamp", timestamp);
	if (old_state != 0 || lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
							   "channel_state_changed", "old_state.unknown",
							   "v25.05", "v26.03"))
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
	struct jsonrpc_notification *n = notify_start(ld, "channel_state_changed");
	if (!n)
		return;
	channel_state_changed_notification_serialize(n->stream, ld, peer_id, cid, scid, timestamp, old_state, new_state, cause, message);
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
	cur->channel_in = channel_scid_or_local_alias(in->key.channel);

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
	struct jsonrpc_notification *n = notify_start(ld, "forward_event");
	if (!n)
		return;
	forward_event_notification_serialize(n->stream, in, scid_out, amount_out, state, failcode, resolved_time, forward_style, created_index, updated_index);
	notify_send(ld, n);
}

REGISTER_NOTIFICATION(sendpay_success);

void notify_sendpay_success(struct lightningd *ld,
			    const struct wallet_payment *payment)
{
	struct jsonrpc_notification *n = notify_start(ld, "sendpay_success");
	if (!n)
		return;
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
	struct jsonrpc_notification *n = notify_start(ld, "sendpay_failure");
	if (!n)
		return;
	sendpay_failure_notification_serialize(n->stream, payment, pay_errcode, onionreply, fail, errmsg);
	notify_send(ld, n);
}

static void json_add_standard_notify_mvt_fields(struct json_stream *stream,
						struct lightningd *ld,
						const char *type)
{
	json_add_num(stream, "version", COIN_MVT_VERSION);
 	json_add_string(stream, "coin_type", chainparams->lightning_hrp);
 	json_add_node_id(stream, "node_id", &ld->our_nodeid);
	json_add_string(stream, "type", type);
}

REGISTER_NOTIFICATION(coin_movement);

void notify_channel_mvt(struct lightningd *ld,
			const struct channel_coin_mvt *chan_mvt)
{
	bool include_tags_arr;
	struct jsonrpc_notification *n = notify_start(ld, "coin_movement");
	if (!n)
		return;
	include_tags_arr = lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
							"coin_movement", "tags",
							"v25.09", "v26.09");

	json_add_standard_notify_mvt_fields(n->stream, ld, "channel_mvt");
	/* Adding (empty) extra_tags field unifies this with notify_chain_mvt */
	json_add_channel_mvt_fields(n->stream, include_tags_arr, chan_mvt, true);
	notify_send(ld, n);
}

void notify_chain_mvt(struct lightningd *ld,
		      const struct chain_coin_mvt *chain_mvt)
{
	bool include_tags_arr, include_old_utxo_fields, include_old_txid_field;
	struct jsonrpc_notification *n = notify_start(ld, "coin_movement");
	if (!n)
		return;

	include_tags_arr = lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
							"coin_movement", "tags",
							"v25.09", "v26.09");
	include_old_utxo_fields = lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
							"coin_movement", "utxo_txid",
							"v25.09", "v26.09");
	include_old_txid_field = lightningd_deprecated_out_ok(ld, ld->deprecated_ok,
							"coin_movement", "txid",
							"v25.09", "v26.09");

	json_add_standard_notify_mvt_fields(n->stream, ld, "chain_mvt");
	json_add_chain_mvt_fields(n->stream,
				  include_tags_arr,
				  include_old_utxo_fields,
				  include_old_txid_field,
				  chain_mvt);
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
	struct jsonrpc_notification *n = notify_start(ld, "balance_snapshot");
	if (!n)
		return;
	balance_snapshot_serialize(n->stream, snap);
	notify_send(ld, n);
}

static void block_added_notification_serialize(struct json_stream *stream,
					       const struct block *block)
{
	json_add_string(stream, "hash",
			fmt_bitcoin_blkid(tmpctx, &block->blkid));
	json_add_u32(stream, "height", block->height);
}
REGISTER_NOTIFICATION(block_added);

void notify_block_added(struct lightningd *ld,
			const struct block *block)
{
	struct jsonrpc_notification *n = notify_start(ld, "block_added");
	if (!n)
		return;
	block_added_notification_serialize(n->stream, block);
	notify_send(ld, n);
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
	struct jsonrpc_notification *n = notify_start(ld, "openchannel_peer_sigs");
	if (!n)
		return;
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
	struct jsonrpc_notification *n = notify_start(ld, "channel_open_failed");
	if (!n)
		return;
	channel_open_failed_serialize(n->stream, cid);
	notify_send(ld, n);
}

REGISTER_NOTIFICATION(shutdown);

bool notify_plugin_shutdown(struct lightningd *ld, struct plugin *p)
{
	struct jsonrpc_notification *n = notify_start(ld, "shutdown");
	if (!n)
		return false;
	json_object_end(n->stream);
	jsonrpc_notification_end(n);
	return plugin_single_notify(p, take(n));
}

bool notify_deprecated_oneshot(struct lightningd *ld,
			       struct plugin *p,
			       bool deprecated_ok)
{
	struct jsonrpc_notification *n = notify_start(ld, "deprecated_oneshot");
	if (!n)
		return false;
	json_add_bool(n->stream, "deprecated_ok", deprecated_ok);
	json_object_end(n->stream);
	jsonrpc_notification_end(n);
	return plugin_single_notify(p, take(n));
}
REGISTER_NOTIFICATION(deprecated_oneshot);

static void log_notification_serialize(struct json_stream *stream,
				       const struct log_entry *l)
{
	json_add_string(stream, "level", log_level_name(l->level));
	json_add_timestr(stream, "time", l->time.ts);
	json_add_timeiso(stream, "timestamp", l->time);
	json_add_string(stream, "source", l->prefix->prefix);
	json_add_string(stream, "log", l->log);
}


REGISTER_NOTIFICATION(log);

void notify_log(struct lightningd *ld, const struct log_entry *l)
{
	struct jsonrpc_notification *n;

	n = notify_start(ld, "log");
	if (!n)
		return;
	log_notification_serialize(n->stream, l);
	notify_send(ld, n);
}

static void plugin_notification_serialize(struct json_stream *stream,
					  struct plugin *plugin)
{
	json_add_string(stream, "plugin_name", plugin->shortname);
	json_add_string(stream, "plugin_path", plugin->cmd);
	json_array_start(stream, "methods");
	for (size_t i = 0; i < tal_count(plugin->methods); i++) {
		json_add_string(stream, NULL, plugin->methods[i]);
	}
	json_array_end(stream);
}

REGISTER_NOTIFICATION(plugin_started);

void notify_plugin_started(struct lightningd *ld, struct plugin *plugin)
{
	struct jsonrpc_notification *n = notify_start(ld, "plugin_started");
	if (!n)
		return;
	plugin_notification_serialize(n->stream, plugin);
	notify_send(ld, n);
}

REGISTER_NOTIFICATION(plugin_stopped);

void notify_plugin_stopped(struct lightningd *ld, struct plugin *plugin)
{
	struct jsonrpc_notification *n = notify_start(ld, "plugin_stopped");
	if (!n)
		return;
	plugin_notification_serialize(n->stream, plugin);
	notify_send(ld, n);
}
