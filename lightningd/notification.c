#include <ccan/array_size/array_size.h>
#include <common/json_helpers.h>
#include <lightningd/channel.h>
#include <lightningd/json.h>
#include <lightningd/notification.h>
#include <lightningd/peer_htlcs.h>

static struct notification *find_notification_by_topic(const char* topic)
{
	static struct notification **notilist = NULL;
	static size_t num_notis;
	if (!notilist)
		notilist = autodata_get(notifications, &num_notis);

	for (size_t i=0; i<num_notis; i++)
		if (streq(notilist[i]->topic, topic))
			return notilist[i];
	return NULL;
}

bool notifications_have_topic(const char *topic)
{
	struct notification *noti = find_notification_by_topic(topic);
	if (noti)
		return true;

	return false;
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

REGISTER_NOTIFICATION(connect,
		      connect_notification_serialize);

void notify_connect(struct lightningd *ld,
		    const struct node_id *nodeid,
		    bool incoming,
		    const struct wireaddr_internal *addr)
{
	void (*serialize)(struct json_stream *,
			  const struct node_id *,
			  bool,
			  const struct wireaddr_internal *) = connect_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, connect_notification_gen.topic);
	serialize(n->stream, nodeid, incoming, addr);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void disconnect_notification_serialize(struct json_stream *stream,
					      struct node_id *nodeid)
{
	json_add_node_id(stream, "id", nodeid);
}

REGISTER_NOTIFICATION(disconnect,
		      disconnect_notification_serialize);

void notify_disconnect(struct lightningd *ld, struct node_id *nodeid)
{
	void (*serialize)(struct json_stream *,
			  struct node_id *) = disconnect_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, disconnect_notification_gen.topic);
	serialize(n->stream, nodeid);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

/*'warning' is based on LOG_UNUSUAL/LOG_BROKEN level log
 *(in plugin module, they're 'warn'/'error' level). */
static void warning_notification_serialize(struct json_stream *stream,
					   struct log_entry *l)
{
	json_object_start(stream, "warning");
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
	json_add_time(stream, "time", l->time.ts);
	json_add_timeiso(stream, "timestamp", &l->time);
	json_add_string(stream, "source", l->prefix);
	json_add_string(stream, "log", l->log);
	json_object_end(stream); /* .warning */
}

REGISTER_NOTIFICATION(warning,
		      warning_notification_serialize);

void notify_warning(struct lightningd *ld, struct log_entry *l)
{
	void (*serialize)(struct json_stream *,
			  struct log_entry *) = warning_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, warning_notification_gen.topic);
	serialize(n->stream, l);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void invoice_payment_notification_serialize(struct json_stream *stream,
						   struct amount_msat amount,
						   struct preimage preimage,
						   const struct json_escape *label)
{
	json_object_start(stream, "invoice_payment");
	json_add_string(stream, "msat",
			type_to_string(tmpctx, struct amount_msat, &amount));
	json_add_hex(stream, "preimage", &preimage, sizeof(preimage));
	json_add_escaped_string(stream, "label", label);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(invoice_payment,
		      invoice_payment_notification_serialize)

void notify_invoice_payment(struct lightningd *ld, struct amount_msat amount,
			    struct preimage preimage, const struct json_escape *label)
{
	void (*serialize)(struct json_stream *,
			  struct amount_msat,
			  struct preimage,
			  const struct json_escape *) = invoice_payment_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, invoice_payment_notification_gen.topic);
	serialize(n->stream, amount, preimage, label);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void invoice_creation_notification_serialize(struct json_stream *stream,
						   struct amount_msat *amount,
						   struct preimage preimage,
						   const struct json_escape *label)
{
	json_object_start(stream, "invoice_creation");
	if (amount != NULL)
		json_add_string(
		    stream, "msat",
		    type_to_string(tmpctx, struct amount_msat, amount));

	json_add_hex(stream, "preimage", &preimage, sizeof(preimage));
	json_add_escaped_string(stream, "label", label);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(invoice_creation,
		      invoice_creation_notification_serialize)

void notify_invoice_creation(struct lightningd *ld, struct amount_msat *amount,
			     struct preimage preimage,
			     const struct json_escape *label)
{
	void (*serialize)(struct json_stream *,
			  struct amount_msat *,
			  struct preimage,
			  const struct json_escape *) = invoice_creation_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, invoice_creation_notification_gen.topic);
	serialize(n->stream, amount, preimage, label);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void channel_opened_notification_serialize(struct json_stream *stream,
						  struct node_id *node_id,
						  struct amount_sat *funding_sat,
						  struct bitcoin_txid *funding_txid,
						  bool *funding_locked)
{
	json_object_start(stream, "channel_opened");
	json_add_node_id(stream, "id", node_id);
	json_add_amount_sat_only(stream, "amount", *funding_sat);
	json_add_txid(stream, "funding_txid", funding_txid);
	json_add_bool(stream, "funding_locked", funding_locked);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(channel_opened,
		      channel_opened_notification_serialize)

void notify_channel_opened(struct lightningd *ld, struct node_id *node_id,
			   struct amount_sat *funding_sat, struct bitcoin_txid *funding_txid,
			   bool *funding_locked)
{
	void (*serialize)(struct json_stream *,
			  struct node_id *,
			  struct amount_sat *,
			  struct bitcoin_txid *,
			  bool *) = channel_opened_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, channel_opened_notification_gen.topic);
	serialize(n->stream, node_id, funding_sat, funding_txid, funding_locked);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void channel_state_changed_notification_serialize(struct json_stream *stream,
							 struct node_id *peer_id,
							 struct channel_id *cid,
							 struct short_channel_id *scid,
							 struct timeabs *timestamp,
							 enum channel_state old_state,
							 enum channel_state new_state,
							 enum state_change cause,
							 char *message)
{
	json_object_start(stream, "channel_state_changed");
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
	json_object_end(stream);
}


REGISTER_NOTIFICATION(channel_state_changed,
		      channel_state_changed_notification_serialize)

void notify_channel_state_changed(struct lightningd *ld,
				  struct node_id *peer_id,
				  struct channel_id *cid,
				  struct short_channel_id *scid,
				  struct timeabs *timestamp,
				  enum channel_state old_state,
				  enum channel_state new_state,
				  enum state_change cause,
				  char *message)
{
	void (*serialize)(struct json_stream *,
			  struct node_id *,
			  struct channel_id *,
			  struct short_channel_id *,
			  struct timeabs *timestamp,
			  enum channel_state,
			  enum channel_state,
			  enum state_change,
			  char *message) = channel_state_changed_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, channel_state_changed_notification_gen.topic);
	serialize(n->stream, peer_id, cid, scid, timestamp, old_state, new_state, cause, message);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void forward_event_notification_serialize(struct json_stream *stream,
						 const struct htlc_in *in,
						 const struct short_channel_id *scid_out,
						 const struct amount_msat *amount_out,
						 enum forward_status state,
						 enum onion_wire failcode,
						 struct timeabs *resolved_time)
{
	/* Here is more neat to initial a forwarding structure than
	 * to pass in a bunch of parameters directly*/
	struct forwarding *cur = tal(tmpctx, struct forwarding);
	cur->channel_in = *in->key.channel->scid;
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
	cur->payment_hash = tal_dup(cur, struct sha256, &in->payment_hash);
	cur->status = state;
	cur->failcode = failcode;
	cur->received_time = in->received_time;
	cur->resolved_time = tal_steal(cur, resolved_time);

	json_format_forwarding_object(stream, "forward_event", cur);
}

REGISTER_NOTIFICATION(forward_event,
		      forward_event_notification_serialize);

void notify_forward_event(struct lightningd *ld,
			  const struct htlc_in *in,
			  const struct short_channel_id *scid_out,
			  const struct amount_msat *amount_out,
			  enum forward_status state,
			  enum onion_wire failcode,
			  struct timeabs *resolved_time)
{
	void (*serialize)(struct json_stream *,
			  const struct htlc_in *,
			  const struct short_channel_id *,
			  const struct amount_msat *,
			  enum forward_status,
			  enum onion_wire,
			  struct timeabs *) = forward_event_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, forward_event_notification_gen.topic);
	serialize(n->stream, in, scid_out, amount_out, state, failcode, resolved_time);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void sendpay_success_notification_serialize(struct json_stream *stream,
						   const struct wallet_payment *payment)
{
	json_object_start(stream, "sendpay_success");
	json_add_payment_fields(stream, payment);
	json_object_end(stream); /* .sendpay_success */
}

REGISTER_NOTIFICATION(sendpay_success,
		      sendpay_success_notification_serialize);

void notify_sendpay_success(struct lightningd *ld,
			    const struct wallet_payment *payment)
{
	void (*serialize)(struct json_stream *,
			  const struct wallet_payment *) = sendpay_success_notification_gen.serialize;

	struct jsonrpc_notification *n =
	    jsonrpc_notification_start(NULL, "sendpay_success");
	serialize(n->stream, payment);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void sendpay_failure_notification_serialize(struct json_stream *stream,
						   const struct wallet_payment *payment,
						   errcode_t pay_errcode,
						   const struct onionreply *onionreply,
						   const struct routing_failure *fail,
						   char *errmsg)
{
	json_object_start(stream, "sendpay_failure");

	/* In line with the format of json error returned
	 * by sendpay_fail(). */
	json_add_member(stream, "code", false, "%" PRIerrcode, pay_errcode);
	json_add_string(stream, "message", errmsg);

	json_object_start(stream, "data");
	json_sendpay_fail_fields(stream,
				 payment,
				 pay_errcode,
				 onionreply,
				 fail);

	json_object_end(stream); /* .data */
	json_object_end(stream); /* .sendpay_failure */
}

REGISTER_NOTIFICATION(sendpay_failure,
		      sendpay_failure_notification_serialize);

void notify_sendpay_failure(struct lightningd *ld,
			    const struct wallet_payment *payment,
			    errcode_t pay_errcode,
			    const struct onionreply *onionreply,
			    const struct routing_failure *fail,
			    const char *errmsg)
{
	void (*serialize)(struct json_stream *,
			  const struct wallet_payment *,
			  errcode_t,
			  const struct onionreply *,
			  const struct routing_failure *,
			  const char *) = sendpay_failure_notification_gen.serialize;

	struct jsonrpc_notification *n =
	    jsonrpc_notification_start(NULL, "sendpay_failure");
	serialize(n->stream, payment, pay_errcode, onionreply, fail, errmsg);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void json_mvt_id(struct json_stream *stream, enum mvt_type mvt_type,
			struct mvt_id *id)
{
	switch (mvt_type) {
		case CHAIN_MVT:
			/* some 'journal entries' don't have a txid */
			if (id->tx_txid)
				json_add_string(stream, "txid",
						type_to_string(tmpctx, struct bitcoin_txid,
							       id->tx_txid));
			/* some chain ledger entries aren't associated with a utxo
			 * e.g. journal updates (due to penalty/state loss) and
			 * chain_fee entries */
			if (id->output_txid) {
				json_add_string(stream, "utxo_txid",
						type_to_string(tmpctx, struct bitcoin_txid,
							       id->output_txid));
				json_add_u32(stream, "vout", id->vout);
			}

			/* on-chain htlcs include a payment hash */
			if (id->payment_hash)
				json_add_sha256(stream, "payment_hash", id->payment_hash);
			return;
		case CHANNEL_MVT:
			json_add_sha256(stream, "payment_hash", id->payment_hash);
			if (id->part_id)
				json_add_u64(stream, "part_id", *id->part_id);
			return;
	}
	abort();
}

static void coin_movement_notification_serialize(struct json_stream *stream,
						 struct coin_mvt *mvt)
{
	json_object_start(stream, "coin_movement");
	json_add_num(stream, "version", mvt->version);
	json_add_node_id(stream, "node_id", mvt->node_id);
	json_add_u64(stream, "movement_idx", mvt->counter);
	json_add_string(stream, "type", mvt_type_str(mvt->type));
	json_add_string(stream, "account_id", mvt->account_id);
	json_mvt_id(stream, mvt->type, &mvt->id);
	json_add_amount_msat_only(stream, "credit", mvt->credit);
	json_add_amount_msat_only(stream, "debit", mvt->debit);
	json_add_string(stream, "tag", mvt_tag_str(mvt->tag));

	/* Only chain movements have blockheights. A blockheight
	 * of 'zero' means we haven't seen this tx confirmed yet. */
	if (mvt->type == CHAIN_MVT) {
		if (mvt->blockheight)
			json_add_u32(stream, "blockheight", mvt->blockheight);
		else
			json_add_null(stream, "blockheight");
	}
	json_add_u32(stream, "timestamp", mvt->timestamp);
	json_add_string(stream, "coin_type", mvt->bip173_name);

	json_object_end(stream);
}

REGISTER_NOTIFICATION(coin_movement,
		      coin_movement_notification_serialize);

void notify_coin_mvt(struct lightningd *ld,
		     const struct coin_mvt *mvt)
{
	void (*serialize)(struct json_stream *,
			  const struct coin_mvt *) = coin_movement_notification_gen.serialize;

	struct jsonrpc_notification *n =
		jsonrpc_notification_start(NULL, "coin_movement");
	serialize(n->stream, mvt);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void openchannel_peer_sigs_serialize(struct json_stream *stream,
					    const struct channel_id *cid,
					    const struct wally_psbt *psbt)
{
	json_object_start(stream, "openchannel_peer_sigs");
	json_add_channel_id(stream, "channel_id", cid);
	json_add_psbt(stream, "signed_psbt", psbt);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(openchannel_peer_sigs,
		      openchannel_peer_sigs_serialize);

void notify_openchannel_peer_sigs(struct lightningd *ld,
				  const struct channel_id *cid,
				  const struct wally_psbt *psbt)
{
	void (*serialize)(struct json_stream *,
			  const struct channel_id *cid,
			  const struct wally_psbt *) = openchannel_peer_sigs_notification_gen.serialize;

	struct jsonrpc_notification *n =
		jsonrpc_notification_start(NULL, "openchannel_peer_sigs");
	serialize(n->stream, cid, psbt);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}

static void channel_open_failed_serialize(struct json_stream *stream,
					  const struct channel_id *cid)
{
	json_object_start(stream, "channel_open_failed");
	json_add_channel_id(stream, "channel_id", cid);
	json_object_end(stream);
}

REGISTER_NOTIFICATION(channel_open_failed,
		      channel_open_failed_serialize);

void notify_channel_open_failed(struct lightningd *ld,
				const struct channel_id *cid)
{
	void (*serialize)(struct json_stream *,
			  const struct channel_id *) = channel_open_failed_notification_gen.serialize;

	struct jsonrpc_notification *n =
		jsonrpc_notification_start(NULL, "channel_open_failed");
	serialize(n->stream, cid);
	jsonrpc_notification_end(n);
	plugins_notify(ld->plugins, take(n));
}
