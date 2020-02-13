#include <ccan/array_size/array_size.h>
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
					   struct node_id *nodeid,
					   struct wireaddr_internal *addr)
{
	json_add_node_id(stream, "id", nodeid);
	json_add_address_internal(stream, "address", addr);
}

REGISTER_NOTIFICATION(connect,
		      connect_notification_serialize);

void notify_connect(struct lightningd *ld, struct node_id *nodeid,
		    struct wireaddr_internal *addr)
{
	void (*serialize)(struct json_stream *,
			  struct node_id *,
			  struct wireaddr_internal *) = connect_notification_gen.serialize;

	struct jsonrpc_notification *n
		= jsonrpc_notification_start(NULL, connect_notification_gen.topic);
	serialize(n->stream, nodeid, addr);
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

static void forward_event_notification_serialize(struct json_stream *stream,
						 const struct htlc_in *in,
						 const struct short_channel_id *scid_out,
						 const struct amount_msat *amount_out,
						 enum forward_status state,
						 enum onion_type failcode,
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
			  enum onion_type failcode,
			  struct timeabs *resolved_time)
{
	void (*serialize)(struct json_stream *,
			  const struct htlc_in *,
			  const struct short_channel_id *,
			  const struct amount_msat *,
			  enum forward_status,
			  enum onion_type,
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
