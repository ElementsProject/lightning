#include <channeld/gen_channel_wire.h>
#include <common/json_helpers.h>
#include <lightningd/channel.h>
#include <lightningd/onion_message.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/plugin_hook.h>
#include <lightningd/subd.h>

#if EXPERIMENTAL_FEATURES
struct onion_message_hook_payload {
	/* plaintext is NULL if we couldn't decrypt. */
	const u8 *plaintext;
	struct secret ss;
	u8 *e2e_payload;
	/* These are *optional* */
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	u8 *reply_onion;
};

static void
onion_message_serialize(struct onion_message_hook_payload *payload,
			   struct json_stream *stream)
{
	json_object_start(stream, "onion_message");
	if (payload->plaintext) {
		json_add_hex_talarr(stream, "plaintext", payload->plaintext);
	} else {
		json_add_hex_talarr(stream, "payload", payload->e2e_payload);
	}
	json_add_secret(stream, "shared_secret", &payload->ss);
	if (payload->next_scid)
		json_add_short_channel_id(stream, "next_short_channel_id",
					  payload->next_scid);
	if (payload->next_node)
		json_add_node_id(stream, "next_node_id", payload->next_node);
	if (payload->reply_onion)
		json_add_hex_talarr(stream, "reply_onion", payload->reply_onion);
	json_object_end(stream);
}

static void
onion_message_hook_cb(struct onion_message_hook_payload *payload,
			 const char *buffer,
			 const jsmntok_t *toks)
{
	/* The core infra checks the "result"; anything other than continue
	 * just stops. */
	tal_free(payload);
}

REGISTER_PLUGIN_HOOK(onion_message,
		     PLUGIN_HOOK_CHAIN,
		     onion_message_hook_cb,
		     struct onion_message_hook_payload *,
		     onion_message_serialize,
		     struct onion_message_hook_payload *);

/* Returns false if we can't tell it */
static bool make_peer_send(struct lightningd *ld,
			   struct channel *dst, const u8 *msg TAKES)
{
	/* Take ownership of msg (noop if it's taken) */
	msg = tal_dup_talarr(tmpctx, u8, msg);

	if (!dst) {
		log_debug(ld->log, "Can't send %s: no channel",
			  channel_wire_type_name(fromwire_peektype(msg)));
		return false;
	}

	if (!dst->owner) {
		log_debug(ld->log, "Can't send %s: not connected",
			  channel_wire_type_name(fromwire_peektype(msg)));
		return false;
	}

	/* FIXME: We should allow this for closingd too, and we should
	 * allow incoming via openingd!. */
	if (!streq(dst->owner->name, "channeld")) {
		log_debug(ld->log, "Can't send %s: owned by %s",
			  channel_wire_type_name(fromwire_peektype(msg)),
			  dst->owner->name);
		return false;
	}
	subd_send_msg(dst->owner, take(msg));
	return true;
}

void handle_onionmsg_to_us(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct onion_message_hook_payload *payload;

	payload = tal(ld, struct onion_message_hook_payload);
	if (!fromwire_got_onionmsg_to_us(payload, msg,
					 &payload->next_scid,
					 &payload->next_node,
					 &payload->reply_onion,
					 &payload->ss,
					 &payload->e2e_payload)) {
		channel_internal_error(channel, "bad got_onionmsg_tous: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	payload->plaintext = final_e2e_payload(payload,
					       payload->e2e_payload,
					       &payload->ss);
	if (!payload->plaintext) {
		log_info(channel->log, "Received invalid onion message %s%s",
			 tal_hex(tmpctx, payload->e2e_payload),
			 payload->reply_onion ? " (with reply_onion)": "");
	} else {
		log_info(channel->log, "Received onion message %s%s",
			 tal_hex(tmpctx, payload->plaintext),
			 payload->reply_onion ? " (with reply_onion)": "");
	}
	plugin_hook_call_onion_message(ld, payload, payload);
}

void handle_onionmsg_forward(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	u8 *e2e_payload;
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	u8 onion[TOTAL_PACKET_SIZE];
	struct channel *outchan;

	if (!fromwire_got_onionmsg_forward(msg, msg, &next_scid, &next_node,
					   onion, &e2e_payload)) {
		channel_internal_error(channel, "bad got_onionmsg_forward: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	if (next_scid)
		outchan = active_channel_by_scid(ld, next_scid);
	else if (next_node) {
		struct peer *p = peer_by_id(ld, next_node);
		if (p)
			outchan = peer_active_channel(p);
		else
			outchan = NULL;
	} else
		outchan = NULL;

	make_peer_send(ld, outchan,
		       take(towire_send_onionmsg(NULL, onion, e2e_payload)));
}
#endif /* EXPERIMENTAL_FEATURES */
