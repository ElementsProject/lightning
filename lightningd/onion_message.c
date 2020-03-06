#include <channeld/gen_channel_wire.h>
#include <lightningd/channel.h>
#include <lightningd/onion_message.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

#if EXPERIMENTAL_FEATURES
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
	u8 *e2e_payload, *plaintext;
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	u8 *next_onion;
	struct secret ss;

	if (!fromwire_got_onionmsg_to_us(msg, msg, &next_scid, &next_node,
					 &next_onion, &ss, &e2e_payload)) {
		channel_internal_error(channel, "bad got_onionmsg_tous: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	/* FIXME: Wire up onion message handling! */
	plaintext = final_e2e_payload(msg, e2e_payload, &ss);
	if (!plaintext) {
		log_info(channel->log, "Received invalid onion message %s%s",
			 tal_hex(tmpctx, e2e_payload),
			 next_onion ? " (with next_onion)": "");
	} else {
		log_info(channel->log, "Received onion message %s%s",
			 tal_hex(tmpctx, plaintext),
			 next_onion ? " (with next_onion)": "");
	}
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
