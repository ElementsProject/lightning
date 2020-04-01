#include <channeld/gen_channel_wire.h>
#include <lightningd/channel.h>
#include <lightningd/lightningd.h>
#include <lightningd/onion_message.h>
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
	struct pubkey *reply_blinding;
	struct onionmsg_path **reply_path;

	if (!fromwire_got_onionmsg_to_us(msg, msg,
					 &reply_blinding, &reply_path)) {
		channel_internal_error(channel, "bad got_onionmsg_tous: %s",
				       tal_hex(tmpctx, msg));
		return;
	}

	log_info(channel->log, "Got onionmsg%s%s",
		 reply_blinding ? " reply_blinding": "",
		 reply_path ? " reply_path": "");
}

void handle_onionmsg_forward(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct short_channel_id *next_scid;
	struct node_id *next_node;
	struct pubkey *next_blinding;
	u8 onion[TOTAL_PACKET_SIZE];
	struct channel *outchan;

	if (!fromwire_got_onionmsg_forward(msg, msg, &next_scid, &next_node,
					   &next_blinding, onion)) {
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
		       take(towire_send_onionmsg(NULL, onion, next_blinding)));
}
#endif /* EXPERIMENTAL_FEATURES */
