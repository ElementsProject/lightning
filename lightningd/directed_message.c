#include <channeld/gen_channel_wire.h>
#include <lightningd/channel.h>
#include <lightningd/directed_message.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

#define DIRECTED_MSG_MAX	1000

#if EXPERIMENTAL_FEATURES
static void destroy_directed_msg(struct directed_msg *di,
				  struct directed_msg_htable *ht)
{
	directed_msg_htable_del(ht, di);
}

static void directed_table_add(struct lightningd *ld,
			       struct peer *source,
			       const struct sha256 *hash_in,
			       const struct sha256 *hash_out,
			       const struct secret *ss)
{
	struct directed_msg *di;

	/* Duplicate?  Forget original. */
	di = directed_msg_htable_get(&ld->directed_msg_htable, hash_out);
	if (di)
		tal_free(di);

	/* Free random one if we've reached capacity. */
	if (directed_msg_htable_count(&ld->directed_msg_htable)
	    > DIRECTED_MSG_MAX) {
		struct directed_msg_htable_iter it;

		/* Prefer to delete same peer. */
		for (size_t i = 0; i < 3; i++) {
			di = directed_msg_htable_pick(&ld->directed_msg_htable,
						      pseudorand_u64(),
						      &it);
			if (di->source == source)
				break;
		}
		directed_msg_htable_delval(&ld->directed_msg_htable, &it);
		tal_free(di);
	}

	/* We forget this if we forget peer. */
	di = tal(source, struct directed_msg);
	di->source = source;
	di->hash_in = *hash_in;
	di->hash_out = *hash_out;
	di->shared_secret = *ss;

	directed_msg_htable_add(&ld->directed_msg_htable, di);
	tal_add_destructor2(di, destroy_directed_msg,
			    &ld->directed_msg_htable);
}

/* Returns false if we can't tell it */
static bool make_peer_send(struct lightningd *ld,
			   struct channel *dst, const u8 *msg TAKES)
{
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
	/* FIXME: We should probably allow this for closingd too. */
	if (!streq(dst->owner->name, "channeld")) {
		log_debug(ld->log, "Can't send %s: owned by %s",
			  channel_wire_type_name(fromwire_peektype(msg)),
			  dst->owner->name);
		return false;
	}
	subd_send_msg(dst->owner, msg);
	return true;
}

void handle_directed_to_us(struct channel *channel, const u8 *msg)
{
	struct sha256 hash_in;
	struct secret ss;
	u8 *payload;

	if (!fromwire_got_directed_tous(msg, msg, &hash_in, &ss, &payload))
		channel_internal_error(channel, "bad got_directed_tous: %s",
				       tal_hex(tmpctx, msg));

	/* FIXME: Wire up directed message handling! */
	log_info(channel->log, "Received directed message %s",
		 tal_hex(tmpctx, payload));
}

void handle_directed_forward(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct secret ss;
	struct node_id next;
	struct sha256 hash_in, hash_out;
	u8 onion[TOTAL_PACKET_SIZE];

	if (!fromwire_got_directed_forward(msg, &hash_in, &ss, &next, onion))
		channel_internal_error(channel, "bad got_directed_forward: %s",
				       tal_hex(tmpctx, msg));

	if (make_peer_send(ld, active_channel_by_id(ld, &next, NULL),
			   take(towire_send_directed_msg(NULL, onion)))) {
		sha256(&hash_out, onion, sizeof(onion));
		/* OK, now remember it so we can route reply */
		directed_table_add(ld, channel->peer, &hash_in, &hash_out, &ss);
	}
}

void handle_directed_reply(struct channel *channel, const u8 *msg)
{
	struct lightningd *ld = channel->peer->ld;
	struct sha256 hash;
	struct onionreply *onionreply;
	struct directed_msg *di;

	if (!fromwire_got_directed_reply(msg, msg, &hash, &onionreply))
		channel_internal_error(channel, "bad got_directed_reply: %s",
				       tal_hex(tmpctx, msg));

	di = directed_msg_htable_get(&ld->directed_msg_htable, &hash);
	if (!di) {
		log_debug(channel->log, "DM reply for unknown hash %s",
			  type_to_string(tmpctx, struct sha256, &hash));
		return;
	}

	make_peer_send(ld, peer_active_channel(di->source),
		       take(towire_send_directed_reply_msg(NULL,
							   &di->hash_in,
							   &di->shared_secret,
							   onionreply)));
	/* Replies are one-shot. */
	tal_free(di);
}
#endif /* EXPERIMENTAL_FEATURES */
