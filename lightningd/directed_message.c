#include <channeld/gen_channel_wire.h>
#include <common/json_helpers.h>
#include <lightningd/channel.h>
#include <lightningd/directed_message.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <lightningd/subd.h>

#define DIRECTED_MSG_MAX	1000

#if EXPERIMENTAL_FEATURES
static LIST_HEAD(our_dms);

struct our_dm {
	struct list_node list;
	struct command *cmd;
	struct sha256 hash;
	struct secret *shared_secrets;
};

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
	struct onionreply *onionreply;
	u8 *payload;

	if (!fromwire_got_directed_tous(msg, msg, &hash_in, &ss, &payload))
		channel_internal_error(channel, "bad got_directed_tous: %s",
				       tal_hex(tmpctx, msg));

	/* FIXME: Wire up directed message handling! */
	log_info(channel->log, "Received directed message %s",
		 tal_hex(tmpctx, payload));

	onionreply = create_onionreply(tmpctx, &ss,
				       (u8 *)tal_fmt(tmpctx, "Reply to msg len %zu",
						     tal_bytelen(payload)));

	make_peer_send(channel->peer->ld, channel,
		       take(towire_send_directed_reply_msg(NULL, &hash_in, &ss,
							   onionreply)));
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

static struct our_dm *find_our_dm(struct lightningd *ld,
				  const struct sha256 *hash)
{
	struct our_dm *dm;

	list_for_each(&our_dms, dm, list) {
		if (sha256_eq(&dm->hash, hash))
			return dm;
	}
	return NULL;
}

static bool handle_reply_to_our_dm(struct lightningd *ld,
				   const struct sha256 *hash,
				   const struct onionreply *onionreply)
{
	int origin;
	u8 *resp;
	struct our_dm *dm = find_our_dm(ld, hash);

	if (!dm)
		return false;

	list_del_from(&our_dms, &dm->list);
	resp = unwrap_onionreply(dm->cmd, dm->shared_secrets,
				 tal_count(dm->shared_secrets),
				 onionreply, &origin);
	if (!resp) {
		was_pending(command_fail(dm->cmd, LIGHTNINGD,
					 "Invalid onionreply"));
	} else if (origin != tal_count(dm->shared_secrets)-1) {
		was_pending(command_fail(dm->cmd, LIGHTNINGD,
					 "Onionreply from node %i", origin));
	} else {
		struct json_stream *response = json_stream_success(dm->cmd);
		json_add_hex(response, "reply", resp, tal_bytelen(resp));
		was_pending(command_success(dm->cmd, response));
	}
	return true;
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

	if (handle_reply_to_our_dm(ld, &hash, onionreply))
		return;

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

static struct command_result *param_pubkey_array(struct command *cmd,
						 const char *name,
						 const char *buffer,
						 const jsmntok_t *tok,
						 struct pubkey **arr)
{
	const jsmntok_t *t;
	size_t i;

	if (tok->type != JSMN_ARRAY)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "'%s' should be an array, not '%.*s'",
				    name, tok->end - tok->start,
				    buffer + tok->start);

	*arr = tal_arr(cmd, struct pubkey, tok->size);
	json_for_each_arr(i, t, tok) {
		if (!json_to_pubkey(buffer, t, &(*arr)[i]))
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s[%zu] '%.*s' not a valid node id",
					    name, i, t->end - t->start,
					    buffer + t->start);
	}
	return NULL;
}

/* This would be a better sphinx API, once we remove legacy payloads! */
static void sphinx_add_tlv_hop(struct log *log,
			       struct sphinx_path *sp,
			       const struct pubkey *pubkey,
			       const void *arr,
			       size_t arrlen)
{
	u8 *payload = tal_arr(NULL, u8, 0);
	towire_bigsize(&payload, arrlen);
	towire(&payload, arr, arrlen);
	sphinx_add_hop(sp, pubkey, take(payload));
}

static struct command_result *json_send_message(struct command *cmd,
						const char *buffer,
						const jsmntok_t *obj UNNEEDED,
						const jsmntok_t *params)
{
	struct pubkey *nodes;
	const char *message;
	struct sphinx_path *sp;
	struct onionpacket *packet;
	const u8 *ser;
	struct our_dm *dm;
	struct node_id first;
	struct peer *peer;

	if (!param(cmd, buffer, params,
		   p_req("message", param_string, &message),
		   p_req("nodes", param_pubkey_array, &nodes),
		   NULL))
		return command_param_failed();

	if (tal_count(nodes) == 0)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Empty nodes parameter");

	/* Sphinx path, with each one containing the next hop */
	sp = sphinx_path_new(cmd, NULL);
	for (size_t i = 0; i < tal_count(nodes) - 1; i++) {
		u8 *payload = tal_arr(sp, u8, 0);
		towire_pubkey(&payload, &nodes[i+1]);
		sphinx_add_tlv_hop(cmd->ld->log,
				   sp, &nodes[i], payload, tal_bytelen(payload));
	}
	/* Final one contains message. */
	sphinx_add_tlv_hop(cmd->ld->log,sp, &nodes[tal_count(nodes)-1],
			   message, strlen(message));

	if (sphinx_path_payloads_size(sp) > ROUTING_INFO_SIZE)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Payloads exceed maximum onion packet size.");

	node_id_from_pubkey(&first, &nodes[0]);
	peer = peer_by_id(cmd->ld, &first);
	if (!peer)
		return command_fail(cmd, LIGHTNINGD, "First peer not connected");

	dm = tal(cmd, struct our_dm);
	dm->cmd = cmd;
	packet = create_onionpacket(dm, sp, &dm->shared_secrets);

	for (size_t i = 0; i < tal_count(dm->shared_secrets); i++)
		log_debug(cmd->ld->log, "shared_secrets[%zi] = %s",
			  i, type_to_string(tmpctx, struct secret,
					    &dm->shared_secrets[i]));

	ser = serialize_onionpacket(NULL, packet);
	sha256(&dm->hash, ser, tal_bytelen(ser));

	if (!make_peer_send(cmd->ld, peer_active_channel(peer),
			    take(towire_send_directed_msg(NULL, ser))))
		return command_fail(cmd, LIGHTNINGD, "First peer not ready");

	list_add(&our_dms, &dm->list);
	return command_still_pending(cmd);
}

static const struct json_command send_message_command = {
	"sendmessage",
	"utility",
	json_send_message,
	"Send {message} via onion message via {route} node id array"
};
AUTODATA(json_command, &send_message_command);
#endif /* EXPERIMENTAL_FEATURES */
