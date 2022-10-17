/*~ This contains all the code to handle onion messages. */
#include "config.h"
#include <ccan/cast/cast.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/daemon_conn.h>
#include <common/ecdh_hsmd.h>
#include <common/features.h>
#include <common/sphinx.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <connectd/connectd.h>
#include <connectd/connectd_wiregen.h>
#include <connectd/multiplex.h>
#include <connectd/onion_message.h>
#include <wire/peer_wire.h>

void onionmsg_req(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	u8 *onionmsg;
	struct pubkey blinding;
	struct peer *peer;

	if (!fromwire_connectd_send_onionmsg(msg, msg, &id, &onionmsg, &blinding))
		master_badmsg(WIRE_CONNECTD_SEND_ONIONMSG, msg);

	/* Even though lightningd checks for valid ids, there's a race
	 * where it might vanish before we read this command. */
	peer = peer_htable_get(&daemon->peers, &id);
	if (peer) {
		u8 *omsg = towire_onion_message(NULL, &blinding, onionmsg);
		inject_peer_msg(peer, take(omsg));
	}
}

static bool decrypt_final_onionmsg(const tal_t *ctx,
				   const struct pubkey *blinding,
				   const struct secret *ss,
				   const u8 *enctlv,
				   const struct pubkey *my_id,
				   struct pubkey *alias,
				   struct secret **path_id)
{
	struct tlv_encrypted_data_tlv *encmsg;

	if (!blindedpath_get_alias(ss, my_id, alias))
		return false;

	encmsg = decrypt_encrypted_data(tmpctx, blinding, ss, enctlv);
	if (!encmsg)
		return false;

	if (tal_bytelen(encmsg->path_id) == sizeof(**path_id)) {
		*path_id = tal(ctx, struct secret);
		memcpy(*path_id, encmsg->path_id, sizeof(**path_id));
	} else
		*path_id = NULL;

	return true;
}

static bool decrypt_forwarding_onionmsg(const struct pubkey *blinding,
					const struct secret *ss,
					const u8 *enctlv,
					struct pubkey *next_node,
					struct pubkey *next_blinding)
{
	struct tlv_encrypted_data_tlv *encmsg;

	encmsg = decrypt_encrypted_data(tmpctx, blinding, ss, enctlv);
	if (!encmsg)
		return false;

	/* BOLT-onion-message #4:
	 *
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `enctlv` ... does not contain
	 *      `next_node_id`:
	 *      - MUST drop the message.
	 */
	if (!encmsg->next_node_id)
		return false;

	/* BOLT-onion-message #4:
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `enctlv` contains `path_id`:
	 *      - MUST drop the message.
	 */
	if (encmsg->path_id)
		return false;

	*next_node = *encmsg->next_node_id;
	blindedpath_next_blinding(encmsg, blinding, ss, next_blinding);
	return true;
}

/* Peer sends an onion msg. */
void handle_onion_message(struct daemon *daemon,
			  struct peer *peer, const u8 *msg)
{
	enum onion_wire badreason;
	struct onionpacket *op;
	struct pubkey blinding, ephemeral;
	struct route_step *rs;
	u8 *onion;
	struct tlv_onionmsg_tlv *om;
	struct secret ss, onion_ss;
	const u8 *cursor;
	size_t max, maxlen;

	/* Ignore unless explicitly turned on. */
	if (!feature_offered(daemon->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return;

	/* FIXME: ratelimit! */
	if (!fromwire_onion_message(msg, msg, &blinding, &onion)) {
		inject_peer_msg(peer,
				towire_warningfmt(NULL, NULL,
						  "Bad onion_message"));
		return;
	}

	/* We unwrap the onion now. */
	op = parse_onionpacket(tmpctx, onion, tal_bytelen(onion), &badreason);
	if (!op) {
		status_peer_debug(&peer->id, "onion msg: can't parse onionpacket: %s",
				  onion_wire_name(badreason));
		return;
	}

	ephemeral = op->ephemeralkey;
	if (!unblind_onion(&blinding, ecdh, &ephemeral, &ss)) {
		status_peer_debug(&peer->id, "onion msg: can't unblind onionpacket");
		return;
	}

	/* Now get onion shared secret and parse it. */
	ecdh(&ephemeral, &onion_ss);
	rs = process_onionpacket(tmpctx, op, &onion_ss, NULL, 0, false);
	if (!rs) {
		status_peer_debug(&peer->id,
				  "onion msg: can't process onionpacket ss=%s",
				  type_to_string(tmpctx, struct secret, &onion_ss));
		return;
	}

	/* The raw payload is prepended with length in the modern onion. */
	cursor = rs->raw_payload;
	max = tal_bytelen(rs->raw_payload);
	maxlen = fromwire_bigsize(&cursor, &max);
	if (!cursor) {
		status_peer_debug(&peer->id, "onion msg: Invalid hop payload %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return;
	}
	if (maxlen > max) {
		status_peer_debug(&peer->id, "onion msg: overlong hop payload %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return;
	}

	om = fromwire_tlv_onionmsg_tlv(msg, &cursor, &maxlen);
	if (!om) {
		status_peer_debug(&peer->id, "onion msg: invalid onionmsg_tlv %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return;
	}

	if (rs->nextcase == ONION_END) {
		struct pubkey alias;
		struct secret *self_id;
		u8 *omsg;

		/* Final enctlv is actually optional */
		if (!om->encrypted_recipient_data) {
			alias = daemon->mykey;
			self_id = NULL;
		} else if (!decrypt_final_onionmsg(tmpctx, &blinding, &ss,
						   om->encrypted_recipient_data, &daemon->mykey, &alias,
						   &self_id)) {
			status_peer_debug(&peer->id,
					  "onion msg: failed to decrypt encrypted_recipient_data"
					  " %s", tal_hex(tmpctx, om->encrypted_recipient_data));
			return;
		}

		/* We re-marshall here by policy, before handing to lightningd */
		omsg = tal_arr(tmpctx, u8, 0);
		towire_tlvstream_raw(&omsg, om->fields);
		daemon_conn_send(daemon->master,
				 take(towire_connectd_got_onionmsg_to_us(NULL,
							&alias, self_id,
							om->reply_path,
							omsg)));
	} else {
		struct pubkey next_node, next_blinding;
		struct peer *next_peer;
		struct node_id next_node_id;

		/* This fails as expected if no enctlv. */
		if (!decrypt_forwarding_onionmsg(&blinding, &ss, om->encrypted_recipient_data, &next_node,
					       &next_blinding)) {
			status_peer_debug(&peer->id,
					  "onion msg: invalid encrypted_recipient_data %s",
					  tal_hex(tmpctx, om->encrypted_recipient_data));
			return;
		}

		/* FIXME: Handle short_channel_id! */
		node_id_from_pubkey(&next_node_id, &next_node);
		next_peer = peer_htable_get(&daemon->peers, &next_node_id);
		if (!next_peer) {
			status_peer_debug(&peer->id,
					  "onion msg: unknown next peer %s",
					  type_to_string(tmpctx,
							 struct pubkey,
							 &next_node));
			return;
		}
		inject_peer_msg(next_peer,
				take(towire_onion_message(NULL,
							  &next_blinding,
							  serialize_onionpacket(tmpctx, rs->next))));
	}
}

