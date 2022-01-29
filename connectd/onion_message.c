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

/* Peer sends obsolete onion msg. */
void handle_obs2_onion_message(struct daemon *daemon,
			       struct peer *peer, const u8 *msg)
{
	enum onion_wire badreason;
	struct onionpacket *op;
	struct pubkey blinding, ephemeral;
	struct route_step *rs;
	u8 *onion;
	struct tlv_obs2_onionmsg_payload *om;
	struct secret ss, onion_ss;
	const u8 *cursor;
	size_t max, maxlen;

	/* Ignore unless explicitly turned on. */
	if (!feature_offered(daemon->our_features->bits[NODE_ANNOUNCE_FEATURE],
			     OPT_ONION_MESSAGES))
		return;

	/* FIXME: ratelimit! */
	if (!fromwire_obs2_onion_message(msg, msg, &blinding, &onion)) {
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

	om = tlv_obs2_onionmsg_payload_new(msg);
	if (!fromwire_obs2_onionmsg_payload(&cursor, &maxlen, om)) {
		status_peer_debug(&peer->id, "onion msg: invalid onionmsg_payload %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return;
	}

	if (rs->nextcase == ONION_END) {
		struct pubkey *reply_blinding, *first_node_id, me, alias;
		const struct onionmsg_path **reply_path;
		struct secret *self_id;
		u8 *omsg;

		if (!pubkey_from_node_id(&me, &daemon->id)) {
			status_broken("Failed to convert own id");
			return;
		}

		/* Final enctlv is actually optional */
		if (!om->enctlv) {
			alias = me;
			self_id = NULL;
		} else if (!decrypt_obs2_final_enctlv(tmpctx, &blinding, &ss,
						      om->enctlv, &me, &alias,
						      &self_id)) {
			status_peer_debug(&peer->id,
					  "onion msg: failed to decrypt enctlv"
					  " %s", tal_hex(tmpctx, om->enctlv));
			return;
		}

		if (om->reply_path) {
			first_node_id = &om->reply_path->first_node_id;
			reply_blinding = &om->reply_path->blinding;
			reply_path = cast_const2(const struct onionmsg_path **,
						 om->reply_path->path);
		} else {
			first_node_id = NULL;
			reply_blinding = NULL;
			reply_path = NULL;
		}

		/* We re-marshall here by policy, before handing to lightningd */
		omsg = tal_arr(tmpctx, u8, 0);
		towire_tlvstream_raw(&omsg, om->fields);
		daemon_conn_send(daemon->master,
				 take(towire_connectd_got_onionmsg_to_us(NULL,
							true, /* obs2 */
							&alias, self_id,
							reply_blinding,
							first_node_id,
							reply_path,
							omsg)));
	} else {
		struct pubkey next_node, next_blinding;
		struct peer *next_peer;
		struct node_id next_node_id;

		/* This fails as expected if no enctlv. */
		if (!decrypt_obs2_enctlv(&blinding, &ss, om->enctlv, &next_node,
					 &next_blinding)) {
			status_peer_debug(&peer->id,
					  "onion msg: invalid enctlv %s",
					  tal_hex(tmpctx, om->enctlv));
			return;
		}

		/* Even though lightningd checks for valid ids, there's a race
		 * where it might vanish before we read this command. */
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
				take(towire_obs2_onion_message(NULL,
							       &next_blinding,
							       serialize_onionpacket(tmpctx, rs->next))));
	}
}

void onionmsg_req(struct daemon *daemon, const u8 *msg)
{
	struct node_id id;
	u8 *onionmsg;
	struct pubkey blinding;
	struct peer *peer;
	bool obs2;

	if (!fromwire_connectd_send_onionmsg(msg, msg, &obs2, &id, &onionmsg, &blinding))
		master_badmsg(WIRE_CONNECTD_SEND_ONIONMSG, msg);

	/* Even though lightningd checks for valid ids, there's a race
	 * where it might vanish before we read this command. */
	peer = peer_htable_get(&daemon->peers, &id);
	if (peer) {
		u8 *omsg;
		if (obs2)
			omsg = towire_obs2_onion_message(NULL, &blinding, onionmsg);
		else
			omsg = towire_onion_message(NULL, &blinding, onionmsg);
		inject_peer_msg(peer, take(omsg));
	}
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
	struct tlv_onionmsg_payload *om;
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

	om = tlv_onionmsg_payload_new(msg);
	if (!fromwire_onionmsg_payload(&cursor, &maxlen, om)) {
		status_peer_debug(&peer->id, "onion msg: invalid onionmsg_payload %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return;
	}

	if (rs->nextcase == ONION_END) {
		struct pubkey *reply_blinding, *first_node_id, me, alias;
		const struct onionmsg_path **reply_path;
		struct secret *self_id;
		u8 *omsg;

		if (!pubkey_from_node_id(&me, &daemon->id)) {
			status_broken("Failed to convert own id");
			return;
		}

		/* Final enctlv is actually optional */
		if (!om->encrypted_data_tlv) {
			alias = me;
			self_id = NULL;
		} else if (!decrypt_final_enctlv(tmpctx, &blinding, &ss,
						 om->encrypted_data_tlv, &me, &alias,
						 &self_id)) {
			status_peer_debug(&peer->id,
					  "onion msg: failed to decrypt enctlv"
					  " %s", tal_hex(tmpctx, om->encrypted_data_tlv));
			return;
		}

		if (om->reply_path) {
			first_node_id = &om->reply_path->first_node_id;
			reply_blinding = &om->reply_path->blinding;
			reply_path = cast_const2(const struct onionmsg_path **,
						 om->reply_path->path);
		} else {
			first_node_id = NULL;
			reply_blinding = NULL;
			reply_path = NULL;
		}

		/* We re-marshall here by policy, before handing to lightningd */
		omsg = tal_arr(tmpctx, u8, 0);
		towire_tlvstream_raw(&omsg, om->fields);
		daemon_conn_send(daemon->master,
				 take(towire_connectd_got_onionmsg_to_us(NULL,
							false, /* !obs2 */
							&alias, self_id,
							reply_blinding,
							first_node_id,
							reply_path,
							omsg)));
	} else {
		struct pubkey next_node, next_blinding;
		struct peer *next_peer;
		struct node_id next_node_id;

		/* This fails as expected if no enctlv. */
		if (!decrypt_enctlv(&blinding, &ss, om->encrypted_data_tlv, &next_node,
					 &next_blinding)) {
			status_peer_debug(&peer->id,
					  "onion msg: invalid enctlv %s",
					  tal_hex(tmpctx, om->encrypted_data_tlv));
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

