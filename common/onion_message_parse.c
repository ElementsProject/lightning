/* Caller does fromwire_onion_message(), this does the rest. */
#include "config.h"
#include <assert.h>
#include <common/blindedpath.h>
#include <common/ecdh.h>
#include <common/onion_message_parse.h>
#include <common/sphinx.h>
#include <common/status.h>
#include <common/utils.h>
#include <wire/onion_wire.h>
#include <wire/peer_wire.h>

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

	/* BOLT #4:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `encrypted_data_tlv` contains `path_id`:
	 *      - MUST ignore the message.
	 */
	if (encmsg->path_id)
		return false;

	/* BOLT #4:
	 * - SHOULD forward the message using `onion_message` to the next peer
	 *   indicated by `next_node_id`.
	 */
	if (!encmsg->next_node_id)
		return false;

	*next_node = *encmsg->next_node_id;
	blindedpath_next_blinding(encmsg, blinding, ss, next_blinding);
	return true;
}

/* Returns false on failure */
bool onion_message_parse(const tal_t *ctx,
			 const u8 *onion_message_packet,
			 const struct pubkey *blinding,
			 const struct node_id *peer,
			 const struct pubkey *me,
			 u8 **next_onion_msg,
			 struct pubkey *next_node_id,
			 struct tlv_onionmsg_tlv **final_om,
			 struct pubkey *final_alias,
			 struct secret **final_path_id)
{
	enum onion_wire badreason;
	struct onionpacket *op;
	struct pubkey ephemeral;
	struct route_step *rs;
	struct tlv_onionmsg_tlv *om;
	struct secret ss, onion_ss;
	const u8 *cursor;
	size_t max, maxlen;

	/* We unwrap the onion now. */
	op = parse_onionpacket(tmpctx,
			       onion_message_packet,
			       tal_bytelen(onion_message_packet),
			       &badreason);
	if (!op) {
		status_peer_debug(peer, "onion_message_parse: can't parse onionpacket: %s",
				  onion_wire_name(badreason));
		return false;
	}

	ephemeral = op->ephemeralkey;
	if (!unblind_onion(blinding, ecdh, &ephemeral, &ss)) {
		status_peer_debug(peer, "onion_message_parse: can't unblind onionpacket");
		return false;
	}

	/* Now get onion shared secret and parse it. */
	ecdh(&ephemeral, &onion_ss);
	rs = process_onionpacket(tmpctx, op, &onion_ss, NULL, 0, false);
	if (!rs) {
		status_peer_debug(peer,
				  "onion_message_parse: can't process onionpacket ss=%s",
				  fmt_secret(tmpctx, &onion_ss));
		return false;
	}

	/* The raw payload is prepended with length in the modern onion. */
	cursor = rs->raw_payload;
	max = tal_bytelen(rs->raw_payload);
	maxlen = fromwire_bigsize(&cursor, &max);
	if (!cursor) {
		status_peer_debug(peer, "onion_message_parse: Invalid hop payload %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return false;
	}
	if (maxlen > max) {
		status_peer_debug(peer, "onion_message_parse: overlong hop payload %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return false;
	}

	om = fromwire_tlv_onionmsg_tlv(tmpctx, &cursor, &maxlen);
	if (!om) {
		status_peer_debug(peer, "onion_message_parse: invalid onionmsg_tlv %s",
				  tal_hex(tmpctx, rs->raw_payload));
		return false;
	}
	if (rs->nextcase == ONION_END) {
		*next_onion_msg = NULL;
		*final_om = tal_steal(ctx, om);
		/* Final enctlv is actually optional */
		if (!om->encrypted_recipient_data) {
			*final_alias = *me;
			*final_path_id = NULL;
		} else if (!decrypt_final_onionmsg(ctx, blinding, &ss,
						   om->encrypted_recipient_data, me,
						   final_alias,
						   final_path_id)) {
			status_peer_debug(peer,
					  "onion_message_parse: failed to decrypt encrypted_recipient_data"
					  " %s", tal_hex(tmpctx, om->encrypted_recipient_data));
			return false;
		}
	} else {
		struct pubkey next_blinding;

		*final_om = NULL;

		/* BOLT #4:
		 * - if it is not the final node according to the onion encryption:
		 *   - if the `onionmsg_tlv` contains other tlv fields than `encrypted_recipient_data`:
		 *     - MUST ignore the message.
		 */
		if (tal_count(om->fields) != 1) {
			status_peer_debug(peer,
					  "onion_message_parse: "
					  "disallowed tlv field");
			return false;
		}

		/* This fails as expected if no enctlv. */
		if (!decrypt_forwarding_onionmsg(blinding, &ss, om->encrypted_recipient_data, next_node_id,
						 &next_blinding)) {
			status_peer_debug(peer,
					  "onion_message_parse: invalid encrypted_recipient_data %s",
					  tal_hex(tmpctx, om->encrypted_recipient_data));
			return false;
		}
		*next_onion_msg = towire_onion_message(ctx,
						       &next_blinding,
						       serialize_onionpacket(tmpctx, rs->next));
	}

	/* Exactly one is set */
	assert(!*next_onion_msg + !*final_om == 1);
	return true;
}
