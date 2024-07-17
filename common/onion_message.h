#ifndef LIGHTNING_COMMON_ONION_MESSAGE_H
#define LIGHTNING_COMMON_ONION_MESSAGE_H
#include "config.h"
#include <ccan/tal/tal.h>
#include <common/sciddir_or_pubkey.h>
#include <common/utils.h>

struct tlv_onionmsg_tlv;
struct secret;

/* Onion messages are kind of complicated, so read carefully!
 *
 * An onion message is an array of struct tlv_onionmsg_tlv:
 * encrypted struct tlv_encrypted_data_tlv:
 *	encrypted_recipient_data
 *
 * The final entry can also have unencrypted fields:
 * 	struct blinded_path *reply_path;
 *	u8 *invoice_request;
 *	u8 *invoice;
 *	u8 *invoice_error;
 *
 * The struct tlv_encrypted_data_tlv contains the interesting things:
 *
 * Intermediate nodes:
 *	short_channel_id/next_node_id (always)
 *	next_blinding_override (optional)
 *	payment_relay/payment_constraints (required, for payments only)
 *	allowed_features (optional)
 *
 * Final nodes:
 *      path_id (so it can tell blinded path was correctly used).
 */

/* Low level routines: */

/**
 * Stage 0: populate tlv_encrypted_data_tlv[] array.
 * @ctx: tal context
 * @ids: array of pubkeys defining path destinations
 * @scids: optional array of scids: if non-NULL, use this instead of pubkey for
 *         next hop values.
 *
 * This simply populates the short_channel_id/next_node_id fields; you will want to
 * add others.
 */
struct tlv_encrypted_data_tlv **new_encdata_tlvs(const tal_t *ctx,
						 const struct pubkey *ids,
						 const struct short_channel_id **scids);

/**
 * Stage 1: tlv_encrypted_data_tlv[] -> struct blinded_path.
 * @ctx: tal context
 * @tlvs: tlvs to be encrypted
 * @ids: array of pubkeys.
 *
 * ids[0] needs to be first node id, but rest don't have to be there unless
 * a tlv uses short_channel_id instead of next_node_id.
 *
 * You can turn the first_node_id into an scidd after if you want to.
 */
struct blinded_path *blinded_path_from_encdata_tlvs(const tal_t *ctx,
						    const struct tlv_encrypted_data_tlv **tlvs,
						    const struct pubkey *ids);

/**
 * Stage 2: turn struct blinded_path into array of tlv_onionmsg_tlv.
 * @ctx: tal context
 * @bpath: path containing the encrypted blobs.
 *
 * You normally then add payload fields to the final tlv_onionmsg_tlv.
 */
struct tlv_onionmsg_tlv **onionmsg_tlvs_from_blinded_path(const tal_t *ctx,
							  const struct blinded_path *bpath);

/**
 * Stage 3: linearize each struct tlv_onionmsg_tlv into onionmsg_hops
 * @ctx: tal context
 * @bpath: the path (for the pubkeys)
 * @tlvs: the tlvs for each hop.
 *
 * This is the format the sphinx wants to encode the actual onion message.
 */
struct sphinx_hop **onionmsg_tlvs_to_hops(const tal_t *ctx,
					  const struct blinded_path *bpath,
					  const struct tlv_onionmsg_tlv **tlvs);


/* Stage 4: turn into sphinx_hop * into linear onionmsg (e.g. via injectonionmessage,
 * or directly using common/sphinx.c) */

/* Higher level helpers. */

/**
 * incoming_message_blinded_path - create incoming blinded path for messages.
 * @ctx: context to tallocate off
 * @ids: array of node ids.
 * @scids: optional, if these are set, use these for directions instead of node ids.
 * @path_secret: put this into final entry, so we can verify.
 */
struct blinded_path *incoming_message_blinded_path(const tal_t *ctx,
						   const struct pubkey *ids,
						   const struct short_channel_id **scids,
						   const struct secret *path_secret);


/* A ready-to-be-encrypted-and-sent onion message. */
struct onion_message {
	struct pubkey first_blinding;
	struct sphinx_hop **hops;
};

/**
 * outgoing_message_tlvs - create encrypted blobs to send msg
 * @ctx: context to tallocate off
 * @ids: array of node ids (first is our peer, must be at least one).
 * @scids: optional, if these are set, use these for directions instead of node ids.
 * @their_path: blinded path they told us to use for reply (or NULL)
 * @final_tlv: extra fields to put in final tlv (consumed)
 *
 * If @their_path is set, the final @ids entry must be @their_path->first_node_id.
 * We cannot check this if their_path->first_node_id is not a pubkey, of course.
 */
struct onion_message *outgoing_onion_message(const tal_t *ctx,
					     const struct pubkey *ids,
					     const struct short_channel_id **scids,
					     const struct blinded_path *their_path,
					     struct tlv_onionmsg_tlv *final_tlv STEALS);

#endif /* LIGHTNING_COMMON_ONION_MESSAGE_H */
