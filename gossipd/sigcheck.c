#include "config.h"
#include <bitcoin/shadouble.h>
#include <bitcoin/signature.h>
#include <ccan/tal/str/str.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <gossipd/sigcheck.h>

/* Verify the signature of a channel_update message */
const char *sigcheck_channel_update(const tal_t *ctx,
				    const struct node_id *node_id,
				    const secp256k1_ecdsa_signature *node_sig,
				    const u8 *update)
{
	/* BOLT #7:
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *     * [`signature`:`signature`]
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`short_channel_id`:`short_channel_id`]
	 *     * [`u32`:`timestamp`]
	 *     * [`byte`:`message_flags`]
	 *     * [`byte`:`channel_flags`]
	 *     * [`u16`:`cltv_expiry_delta`]
	 *     * [`u64`:`htlc_minimum_msat`]
	 *     * [`u32`:`fee_base_msat`]
	 *     * [`u32`:`fee_proportional_millionths`]
	 *     * [`u64`:`htlc_maximum_msat`]
	 */
	/* 2 byte msg type + 64 byte signatures */
	int offset = 66;
	struct sha256_double hash;

	sha256_double(&hash, update + offset, tal_count(update) - offset);

	if (!check_signed_hash_nodeid(&hash, node_sig, node_id))
		return tal_fmt(ctx,
			       "Bad signature for %s hash %s"
			       " on channel_update %s",
			       fmt_secp256k1_ecdsa_signature(tmpctx, node_sig),
			       fmt_sha256_double(tmpctx, &hash),
			       tal_hex(tmpctx, update));
	return NULL;
}

const char *sigcheck_channel_announcement(const tal_t *ctx,
					  const struct node_id *node1_id,
					  const struct node_id *node2_id,
					  const struct pubkey *bitcoin1_key,
					  const struct pubkey *bitcoin2_key,
					  const secp256k1_ecdsa_signature *node1_sig,
					  const secp256k1_ecdsa_signature *node2_sig,
					  const secp256k1_ecdsa_signature *bitcoin1_sig,
					  const secp256k1_ecdsa_signature *bitcoin2_sig,
					  const u8 *announcement)
{
	/* BOLT #7:
	 * 1. type: 256 (`channel_announcement`)
	 * 2. data:
	 *     * [`signature`:`node_signature_1`]
	 *     * [`signature`:`node_signature_2`]
	 *     * [`signature`:`bitcoin_signature_1`]
	 *     * [`signature`:`bitcoin_signature_2`]
	 *     * [`u16`:`len`]
	 *     * [`len*byte`:`features`]
	 *     * [`chain_hash`:`chain_hash`]
	 *     * [`short_channel_id`:`short_channel_id`]
	 *     * [`point`:`node_id_1`]
	 *     * [`point`:`node_id_2`]
	 *     * [`point`:`bitcoin_key_1`]
	 *     * [`point`:`bitcoin_key_2`]
	 */
	/* 2 byte msg type + 256 byte signatures */
	int offset = 258;
	struct sha256_double hash;
	sha256_double(&hash, announcement + offset,
		      tal_count(announcement) - offset);

	if (!check_signed_hash_nodeid(&hash, node1_sig, node1_id)) {
		return tal_fmt(ctx,
			       "Bad node_signature_1 %s hash %s"
			       " on channel_announcement %s",
			       fmt_secp256k1_ecdsa_signature(tmpctx,
							     node1_sig),
			       fmt_sha256_double(tmpctx, &hash),
			       tal_hex(tmpctx, announcement));
	}
	if (!check_signed_hash_nodeid(&hash, node2_sig, node2_id)) {
		return tal_fmt(ctx,
			       "Bad node_signature_2 %s hash %s"
			       " on channel_announcement %s",
			       fmt_secp256k1_ecdsa_signature(tmpctx,
							     node2_sig),
			       fmt_sha256_double(tmpctx, &hash),
			       tal_hex(tmpctx, announcement));
	}
	if (!check_signed_hash(&hash, bitcoin1_sig, bitcoin1_key)) {
		return tal_fmt(ctx,
			       "Bad bitcoin_signature_1 %s hash %s"
			       " on channel_announcement %s",
			       fmt_secp256k1_ecdsa_signature(tmpctx,
							     bitcoin1_sig),
			       fmt_sha256_double(tmpctx, &hash),
			       tal_hex(tmpctx, announcement));
	}
	if (!check_signed_hash(&hash, bitcoin2_sig, bitcoin2_key)) {
		return tal_fmt(ctx,
			       "Bad bitcoin_signature_2 %s hash %s"
			       " on channel_announcement %s",
			       fmt_secp256k1_ecdsa_signature(tmpctx,
							     bitcoin2_sig),
			       fmt_sha256_double(tmpctx, &hash),
			       tal_hex(tmpctx, announcement));
	}
	return NULL;
}

/* Returns warning msg if signature wrong, else NULL */
const char *sigcheck_node_announcement(const tal_t *ctx,
				       const struct node_id *node_id,
				       const secp256k1_ecdsa_signature *signature,
				       const u8 *node_announcement)
{
	/* BOLT #7:
	 *
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`u16`:`flen`]
	 *    * [`flen*byte`:`features`]
	 *    * [`u32`:`timestamp`]
	 *    * [`point`:`node_id`]
	 *    * [`3*byte`:`rgb_color`]
	 *    * [`32*byte`:`alias`]
	 *    * [`u16`:`addrlen`]
	 *    * [`addrlen*byte`:`addresses`]
	 */
	/* 2 byte msg type + 64 byte signatures */
	int offset = 66;
	struct sha256_double hash;

	sha256_double(&hash, node_announcement + offset, tal_count(node_announcement) - offset);
	/* If node_id is invalid, it fails here */
	if (!check_signed_hash_nodeid(&hash, signature, node_id)) {
		/* BOLT #7:
		 *
		 * - if `signature` is not a valid signature, using
                 *   `node_id` of the double-SHA256 of the entire
                 *   message following the `signature` field
                 *   (including unknown fields following
                 *   `fee_proportional_millionths`):
                 *     - SHOULD send a `warning` and close the connection.
                 *     - MUST NOT process the message further.
		 */
		return tal_fmt(ctx,
			       "Bad signature for %s hash %s"
			       " on node_announcement %s",
			       fmt_secp256k1_ecdsa_signature(tmpctx,
							     signature),
			       fmt_sha256_double(tmpctx, &hash),
			       tal_hex(tmpctx, node_announcement));
	}

	return NULL;
}
