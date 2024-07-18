#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <common/features.h>
#include <common/htlc.h>
#include <common/node_id.h>
#include <lightningd/channel.h>
#include <lightningd/gossip_generation.h>
#include <lightningd/lightningd.h>
#include <lightningd/peer_control.h>
#include <wire/peer_wire.h>

/* Once we know which way nodes go, it's easy to construct */
static u8 *create_channel_announcement_dir(const tal_t *ctx,
					   const u8 *features,
					   struct short_channel_id scid,
					   const secp256k1_ecdsa_signature node_signature[NUM_SIDES],
					   const secp256k1_ecdsa_signature bitcoin_signature[NUM_SIDES],
					   const struct node_id node_id[NUM_SIDES],
					   const struct pubkey funding_pubkey[NUM_SIDES])
{
	enum side first, second;

	if (node_id_cmp(&node_id[LOCAL], &node_id[REMOTE]) < 0)
		first = LOCAL;
	else
		first = REMOTE;
	second = !first;

	return towire_channel_announcement(ctx,
					   &node_signature[first],
					   &node_signature[second],
					   &bitcoin_signature[first],
					   &bitcoin_signature[second],
					   features,
					   &chainparams->genesis_blockhash,
					   scid,
					   &node_id[first],
					   &node_id[second],
					   &funding_pubkey[first],
					   &funding_pubkey[second]);
}

static void copysig_or_zero(secp256k1_ecdsa_signature *dst,
			    const secp256k1_ecdsa_signature *src)
{
	if (!src)
		memset(dst, 0, sizeof(*dst));
	else
		*dst = *src;
}

u8 *create_channel_announcement(const tal_t *ctx,
				const struct channel *channel,
				struct short_channel_id scid,
				const secp256k1_ecdsa_signature *local_node_signature,
				const secp256k1_ecdsa_signature *local_bitcoin_signature,
				const secp256k1_ecdsa_signature *remote_node_signature,
				const secp256k1_ecdsa_signature *remote_bitcoin_signature)
{
	secp256k1_ecdsa_signature node_signature[NUM_SIDES], bitcoin_signature[NUM_SIDES];
	struct node_id node_id[NUM_SIDES];
	struct pubkey funding_pubkey[NUM_SIDES];
	u8 *features;

	features = get_agreed_channelfeatures(tmpctx, channel->peer->ld->our_features,
					      channel->peer->their_features);

	copysig_or_zero(&bitcoin_signature[LOCAL], local_bitcoin_signature);
	copysig_or_zero(&bitcoin_signature[REMOTE], remote_bitcoin_signature);
	copysig_or_zero(&node_signature[LOCAL], local_node_signature);
	copysig_or_zero(&node_signature[REMOTE], remote_node_signature);
	node_id[LOCAL] = channel->peer->ld->our_nodeid;
	node_id[REMOTE] = channel->peer->id;
	funding_pubkey[LOCAL] = channel->local_funding_pubkey;
	funding_pubkey[REMOTE] = channel->channel_info.remote_fundingkey;
	return create_channel_announcement_dir(ctx, features, scid,
					       node_signature, bitcoin_signature, node_id, funding_pubkey);
}

u8 *unsigned_channel_update(const tal_t *ctx,
			    const struct channel *channel,
			    struct short_channel_id scid,
			    const u32 *old_timestamp,
			    bool forwardable,
			    bool enabled)
{
	struct lightningd *ld = channel->peer->ld;
	secp256k1_ecdsa_signature dummy_sig;
	u8 message_flags, channel_flags;
	u32 timestamp;

	/* hsmd fills this in */
	memset(&dummy_sig, 0, sizeof(dummy_sig));
	/* BOLT #7:

	 * The `channel_flags` bitfield is used to indicate the direction of
	 * the channel: it identifies the node that this update originated
	 * from and signals various options concerning the channel. The
	 * following table specifies the meaning of its individual bits:
	 *
	 * | Bit Position  | Name        | Meaning                          |
	 * | ------------- | ----------- | -------------------------------- |
	 * | 0             | `direction` | Direction this update refers to. |
	 * | 1             | `disable`   | Disable the channel.             |
	 */
	channel_flags = node_id_idx(&channel->peer->ld->our_nodeid,
				    &channel->peer->id);
	if (!enabled)
		channel_flags |= ROUTING_FLAGS_DISABLED;

	/* BOLT #7:
	 *
	 * The `message_flags` bitfield is used to provide additional details
	 * about the message:
	 *
	 * | Bit Position  | Name           |
	 * | ------------- | ---------------|
	 * | 0             | `must_be_one`  |
	 * | 1             | `dont_forward` |
	 */
	message_flags = 1;
	if (!forwardable)
		message_flags |= ROUTING_OPT_DONT_FORWARD;

	/* Make sure timestamp changes! */
	timestamp = time_now().ts.tv_sec;
	/* FIXME: @endothermicdev points out that our clock could be
	 * wrong once, and now we'll keep producing future timestamps.
	 * We could sanity check that old_timestamp is within 2 weeks and
	 * discard? */
	if (old_timestamp && timestamp <= *old_timestamp)
		timestamp = *old_timestamp + 1;

	return towire_channel_update(ctx,
				     &dummy_sig,
				     &chainparams->genesis_blockhash,
				     scid,
				     timestamp,
				     message_flags,
				     channel_flags,
				     ld->config.cltv_expiry_delta,
				     channel->htlc_minimum_msat,
				     channel->feerate_base,
				     channel->feerate_ppm,
				     channel->htlc_maximum_msat);
}

/* Helper to get non-signature, non-timestamp parts of (valid!) channel_update */
static void get_cupdate_parts(const u8 *channel_update,
			      const u8 *parts[2],
			      size_t sizes[2])
{
	/* BOLT #7:
	 *
	 * 1. type: 258 (`channel_update`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`chain_hash`:`chain_hash`]
	 *    * [`short_channel_id`:`short_channel_id`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* Note: 2 bytes for `type` field */
	/* We already checked it's valid before accepting */
	assert(tal_count(channel_update) > 2 + 64 + 32 + 8 + 4);
	parts[0] = channel_update + 2 + 64;
	sizes[0] = 32 + 8;
	parts[1] = channel_update + 2 + 64 + 32 + 8 + 4;
	sizes[1] = tal_count(channel_update) - (64 + 2 + 32 + 8 + 4);
}

bool channel_update_same(const u8 *cupdate1, const u8 *cupdate2)
{
	const u8 *parts1[2], *parts2[2];
	size_t sizes1[2], sizes2[2];

	get_cupdate_parts(cupdate1, parts1, sizes1);
	get_cupdate_parts(cupdate2, parts2, sizes2);

	return memeq(parts1[0], sizes1[0], parts2[0], sizes2[0])
		&& memeq(parts1[1], sizes1[1], parts2[1], sizes2[1]);
}

bool channel_update_details(const u8 *channel_update,
			    u32 *timestamp,
			    bool *enabled)
{
	u16 cltv_expiry_delta;
	struct amount_msat htlc_minimum, htlc_maximum;
	u32 fee_base_msat, fee_proportional_millionths, tstamp;
	u8 message_flags, channel_flags;
	secp256k1_ecdsa_signature signature;
	struct bitcoin_blkid chain_hash;
	struct short_channel_id short_channel_id;

	if (!fromwire_channel_update(channel_update,
				     &signature, &chain_hash,
				     &short_channel_id, &tstamp,
				     &message_flags, &channel_flags,
				     &cltv_expiry_delta,
				     &htlc_minimum,
				     &fee_base_msat,
				     &fee_proportional_millionths,
				     &htlc_maximum))
		return false;

	if (timestamp)
		*timestamp = tstamp;
	if (enabled)
		*enabled = !(channel_flags & ROUTING_FLAGS_DISABLED);
	return true;
}

const char *check_announce_sigs(const struct channel *channel,
				struct short_channel_id scid,
				const secp256k1_ecdsa_signature *remote_node_signature,
				const secp256k1_ecdsa_signature *remote_bitcoin_signature)
{
	struct sha256_double hash;
	const u8 *cannounce;

	cannounce = create_channel_announcement(tmpctx, channel, scid,
						NULL, NULL, NULL, NULL);

	/* BOLT #7:
	 *
	 * - MUST compute the double-SHA256 hash `h` of the message, beginning
	 *   at offset 256, up to the end of the message.
	 *     - Note: the hash skips the 4 signatures but hashes the rest of the
	 *       message, including any future fields appended to the end.
	 */
	/* First two bytes are the msg type */
	int offset = 258;
	sha256_double(&hash, cannounce + offset, tal_count(cannounce) - offset);

	if (!check_signed_hash_nodeid(&hash, remote_node_signature,
				      &channel->peer->id))
		return "invalid node_signature";

	if (!check_signed_hash(&hash, remote_bitcoin_signature,
			       &channel->channel_info.remote_fundingkey))
		return "invalid bitcoin_signature";

	return NULL;
}

/* Get non-signature, non-timestamp parts of (valid!) node_announcement,
 * with TLV broken out separately  */
static void get_nannounce_parts(const u8 *node_announcement,
				const u8 *parts[3],
				size_t sizes[3])
{
	size_t len, ad_len;
	const u8 *flen, *ad_start;

	/* BOLT #7:
	 *
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`u16`:`flen`]
	 *    * [`flen*byte`:`features`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	/* Note: 2 bytes for `type` field */
	/* We already checked it's valid before accepting */
	assert(tal_count(node_announcement) > 2 + 64);
	parts[0] = node_announcement + 2 + 64;

	/* Read flen to get size */
	flen = parts[0];
	len = tal_count(node_announcement) - (2 + 64);
	sizes[0] = 2 + fromwire_u16(&flen, &len);
	assert(flen != NULL && len >= 4);

	/* BOLT-0fe3485a5320efaa2be8cfa0e570ad4d0259cec3 #7:
	 *
	 *    * [`u32`:`timestamp`]
	 *    * [`point`:`node_id`]
	 *    * [`3*byte`:`rgb_color`]
	 *    * [`32*byte`:`alias`]
	 *    * [`u16`:`addrlen`]
	 *    * [`addrlen*byte`:`addresses`]
	 *    * [`node_ann_tlvs`:`tlvs`]
	*/
	parts[1] = node_announcement + 2 + 64 + sizes[0] + 4;

	/* Find the end of the addresses */
	ad_start = parts[1] + 33 + 3 + 32;
	len = tal_count(node_announcement)
		- (2 + 64 + sizes[0] + 4 + 33 + 3 + 32);
	ad_len = fromwire_u16(&ad_start, &len);
	assert(ad_start != NULL && len >= ad_len);

	sizes[1] = 33 + 3 + 32 + 2 + ad_len;

	/* Is there a TLV ? */
	sizes[2] = len - ad_len;
	if (sizes[2] != 0)
		parts[2] = parts[1] + sizes[1];
	else
		parts[2] = NULL;
}

/* Get timestamp of a (valid!) node_announcement  */
static u32 get_nannounce_timestamp(const u8 *node_announcement)
{
	const u8 *p;
	u16 flen;
	size_t len;
	u32 timestamp;

	/* BOLT #7:
	 *
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 *    * [`u16`:`flen`]
	 *    * [`flen*byte`:`features`]
	 *    * [`u32`:`timestamp`]
	 *...
	 */
	len = tal_count(node_announcement);
	p = node_announcement;

	/* Note: 2 bytes for `type` field */
	fromwire_u16(&p, &len);
	fromwire(&p, &len, NULL, 64);
	flen = fromwire_u16(&p, &len);
	fromwire(&p, &len, NULL, flen);

	timestamp = fromwire_u32(&p, &len);
	assert(p != NULL);

	return timestamp;
}

/* Is nann1 same as nann2 (not sigs and timestamps)? */
bool node_announcement_same(const u8 *nann1, const u8 *nann2)
{
	const u8 *parts1[3], *parts2[3];
	size_t sizes1[3], sizes2[3];

	get_nannounce_parts(nann1, parts1, sizes1);
	get_nannounce_parts(nann2, parts2, sizes2);

	return memeq(parts1[0], sizes1[0], parts2[0], sizes2[0])
		&& memeq(parts1[1], sizes1[1], parts2[1], sizes2[1])
		&& memeq(parts1[2], sizes1[2], parts2[2], sizes2[2]);
}

static u8 *create_nannounce(const tal_t *ctx,
			    struct lightningd *ld,
			    const secp256k1_ecdsa_signature *sig,
			    const struct wireaddr *addrs,
			    u32 timestamp,
			    const struct lease_rates *rates)
{
	u8 *addresses = tal_arr(tmpctx, u8, 0);
	u8 *announcement;
	struct tlv_node_ann_tlvs *na_tlv;

	for (size_t i = 0; i < tal_count(addrs); i++)
		towire_wireaddr(&addresses, &addrs[i]);

	na_tlv = tlv_node_ann_tlvs_new(tmpctx);
	na_tlv->option_will_fund = cast_const(struct lease_rates *, rates);

	announcement =
	    towire_node_announcement(ctx, sig,
				     ld->our_features->bits[NODE_ANNOUNCE_FEATURE],
				     timestamp,
				     &ld->our_nodeid, ld->rgb, ld->alias,
				     addresses,
				     na_tlv);
	return announcement;
}

/* Return an array of wireaddr to announce */
static const struct wireaddr *gather_addresses(const tal_t *ctx,
					       struct lightningd *ld)
{
	struct wireaddr *addrs;

	/* Note: If ld->announceable is NULL, tal_dup_talarr returns NULL! */
	addrs = tal_dup_talarr(ctx, struct wireaddr, ld->announceable);
	if (!addrs)
		addrs = tal_arr(ctx, struct wireaddr, 0);

	/* Add discovered IPs v4/v6 verified by peer `remote_addr` feature. */
	/* Only do that if we don't have any addresses announced or
	 * `config.ip_discovery` is explicitly enabled. */
	switch (ld->config.ip_discovery) {
	case OPT_AUTOBOOL_FALSE:
		return addrs;
	case OPT_AUTOBOOL_TRUE:
		break;
	case OPT_AUTOBOOL_AUTO:
		if (tal_count(addrs) != 0)
			return addrs;
		break;
	}

	if (ld->discovered_ip_v4)
		tal_arr_expand(&addrs, *ld->discovered_ip_v4);
	if (ld->discovered_ip_v6)
		tal_arr_expand(&addrs, *ld->discovered_ip_v6);

	return addrs;
}

u8 *unsigned_node_announcement(const tal_t *ctx,
			       struct lightningd *ld,
			       const u8 *prev)
{
	secp256k1_ecdsa_signature sig;
	const struct wireaddr *addrs;
	u32 timestamp = time_now().ts.tv_sec;

	addrs = gather_addresses(tmpctx, ld);
	/* Even if we're quick, don't duplicate timestamps! */
	if (prev) {
		u32 old_timestamp = get_nannounce_timestamp(prev);
		if (timestamp <= old_timestamp)
			timestamp = old_timestamp + 1;
	}

	memset(&sig, 0, sizeof(sig));
	return create_nannounce(tmpctx, ld, &sig,
				addrs, timestamp,
				ld->lease_rates);
}

void add_node_announcement_sig(u8 *nannounce,
			       const secp256k1_ecdsa_signature *sig)
{
	u8 compact[64];

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact, sig);

	/* BOLT #7:
	 *
	 * 1. type: 257 (`node_announcement`)
	 * 2. data:
	 *    * [`signature`:`signature`]
	 */
	/* First two bytes are type */
	assert(tal_count(nannounce) > 2 + sizeof(compact));
	memcpy(nannounce + 2, compact, sizeof(compact));
}
