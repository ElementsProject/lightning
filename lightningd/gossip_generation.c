#include "config.h"
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
					   &scid,
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
	node_id[LOCAL] = channel->peer->ld->id;
	node_id[REMOTE] = channel->peer->id;
	funding_pubkey[LOCAL] = channel->local_funding_pubkey;
	funding_pubkey[REMOTE] = channel->channel_info.remote_fundingkey;
	return create_channel_announcement_dir(ctx, features, *channel->scid,
					       node_signature, bitcoin_signature, node_id, funding_pubkey);
}

u8 *unsigned_channel_update(const tal_t *ctx,
			    const struct channel *channel,
			    const struct short_channel_id *scid,
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
	channel_flags = node_id_idx(&channel->peer->ld->id,
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
