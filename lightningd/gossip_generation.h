#ifndef LIGHTNING_LIGHTNINGD_GOSSIP_GENERATION_H
#define LIGHTNING_LIGHTNINGD_GOSSIP_GENERATION_H
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <bitcoin/signature.h>

struct channel;

/**
 * create_channel_announcement: create a channel_announcement message
 * @ctx: the tal context to allocate return from
 * @channel: the channel to announce
 * @scid: channel->scid
 * @local_node_signature: optional local node signature
 * @local_bitcoin_signature: optional local node signature
 * @remote_node_signature: optional peer node signature
 * @remote_bitcoin_signature: optional peer node signature
 *
 * The signatures are optional in case you're creating it to sign (or
 * validate).
 */
u8 *create_channel_announcement(const tal_t *ctx,
				const struct channel *channel,
				struct short_channel_id scid,
				const secp256k1_ecdsa_signature *local_node_signature,
				const secp256k1_ecdsa_signature *local_bitcoin_signature,
				const secp256k1_ecdsa_signature *remote_node_signature,
				const secp256k1_ecdsa_signature *remote_bitcoin_signature);

/**
 * unsigned_channel_update: create a channel_update message with zeroed sig
 * @ctx: the tal context to allocate return from
 * @channel: the channel to announce
 * @scid: the short_channel_id to sign
 * @old_timestamp: optional timestamp of previous channel_update to replace.
 * @forwardable: is this channel_update non-public?
 * @enabled: sets channel_update's disabled flag
 */
u8 *unsigned_channel_update(const tal_t *ctx,
			    const struct channel *channel,
			    const struct short_channel_id *scid,
			    const u32 *old_timestamp,
			    bool forwardable,
			    bool enabled);

/**
 * channel_update_same: are these two channel updates the same?
 *
 * Ignoring timestamp and signatures.  Basically, is it redundant?
 */
bool channel_update_same(const u8 *cupdate1, const u8 *cupdate2);

/**
 * channel_update_details: extract timestamp and/or enabled flag.
 * @channel_update: the channel update, or NULL.
 * @timestamp: where to extract the timestamp, or NULL.
 * @enabled: where to extract the enabled flag, or NULL.
 *
 * Returns false (and doesn't touch @timestamp or @enabled) if
 * channel_update NULL or invalid.
 */
bool channel_update_details(const u8 *channel_update,
			    u32 *timestamp,
			    bool *enabled);

/**
 * check_announce_sigs: check that signatures are correct for this scid
 * @channel: the channel (for peer's id / bitcoin key and the channel features)
 * @scid: the short_channel_id it's proposing
 * @remote_node_signature: node signature
 * @remote_bitcoin_signature: bitcoin signature
 *
 * Returns a string literal if one signature is bad.
 */
const char *check_announce_sigs(const struct channel *channel,
				struct short_channel_id scid,
				const secp256k1_ecdsa_signature *remote_node_signature,
				const secp256k1_ecdsa_signature *remote_bitcoin_signature);

/**
 * unsigned_node_announcement: create a current unsigned node announcement.
 * @ctx: the context to allocate return from
 * @ld: the lightningd struct.
 */
u8 *unsigned_node_announcement(const tal_t *ctx, struct lightningd *ld);

/**
 * add_node_announcement_sig: apply the signature to the node announcement
 * @nannounce: the (unsigned) node announcement
 * @sig: the signature (from hsm)
 */
void add_node_announcement_sig(u8 *nannounce,
			       const secp256k1_ecdsa_signature *sig);

/**
 * node_announcement_same: are these two node_announcements the same?
 *
 * Ignoring timestamp and signatures.  Basically, is it redundant?
 */
bool node_announcement_same(const u8 *nann1, const u8 *nann2);

#endif /* LIGHTNING_LIGHTNINGD_GOSSIP_GENERATION_H */
