/* All about the HTLCs/commitment transactions for a particular peer. */
#ifndef LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#define LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/channel_config.h>
#include <common/derive_basepoints.h>
#include <common/htlc_wire.h>

struct channel;
struct htlc_in;
struct htlc_in_map;
struct htlc_out;
struct htlc_out_map;
struct htlc_stub;
struct lightningd;
struct forwarding;
struct json_stream;

/* FIXME: Define serialization primitive for this? */
struct channel_info {
	struct channel_config their_config;
	struct pubkey remote_fundingkey;
	struct basepoints theirbase;
	/* The old_remote_per_commit is for the locked-in remote commit_tx,
	 * and the remote_per_commit is for the commit_tx we're modifying now. */
	struct pubkey remote_per_commit, old_remote_per_commit;
	struct fee_states *fee_states;
};

/* Get all HTLCs for a peer, to send in init message. */
const struct existing_htlc **peer_htlcs(const tal_t *ctx,
					const struct channel *channel);

void free_htlcs(struct lightningd *ld, const struct channel *channel);

void peer_sending_commitsig(struct channel *channel, const u8 *msg);
void peer_got_commitsig(struct channel *channel, const u8 *msg);
void peer_got_revoke(struct channel *channel, const u8 *msg);

void update_per_commit_point(struct channel *channel,
			     const struct pubkey *per_commitment_point);

/* Returns NULL on success, otherwise failmsg (and sets *needs_update_appended)*/
const u8 *send_htlc_out(const tal_t *ctx,
			struct channel *out,
			struct amount_msat amount, u32 cltv,
			const struct sha256 *payment_hash,
			const struct pubkey *blinding,
			u64 partid,
			const u8 *onion_routing_packet,
			struct htlc_in *in,
			struct htlc_out **houtp,
			bool *needs_update_appended);

void onchain_failed_our_htlc(const struct channel *channel,
			     const struct htlc_stub *htlc,
			     const char *why);
void onchain_fulfilled_htlc(struct channel *channel,
			    const struct preimage *preimage);

void htlcs_notify_new_block(struct lightningd *ld, u32 height);

/* Only defined if COMPAT_V061 */
void fixup_htlcs_out(struct lightningd *ld);

void htlcs_resubmit(struct lightningd *ld,
		    struct htlc_in_map *unconnected_htlcs_in);

/* For HTLCs which terminate here, invoice payment calls one of these. */
void fulfill_htlc(struct htlc_in *hin, const struct preimage *preimage);
void local_fail_in_htlc(struct htlc_in *hin, const u8 *failmsg TAKES);
void local_fail_in_htlc_needs_update(struct htlc_in *hin,
				     const u8 *failmsg_needs_update TAKES,
				     const struct short_channel_id *failmsg_scid);

/* This json process will be used as the serialize method for
 * forward_event_notification_gen and be used in
 * `listforwardings_add_forwardings()`. */
void json_format_forwarding_object(struct json_stream *response, const char *fieldname,
				   const struct forwarding *cur);

/* Helper to create (common) WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS */
#define failmsg_incorrect_or_unknown(ctx, ld, hin) \
	failmsg_incorrect_or_unknown_((ctx), (ld), (hin), __FILE__, __LINE__)

const u8 *failmsg_incorrect_or_unknown_(const tal_t *ctx,
					struct lightningd *ld,
					const struct htlc_in *hin,
					const char *file, int line);
#endif /* LIGHTNING_LIGHTNINGD_PEER_HTLCS_H */
