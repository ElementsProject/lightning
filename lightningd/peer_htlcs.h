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
struct htlc_out;
struct htlc_stub;
struct lightningd;

/* FIXME: Define serialization primitive for this? */
struct channel_info {
	struct channel_config their_config;
	struct pubkey remote_fundingkey;
	struct basepoints theirbase;
	/* The old_remote_per_commit is for the locked-in remote commit_tx,
	 * and the remote_per_commit is for the commit_tx we're modifying now. */
	struct pubkey remote_per_commit, old_remote_per_commit;
	/* In transition, these can be different! */
	u32 feerate_per_kw[NUM_SIDES];
};

/* Get all HTLCs for a peer, to send in init message. */
void peer_htlcs(const tal_t *ctx,
		const struct channel *channel,
		struct added_htlc **htlcs,
		enum htlc_state **htlc_states,
		struct fulfilled_htlc **fulfilled_htlcs,
		enum side **fulfilled_sides,
		const struct failed_htlc ***failed_htlcs,
		enum side **failed_sides);

void free_htlcs(struct lightningd *ld, const struct channel *channel);

void peer_sending_commitsig(struct channel *channel, const u8 *msg);
void peer_got_commitsig(struct channel *channel, const u8 *msg);
void peer_got_revoke(struct channel *channel, const u8 *msg);

void update_per_commit_point(struct channel *channel,
			     const struct pubkey *per_commitment_point);

enum onion_type send_htlc_out(struct channel *out, u64 amount, u32 cltv,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      struct htlc_in *in,
			      struct htlc_out **houtp);

struct htlc_out *find_htlc_out_by_ripemd(const struct channel *channel,
					 const struct ripemd160 *ripemd160);
void onchain_failed_our_htlc(const struct channel *channel,
			     const struct htlc_stub *htlc,
			     const char *why);
void onchain_fulfilled_htlc(struct channel *channel,
			    const struct preimage *preimage);

void htlcs_notify_new_block(struct lightningd *ld, u32 height);
#endif /* LIGHTNING_LIGHTNINGD_PEER_HTLCS_H */
