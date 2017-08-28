/* All about the HTLCs/commitment transactions for a particular peer. */
#ifndef LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#define LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <common/derive_basepoints.h>
#include <lightningd/htlc_wire.h>

/* FIXME: Define serialization primitive for this? */
struct channel_info {
	struct channel_config their_config;
	struct pubkey remote_fundingkey;
	struct basepoints theirbase;
	/* The old_remote_per_commit is for the locked-in remote commit_tx,
	 * and the remote_per_commit is for the commit_tx we're modifying now. */
	struct pubkey remote_per_commit, old_remote_per_commit;
	u32 feerate_per_kw;
};

/* Get all HTLCs for a peer, to send in init message. */
void peer_htlcs(const tal_t *ctx,
		const struct peer *peer,
		struct added_htlc **htlcs,
		enum htlc_state **htlc_states,
		struct fulfilled_htlc **fulfilled_htlcs,
		enum side **fulfilled_sides,
		struct failed_htlc **failed_htlcs,
		enum side **failed_sides);

int peer_sending_commitsig(struct peer *peer, const u8 *msg);
int peer_got_commitsig(struct peer *peer, const u8 *msg);
int peer_got_revoke(struct peer *peer, const u8 *msg);

void update_per_commit_point(struct peer *peer,
			     const struct pubkey *per_commitment_point);

enum onion_type send_htlc_out(struct peer *out, u64 amount, u32 cltv,
			      const struct sha256 *payment_hash,
			      const u8 *onion_routing_packet,
			      struct htlc_in *in,
			      struct pay_command *pc,
			      struct htlc_out **houtp);

void onchain_fulfilled_htlc(struct peer *peer, const struct preimage *preimage);
#endif /* LIGHTNING_LIGHTNINGD_PEER_HTLCS_H */
