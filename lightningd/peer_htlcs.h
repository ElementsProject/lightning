/* All about the HTLCs/commitment transactions for a particular peer. */
#ifndef LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#define LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* FIXME: Define serialization primitive for this? */
struct channel_info {
	secp256k1_ecdsa_signature commit_sig;
	struct channel_config their_config;
	struct pubkey remote_fundingkey;
	struct basepoints theirbase;
	struct pubkey their_per_commit_point;
};

/* Get all HTLCs for a peer, to send in init message. */
void peer_htlcs(const tal_t *ctx,
		const struct peer *peer,
		struct added_htlc **htlcs,
		enum htlc_state **htlc_states);

bool peer_save_commitsig_received(struct peer *peer, u64 commitnum);
bool peer_save_commitsig_sent(struct peer *peer, u64 commitnum);

int peer_sending_commitsig(struct peer *peer, const u8 *msg);
int peer_got_commitsig(struct peer *peer, const u8 *msg);
int peer_got_revoke(struct peer *peer, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_PEER_HTLCS_H */
