/* All about the HTLCs/commitment transactions for a particular peer. */
#ifndef LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#define LIGHTNING_LIGHTNINGD_PEER_HTLCS_H
#include "config.h"
#include <ccan/short_types/short_types.h>

int peer_accepted_htlc(struct peer *peer, const u8 *msg);
int peer_fulfilled_htlc(struct peer *peer, const u8 *msg);
int peer_failed_htlc(struct peer *peer, const u8 *msg);
int peer_failed_malformed_htlc(struct peer *peer, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_PEER_HTLCS_H */
