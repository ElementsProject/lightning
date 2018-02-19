#ifndef LIGHTNING_COMMON_PEER_FAILED_H
#define LIGHTNING_COMMON_PEER_FAILED_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>

struct channel_id;

/**
 * peer_failed - Exit with error for peer.
 * @cs: the peer's current crypto state.
 * @gossip_index: the peer's current gossip_index.
 * @channel_id: channel with error, or NULL for all.
 * @fmt...: format as per status_failed(STATUS_FAIL_PEER_BAD)
 */
#define peer_failed(cs, gossip_index, channel_id, ...) \
	peer_failed_(PEER_FD, GOSSIP_FD, (cs), (gossip_index), (channel_id), \
		     __VA_ARGS__)

void peer_failed_(int peer_fd, int gossip_fd,
		  struct crypto_state *cs, u64 gossip_index,
		  const struct channel_id *channel_id,
		  const char *fmt, ...)
	PRINTF_FMT(6,7) NORETURN;
#endif /* LIGHTNING_COMMON_PEER_FAILED_H */
