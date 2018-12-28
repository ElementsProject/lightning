#ifndef LIGHTNING_COMMON_PEER_FAILED_H
#define LIGHTNING_COMMON_PEER_FAILED_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>

struct channel_id;

/**
 * peer_failed - Exit with error for peer.
 * @cs: the peer's current crypto state.
 * @channel_id: channel with error, or NULL for all.
 * @fmt...: format as per status_failed(STATUS_FAIL_PEER_BAD)
 */
#define peer_failed(cs, channel_id, ...) \
	peer_failed_(PEER_FD, GOSSIP_FD, (cs), (channel_id), __VA_ARGS__)

void peer_failed_(int peer_fd, int gossip_fd,
		  struct crypto_state *cs,
		  const struct channel_id *channel_id,
		  const char *fmt, ...)
	PRINTF_FMT(5,6) NORETURN;

/* We're failing because peer sent us an error message: NULL
 * channel_id means all channels. */
void peer_failed_received_errmsg(int peer_fd, int gossip_fd,
				 struct crypto_state *cs,
				 const char *desc,
				 const struct channel_id *channel_id) NORETURN;

/* I/O error */
void peer_failed_connection_lost(void) NORETURN;

#endif /* LIGHTNING_COMMON_PEER_FAILED_H */
