#ifndef LIGHTNING_COMMON_PEER_FAILED_H
#define LIGHTNING_COMMON_PEER_FAILED_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>

struct channel_id;

/**
 * peer_failed - Try sending error to peer, but exit with status.
 * @peer_fd: file descriptor for peer.
 * @cs: the peer's current crypto state.
 * @channel_id: channel with error, or NULL for all.
 * @fmt: format as per status_failed(STATUS_FAIL_PEER_BAD,
 */
void peer_failed(int peer_fd, struct crypto_state *cs,
		const struct channel_id *channel_id,
		const char *fmt, ...)
	PRINTF_FMT(4,5) NORETURN;
#endif /* LIGHTNING_COMMON_PEER_FAILED_H */
