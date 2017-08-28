#ifndef LIGHTNING_LIGHTNINGD_PEER_FAILED_H
#define LIGHTNING_LIGHTNINGD_PEER_FAILED_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>

struct channel_id;

/**
 * peer_failed - Try sending error to peer, but exit with status.
 * @peer_fd: file descriptor for peer.
 * @cs: the peer's current crypto state.
 * @channel_id: channel with error, or NULL for all.
 * @error_code: error code as per status_failed
 * @fmt: format as per status_failed
 */
void peer_failed(int peer_fd, struct crypto_state *cs,
		const struct channel_id *channel_id,
		u16 error_code, const char *fmt, ...)
	PRINTF_FMT(5,6) NORETURN;
#endif /* LIGHTNING_STATUS_H */
