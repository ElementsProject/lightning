#ifndef LIGHTNING_COMMON_PEER_FAILED_H
#define LIGHTNING_COMMON_PEER_FAILED_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>

struct channel_id;
struct per_peer_state;

/* peer_fatal_continue - Send a message to master, we've failed */
void NORETURN peer_fatal_continue(const u8 *msg TAKES, const struct per_peer_state *pps);

/**
 * peer_failed_warn - Send a warning msg and close the connection.
 * @pps: the per-peer state.
 * @channel_id: channel with error, or NULL for no particular channel.
 * @fmt...: format as per status_failed(STATUS_FAIL_PEER_BAD)
 */
void peer_failed_warn(struct per_peer_state *pps,
		      const struct channel_id *channel_id,
		      const char *fmt, ...)
	PRINTF_FMT(3,4) NORETURN;

/**
 * peer_failed_warn_nodisconnect - Send a warning msg, don't close.
 * @pps: the per-peer state.
 * @channel_id: channel with error, or NULL for no particular channel.
 * @fmt...: format as per status_failed(STATUS_FAIL_PEER_BAD)
 */
void peer_failed_warn_nodisconnect(struct per_peer_state *pps,
				   const struct channel_id *channel_id,
				   const char *fmt, ...)
	PRINTF_FMT(3,4) NORETURN;

/**
 * peer_failed_err - Send a warning msg and close the channel.
 * @pps: the per-peer state.
 * @channel_id: channel with error.
 * @fmt...: format as per status_failed(STATUS_FAIL_PEER_BAD)
 */
void peer_failed_err(struct per_peer_state *pps,
		     const struct channel_id *channel_id,
		     const char *fmt, ...)
	PRINTF_FMT(3,4) NORETURN;

/* We're failing because peer sent us an error message: NULL
 * channel_id means all channels. */
void peer_failed_received_errmsg(struct per_peer_state *pps,
				 bool disconnect,
				 const char *desc)
	NORETURN;

/* I/O error */
void peer_failed_connection_lost(void) NORETURN;

#endif /* LIGHTNING_COMMON_PEER_FAILED_H */
