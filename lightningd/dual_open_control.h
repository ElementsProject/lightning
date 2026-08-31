#ifndef LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H

#include "config.h"
#include <lightningd/subd.h>

struct peer_fd;

bool peer_start_dualopend(struct peer *peer, struct peer_fd *peer_fd,
			  struct channel *channel);

bool peer_restart_dualopend(struct peer *peer,
			    struct peer_fd *peer_fd,
			    struct channel *channel,
			    bool from_abort);

void watch_opening_inflight(struct lightningd *ld,
			    struct channel_inflight *inflight);

/* Close connection to an unsaved channel */
void channel_unsaved_close_conn(struct channel *channel, const char *why);

/* Bound retention of a pending saved dual-open while its peer is absent. */
void dual_open_attempt_peer_disconnected(struct channel *channel);

/* Serialize replacement behind destruction of the current dualopend. */
void dual_open_owner_begin_retirement(struct channel *channel,
				      struct subd *retiring_owner);

/* True when an RPC has been serialized but not delivered to a ready owner. */
bool dual_open_attempt_waiting_for_owner(const struct channel *channel);

/* Connectd accepted (or rejected) the pending dualopend peer route. */
void dual_open_owner_route_result(struct lightningd *ld, const u8 *msg);

/* Connectd has fully removed a terminal initial-open route. */
void dual_open_initial_release_result(struct lightningd *ld, const u8 *msg);

void NO_NULL_ARGS json_add_unsaved_channel(struct command *cmd,
					   struct json_stream *response,
					   const struct channel *channel,
					   const struct peer *peer);

void channel_update_reserve(struct channel *channel,
			    struct channel_config *their_config,
			    struct amount_sat funding_total);
#endif /* LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H */
