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

void dualopend_tell_depth(struct channel *channel,
			  const struct bitcoin_txid *txid,
			  u32 depth);

void watch_opening_inflight(struct lightningd *ld,
			    struct channel_inflight *inflight);

/* Close connection to an unsaved channel */
void channel_unsaved_close_conn(struct channel *channel, const char *why);

void json_add_unsaved_channel(struct json_stream *response,
			      const struct channel *channel,
			      /* Only set for listpeerchannels */
			      const struct peer *peer);

void channel_update_reserve(struct channel *channel,
			    struct channel_config *their_config,
			    struct amount_sat funding_total);
#endif /* LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H */
