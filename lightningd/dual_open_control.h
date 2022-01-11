#ifndef LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H

#include "config.h"
#include <lightningd/subd.h>

struct peer_fd;

void peer_start_dualopend(struct peer *peer, struct peer_fd *peer_fd);

void peer_restart_dualopend(struct peer *peer,
			    struct peer_fd *peer_fd,
			    struct channel *channel);

void dualopen_tell_depth(struct subd *dualopend,
			 struct channel *channel,
			 const struct bitcoin_txid *txid,
			 u32 depth);

/* Close connection to an unsaved channel */
void channel_unsaved_close_conn(struct channel *channel, const char *why);

void json_add_unsaved_channel(struct json_stream *response,
			      const struct channel *channel);

void channel_update_reserve(struct channel *channel,
			    struct channel_config *their_config,
			    struct amount_sat funding_total);
#endif /* LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H */
