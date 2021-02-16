#ifndef LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H

#include "config.h"
#include <lightningd/subd.h>

struct per_peer_state;

void peer_start_dualopend(struct peer *peer,
			  struct per_peer_state *pps,
			  const u8 *send_msg);

void peer_restart_dualopend(struct peer *peer,
			    struct per_peer_state *pps,
			    struct channel *channel,
			    const u8 *send_msg);

void dualopen_tell_depth(struct subd *dualopend,
			 struct channel *channel,
			 const struct bitcoin_txid *txid,
			 u32 depth);

void channel_close_conn(struct channel *channel,
			const char *why);

void json_add_unsaved_channel(struct json_stream *response,
			      const struct channel *channel);
#endif /* LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H */
