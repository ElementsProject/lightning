#ifndef LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H
#define LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H

#include "config.h"
#include <lightningd/subd.h>

struct per_peer_state;

void peer_start_dualopend(struct peer *peer,
			  struct per_peer_state *pps,
			  const u8 *send_msg);

void dualopen_tell_depth(struct subd *dualopend,
			 struct channel *channel,
			 u32 depth);
#endif /* LIGHTNING_LIGHTNINGD_DUAL_OPEN_CONTROL_H */
