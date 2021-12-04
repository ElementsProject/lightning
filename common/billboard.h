#ifndef LIGHTNING_COMMON_BILLBOARD_H
#define LIGHTNING_COMMON_BILLBOARD_H
#include "config.h"
#include <ccan/ccan/tal/tal.h>
#include <common/htlc.h>

char *billboard_message(const tal_t *ctx,
			const bool funding_locked[NUM_SIDES],
			const bool have_sigs[NUM_SIDES],
			const bool shutdown_sent[NUM_SIDES],
			u32 depth_togo,
			size_t num_htlcs);

#endif /* LIGHTNING_COMMON_BILLBOARD_H */
