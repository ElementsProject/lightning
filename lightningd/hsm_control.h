#ifndef LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#define LIGHTNING_LIGHTNINGD_HSM_CONTROL_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

struct lightningd;

u8 *hsm_sync_read(const tal_t *ctx, struct lightningd *ld);
void hsm_init(struct lightningd *ld, bool newdir);
#endif /* LIGHTNING_LIGHTNINGD_HSM_CONTROL_H */
