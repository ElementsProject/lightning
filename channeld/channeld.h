#ifndef LIGHTNING_CHANNELD_CHANNELD_H
#define LIGHTNING_CHANNELD_CHANNELD_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/take/take.h>
#include <ccan/tal/tal.h>

const u8 *hsm_req(const tal_t *ctx, const u8 *req TAKES);

#endif /* LIGHTNING_CHANNELD_CHANNELD_H */
