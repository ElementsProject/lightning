#ifndef LIGHTNING_COMMON_CLOSING_FEE_H
#define LIGHTNING_COMMON_CLOSING_FEE_H

#include "config.h"

#include <ccan/short_types/short_types.h>

/** During closing fee negotiation give up N% of the range between our
 * proposal and the peer's proposal on each step. */
static const u8 CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE = 0;

/** During closing fee negotiation give up N satoshi of the range between our
 * proposal and the peer's proposal on each step. */
static const u8 CLOSING_FEE_NEGOTIATION_STEP_UNIT_SATOSHI = 1;

#endif /* LIGHTNING_COMMON_CLOSING_FEE_H */
