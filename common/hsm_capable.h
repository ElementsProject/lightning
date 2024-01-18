#ifndef LIGHTNING_COMMON_HSM_CAPABLE_H
#define LIGHTNING_COMMON_HSM_CAPABLE_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

/* Is this capability supported by the HSM? (So far, always a message
 * number) */
bool hsm_is_capable(const u32 *capabilities, u32 msgtype);
#endif /* LIGHTNING_COMMON_HSM_CAPABLE_H */
