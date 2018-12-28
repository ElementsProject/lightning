#ifndef LIGHTNING_LIGHTNINGD_PING_H
#define LIGHTNING_LIGHTNINGD_PING_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct subd;
void ping_reply(struct subd *subd, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_PING_H */
