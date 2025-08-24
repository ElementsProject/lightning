#ifndef LIGHTNING_LIGHTNINGD_PING_H
#define LIGHTNING_LIGHTNINGD_PING_H
#include "config.h"

struct subd;

void handle_ping_done(struct subd *connectd, const u8 *msg);
#endif /* LIGHTNING_LIGHTNINGD_PING_H */
