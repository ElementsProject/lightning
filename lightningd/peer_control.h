#ifndef LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#define LIGHTNING_LIGHTNINGD_PEER_CONTROL_H
#include "config.h"
#include <stdbool.h>

struct lightningd;

struct peer *peer_by_unique_id(struct lightningd *ld, u64 unique_id);

void setup_listeners(struct lightningd *ld);
#endif /* LIGHTNING_LIGHTNINGD_PEER_CONTROL_H */
