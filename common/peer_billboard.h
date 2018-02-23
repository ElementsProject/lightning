#ifndef LIGHTNING_COMMON_PEER_BILLBOARD_H
#define LIGHTNING_COMMON_PEER_BILLBOARD_H
#include "config.h"
#include <stdbool.h>

/* Key information for RPC display: perm means it outlasts this daemon. */
void peer_billboard(bool perm, const char *fmt, ...);

#endif /* LIGHTNING_COMMON_PEER_BILLBOARD_H */
