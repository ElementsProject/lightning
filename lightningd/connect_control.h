#ifndef LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#include "config.h"

struct lightningd;
struct pubkey;

void connect_succeeded(struct lightningd *ld, const struct pubkey *id);
void connect_failed(struct lightningd *ld, const struct pubkey *id,
		    const char *error);

/* Gossipd was unable to connect to the peer */
void peer_connection_failed(struct lightningd *ld, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H */
