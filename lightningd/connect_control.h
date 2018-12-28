#ifndef LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#include "config.h"

struct lightningd;
struct pubkey;
struct wireaddr_internal;

/* Returns fd for gossipd to talk to connectd */
int connectd_init(struct lightningd *ld);
void connectd_activate(struct lightningd *ld);

void delay_then_reconnect(struct channel *channel, u32 seconds_delay,
			  const struct wireaddr_internal *addrhint TAKES);
void connect_succeeded(struct lightningd *ld, const struct pubkey *id);
void gossip_connect_result(struct lightningd *ld, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H */
