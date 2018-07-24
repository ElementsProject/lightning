#ifndef LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#define LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H
#include "config.h"

struct lightningd;
struct pubkey;

/* Returns fd for gossipd to talk to connectd */
int connectd_init(struct lightningd *ld);
void connectd_activate(struct lightningd *ld);

void gossip_connect_result(struct lightningd *ld, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_CONNECT_CONTROL_H */
