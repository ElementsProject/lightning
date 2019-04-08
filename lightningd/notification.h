#ifndef LIGHTNING_LIGHTNINGD_NOTIFICATION_H
#define LIGHTNING_LIGHTNINGD_NOTIFICATION_H
#include "config.h"
#include <lightningd/jsonrpc.h>
#include <lightningd/lightningd.h>
#include <lightningd/plugin.h>

bool notifications_have_topic(const char *topic);

void notify_connect(struct lightningd *ld, struct node_id *nodeid,
		    struct wireaddr_internal *addr);
void notify_disconnect(struct lightningd *ld, struct node_id *nodeid);

#endif /* LIGHTNING_LIGHTNINGD_NOTIFICATION_H */
