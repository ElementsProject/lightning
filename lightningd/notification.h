#ifndef LIGHTNING_LIGHTNINGD_NOTIFICATION_H
#define LIGHTNING_LIGHTNINGD_NOTIFICATION_H
#include "config.h"
#include <lightningd/jsonrpc.h>
#include <lightningd/plugin.h>

bool notifications_have_topic(const char *topic);

#endif /* LIGHTNING_LIGHTNINGD_NOTIFICATION_H */
