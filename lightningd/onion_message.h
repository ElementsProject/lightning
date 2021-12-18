#ifndef LIGHTNING_LIGHTNINGD_ONION_MESSAGE_H
#define LIGHTNING_LIGHTNINGD_ONION_MESSAGE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct lightningd;

void handle_onionmsg_to_us(struct lightningd *ld, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_ONION_MESSAGE_H */
