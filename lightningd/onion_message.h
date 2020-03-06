#ifndef LIGHTNING_LIGHTNINGD_ONION_MESSAGE_H
#define LIGHTNING_LIGHTNINGD_ONION_MESSAGE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

struct channel;

void handle_onionmsg_to_us(struct channel *channel, const u8 *msg);
void handle_onionmsg_forward(struct channel *channel, const u8 *msg);

#endif /* LIGHTNING_LIGHTNINGD_ONION_MESSAGE_H */
