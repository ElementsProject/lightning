#ifndef LIGHTNING_CONNECTD_ONION_MESSAGE_H
#define LIGHTNING_CONNECTD_ONION_MESSAGE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* Onion message comes in from peer. */
void handle_onion_message(struct daemon *daemon,
			  struct peer *peer, const u8 *msg);

/* Lightningd tells us to send an onion message */
void onionmsg_req(struct daemon *daemon, const u8 *msg);

/* Lightning tells us unwrap onion message as if from peer */
void inject_onionmsg_req(struct daemon *daemon, const u8 *msg);

#endif /* LIGHTNING_CONNECTD_ONION_MESSAGE_H */
