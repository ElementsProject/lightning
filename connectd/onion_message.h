#ifndef LIGHTNING_CONNECTD_ONION_MESSAGE_H
#define LIGHTNING_CONNECTD_ONION_MESSAGE_H
#include "config.h"
#include <ccan/short_types/short_types.h>

/* Various messages come in from peer */
void handle_obs2_onion_message(struct daemon *daemon,
			       struct peer *peer, const u8 *msg);
void handle_onion_message(struct daemon *daemon,
			  struct peer *peer, const u8 *msg);

/* Lightningd tells us to send an onion message */
void onionmsg_req(struct daemon *daemon, const u8 *msg);

#endif /* LIGHTNING_CONNECTD_ONION_MESSAGE_H */
