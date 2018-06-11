/* Application-specific connection */
#ifndef LIGHTNING_LIGHTNINGD_APP_CONNECTION_H
#define LIGHTNING_LIGHTNINGD_APP_CONNECTION_H
#include "config.h"
#include <common/htlc_wire.h>

void handle_app_payment(enum onion_type *failcode, u8 realm, struct onionpacket *op);

#endif /* LIGHTNING_LIGHTNINGD_APP_CONNECTION_H */
