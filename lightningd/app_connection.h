/* Application-specific connection */
#ifndef LIGHTNING_LIGHTNINGD_APP_CONNECTION_H
#define LIGHTNING_LIGHTNINGD_APP_CONNECTION_H
#include "config.h"
#include <common/htlc_wire.h>
#include <common/sphinx.h>

struct htlc_in;

void handle_app_payment(
	enum onion_type *failcode,
	const struct htlc_in *hin,
	const struct route_step *rs);

#endif /* LIGHTNING_LIGHTNINGD_APP_CONNECTION_H */
