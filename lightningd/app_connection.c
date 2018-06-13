#include <lightningd/app_connection.h>

void handle_app_payment(
	enum onion_type *failcode,
	const struct htlc_in *hin,
	const struct route_step *rs)
{
	/* FIXME: implement this function */

	*failcode = WIRE_INVALID_REALM;
}

