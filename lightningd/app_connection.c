#include <lightningd/app_connection.h>

void handle_app_payment(enum onion_type *failcode, u8 realm, struct onionpacket *op)
{
	/* FIXME: implement this function */

	*failcode = WIRE_INVALID_REALM;
}

