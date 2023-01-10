#include "config.h"
#include <common/tx_roles.h>
#include <wire/wire.h>

void towire_tx_role(u8 **pptr, const enum tx_role tx_role)
{
	towire_u8(pptr, tx_role);
}

enum tx_role fromwire_tx_role(const u8 **cursor, size_t *max)
{
	u8 tx_role = fromwire_u8(cursor, max);
	if (tx_role >= NUM_TX_ROLES) {
		tx_role = TX_INITIATOR;
		fromwire_fail(cursor, max);
	}
	return tx_role;
}
