#ifndef LIGHTNING_COMMON_TX_ROLES_H
#define LIGHTNING_COMMON_TX_ROLES_H

#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stddef.h>

#define NUM_TX_ROLES (TX_ACCEPTER + 1)
enum tx_role {
	TX_INITIATOR,
	TX_ACCEPTER,
};


void towire_tx_role(u8 **pptr, const enum tx_role tx_role);
enum tx_role fromwire_tx_role(const u8 **cursor, size_t *max);
#endif /* LIGHTNING_COMMON_TX_ROLES_H */
