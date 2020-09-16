#ifndef LIGHTNING_COMMON_TX_ROLES_H
#define LIGHTNING_COMMON_TX_ROLES_H

#include "config.h"

#define NUM_TX_ROLES (TX_ACCEPTER + 1)
enum tx_role {
	TX_INITIATOR,
	TX_ACCEPTER,
};

#endif /* LIGHTNING_COMMON_TX_ROLES_H */
