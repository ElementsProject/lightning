#ifndef LIGHTNING_BITCOIN_ADDRESS_H
#define LIGHTNING_BITCOIN_ADDRESS_H
#include "config.h"
#include <ccan/crypto/ripemd160/ripemd160.h>

/* An address is the RIPEMD160 of the SHA of the public key. */
struct bitcoin_address {
	struct ripemd160 addr;
};
#endif /* LIGHTNING_BITCOIN_ADDRESS_H */
