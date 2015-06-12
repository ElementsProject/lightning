#ifndef LIGHTNING_BITCOIN_ADDRESS_H
#define LIGHTNING_BITCOIN_ADDRESS_H
#include <ccan/short_types/short_types.h>
#include <openssl/ripemd.h>

struct pubkey;

/* An address is the RIPEMD160 of the SHA of the public key. */
struct bitcoin_address {
	u8 addr[RIPEMD160_DIGEST_LENGTH]; /* 20 */
};	

void bitcoin_address(const struct pubkey *key,
		     struct bitcoin_address *addr);
#endif /* LIGHTNING_BITCOIN_ADDRESS_H */
