#ifndef LIGHTNING_BITCOIN_ADDRESS_H
#define LIGHTNING_BITCOIN_ADDRESS_H
#include <openssl/ripemd.h>
#include <ccan/short_types/short_types.h>

/* An address is the RIPEMD160 of the SHA of the public key. */
struct bitcoin_address {
	u8 addr[RIPEMD160_DIGEST_LENGTH]; /* 20 */
};	

/* An ECDSA compressed public key.  33 chars long, even on ARM. */
struct bitcoin_compressed_pubkey {
	u8 key[33];
} __attribute__((aligned(1)));

void bitcoin_address(const struct bitcoin_compressed_pubkey *key,
		     struct bitcoin_address *addr);
#endif /* LIGHTNING_BITCOIN_ADDRESS_H */
