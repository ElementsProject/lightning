#include "bitcoin_address.h"
#include <ccan/crypto/sha256/sha256.h>

void bitcoin_address(const struct bitcoin_compressed_pubkey *key,
		     struct bitcoin_address *addr)
{
	struct sha256 h;

	sha256(&h, key, sizeof(*key));
	RIPEMD160(h.u.u8, sizeof(h), addr->addr);
}
