#include "address.h"
#include "pubkey.h"
#include <ccan/mem/mem.h>
#include <ccan/crypto/sha256/sha256.h>

void bitcoin_address(const struct pubkey *key, struct bitcoin_address *addr)
{
	struct sha256 h;

	sha256(&h, memcheck(key->der, sizeof(key->der)), sizeof(key->der));
	ripemd160(&addr->addr, h.u.u8, sizeof(h));
}
