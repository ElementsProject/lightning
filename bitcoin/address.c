#include <ccan/crypto/sha256/sha256.h>
#include "address.h"
#include "pubkey.h"

void bitcoin_address(const struct pubkey *key, struct bitcoin_address *addr)
{
	struct sha256 h;

	sha256(&h, key->der, pubkey_derlen(key));
	ripemd160(&addr->addr, h.u.u8, sizeof(h));
}
