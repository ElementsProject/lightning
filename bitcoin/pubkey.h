#ifndef LIGHTNING_BITCOIN_PUBKEY_H
#define LIGHTNING_BITCOIN_PUBKEY_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "secp256k1.h"

struct privkey;

struct pubkey {
	/* DER-encoded key (as hashed by bitcoin, for addresses) */
	u8 der[65];
	/* Unpacked pubkey (as used by libsecp256k1 internally) */
	secp256k1_pubkey pubkey;
};

/* Convert from hex string of DER (scriptPubKey from validateaddress) */
bool pubkey_from_hexstr(const char *derstr, struct pubkey *key);

/* Pubkey from privkey */
bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key,
			 unsigned int compressed_flags);

/* Pubkey from DER encoding. */
bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key);

/* How many bytes of key->der are valid. */
size_t pubkey_derlen(const struct pubkey *key);

/* Are these keys equal? */
bool pubkey_eq(const struct pubkey *a, const struct pubkey *b);
#endif /* LIGHTNING_PUBKEY_H */
