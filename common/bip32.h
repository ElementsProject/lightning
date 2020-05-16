#ifndef LIGHTNING_COMMON_BIP32_H
#define LIGHTNING_COMMON_BIP32_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <stddef.h>

struct ext_key;

void towire_ext_key(u8 **pptr, const struct ext_key *bip32);
void fromwire_ext_key(const u8 **cursor, size_t *max, struct ext_key *bip32);

struct bip32_key_version {
	u32 bip32_pubkey_version;
	u32 bip32_privkey_version;
};

void towire_bip32_key_version(u8 **cursor, const struct bip32_key_version *version);
void fromwire_bip32_key_version(const u8 **cursor, size_t *max,
				struct bip32_key_version *version);

#endif /* LIGHTNING_COMMON_BIP32_H */
