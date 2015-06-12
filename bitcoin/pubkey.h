#ifndef LIGHTNING_BITCOIN_PUBKEY_H
#define LIGHTNING_BITCOIN_PUBKEY_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct pubkey {
	u8 key[65];
};

/* 33 or 65 bytes? */
size_t pubkey_len(const struct pubkey *key);

/* Convert from hex string (scriptPubKey from validateaddress) */
bool pubkey_from_hexstr(const char *str, struct pubkey *key);

/* For conversion routines in protobuf_convert.c */
bool pubkey_valid(const u8 *first_char, size_t len);

#endif /* LIGHTNING_PUBKEY_H */
