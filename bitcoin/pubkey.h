#ifndef LIGHTNING_BITCOIN_PUBKEY_H
#define LIGHTNING_BITCOIN_PUBKEY_H
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include "../lightning.pb-c.h"

struct pubkey {
	u8 key[65];
};

/* Convert to-from protobuf to internal representation. */
BitcoinPubkey *pubkey_to_proto(const tal_t *ctx, const struct pubkey *key);
bool proto_to_pubkey(const BitcoinPubkey *pb, struct pubkey *key);

/* 33 or 65 bytes? */
size_t pubkey_len(const struct pubkey *key);

/* Convert from hex string (scriptPubKey from validateaddress) */
bool pubkey_from_hexstr(const char *str, struct pubkey *key);

#endif /* LIGHTNING_PUBKEY_H */
