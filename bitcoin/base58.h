#ifndef LIGHTNING_BITCOIN_BASE58_H
#define LIGHTNING_BITCOIN_BASE58_H
#include "config.h"

#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <secp256k1.h>
#include <stdbool.h>
#include <stdlib.h>

struct pubkey;
struct privkey;
struct bitcoin_address;

/* Encoding is version byte + ripemd160 + 4-byte checksum == 200 bits => 2^200.
 *
 * Now, 58^34 < 2^200, but 58^35 > 2^200.  So 35 digits is sufficient,
 * plus 1 terminator.
 */
#define BASE58_ADDR_MAX_LEN 36

/* For encoding private keys, it's 302 bits.
 * 58^51 < 2^302, but 58^52 > 2^302.  So 52 digits, plus one terminator. */
#define BASE58_KEY_MAX_LEN 53

/* Bitcoin address encoded in base58, with version and checksum */
char *bitcoin_to_base58(const tal_t *ctx, bool test_net,
			const struct bitcoin_address *addr);
bool bitcoin_from_base58(bool *test_net,
			 struct bitcoin_address *addr,
			 const char *base58, size_t len);

/* P2SH address encoded as base58, with version and checksum */
char *p2sh_to_base58(const tal_t *ctx, bool test_net,
		     const struct ripemd160 *p2sh);
bool p2sh_from_base58(bool *test_net,
		      struct ripemd160 *p2sh,
		      const char *base58, size_t len);

char *base58_with_check(char dest[BASE58_ADDR_MAX_LEN],
			u8 buf[1 + sizeof(struct ripemd160) + 4]);

bool key_from_base58(const char *base58, size_t base58_len,
		     bool *test_net, struct privkey *priv, struct pubkey *key);

void base58_get_checksum(u8 csum[4], const u8 buf[], size_t buflen);

#endif /* LIGHTNING_BITCOIN_BASE58_H */
