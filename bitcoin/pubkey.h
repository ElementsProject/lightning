#ifndef LIGHTNING_BITCOIN_PUBKEY_H
#define LIGHTNING_BITCOIN_PUBKEY_H
#include "config.h"
#include <ccan/crypto/ripemd160/ripemd160.h>
#include <ccan/short_types/short_types.h>
#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <secp256k1_extrakeys.h>

struct privkey;
struct secret;

#define PUBKEY_CMPR_LEN 33

struct pubkey {
	/* Unpacked pubkey (as used by libsecp256k1 internally) */
	secp256k1_pubkey pubkey;
};
/* Define pubkey_eq (no padding) */
STRUCTEQ_DEF(pubkey, 0, pubkey.data);

struct point32 {
	/* Unpacked pubkey (as used by libsecp256k1 internally) */
	secp256k1_xonly_pubkey pubkey;
};
/* Define pubkey_eq (no padding) */
STRUCTEQ_DEF(point32, 0, pubkey.data);

/* Convert from hex string of DER (scriptPubKey from validateaddress) */
bool pubkey_from_hexstr(const char *derstr, size_t derlen, struct pubkey *key);

/* Convert from hex string of DER (scriptPubKey from validateaddress) */
char *pubkey_to_hexstr(const tal_t *ctx, const struct pubkey *key);

/* Point from secret */
bool pubkey_from_secret(const struct secret *secret, struct pubkey *key);

/* Pubkey from privkey */
bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key);

/* Pubkey from DER encoding. */
bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key);

/* Pubkey to DER encoding: must be valid pubkey. */
void pubkey_to_der(u8 der[PUBKEY_CMPR_LEN], const struct pubkey *key);

/* Compare the keys `a` and `b`. Return <0 if `a`<`b`, 0 if equal and >0 otherwise */
int pubkey_cmp(const struct pubkey *a, const struct pubkey *b);

/* If the two pubkeys[] are id1 and id2, which index would id1 be? */
static inline int pubkey_idx(const struct pubkey *id1, const struct pubkey *id2)
{
	return pubkey_cmp(id1, id2) > 0;
}

/**
 * pubkey_to_hash160 - Get the hash for p2pkh payments for a given pubkey
 */
void pubkey_to_hash160(const struct pubkey *pk, struct ripemd160 *hash);

/* marshal/unmarshal functions */
void towire_pubkey(u8 **pptr, const struct pubkey *pubkey);
void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey);

/* FIXME: Old spec uses pubkey32 */
#define pubkey32 point32
#define towire_pubkey32 towire_point32
#define fromwire_pubkey32 fromwire_point32

/* marshal/unmarshal functions */
void towire_point32(u8 **pptr, const struct point32 *pubkey);
void fromwire_point32(const u8 **cursor, size_t *max, struct point32 *pubkey);

#endif /* LIGHTNING_BITCOIN_PUBKEY_H */
