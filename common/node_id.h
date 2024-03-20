/* Encapsulation for pubkeys used as node ids: more compact, more dangerous. */
#ifndef LIGHTNING_COMMON_NODE_ID_H
#define LIGHTNING_COMMON_NODE_ID_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <common/pseudorand.h>

struct sha256_double;

struct node_id {
	u8 k[PUBKEY_CMPR_LEN];
};

static inline bool node_id_eq(const struct node_id *a,
			      const struct node_id *b)
{
	return memcmp(a->k, b->k, sizeof(a->k)) == 0;
}

/* Is this actually a valid pubkey?  Relatively expensive. */
bool node_id_valid(const struct node_id *id);

/* Convert from pubkey to compressed pubkey. */
void node_id_from_pubkey(struct node_id *id, const struct pubkey *key);

/* Returns false if not a valid pubkey: relatively expensive */
WARN_UNUSED_RESULT
bool pubkey_from_node_id(struct pubkey *key, const struct node_id *id);

/* Convert to hex string of SEC1 encoding. */
char *fmt_node_id(const tal_t *ctx, const struct node_id *id);

/* Convert from hex string of SEC1 encoding: checks validity! */
bool node_id_from_hexstr(const char *str, size_t slen, struct node_id *id);

/* Compare the keys `a` and `b`. Return <0 if `a`<`b`, 0 if equal and >0 otherwise */
int node_id_cmp(const struct node_id *a, const struct node_id *b);

/* If the two nodes[] are id1 and id2, which index would id1 be? */
static inline int node_id_idx(const struct node_id *id1,
			      const struct node_id *id2)
{
	return node_id_cmp(id1, id2) > 0;
}

/* marshal/unmarshal functions */
void towire_node_id(u8 **pptr, const struct node_id *id);
void fromwire_node_id(const u8 **cursor, size_t *max, struct node_id *id);

/* Hash table functions for node ids */
static inline const struct node_id *node_id_keyof(const struct node_id *id)
{
	return id;
}

/* We need to define a hashing function. siphash24 is a fast yet
 * cryptographic hash in ccan/crypto/siphash24; we might be able to get away
 * with a slightly faster hash with fewer guarantees, but it's good hygiene to
 * use this unless it's a proven bottleneck.  siphash_seed() is a function in
 * common/pseudorand which sets up a seed for our hashing; it's different
 * every time the program is run. */
static inline size_t node_id_hash(const struct node_id *id)
{
	return siphash24(siphash_seed(), id->k, sizeof(id->k));
}

/**
 * check_signed_hash_nodeid - check a raw secp256k1 signature.
 * @h: hash which was signed.
 * @signature: signature.
 * @id: node_id corresponding to private key used to sign.
 *
 * Returns true if the id, hash and signature are correct.  Changing any
 * one of these will make it fail.
 */
bool check_signed_hash_nodeid(const struct sha256_double *hash,
			      const secp256k1_ecdsa_signature *signature,
			      const struct node_id *id);

#endif /* LIGHTNING_COMMON_NODE_ID_H */
