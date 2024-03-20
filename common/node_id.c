#include "config.h"
#include <assert.h>
#include <bitcoin/signature.h>
#include <ccan/array_size/array_size.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <common/node_id.h>
#include <common/type_to_string.h>
#include <wire/wire.h>

/* Convert from pubkey to compressed pubkey. */
void node_id_from_pubkey(struct node_id *id, const struct pubkey *key)
{
	size_t outlen = ARRAY_SIZE(id->k);
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, id->k, &outlen,
					   &key->pubkey,
					   SECP256K1_EC_COMPRESSED))
		abort();
}

WARN_UNUSED_RESULT
bool pubkey_from_node_id(struct pubkey *key, const struct node_id *id)
{
	return secp256k1_ec_pubkey_parse(secp256k1_ctx, &key->pubkey,
					 memcheck(id->k, sizeof(id->k)),
					 sizeof(id->k));
}

/* It's valid if we can convert to a real pubkey. */
bool node_id_valid(const struct node_id *id)
{
	struct pubkey key;
	return pubkey_from_node_id(&key, id);
}

/* Convert to hex string of SEC1 encoding */
char *fmt_node_id(const tal_t *ctx, const struct node_id *id)
{
	return tal_hexstr(ctx, id->k, sizeof(id->k));
}
REGISTER_TYPE_TO_STRING(node_id, fmt_node_id);

/* Convert from hex string of SEC1 encoding */
bool node_id_from_hexstr(const char *str, size_t slen, struct node_id *id)
{
	return hex_decode(str, slen, id->k, sizeof(id->k))
		&& node_id_valid(id);
}

int node_id_cmp(const struct node_id *a, const struct node_id *b)
{
	return memcmp(a->k, b->k, sizeof(a->k));
}

void fromwire_node_id(const u8 **cursor, size_t *max, struct node_id *id)
{
	fromwire(cursor, max, &id->k, sizeof(id->k));
}

void towire_node_id(u8 **pptr, const struct node_id *id)
{
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
	/* Cheap sanity check. For wire fuzzing, we only care about correct
	 * encoding of node IDs and not whether the IDs are valid, so we disable
	 * this check while fuzzing. */
	assert(id->k[0] == 0x2 || id->k[0] == 0x3);
#endif
	towire(pptr, id->k, sizeof(id->k));
}

bool check_signed_hash_nodeid(const struct sha256_double *hash,
			      const secp256k1_ecdsa_signature *signature,
			      const struct node_id *id)
{
	struct pubkey key;

	return pubkey_from_node_id(&key, id)
		&& check_signed_hash(hash, signature, &key);
}
