#include "bitcoin/locktime.h"
#include "bitcoin/preimage.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/signature.h"
#include "protobuf_convert.h"
#include "type_to_string.h"
#include "utils.h"
#include <ccan/crypto/sha256/sha256.h>

Signature *signature_to_proto(const tal_t *ctx, const secp256k1_ecdsa_signature *sig)
{
	u8 compact[64];
	Signature *pb = tal(ctx, Signature);
	signature__init(pb);

	assert(sig_valid(sig));

	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx,
						    compact, sig);

	/* Kill me now... */
	memcpy(&pb->r1, compact, 8);
	memcpy(&pb->r2, compact + 8, 8);
	memcpy(&pb->r3, compact + 16, 8);
	memcpy(&pb->r4, compact + 24, 8);
	memcpy(&pb->s1, compact + 32, 8);
	memcpy(&pb->s2, compact + 40, 8);
	memcpy(&pb->s3, compact + 48, 8);
	memcpy(&pb->s4, compact + 56, 8);

	return pb;
}

bool proto_to_signature(const Signature *pb, secp256k1_ecdsa_signature *sig)
{
	u8 compact[64];

 	/* Kill me again. */
	memcpy(compact, &pb->r1, 8);
	memcpy(compact + 8, &pb->r2, 8);
	memcpy(compact + 16, &pb->r3, 8);
	memcpy(compact + 24, &pb->r4, 8);
	memcpy(compact + 32, &pb->s1, 8);
	memcpy(compact + 40, &pb->s2, 8);
	memcpy(compact + 48, &pb->s3, 8);
	memcpy(compact + 56, &pb->s4, 8);

	if (secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx,
						    sig, compact)
	    != 1)
		return false;

	return sig_valid(sig);
}

BitcoinPubkey *pubkey_to_proto(const tal_t *ctx, const struct pubkey *key)
{
	BitcoinPubkey *p = tal(ctx, BitcoinPubkey);

	bitcoin_pubkey__init(p);
	p->key.len = PUBKEY_DER_LEN;
	p->key.data = tal_arr(p, u8, p->key.len);

	pubkey_to_der(p->key.data, key);

	return p;
}

bool proto_to_pubkey(const BitcoinPubkey *pb, struct pubkey *key)
{
	return pubkey_from_der(pb->key.data, pb->key.len, key);
}

Sha256Hash *sha256_to_proto(const tal_t *ctx, const struct sha256 *hash)
{
	Sha256Hash *h = tal(ctx, Sha256Hash);
	sha256_hash__init(h);

	/* Kill me now... */
	memcpy(&h->a, hash->u.u8, 8);
	memcpy(&h->b, hash->u.u8 + 8, 8);
	memcpy(&h->c, hash->u.u8 + 16, 8);
	memcpy(&h->d, hash->u.u8 + 24, 8);
	return h;
}

void proto_to_sha256(const Sha256Hash *pb, struct sha256 *hash)
{
	/* Kill me again. */
	memcpy(hash->u.u8, &pb->a, 8);
	memcpy(hash->u.u8 + 8, &pb->b, 8);
	memcpy(hash->u.u8 + 16, &pb->c, 8);
	memcpy(hash->u.u8 + 24, &pb->d, 8);
}

Preimage *preimage_to_proto(const tal_t *ctx, const struct preimage *r)
{
	Preimage *pb = tal(ctx, Preimage);
	preimage__init(pb);

	/* Kill me now... */
	memcpy(&pb->a, r->r, 8);
	memcpy(&pb->b, r->r + 8, 8);
	memcpy(&pb->c, r->r + 16, 8);
	memcpy(&pb->d, r->r + 24, 8);
	return pb;
}

void proto_to_preimage(const Preimage *pb, struct preimage *r)
{
	/* Kill me again. */
	memcpy(r->r, &pb->a, 8);
	memcpy(r->r + 8, &pb->b, 8);
	memcpy(r->r + 16, &pb->c, 8);
	memcpy(r->r + 24, &pb->d, 8);
}


bool proto_to_rel_locktime(const Locktime *l, struct rel_locktime *locktime)
{
	switch (l->locktime_case) {
	case LOCKTIME__LOCKTIME_SECONDS:
		return seconds_to_rel_locktime(l->seconds, locktime);
	case LOCKTIME__LOCKTIME_BLOCKS:
		return blocks_to_rel_locktime(l->blocks, locktime);
	default:
		return false;
	}
}

bool proto_to_abs_locktime(const Locktime *l, struct abs_locktime *locktime)
{
	switch (l->locktime_case) {
	case LOCKTIME__LOCKTIME_SECONDS:
		return seconds_to_abs_locktime(l->seconds, locktime);
	case LOCKTIME__LOCKTIME_BLOCKS:
		return blocks_to_abs_locktime(l->blocks, locktime);
	default:
		return false;
	}
}

Locktime *rel_locktime_to_proto(const tal_t *ctx,
				const struct rel_locktime *locktime)
{
	Locktime *l = tal(ctx, Locktime);
	locktime__init(l);

	if (rel_locktime_is_seconds(locktime)) {
		l->locktime_case = LOCKTIME__LOCKTIME_SECONDS;
		l->seconds = rel_locktime_to_seconds(locktime);
	} else {
		l->locktime_case = LOCKTIME__LOCKTIME_BLOCKS;
		l->blocks = rel_locktime_to_blocks(locktime);
	}
	return l;
}

Locktime *abs_locktime_to_proto(const tal_t *ctx,
				const struct abs_locktime *locktime)
{
	Locktime *l = tal(ctx, Locktime);
	locktime__init(l);

	if (abs_locktime_is_seconds(locktime)) {
		l->locktime_case = LOCKTIME__LOCKTIME_SECONDS;
		l->seconds = abs_locktime_to_seconds(locktime);
	} else {
		l->locktime_case = LOCKTIME__LOCKTIME_BLOCKS;
		l->blocks = abs_locktime_to_blocks(locktime);
	}
	return l;
}

static void *proto_tal_alloc(void *allocator_data, size_t size)
{
	return tal_arr(allocator_data, char, size);
}

static void proto_tal_free(void *allocator_data, void *pointer)
{
	tal_free(pointer);
}

/* Get allocator so decoded protobuf will be tal off it. */
struct ProtobufCAllocator *make_prototal(const tal_t *ctx)
{
	struct ProtobufCAllocator *prototal;

	prototal = tal(ctx, struct ProtobufCAllocator);
	prototal->alloc = proto_tal_alloc;
	prototal->free = proto_tal_free;
	prototal->allocator_data = tal(prototal, char);

	return prototal;
}

/* Now steal object off of allocator (and free prototal) */
void steal_from_prototal(const tal_t *ctx, struct ProtobufCAllocator *prototal,
			 const void *pb)
{
	tal_steal(ctx, pb);
	tal_steal(pb, prototal->allocator_data);
	tal_free(prototal);
}
REGISTER_TYPE_TO_HEXSTR(preimage);
