#include "bitcoin/locktime.h"
#include "bitcoin/pubkey.h"
#include "bitcoin/signature.h"
#include "protobuf_convert.h"
#include <ccan/crypto/sha256/sha256.h>

Signature *signature_to_proto(const tal_t *ctx, const struct signature *sig)
{
	Signature *pb = tal(ctx, Signature);
	signature__init(pb);

	assert(sig_valid(sig));

	/* FIXME: Need a portable way to encode signatures in libsecp! */
	
	/* Kill me now... */
	memcpy(&pb->r1, sig->sig.data, 8);
	memcpy(&pb->r2, sig->sig.data + 8, 8);
	memcpy(&pb->r3, sig->sig.data + 16, 8);
	memcpy(&pb->r4, sig->sig.data + 24, 8);
	memcpy(&pb->s1, sig->sig.data + 32, 8);
	memcpy(&pb->s2, sig->sig.data + 40, 8);
	memcpy(&pb->s3, sig->sig.data + 48, 8);
	memcpy(&pb->s4, sig->sig.data + 56, 8);
	
	return pb;
}

bool proto_to_signature(const Signature *pb, struct signature *sig)
{
	/* Kill me again. */
	/* FIXME: Need a portable way to encode signatures in libsecp! */
	
	memcpy(sig->sig.data, &pb->r1, 8);
	memcpy(sig->sig.data + 8, &pb->r2, 8);
	memcpy(sig->sig.data + 16, &pb->r3, 8);
	memcpy(sig->sig.data + 24, &pb->r4, 8);
	memcpy(sig->sig.data + 32, &pb->s1, 8);
	memcpy(sig->sig.data + 40, &pb->s2, 8);
	memcpy(sig->sig.data + 48, &pb->s3, 8);
	memcpy(sig->sig.data + 56, &pb->s4, 8);

	return sig_valid(sig);
}

BitcoinPubkey *pubkey_to_proto(const tal_t *ctx,
			       secp256k1_context *secpctx,
			       const struct pubkey *key)
{
	BitcoinPubkey *p = tal(ctx, BitcoinPubkey);

	bitcoin_pubkey__init(p);
	p->key.len = PUBKEY_DER_LEN;
	p->key.data = tal_arr(p, u8, p->key.len);

	pubkey_to_der(secpctx, p->key.data, key);

	return p;
}

bool proto_to_pubkey(secp256k1_context *secpctx,
		     const BitcoinPubkey *pb, struct pubkey *key)
{
	return pubkey_from_der(secpctx, pb->key.data, pb->key.len, key);
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

Rval *rval_to_proto(const tal_t *ctx, const struct rval *r)
{
	Rval *pb = tal(ctx, Rval);
	rval__init(pb);

	/* Kill me now... */
	memcpy(&pb->a, r->r, 8);
	memcpy(&pb->b, r->r + 8, 8);
	memcpy(&pb->c, r->r + 16, 8);
	memcpy(&pb->d, r->r + 24, 8);
	return pb;
}

void proto_to_rval(const Rval *pb, struct rval *r)
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
