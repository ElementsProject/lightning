#include <ccan/crypto/sha256/sha256.h>
#include "bitcoin/pubkey.h"
#include "bitcoin/signature.h"
#include "protobuf_convert.h"

Signature *signature_to_proto(const tal_t *ctx, const struct signature *sig)
{
	Signature *pb = tal(ctx, Signature);
	signature__init(pb);

	assert(sig_valid(sig));

	/* Kill me now... */
	memcpy(&pb->r1, sig->r, 8);
	memcpy(&pb->r2, sig->r + 8, 8);
	memcpy(&pb->r3, sig->r + 16, 8);
	memcpy(&pb->r4, sig->r + 24, 8);
	memcpy(&pb->s1, sig->s, 8);
	memcpy(&pb->s2, sig->s + 8, 8);
	memcpy(&pb->s3, sig->s + 16, 8);
	memcpy(&pb->s4, sig->s + 24, 8);

	return pb;
}

bool proto_to_signature(const Signature *pb, struct signature *sig)
{
	/* Kill me again. */
	memcpy(sig->r, &pb->r1, 8);
	memcpy(sig->r + 8, &pb->r2, 8);
	memcpy(sig->r + 16, &pb->r3, 8);
	memcpy(sig->r + 24, &pb->r4, 8);
	memcpy(sig->s, &pb->s1, 8);
	memcpy(sig->s + 8, &pb->s2, 8);
	memcpy(sig->s + 16, &pb->s3, 8);
	memcpy(sig->s + 24, &pb->s4, 8);

	return sig_valid(sig);
}

BitcoinPubkey *pubkey_to_proto(const tal_t *ctx, const struct pubkey *key)
{
	BitcoinPubkey *p = tal(ctx, BitcoinPubkey);

	bitcoin_pubkey__init(p);
	p->key.len = pubkey_len(key);
	p->key.data = tal_dup_arr(p, u8, key->key, p->key.len, 0);

	assert(pubkey_valid(p->key.data, p->key.len));
	return p;
}

bool proto_to_pubkey(const BitcoinPubkey *pb, struct pubkey *key)
{
	if (!pubkey_valid(pb->key.data, pb->key.len))
		return false;

	memcpy(key->key, pb->key.data, pb->key.len);
	return true;
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

bool proto_to_locktime(const OpenChannel *o, uint32_t *locktime)
{
	switch (o->locktime_case) {
	case OPEN_CHANNEL__LOCKTIME_LOCKTIME_SECONDS:
		*locktime = 500000000 + o->locktime_seconds;
		break;
	case OPEN_CHANNEL__LOCKTIME_LOCKTIME_BLOCKS:
		*locktime = o->locktime_blocks;
		break;
	default:
		return false;
	}
	return true;
}
