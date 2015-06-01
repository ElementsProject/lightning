#include "signature.h"
#include "shadouble.h"
#include "bitcoin_tx.h"
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <assert.h>
#include <ccan/cast/cast.h>

struct signature *sign_hash(const tal_t *ctx, EC_KEY *private_key,
			    const struct sha256_double *h)
{
	ECDSA_SIG *sig;
	int len;
	struct signature *s;
	
	sig = ECDSA_do_sign(h->sha.u.u8, sizeof(*h), private_key);
	if (!sig)
		return NULL;

	/* See https://github.com/sipa/bitcoin/commit/a81cd9680.
	 * There can only be one signature with an even S, so make sure we
	 * get that one. */
	if (BN_is_odd(sig->s)) {
		const EC_GROUP *group;
		BIGNUM order;

		BN_init(&order);
		group = EC_KEY_get0_group(private_key);
		EC_GROUP_get_order(group, &order, NULL);
		BN_sub(sig->s, &order, sig->s);
		BN_free(&order);

		assert(!BN_is_odd(sig->s));
        }

	s = talz(ctx, struct signature);

	/* Pack r and s into signature, 32 bytes each. */
	len = BN_num_bytes(sig->r);
	assert(len <= sizeof(s->r));
	BN_bn2bin(sig->r, s->r + sizeof(s->r) - len);
	len = BN_num_bytes(sig->s);
	assert(len <= sizeof(s->s));
	BN_bn2bin(sig->s, s->s + sizeof(s->s) - len);

	ECDSA_SIG_free(sig);
	return s;
}

struct signature *sign_tx_input(const tal_t *ctx, struct bitcoin_tx *tx,
				unsigned int in,
				const u8 *subscript, size_t subscript_len,
				EC_KEY *privkey)
{
	struct sha256_double hash;
	struct sha256_ctx shactx;

	/* Transaction gets signed as if the output subscript is the
	 * only input script. */
	tx->input[in].script_length = subscript_len;
	tx->input[in].script = cast_const(u8 *, subscript);

	sha256_init(&shactx);
	sha256_tx(&shactx, tx);
	sha256_le32(&shactx, SIGHASH_ALL);
	sha256_double_done(&shactx, &hash);

	/* Reset it for next time. */
	tx->input[in].script_length = 0;
	tx->input[in].script = NULL;

	return sign_hash(ctx, privkey, &hash);
}

Signature *signature_to_proto(const tal_t *ctx, const struct signature *sig)
{
	Signature *pb = tal(ctx, Signature);
	signature__init(pb);

	assert((sig->s[31] & 1) == 0);

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

	/* S must be even */
	return (sig->s[31] & 1) == 0;
}

