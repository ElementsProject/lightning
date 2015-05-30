#include "signature.h"
#include "shadouble.h"
#include "bitcoin_tx.h"
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <assert.h>
#include <ccan/cast/cast.h>

u8 *sign_hash(const tal_t *ctx, EC_KEY *private_key,
	      const struct sha256_double *h)
{
	ECDSA_SIG *sig;
	int len;
	unsigned char *der, *ret;
	
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

	/* This tells it to allocate for us. */
	der = NULL;
	len = i2d_ECDSA_SIG(sig, &der);
	ECDSA_SIG_free(sig);

	if (len <= 0)
		return NULL;

	ret = tal_dup_arr(ctx, u8, der, len, 0);
	OPENSSL_free(der);
	return ret;
}

u8 *sign_tx_input(const tal_t *ctx, struct bitcoin_tx *tx, unsigned int in,
		  const u8 *subscript, size_t subscript_len, EC_KEY *privkey)
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
