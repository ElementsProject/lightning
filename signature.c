#include "signature.h"
#include "shadouble.h"
#include "bitcoin_tx.h"
#include "pubkey.h"
#include "bitcoin_script.h"
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <assert.h>
#include <ccan/cast/cast.h>

#undef DEBUG
#ifdef DEBUG
#include <ccan/err/err.h>
#define SHA_FMT					   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"

#define SHA_VALS(e)							\
	e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7],			\
		e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15],	\
		e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23], \
		e[24], e[25], e[25], e[26], e[28], e[29], e[30], e[31]

static void dump_tx(const char *msg,
		    const struct bitcoin_tx *tx, size_t inputnum,
		    const u8 *script, size_t script_len,
		    const struct pubkey *key)
{
	size_t i, j;
	warnx("%s tx version %u locktime %#x:",
	      msg, tx->version, tx->lock_time);
	for (i = 0; i < tx->input_count; i++) {
		warnx("input[%zu].txid = "SHA_FMT, i,
		      SHA_VALS(tx->input[i].txid.sha.u.u8));
		warnx("input[%zu].index = %u", i, tx->input[i].index);
	}
	for (i = 0; i < tx->output_count; i++) {
		warnx("output[%zu].amount = %llu",
		      i, (long long)tx->output[i].amount);
		warnx("output[%zu].script = %llu",
		      i, (long long)tx->output[i].script_length);
		for (j = 0; j < tx->output[i].script_length; j++)
			fprintf(stderr, "%02x", tx->output[i].script[j]);
		fprintf(stderr, "\n");
	}
	warnx("input[%zu].script = %zu", inputnum, script_len);
	for (i = 0; i < script_len; i++)
		fprintf(stderr, "%02x", script[i]);
	if (key) {
		fprintf(stderr, "\nPubkey: ");
		for (i = 0; i < pubkey_len(key); i++)
			fprintf(stderr, "%02x", key->key[i]);
		fprintf(stderr, "\n");
	}
}
#else
static void dump_tx(const char *msg,
		    const struct bitcoin_tx *tx, size_t inputnum,
		    const u8 *script, size_t script_len,
		    const struct pubkey *key)
{
}
#endif
	
bool sign_hash(const tal_t *ctx, EC_KEY *private_key,
	       const struct sha256_double *h,
	       struct signature *s)
{
	ECDSA_SIG *sig;
	int len;
	
	sig = ECDSA_do_sign(h->sha.u.u8, sizeof(*h), private_key);
	if (!sig)
		return false;

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

	/* In case numbers are small. */
	memset(s, 0, sizeof(*s));

	/* Pack r and s into signature, 32 bytes each. */
	len = BN_num_bytes(sig->r);
	assert(len <= sizeof(s->r));
	BN_bn2bin(sig->r, s->r + sizeof(s->r) - len);
	len = BN_num_bytes(sig->s);
	assert(len <= sizeof(s->s));
	BN_bn2bin(sig->s, s->s + sizeof(s->s) - len);

	ECDSA_SIG_free(sig);
	return true;
}

/* Only does SIGHASH_ALL */
static void sha256_tx_one_input(struct bitcoin_tx *tx,
				size_t input_num,
				const u8 *script, size_t script_len,
				struct sha256_double *hash)
{
	struct sha256_ctx ctx = SHA256_INIT;
	size_t i;

	assert(input_num < tx->input_count);

	/* You must have all inputs zeroed to start. */
	for (i = 0; i < tx->input_count; i++)
		assert(tx->input[i].script_length == 0);

	tx->input[input_num].script_length = script_len;
	tx->input[input_num].script = cast_const(u8 *, script);

	sha256_init(&ctx);
	sha256_tx(&ctx, tx);
	sha256_le32(&ctx, SIGHASH_ALL);
	sha256_double_done(&ctx, hash);

	/* Reset it for next time. */
	tx->input[input_num].script_length = 0;
	tx->input[input_num].script = NULL;
}

/* Only does SIGHASH_ALL */
bool sign_tx_input(const tal_t *ctx, struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript, size_t subscript_len,
		   EC_KEY *privkey, const struct pubkey *key,
		   struct signature *sig)
{
	struct sha256_double hash;

	sha256_tx_one_input(tx, in, subscript, subscript_len, &hash);
	dump_tx("Signing", tx, in, subscript, subscript_len, key);
	return sign_hash(ctx, privkey, &hash, sig);
}

static bool check_signed_hash(const struct sha256_double *hash,
			      const struct signature *signature,
			      const struct pubkey *key)
{
	bool ok = false;	
	BIGNUM r, s;
	ECDSA_SIG sig = { &r, &s };
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_secp256k1);
	const unsigned char *k = key->key;

	/* S must be even: https://github.com/sipa/bitcoin/commit/a81cd9680 */
	assert((signature->s[31] & 1) == 0);

	/* Unpack public key. */
	if (!o2i_ECPublicKey(&eckey, &k, pubkey_len(key)))
		goto out;

	/* Unpack signature. */
	BN_init(&r);
	BN_init(&s);
	if (!BN_bin2bn(signature->r, sizeof(signature->r), &r)
	    || !BN_bin2bn(signature->s, sizeof(signature->s), &s))
		goto free_bns;

	/* Now verify hash with public key and signature. */
	switch (ECDSA_do_verify(hash->sha.u.u8, sizeof(hash->sha.u), &sig,
				eckey)) {
	case 0:
		/* Invalid signature */
		goto free_bns;
	case -1:
		/* Malformed or other error. */
		goto free_bns;
	}

	ok = true;

free_bns:
	BN_free(&r);
	BN_free(&s);

out:
	EC_KEY_free(eckey);
        return ok;
}

bool check_tx_sig(struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript, size_t redeemscript_len,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig)
{
	struct sha256_double hash;
	bool ret;

	assert(input_num < tx->input_count);

	sha256_tx_one_input(tx, input_num, redeemscript, redeemscript_len,
			    &hash);

	/* We only use SIGHASH_ALL for the moment. */
	if (sig->stype != SIGHASH_ALL)
		return false;
	
	ret = check_signed_hash(&hash, &sig->sig, key);
	if (!ret)
		dump_tx("Sig failed", tx, input_num,
			redeemscript, redeemscript_len, key);
	return ret;
}

bool check_2of2_sig(struct bitcoin_tx *tx, size_t input_num,
		    const u8 *redeemscript, size_t redeemscript_len,
		    const struct pubkey *key1, const struct pubkey *key2,
		    const struct bitcoin_signature *sig1,
		    const struct bitcoin_signature *sig2)
{
	struct sha256_double hash;
	assert(input_num < tx->input_count);

	sha256_tx_one_input(tx, input_num, redeemscript, redeemscript_len,
			    &hash);

	/* We only use SIGHASH_ALL for the moment. */
	if (sig1->stype != SIGHASH_ALL || sig2->stype != SIGHASH_ALL)
		return false;
	
	return check_signed_hash(&hash, &sig1->sig, key1)
		&& check_signed_hash(&hash, &sig2->sig, key2);
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

