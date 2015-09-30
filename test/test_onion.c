#define _GNU_SOURCE 1
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <assert.h>
#include <ccan/tal/tal.h>
#include <ccan/mem/mem.h>
#include <ccan/crypto/sha256/sha256.h>

/* 
 * The client knows the server's public key S (which has corresponding
 private key s) in advance.
 * The client generates an ephemeral private key r, and its corresponding
 public key R.
 * The client computes K = ECDH(r, S), and sends R to the server at
 connection establishing time.
 * The server receives R, and computes K = ECHD(R, s).
 * Both client and server compute Kenc = SHA256(K || 0) and Kmac = SHA256(K
 || 1), and now send HMAC-SHA256(key=Kmac, msg=AES(key=Kenc, msg=m)) instead
 of m, for each message.
*/

//#define EXPORT_FRIENDLY 1 /* No crypto! */
//#define NO_HMAC 1 /* No real hmac */

struct seckey {
	struct sha256 k;
};

struct enckey {
	struct sha256 k;
};

struct hmackey {
	struct sha256 k;
};

struct iv {
	unsigned char iv[AES_BLOCK_SIZE];
};

static void sha_with_seed(const unsigned char secret[32],
			  unsigned char seed,
			  struct sha256 *res)
{
	struct sha256_ctx ctx;

	sha256_init(&ctx);
	sha256_update(&ctx, memcheck(secret, 32), 32);
	sha256_u8(&ctx, seed);
	sha256_done(&ctx, res);
}

static struct enckey enckey_from_secret(const unsigned char secret[32])
{
	struct enckey enckey;
	sha_with_seed(secret, 0, &enckey.k);
	return enckey;
}

static struct hmackey hmackey_from_secret(const unsigned char secret[32])
{
	struct hmackey hmackey;
	sha_with_seed(secret, 1, &hmackey.k);
	memcheck(&hmackey, 1);
	return hmackey;
}


static struct iv iv_from_secret(const unsigned char secret[32], size_t i)
{
	struct iv iv;
	struct sha256 sha;
	sha_with_seed(secret, 2, &sha);
	memcpy(iv.iv, sha.u.u8, sizeof(iv.iv));
#ifdef EXPORT_FRIENDLY
	iv.iv[0] = i*2;
#endif
	return iv;
}

static struct iv pad_iv_from_secret(const unsigned char secret[32], size_t i)
{
	struct iv iv;
	struct sha256 sha;
	sha_with_seed(secret, 3, &sha);
	memcpy(iv.iv, sha.u.u8, sizeof(iv.iv));
#ifdef EXPORT_FRIENDLY
	iv.iv[0] = i*2 + 1;
#endif
	return iv;
}

/* Not really! */
static void random_bytes(void *dst, size_t n)
{
	size_t i;
	unsigned char *d = dst;

	for (i = 0; i < n; i++)
		d[i] = random() % 256;
}

static void gen_keys(secp256k1_context *ctx,
		     struct seckey *seckey, secp256k1_pubkey *pubkey)
{
	do {
		random_bytes(seckey->k.u.u8, sizeof(seckey->k));
	} while (!secp256k1_ec_pubkey_create(ctx, pubkey, seckey->k.u.u8));
}

/*
 * Onion routing:
 *
 * Each step decrypts the payload, and removes its message.  It then
 * pads at the end to keep constant size, by encrypting 0 bytes (ZPAD)
 *
 * You can see the result of the unwrapping here:
 *
 * ENC1(PKT1 ENC2(PKT2 ENC3(PKT3 ENC4(PKT4 ENC5(PKT5 RPAD)))))
 * After 1: ENC2(PKT2 ENC3(PKT3 ENC4(PKT4 ENC5(PKT5 RPAD))))
 *		ENC1(ZPAD)
 * After 2: ENC3(PKT3 ENC4(PKT4 ENC5(PKT5 RPAD)))
 *		DEC2(ENC1(ZPAD))
 *		ENC2(ZPAD)
 * After 3: ENC4(PKT4 ENC5(PKT5 RPAD)))
 *		DEC3(DEC2(ENC1(ZPAD)) ENC2(ZPAD)) 
 *		ENC3(ZPAD)
 * After 4: ENC5(PKT5 RPAD)
 *		DEC4(DEC3(DEC2(ENC1(ZPAD)) ENC2(ZPAD)) ENC3(ZPAD))
 *		ENC4(ZPAD)
 *
 * ENC1(PKT1 ENC2(PKT2))
 * => ENC2(PKT2) ENC1(ZPAD)
 * => PKT2 DEC2(ENC1(ZPAD))
 */
#define MESSAGE_SIZE 128
#define MAX_HOPS 20

struct hop {
	struct sha256 hmac;
	/* FIXME: Must use parse/serialize functions. */
	secp256k1_pubkey pubkey;
	unsigned char msg[MESSAGE_SIZE];
};

struct onion {
	struct hop hop[MAX_HOPS];
};

static bool aes_encrypt(void *dst, const void *src, size_t len,
			const struct enckey *enckey, const struct iv *iv)
{
#ifdef EXPORT_FRIENDLY
	unsigned char *dptr = dst;
	const unsigned char *sptr = memcheck(src, len);
	size_t i;

	for (i = 0; i < len; i++)
		dptr[i] = sptr[i] + iv->iv[0] + i / sizeof(struct hop);
	return true;
#else
	EVP_CIPHER_CTX evpctx;
	int outlen;

	/* Counter mode allows parallelism in future. */
	if (EVP_EncryptInit(&evpctx, EVP_aes_256_ctr(),
			    memcheck(enckey->k.u.u8, sizeof(enckey->k)),
			    memcheck(iv->iv, sizeof(iv->iv))) != 1)
		return false;

	/* No padding, we're a multiple of 128 bits. */
	if (EVP_CIPHER_CTX_set_padding(&evpctx, 0) != 1)
		return false;

	EVP_EncryptUpdate(&evpctx, dst, &outlen, memcheck(src, len), len);
	assert(outlen == len);
	/* Shouldn't happen (no padding) */
	if (EVP_EncryptFinal(&evpctx, dst, &outlen) != 1)
		return false;
	assert(outlen == 0);
	return true;
#endif
}

static bool aes_decrypt(void *dst, const void *src, size_t len,
			const struct enckey *enckey, const struct iv *iv)
{
#ifdef EXPORT_FRIENDLY
	unsigned char *dptr = dst;
	const unsigned char *sptr = memcheck(src, len);
	size_t i;

	for (i = 0; i < len; i++)
		dptr[i] = sptr[i] - iv->iv[0] - i / sizeof(struct hop);
	return true;
#else
	EVP_CIPHER_CTX evpctx;
	int outlen;

	/* Counter mode allows parallelism in future. */
	if (EVP_DecryptInit(&evpctx, EVP_aes_256_ctr(),
			    memcheck(enckey->k.u.u8, sizeof(enckey->k)),
			    memcheck(iv->iv, sizeof(iv->iv))) != 1)
		return false;

	/* No padding, we're a multiple of 128 bits. */
	if (EVP_CIPHER_CTX_set_padding(&evpctx, 0) != 1)
		return false;

	EVP_DecryptUpdate(&evpctx, dst, &outlen, memcheck(src, len), len);
	assert(outlen == len);
	/* Shouldn't happen (no padding) */
	if (EVP_DecryptFinal(&evpctx, dst, &outlen) != 1)
		return false;
	assert(outlen == 0);
	return true;
#endif
}

void dump_contents(const void *data, size_t n)
{
	size_t i;
	const unsigned char *p = memcheck(data, n);

	for (i = 0; i < n; i++) {
		printf("%02x", p[i]);
		if (i % 16 == 15)
			printf("\n");
	}
}

static bool decrypt_padding(struct hop *padding, size_t nhops,
			    const struct enckey *enckey,
			    const struct iv *iv)
{
	/*
	 * FIXME: This would be easier if we could set the counter; instead
	 * we simulate it by decrypting junk before the actual padding.
	 */
	struct hop tmp[MAX_HOPS];

	/* Keep valgrind happy. */
	memset(tmp, 0, (MAX_HOPS - nhops) * sizeof(struct hop));

	memcpy(tmp + MAX_HOPS - nhops, padding, nhops * sizeof(struct hop));

	/* FIXME: Assumes we are allowed to decrypt in place! */
	if (!aes_decrypt((char *)tmp + offsetof(struct hop, msg),
			 (char *)tmp + offsetof(struct hop, msg),
			 sizeof(tmp) - offsetof(struct hop, msg), enckey, iv))
		return false;

	memcpy(padding, tmp + MAX_HOPS - nhops, nhops * sizeof(struct hop));
	return true;
}

/* Padding is created by encrypting zeroes. */ 
static void add_padding(struct hop *padding, 
			const struct enckey *enckey,
			const struct iv *pad_iv)
{
	static struct hop zerohop;

	aes_encrypt(padding, &zerohop, sizeof(zerohop), enckey, pad_iv);
}

static void make_hmac(const struct hop *hops, size_t num_hops,
		      const struct hop *padding,
		      const struct hmackey *hmackey,
		      struct sha256 *hmac)
{
#ifdef NO_HMAC
	/* Copy first byte of message on each hop. */
	size_t i;

	memset(hmac, 0, sizeof(*hmac));
	for (i = 0; i < MAX_HOPS; i++) {
		if (i < num_hops)
			hmac->u.u8[i] = hops[i].msg[0];
		else
			hmac->u.u8[i] = padding[i - num_hops].msg[0];
	}
#else
	HMAC_CTX ctx;
	size_t len, padlen;

	/* Calculate HMAC of pubkey onwards, plus padding. */
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, memcheck(hmackey->k.u.u8, sizeof(hmackey->k)),
		     sizeof(hmackey->k), EVP_sha256(), NULL);
	len = num_hops*sizeof(struct hop) - offsetof(struct hop, pubkey);
	HMAC_Update(&ctx, memcheck((unsigned char *)hops + offsetof(struct hop, pubkey),
				   len), len);
	padlen = (MAX_HOPS - num_hops) * sizeof(struct hop);
	HMAC_Update(&ctx, memcheck((unsigned char *)padding, padlen), padlen);
	HMAC_Final(&ctx, hmac->u.u8, NULL);
#endif
}

static bool check_hmac(struct onion *onion, const struct hmackey *hmackey)
{
	struct sha256 hmac;

	make_hmac(onion->hop, MAX_HOPS, NULL, hmackey, &hmac);
	return CRYPTO_memcmp(&hmac, &onion->hop[0].hmac, sizeof(hmac)) == 0;
}

bool create_onion(const secp256k1_pubkey pubkey[],
		  char *const msg[],
		  size_t num,
		  struct onion *onion)
{
	int i;
	struct seckey *seckeys = tal_arr(NULL, struct seckey, num);
	secp256k1_pubkey *pubkeys = tal_arr(seckeys, secp256k1_pubkey, num);
	struct enckey *enckeys = tal_arr(seckeys, struct enckey, num);
	struct hmackey *hmackeys = tal_arr(seckeys, struct hmackey, num);
	struct iv *ivs = tal_arr(seckeys, struct iv, num);
	struct iv *pad_ivs = tal_arr(seckeys, struct iv, num);
	struct hop **padding = tal_arr(seckeys, struct hop *, num);
	struct hop **hops = tal_arr(seckeys, struct hop *, num);
	size_t junk_hops;
	secp256k1_context *ctx;
	bool ok = false;

	if (num > MAX_HOPS)
		goto fail;

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

	/* First generate all the keys. */
	for (i = 0; i < num; i++) {
		unsigned char secret[32];

		gen_keys(ctx, &seckeys[i], &pubkeys[i]);

		/* Make shared secret. */
		if (!secp256k1_ecdh(ctx, secret, &pubkey[i], seckeys[i].k.u.u8))
			goto fail;

		hmackeys[i] = hmackey_from_secret(memcheck(secret, 32));
		enckeys[i] = enckey_from_secret(secret);
		ivs[i] = iv_from_secret(secret, i);
		pad_ivs[i] = pad_iv_from_secret(secret, i);
	}

	/*
	 * Building the onion is a little tricky.
	 *
	 * First, there is the padding.  That's generated by previous nodes,
	 * and "decrypted" by the others.  So we have to generate that
	 * forwards.
	 */
	for (i = 1; i < num; i++) {
		/* Each one has 1 padding from previous. */
		padding[i] = tal_arr(padding, struct hop, i);

		/* Copy padding from previous node. */
		memcpy(padding[i], padding[i-1], sizeof(struct hop)*(i-1));
		/* Previous node "decrypts" it before handing to us */
		if (!decrypt_padding(padding[i], i-1,
				     &enckeys[i-1], &ivs[i-1]))
			goto fail;
		/* And generates another lot of padding. */
		add_padding(padding[i]+i-1, &enckeys[i-1], &pad_ivs[i-1]);
	}

	/*
	 * Now the normal onion is generated backwards.
	 */

	/* Unused hops filled with random, so even recipient can't tell
	 * how many were used. */
	junk_hops = MAX_HOPS - num;

	for (i = num - 1; i >= 0; i--) {
		size_t other_hops;
		struct hop *myonion;

		other_hops = num - i - 1 + junk_hops;
		myonion = hops[i] = tal_arr(hops, struct hop, 1 + other_hops);
		if (i == num - 1) {
			/* Fill with junk. */
			random_bytes(myonion + 1,
				     other_hops * sizeof(struct hop));
		} else {
			/* Copy from next hop. */
			memcpy(myonion + 1, hops[i+1],
			       other_hops * sizeof(struct hop));
		}

		/* Now populate our hop. */
		myonion->pubkey = pubkeys[i];
		/* Set message. */
		assert(strlen(msg[i]) < MESSAGE_SIZE);
		memset(myonion->msg, 0, MESSAGE_SIZE);
		strcpy((char *)myonion->msg, msg[i]);

		/* Encrypt whole thing from message onwards. */
		if (!aes_encrypt(&myonion->msg, &myonion->msg,
				 (1 + other_hops) * sizeof(struct hop)
				 - offsetof(struct hop, msg),
				 &enckeys[i], &ivs[i]))
			goto fail;

		/* HMAC covers entire thing except hmac itself. */
		make_hmac(myonion, 1 + other_hops, padding[i],
			  &hmackeys[i], &myonion->hmac);
	}

	/* Transfer results to onion, for first node. */
	assert(tal_count(hops[0]) == MAX_HOPS);
	memcpy(onion->hop, hops[0], sizeof(onion->hop));
	ok = true;

fail:
	tal_free(seckeys);
	secp256k1_context_destroy(ctx);
	return ok;
}

/*
 * Decrypt onion, return true if onion->hop[0] is valid.
 *
 * Returns enckey and pad_iv for use in unwrap.
 */
bool decrypt_onion(const struct seckey *myseckey, struct onion *onion,
		   struct enckey *enckey, struct iv *pad_iv, size_t i)
{
	secp256k1_context *ctx;
	unsigned char secret[32];
	struct hmackey hmackey;
	struct iv iv;

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

	/* Extract shared secret. */
	if (!secp256k1_ecdh(ctx, secret, &onion->hop[0].pubkey,
			    myseckey->k.u.u8))
		goto fail;

	hmackey = hmackey_from_secret(secret);
	*enckey = enckey_from_secret(secret);
	iv = iv_from_secret(secret, i);
	*pad_iv = pad_iv_from_secret(secret, i);

	/* Check HMAC. */
#if 0
	printf("Checking HMAC using key%02x%02x%02x%02x%02x%02x%02x%02x (offset %u len %zu) for %02x%02x%02x%02x%02x%02x%02x%02x...%02x%02x%02x\n",
	       hmackey.k[0], hmackey.k[1],
	       hmackey.k[2], hmackey.k[3],
	       hmackey.k[4], hmackey.k[5],
	       hmackey.k[6], hmackey.k[7],
	       SHA256_DIGEST_LENGTH,
	       sizeof(*onion) - SHA256_DIGEST_LENGTH,
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[0],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[1],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[2],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[3],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[4],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[5],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[6],
	       ((unsigned char *)onion + SHA256_DIGEST_LENGTH)[7],
	       ((unsigned char *)(onion + 1))[-3],
	       ((unsigned char *)(onion + 1))[-2],
	       ((unsigned char *)(onion + 1))[-1]);
	dump_contents((unsigned char *)onion + SHA256_DIGEST_LENGTH,
		      sizeof(*onion) - SHA256_DIGEST_LENGTH);
#endif
	if (!check_hmac(onion, &hmackey))
		goto fail;

	/* Decrypt everything after pubkey. */
	if (!aes_decrypt(onion->hop[0].msg, onion->hop[0].msg,
			 sizeof(*onion) - offsetof(struct hop, msg),
			 enckey, &iv))
		goto fail;
	
	secp256k1_context_destroy(ctx);
	return true;

fail:
	secp256k1_context_destroy(ctx);
	return false;
}

/* Get next layer of onion, for forwarding. */
bool peel_onion(struct onion *onion,
		const struct enckey *enckey, const struct iv *pad_iv)
{
	/* Move next one to front. */
	memmove(&onion->hop[0], &onion->hop[1],
		sizeof(*onion) - sizeof(onion->hop[0]));

	/* Add random-looking (but predictable) padding. */
	memset(&onion->hop[MAX_HOPS-1], 0, sizeof(onion->hop[MAX_HOPS-1]));
	return aes_encrypt(&onion->hop[MAX_HOPS-1], &onion->hop[MAX_HOPS-1],
			   sizeof(onion->hop[MAX_HOPS-1]), enckey, pad_iv);
}

int main(int argc, char *argv[])
{
	secp256k1_context *ctx;
	size_t i, hops;
	struct seckey seckeys[MAX_HOPS];
	secp256k1_pubkey pubkeys[MAX_HOPS];
	char *msgs[MAX_HOPS];
	struct onion onion;

	assert(EVP_CIPHER_iv_length(EVP_aes_256_ctr()) == sizeof(struct iv));
	
	if (argc != 2)
		errx(1, "Usage: %s <num hops>", argv[0]);
	hops = atoi(argv[1]);
	if (hops == 0 || hops > MAX_HOPS)
		errx(1, "%s is invalid number of hops", argv[1]);
	
	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	for (i = 0; i < hops; i++) {
		asprintf(&msgs[i], "Message to %zu", i);
		gen_keys(ctx, &seckeys[i], &pubkeys[i]);
	}

	if (!create_onion(pubkeys, msgs, hops, &onion))
		errx(1, "Creating onion packet failed");

	/* Now parse and peel. */
	for (i = 0; i < hops; i++) {
		struct enckey enckey;
		struct iv pad_iv;

		printf("Decrypting with key %zi\n", i);
		if (!decrypt_onion(&seckeys[i], &onion, &enckey, &pad_iv, i))
			errx(1, "Decrypting onion for hop %zi", i);
		if (strcmp((char *)onion.hop[0].msg, msgs[i]) != 0)
			errx(1, "Bad message for hop %zi", i);
		if (!peel_onion(&onion, &enckey, &pad_iv))
			errx(1, "Peeling onion for hop %zi", i);
	}
	secp256k1_context_destroy(ctx);
	return 0;
}
