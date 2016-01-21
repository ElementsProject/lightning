#define _GNU_SOURCE 1
#include "onion_key.h"
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "version.h"
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/tal/tal.h>
#include <ccan/mem/mem.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/opt/opt.h>
#include <ccan/str/hex/hex.h>

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


static void ivs_from_secret(const unsigned char secret[32],
			    struct iv *iv, struct iv *pad_iv)
{
	struct sha256 sha;
	sha_with_seed(secret, 2, &sha);
	BUILD_ASSERT(sizeof(*iv) + sizeof(*pad_iv) == sizeof(sha));
	memcpy(iv->iv, sha.u.u8, sizeof(iv->iv));
	memcpy(pad_iv->iv, sha.u.u8 + sizeof(iv->iv), sizeof(pad_iv->iv));
}

/* Not really! */
static void random_bytes(void *dst, size_t n)
{
	size_t i;
	unsigned char *d = dst;

	for (i = 0; i < n; i++)
		d[i] = random() % 256;
}

/* Compressed key would start with 0x3?  Subtract from group.  Thanks
 * Greg Maxwell. */
static void flip_key(struct seckey *seckey)
{
	int i;
	bool carry = 0;

	const int64_t group[] = {
		0xFFFFFFFFFFFFFFFFULL,
		0xFFFFFFFFFFFFFFFEULL,
		0xBAAEDCE6AF48A03BULL,
		0xBFD25E8CD0364141ULL
	};

	for (i = 3; i >= 0; i--) {
		uint64_t v = be64_to_cpu(seckey->u.be64[i]);
		if (carry) {
			/* Beware wrap if v == 0xFFFF.... */
			carry = (group[i] <= v);
			v++;
		} else
			carry = (group[i] < v);

		v = group[i] - v;
		seckey->u.be64[i] = cpu_to_be64(v);
	}
}

#if 0
int main(int argc, char *argv[])
{
	struct seckey k;

	k.u.be64[0] = cpu_to_be64(0xFFFFFFFFFFFFFFFFULL);
	k.u.be64[1] = cpu_to_be64(0xFFFFFFFFFFFFFFFEULL);
	k.u.be64[2] = cpu_to_be64(0xBAAEDCE6AF48A03BULL);
	k.u.be64[3] = cpu_to_be64(0xBFD25E8CD0364141ULL);
	flip_key(&k);
	assert(k.u.be64[0] == 0);
	assert(k.u.be64[1] == 0);
	assert(k.u.be64[2] == 0);
	assert(k.u.be64[3] == 0);
	flip_key(&k);
	assert(k.u.be64[0] == cpu_to_be64(0xFFFFFFFFFFFFFFFFULL));
	assert(k.u.be64[1] == cpu_to_be64(0xFFFFFFFFFFFFFFFEULL));
	assert(k.u.be64[2] == cpu_to_be64(0xBAAEDCE6AF48A03BULL));
	assert(k.u.be64[3] == cpu_to_be64(0xBFD25E8CD0364141ULL));

	k.u.be64[0] = cpu_to_be64(0xFFFFFFFFFFFFFFFFULL);
	k.u.be64[1] = cpu_to_be64(0xFFFFFFFFFFFFFFFEULL);
	k.u.be64[2] = cpu_to_be64(0xBAAEDCE6AF48A03BULL);
	k.u.be64[3] = cpu_to_be64(0xBFD25E8CD0364142ULL);
	flip_key(&k);
	assert(k.u.be64[0] == 0xFFFFFFFFFFFFFFFFULL);
	assert(k.u.be64[1] == 0xFFFFFFFFFFFFFFFFULL);
	assert(k.u.be64[2] == 0xFFFFFFFFFFFFFFFFULL);
	assert(k.u.be64[3] == 0xFFFFFFFFFFFFFFFFULL);
	flip_key(&k);
	assert(k.u.be64[0] == cpu_to_be64(0xFFFFFFFFFFFFFFFFULL));
	assert(k.u.be64[1] == cpu_to_be64(0xFFFFFFFFFFFFFFFEULL));
	assert(k.u.be64[2] == cpu_to_be64(0xBAAEDCE6AF48A03BULL));
	assert(k.u.be64[3] == cpu_to_be64(0xBFD25E8CD0364142ULL));

	return 0;
}
#endif

static void random_key(secp256k1_context *ctx,
		       struct seckey *seckey, secp256k1_pubkey *pkey)
{
	do {
		random_bytes(seckey->u.u8, sizeof(seckey->u));
	} while (!secp256k1_ec_pubkey_create(ctx, pkey, seckey->u.u8));
}

/* We don't want to spend a byte encoding sign, so make sure it's 0x2 */
static void gen_keys(secp256k1_context *ctx,
		     struct seckey *seckey, struct onion_pubkey *pubkey)
{
	unsigned char tmp[33];
	secp256k1_pubkey pkey;
	size_t len;

	random_key(ctx, seckey, &pkey);

	secp256k1_ec_pubkey_serialize(ctx, tmp, &len, &pkey,
				      SECP256K1_EC_COMPRESSED);
	assert(len == sizeof(tmp));
	if (tmp[0] == 0x3)
		flip_key(seckey);
	memcpy(pubkey, tmp+1, sizeof(*pubkey));
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
	unsigned char msg[MESSAGE_SIZE];
	struct onion_pubkey pubkey;
	struct sha256 hmac;
};

struct onion {
	struct hop hop[MAX_HOPS];
};

/* We peel from the back. */
static struct hop *myhop(const struct onion *onion)
{
	return (struct hop *)&onion->hop[MAX_HOPS-1];
}

static bool aes_encrypt(void *dst, const void *src, size_t len,
			const struct enckey *enckey, const struct iv *iv)
{
	EVP_CIPHER_CTX evpctx;
	int outlen;

	/* Counter mode allows parallelism in future. */
	if (EVP_EncryptInit(&evpctx, EVP_aes_128_ctr(),
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
}

static bool aes_decrypt(void *dst, const void *src, size_t len,
			const struct enckey *enckey, const struct iv *iv)
{
	EVP_CIPHER_CTX evpctx;
	int outlen;

	/* Counter mode allows parallelism in future. */
	if (EVP_DecryptInit(&evpctx, EVP_aes_128_ctr(),
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
}

#if 0
static void dump_contents(const void *data, size_t n)
{
	size_t i;
	const unsigned char *p = memcheck(data, n);

	for (i = 0; i < n; i++) {
		printf("%02x", p[i]);
		if (i % 16 == 15)
			printf("\n");
	}
}
#endif

static bool aes_encrypt_offset(size_t offset,
			       void *dst, const void *src, size_t len,
			       const struct enckey *enckey,
			       const struct iv *iv)
{
	/*
	 * FIXME: This would be easier if we could set the counter; instead
	 * we simulate it by encrypting junk before the actual data.
	 */
	char tmp[offset + len];
	
	/* Keep valgrind happy. */
	memset(tmp, 0, offset);
	memcpy(tmp + offset, src, len);

	/* FIXME: Assumes we are allowed to encrypt in place! */
	if (!aes_encrypt(tmp, tmp, offset+len, enckey, iv))
		return false;

	memcpy(dst, tmp + offset, len);
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
	HMAC_CTX ctx;
	size_t len, padlen;

	/* Calculate HMAC of padding then onion up to and including pubkey. */
	HMAC_CTX_init(&ctx);
	HMAC_Init_ex(&ctx, memcheck(hmackey->k.u.u8, sizeof(hmackey->k)),
		     sizeof(hmackey->k), EVP_sha256(), NULL);
	padlen = (MAX_HOPS - num_hops) * sizeof(struct hop);
	HMAC_Update(&ctx, memcheck((unsigned char *)padding, padlen), padlen);
	len = num_hops*sizeof(struct hop) - sizeof(hops->hmac);
	HMAC_Update(&ctx, memcheck((unsigned char *)hops, len), len);
	HMAC_Final(&ctx, hmac->u.u8, NULL);
}

#if 0
static void _dump_hex(unsigned char *x, size_t s) {
	printf(" ");
	while (s > 0) {
		printf("%02x", *x);
		x++; s--;
	}
}
#define dump_hex(x) _dump_hex((void*)&x, sizeof(x))

static void dump_pkey(secp256k1_context *ctx, secp256k1_pubkey pkey) {
	unsigned char tmp[65];
	size_t len;
	secp256k1_ec_pubkey_serialize(ctx, tmp, &len, &pkey, 0);
	dump_hex(tmp);
}
#endif

static bool check_hmac(struct onion *onion, const struct hmackey *hmackey)
{
	struct sha256 hmac;

	make_hmac(onion->hop, MAX_HOPS, NULL, hmackey, &hmac);
	return CRYPTO_memcmp(&hmac, &myhop(onion)->hmac, sizeof(hmac)) == 0;
}

static bool create_onion(const secp256k1_pubkey pubkey[],
			 char *const msg[],
			 size_t num,
			 struct onion *onion)
{
	int i;
	struct seckey seckeys[MAX_HOPS];
	struct onion_pubkey pubkeys[MAX_HOPS];
	struct enckey enckeys[MAX_HOPS];
	struct hmackey hmackeys[MAX_HOPS];
	struct iv ivs[MAX_HOPS];
	struct iv pad_ivs[MAX_HOPS];
	HMAC_CTX padding_hmac[MAX_HOPS];
	struct hop padding[MAX_HOPS];
	size_t junk_hops;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	bool ok = false;

	if (num > MAX_HOPS)
		goto fail;

	/* FIXME: I think it would be safe to reuse a single disposable key
	 * here? */
	/* First generate all the keys. */
	for (i = 0; i < num; i++) {
		unsigned char secret[32];

		gen_keys(ctx, &seckeys[i], &pubkeys[i]);


		/* Make shared secret. */
		if (!secp256k1_ecdh(ctx, secret, &pubkey[i], seckeys[i].u.u8))
			goto fail;

		hmackeys[i] = hmackey_from_secret(memcheck(secret, 32));
		enckeys[i] = enckey_from_secret(secret);
		ivs_from_secret(secret, &ivs[i], &pad_ivs[i]);
	}

	/*
	 * Building the onion is a little tricky.
	 *
	 * First, there is the padding.  That's generated by previous nodes,
	 * and "decrypted" by the others.  So we have to generate that
	 * forwards.
	 */
	for (i = 0; i < num; i++) {
		if (i > 0) {
			/* Previous node decrypts padding before passing on. */
			aes_decrypt(padding, padding, sizeof(struct hop)*(i-1),
				    &enckeys[i-1], &ivs[i-1]);
			memmove(padding + 1, padding,
				sizeof(struct hop)*(i-1));
		}
		/* And generates more padding for next node. */
		add_padding(&padding[0], &enckeys[i-1], &pad_ivs[i-1]);
		HMAC_CTX_init(&padding_hmac[i]);
		HMAC_Init_ex(&padding_hmac[i],
			     hmackeys[i].k.u.u8, sizeof(hmackeys[i].k),
			     EVP_sha256(), NULL);
		HMAC_Update(&padding_hmac[i],
			    memcheck((unsigned char *)padding,
				     i * sizeof(struct hop)),
			    i * sizeof(struct hop));
	}

	/*
	 * Now the normal onion is generated backwards.
	 */

	/* Unused hops filled with random, so even recipient can't tell
	 * how many were used. */
	junk_hops = MAX_HOPS - num;
	random_bytes(onion->hop, junk_hops * sizeof(struct hop));

	for (i = num - 1; i >= 0; i--) {
		size_t other_hops, len;
		struct hop *myhop;

		other_hops = num - i - 1 + junk_hops;

		/* Our entry is at tail of onion. */
		myhop = onion->hop + other_hops;

		/* Now populate our hop. */
		myhop->pubkey = pubkeys[i];
		/* Set message. */
		assert(strlen(msg[i]) < MESSAGE_SIZE);
		memset(myhop->msg, 0, MESSAGE_SIZE);
		strcpy((char *)myhop->msg, msg[i]);

		/* Encrypt whole thing, including our message, but we
		 * aware it will be offset by the prepended padding. */
		if (!aes_encrypt_offset(i * sizeof(struct hop),
					onion, onion,
					other_hops * sizeof(struct hop)
					+ sizeof(myhop->msg),
					&enckeys[i], &ivs[i]))
			goto fail;

		/* HMAC covers entire thing except hmac itself. */
		len = (other_hops + 1)*sizeof(struct hop) - sizeof(myhop->hmac);
		HMAC_Update(&padding_hmac[i],
			    memcheck((unsigned char *)onion, len), len);
		HMAC_Final(&padding_hmac[i], myhop->hmac.u.u8, NULL);
	}

	ok = true;
fail:
	secp256k1_context_destroy(ctx);
	return ok;
}

static bool pubkey_parse(const secp256k1_context *ctx,
			 secp256k1_pubkey* pubkey,
			 struct onion_pubkey *pkey)
{
	unsigned char tmp[33];

	tmp[0] = 0x2;
	memcpy(tmp+1, pkey, sizeof(*pkey));
	return secp256k1_ec_pubkey_parse(ctx, pubkey, tmp, sizeof(tmp));
}

/*
 * Decrypt onion, return true if onion->hop[0] is valid.
 *
 * Returns enckey and pad_iv for use in unwrap.
 */
static bool decrypt_onion(const struct seckey *myseckey, struct onion *onion,
			  struct enckey *enckey, struct iv *pad_iv)
{
	secp256k1_context *ctx;
	unsigned char secret[32];
	struct hmackey hmackey;
	struct iv iv;
	secp256k1_pubkey pubkey;

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

	if (!pubkey_parse(ctx, &pubkey, &myhop(onion)->pubkey))
		goto fail;
	
	/* Extract shared secret. */
	if (!secp256k1_ecdh(ctx, secret, &pubkey, myseckey->u.u8))
		goto fail;

	hmackey = hmackey_from_secret(secret);
	*enckey = enckey_from_secret(secret);
	ivs_from_secret(secret, &iv, pad_iv);

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

	/* Decrypt everything up to pubkey. */
	/* FIXME: Assumes we can decrypt in place! */
	if (!aes_decrypt(onion, onion,
			 sizeof(struct hop) * (MAX_HOPS-1)
			 + sizeof(myhop(onion)->msg),
			 enckey, &iv))
		goto fail;
	
	secp256k1_context_destroy(ctx);
	return true;

fail:
	secp256k1_context_destroy(ctx);
	return false;
}

/* Get next layer of onion, for forwarding. */
static bool peel_onion(struct onion *onion,
		       const struct enckey *enckey, const struct iv *pad_iv)
{
	/* Move next one to back. */
	memmove(&onion->hop[1], &onion->hop[0],
		sizeof(*onion) - sizeof(onion->hop[0]));

	/* Add random-looking (but predictable) padding. */
	memset(&onion->hop[0], 0, sizeof(onion->hop[0]));
	return aes_encrypt(&onion->hop[0], &onion->hop[0],
			   sizeof(onion->hop[0]), enckey, pad_iv);
}

static bool parse_onion_pubkey(secp256k1_context *ctx,
			       const char *arg, secp256k1_pubkey *pubkey)
{
	unsigned char tmp[33] = { };

	if (!hex_decode(arg, strlen(arg), tmp, sizeof(tmp)))
		return false;

	return secp256k1_ec_pubkey_parse(ctx, pubkey, tmp, sizeof(tmp));
}

static char *make_message(secp256k1_context *ctx,
		const secp256k1_pubkey *pubkey)
{
	char *m;
	unsigned char tmp[33];
	size_t len;
	char hexstr[hex_str_size(20)];

	secp256k1_ec_pubkey_serialize(ctx, tmp, &len, pubkey,
				      SECP256K1_EC_COMPRESSED);
	hex_encode(tmp+1, 20, hexstr, sizeof(hexstr));
	asprintf(&m, "Message for %s...", hexstr);
	return m;
}

int main(int argc, char *argv[])
{
	secp256k1_context *ctx;
	struct onion onion;
	bool generate = false, decode = false;

	assert(EVP_CIPHER_iv_length(EVP_aes_128_ctr()) == sizeof(struct iv));
	
	opt_register_noarg("--help|-h", opt_usage_and_exit,
			   "--generate <pubkey>... OR\n"
			   "--decode <privkey>\n"
			   "Either create an onion message, or decode one step",
			   "Print this message.");
	opt_register_noarg("--generate",
			   opt_set_bool, &generate,
			   "Generate onion through the given hex pubkeys");
	opt_register_noarg("--decode",
			   opt_set_bool, &decode,
			   "Decode onion given the private key");
	opt_register_version();

 	opt_parse(&argc, argv, opt_log_stderr_exit);

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	if (generate) {
		secp256k1_pubkey pubkeys[MAX_HOPS];
		char *msgs[MAX_HOPS];
		size_t i;

		if (argc == 1)
			opt_usage_exit_fail("Expected at least one pubkey");
		if (argc-1 > MAX_HOPS)
			opt_usage_exit_fail("Expected at most %u pubkeys",
					    MAX_HOPS);
		for (i = 1; i < argc; i++) {
			if (!parse_onion_pubkey(ctx, argv[i], &pubkeys[i-1]))
				errx(1, "Bad pubkey '%s'", argv[i]);
			msgs[i-1] = make_message(ctx, &pubkeys[i-1]);
		}

		if (!create_onion(pubkeys, msgs, argc - 1, &onion))
			errx(1, "Creating onion packet failed");
		if (!write_all(STDOUT_FILENO, &onion, sizeof(onion)))
			err(1, "Writing onion packet");
		return 0;
	} else if (decode) {
		struct seckey seckey;
		secp256k1_pubkey pubkey;
		struct enckey enckey;
		struct iv pad_iv;

		if (argc != 2)
			opt_usage_exit_fail("Expect a privkey with --decode");

		if (!hex_decode(argv[1], strlen(argv[1]), &seckey, sizeof(seckey)))
			errx(1, "Invalid private key hex '%s'", argv[1]);
		if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey.u.u8))
			errx(1, "Invalid private key '%s'", argv[1]);

		if (!read_all(STDIN_FILENO, &onion, sizeof(onion)))
			errx(1, "Reading in onion");

		if (!decrypt_onion(&seckey, &onion, &enckey, &pad_iv))
			errx(1, "Failed decrypting onion for '%s'", argv[1]);
		if (strncmp((char *)myhop(&onion)->msg, make_message(ctx, &pubkey),
			    sizeof(myhop(&onion)->msg)))
			errx(1, "Bad message '%s'", (char *)myhop(&onion)->msg);
		if (!peel_onion(&onion, &enckey, &pad_iv))
			errx(1, "Peeling onion for '%s'", argv[1]);
		if (!write_all(STDOUT_FILENO, &onion, sizeof(onion)))
			err(1, "Writing onion packet");
		return 0;
	} else
		opt_usage_exit_fail("Need --decode or --generate");
		
	secp256k1_context_destroy(ctx);
	return 0;
}
