#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/take/take.h>
#include <common/cryptomsg.h>
#include <common/dev_disconnect.h>
#include <common/status.h>
#include <common/utils.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <stdio.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

#if DISSECTOR
static bool write_sk(char *sk)
{
	FILE *fp;
	char *filename="keys.log";

	fp = fopen(filename, "w+");
	if (fp == NULL)
		return false;

	if (fputs(sk, fp) == -1)
		return false;

	fclose(fp);
	return true;
}
#endif

static void hkdf_two_keys(struct secret *out1, struct secret *out2,
			  const struct secret *in1,
			  const struct secret *in2)
{
	/* BOLT #8:
	 *
	 *  * `HKDF(salt,ikm)`: a function defined in
	 *    `RFC 5869`<sup>[3](#reference-3)</sup>, evaluated with a
	 *     zero-length `info` field
	 *     * All invocations of `HKDF` implicitly return 64 bytes of
	 *       cryptographic randomness using the extract-and-expand component
	 *       of the `HKDF`.
	 */
	struct secret okm[2];

	BUILD_ASSERT(sizeof(okm) == 64);
	hkdf_sha256(okm, sizeof(okm), in1, sizeof(*in1), in2, sizeof(*in2),
		    NULL, 0);
	*out1 = okm[0];
	*out2 = okm[1];
}

static void maybe_rotate_key(u64 *n, struct secret *k, struct secret *ck)
{
	struct secret new_k, new_ck;

	/* BOLT #8:
	 *
	 * A key is to be rotated after a party encrypts or decrypts 1000 times
	 * with it (i.e. every 500 messages). This can be properly accounted
	 * for by rotating the key once the nonce dedicated to it
	 * exceeds 1000.
	 */
	if (*n != 1000)
		return;

	/* BOLT #8:
	 *
	 * Key rotation for a key `k` is performed according to the following
	 * steps:
	 *
	 * 1. Let `ck` be the chaining key obtained at the end of Act Three.
	 * 2. `ck', k' = HKDF(ck, k)`
	 * 3. Reset the nonce for the key to `n = 0`.
	 * 4. `k = k'`
	 * 5. `ck = ck'`
	 */
	hkdf_two_keys(&new_ck, &new_k, ck, k);
#ifdef SUPERVERBOSE
	status_trace("# 0x%s, 0x%s = HKDF(0x%s, 0x%s)",
		     tal_hexstr(trc, &new_ck, sizeof(new_ck)),
		     tal_hexstr(trc, &new_k, sizeof(new_k)),
		     tal_hexstr(trc, ck, sizeof(*ck)),
		     tal_hexstr(trc, k, sizeof(*k)));
#endif
	*ck = new_ck;
	*k = new_k;
	*n = 0;
}

static void le64_nonce(unsigned char *npub, u64 nonce)
{
	/* BOLT #8:
	 *
	 * ...with nonce `n` encoded as 32 zero bits, followed by a
	 * *little-endian* 64-bit value.  Note: this follows the Noise Protocol
	 * convention, rather than our normal endian
	 */
	le64 le_nonce = cpu_to_le64(nonce);
	const size_t zerolen = crypto_aead_chacha20poly1305_ietf_NPUBBYTES - sizeof(le_nonce);

	BUILD_ASSERT(crypto_aead_chacha20poly1305_ietf_NPUBBYTES >= sizeof(le_nonce));
	/* First part is 0, followed by nonce. */
	memset(npub, 0, zerolen);
	memcpy(npub + zerolen, &le_nonce, sizeof(le_nonce));
}

u8 *cryptomsg_decrypt_body(const tal_t *ctx,
			   struct crypto_state *cs, const u8 *in)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen;
	size_t inlen = tal_count(in);
	u8 *decrypted;

	if (inlen < 16)
		return NULL;
	decrypted = tal_arr(ctx, u8, inlen - 16);

	le64_nonce(npub, cs->rn++);

	/* BOLT #8:
	 *
	 * 5. Decrypt `c` (using `ChaCha20-Poly1305`, `rn`, and `rk`), to
	 *    obtain decrypted plaintext packet `p`.
	 *    * The nonce `rn` MUST be incremented after this step.
	 */
	if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted,
						      &mlen, NULL,
						      memcheck(in, inlen),
						      inlen,
						      NULL, 0,
						      npub, cs->rk.data) != 0) {
		/* FIXME: Report error! */
		return tal_free(decrypted);
	}
	assert(mlen == tal_count(decrypted));

	maybe_rotate_key(&cs->rn, &cs->rk, &cs->r_ck);
	return decrypted;
}

bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 hdr[18], u16 *lenp)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen;
	be16 len;

	le64_nonce(npub, cs->rn++);

	/* BOLT #8:
	 *
	 *  2. Let the encrypted length prefix be known as `lc`.
	 *  3. Decrypt `lc` (using `ChaCha20-Poly1305`, `rn`, and `rk`), to
	 *     obtain the size of the encrypted packet `l`.
	 *    * A zero-length byte slice is to be passed as the AD
	 *	(associated data).
	 *    * The nonce `rn` MUST be incremented after this step.
	 */
	if (crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char *)&len,
						      &mlen, NULL,
						      memcheck(hdr, 18), 18,
						      NULL, 0,
						      npub, cs->rk.data) != 0) {
		/* FIXME: Report error! */
		return false;
	}
	assert(mlen == sizeof(len));
	*lenp = be16_to_cpu(len);
	return true;
}



u8 *cryptomsg_encrypt_msg(const tal_t *ctx,
			  struct crypto_state *cs,
			  const u8 *msg TAKES)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long clen, mlen = tal_count(msg);
	be16 l;
	int ret;
	u8 *out;

	out = tal_arr(ctx, u8, sizeof(l) + 16 + mlen + 16);

	/* BOLT #8:
	 *
	 * In order to encrypt and send a Lightning message (`m`) to the
	 * network stream, given a sending key (`sk`) and a nonce (`sn`), the
	 * following steps are completed:
	 *
	 *   1. Let `l = len(m)`.
	 *      * where `len` obtains the length in bytes of the Lightning
	 *        message
	 *
	 *   2. Serialize `l` into 2 bytes encoded as a big-endian integer.
	 */
	l = cpu_to_be16(mlen);

	/* BOLT #8:
	 *
	 * 3. Encrypt `l` (using `ChaChaPoly-1305`, `sn`, and `sk`), to obtain
	 *    `lc` (18 bytes)
	 *    * The nonce `sn` is encoded as a 96-bit little-endian number. As
	 *      the decoded nonce is 64 bits, the 96-bit nonce is encoded as:
	 *      32 bits of leading 0s followed by a 64-bit value.
	 *        * The nonce `sn` MUST be incremented after this step.
	 *    * A zero-length byte slice is to be passed as the AD (associated
                data).
	 */
	le64_nonce(npub, cs->sn++);
	ret = crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen,
							(unsigned char *)
							memcheck(&l, sizeof(l)),
							sizeof(l),
							NULL, 0,
							NULL, npub,
							cs->sk.data);
	assert(ret == 0);
	assert(clen == sizeof(l) + 16);
#ifdef SUPERVERBOSE
	status_trace("# encrypt l: cleartext=0x%s, AD=NULL, sn=0x%s, sk=0x%s => 0x%s",
		     tal_hexstr(trc, &l, sizeof(l)),
		     tal_hexstr(trc, npub, sizeof(npub)),
		     tal_hexstr(trc, &cs->sk, sizeof(cs->sk)),
		     tal_hexstr(trc, out, clen));
#endif

#if DISSECTOR
	/* only update when sk changed */
	if (cs->sn == 1) {
	char *mac = tal_hexstr(NULL, out+2, 16);
	char *sec = tal_hexstr(NULL, &cs->sk, sizeof(cs->sk));
	char ss[200] = {0};
	sprintf(ss, "%s %s\n", mac, sec);
	write_sk(ss);
	tal_free(mac);
	tal_free(sec);
	}
#endif

	/* BOLT #8:
	 *
	 *   4. Finally, encrypt the message itself (`m`) using the same
	 *      procedure used to encrypt the length prefix. Let
	 *      encrypted ciphertext be known as `c`.
	 *
	 *     * The nonce `sn` MUST be incremented after this step.
	 */
	le64_nonce(npub, cs->sn++);
	ret = crypto_aead_chacha20poly1305_ietf_encrypt(out + clen, &clen,
							memcheck(msg, mlen),
							mlen,
							NULL, 0,
							NULL, npub,
							cs->sk.data);
	assert(ret == 0);
	assert(clen == mlen + 16);
#ifdef SUPERVERBOSE
	status_trace("# encrypt m: cleartext=0x%s, AD=NULL, sn=0x%s, sk=0x%s => 0x%s",
		     tal_hexstr(trc, msg, mlen),
		     tal_hexstr(trc, npub, sizeof(npub)),
		     tal_hexstr(trc, &cs->sk, sizeof(cs->sk)),
		     tal_hexstr(trc, out + CRYPTOMSG_HDR_SIZE, clen));
#endif


	maybe_rotate_key(&cs->sn, &cs->sk, &cs->s_ck);

	if (taken(msg))
		tal_free(msg);
	return out;
}
