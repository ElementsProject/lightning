#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <lightningd/cryptomsg.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <status.h>
#include <utils.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

static void hkdf_two_keys(struct sha256 *out1, struct sha256 *out2,
			  const struct sha256 *in1,
			  const struct sha256 *in2)
{
	/* BOLT #8:
	 *
	 *   * `HKDF(salt,ikm)`: a function is defined in [5](#reference-5),
	 *      evaluated with a zero-length `info` field.
	 *      * All invocations of the `HKDF` implicitly return `64-bytes`
	 *        of cryptographic randomness using the extract-and-expand
	 *        component of the `HKDF`.
	 */
	struct sha256 okm[2];

	BUILD_ASSERT(sizeof(okm) == 64);
	hkdf_sha256(okm, sizeof(okm), in1, sizeof(*in1), in2, sizeof(*in2),
		    NULL, 0);
	*out1 = okm[0];
	*out2 = okm[1];
}

static void maybe_rotate_key(u64 *n, struct sha256 *k, struct sha256 *ck)
{
	struct sha256 new_k, new_ck;

	/* BOLT #8:
	 *
	 * A key is to be rotated after a party sends of decrypts
	 * `1000` messages with it.  This can be properly accounted
	 * for by rotating the key once the nonce dedicated to it
	 * exceeds `1000`.
	 */
	if (*n != 1000)
		return;

	/* BOLT #8:
	 *
	 * Key rotation for a key `k` is performed according to the following:
	 *
	 *   * Let `ck` be the chaining key obtained at the end of `Act Three`.
	 *   * `ck', k' = HKDF(ck, k)`
	 *   * Reset the nonce for the key to `n = 0`.
	 *   * `k = k'`
	 *   * `ck = ck'`
	 */
	hkdf_two_keys(&new_ck, &new_k, ck, k);
	status_trace("# 0x%s, 0x%s = HKDF(0x%s, 0x%s)",
		     tal_hexstr(trc, &new_ck, sizeof(new_ck)),
		     tal_hexstr(trc, &new_k, sizeof(new_k)),
		     tal_hexstr(trc, ck, sizeof(*ck)),
		     tal_hexstr(trc, k, sizeof(*k)));
	*ck = new_ck;
	*k = new_k;
	*n = 0;
}

static void le64_nonce(unsigned char *npub, u64 nonce)
{
	/* BOLT #8:
	 *
	 * ...with nonce `n` encoded as 32 zero bits followed by a
	 * *little-endian* 64-bit value (this follows the Noise Protocol
	 * convention, rather than our normal endian).
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
	 * * Decrypt `c` using `ChaCha20-Poly1305`, `rn`, and `rk` to
	 *   obtain decrypted plaintext packet `p`.
	 *
	 *   * The nonce `rn` MUST be incremented after this step.
	 */
	if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted,
						      &mlen, NULL,
						      memcheck(in, inlen),
						      inlen,
						      NULL, 0,
						      npub, cs->rk.u.u8) != 0) {
		/* FIXME: Report error! */
		return tal_free(decrypted);
	}
	assert(mlen == tal_count(decrypted));

	maybe_rotate_key(&cs->rn, &cs->rk, &cs->r_ck);
	return decrypted;
}

static struct io_plan *peer_decrypt_body(struct io_conn *conn,
					 struct crypto_state *cs)
{
	struct io_plan *plan;
	u8 *in, *decrypted;

	decrypted = cryptomsg_decrypt_body(cs->in, cs, cs->in);
	if (!decrypted)
		return io_close(conn);

	/* Steal cs->in: we free it after, and decrypted too unless
	 * they steal but be careful not to touch anything after
	 * next_in (could free itself) */
	in = tal_steal(NULL, cs->in);
	cs->in = NULL;

	plan = cs->next_in(conn, cs->peer, decrypted);
	tal_free(in);
	return plan;
}

bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 *hdr, u16 *lenp)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen;
	be16 len;

	le64_nonce(npub, cs->rn++);

	/* BOLT #8:
	 *
	 *  * Let the encrypted length prefix be known as `lc`
	 *
	 *  * Decrypt `lc` using `ChaCha20-Poy1305`, `rn`, and `rk` to
	 *    obtain size of the encrypted packet `l`.
	 *    * A zero-length byte slice is to be passed as the AD
	 *	(associated data).
	 *    * The nonce `rn` MUST be incremented after this step.
	 */
	if (crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char *)&len,
						      &mlen, NULL,
						      memcheck(hdr,
							       tal_count(hdr)),
						      tal_count(hdr),
						      NULL, 0,
						      npub, cs->rk.u.u8) != 0) {
		/* FIXME: Report error! */
		return false;
	}
	assert(mlen == sizeof(len));
	*lenp = be16_to_cpu(len);
	return true;
}

static struct io_plan *peer_decrypt_header(struct io_conn *conn,
					   struct crypto_state *cs)
{
	u16 len;

	if (!cryptomsg_decrypt_header(cs, cs->in, &len))
		return io_close(conn);

	tal_free(cs->in);

	/* BOLT #8:
	 *
	 * * Read _exactly_ `l+16` bytes from the network buffer, let
	 *   the bytes be known as `c`.
	 */
	cs->in = tal_arr(cs, u8, (u32)len + 16);
	return io_read(conn, cs->in, tal_count(cs->in), peer_decrypt_body, cs);
}

struct io_plan *peer_read_message(struct io_conn *conn,
				  struct crypto_state *cs,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *,
							  u8 *msg))
{
	assert(!cs->in);
	/* BOLT #8:
	 *
	 * ### Decrypting Messages
	 *
	 * In order to decrypt the _next_ message in the network
	 * stream, the following is done:
	 *
	 *  * Read _exactly_ `18-bytes` from the network buffer.
	 */
	cs->in = tal_arr(cs, u8, 18);
	cs->next_in = next;
	return io_read(conn, cs->in, 18, peer_decrypt_header, cs);
}

static struct io_plan *peer_write_done(struct io_conn *conn,
				       struct crypto_state *cs)
{
	cs->out = tal_free(cs->out);
	return cs->next_out(conn, cs->peer);
}

u8 *cryptomsg_encrypt_msg(const tal_t *ctx,
			  struct crypto_state *cs,
			  const u8 *msg)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long clen, mlen = tal_count(msg);
	be16 l;
	int ret;
	u8 *out;

	out = tal_arr(cs, u8, sizeof(l) + 16 + mlen + 16);

	/* BOLT #8:
	 *
	 * In order to encrypt a lightning message (`m`), given a
	 * sending key (`sk`), and a nonce (`sn`), the following is done:
	 *
	 *
	 *   * let `l = len(m)`,
	 *      where `len` obtains the length in bytes of the lightning message.
	 *
	 *   * Serialize `l` into `2-bytes` encoded as a big-endian integer.
	 */
	l = cpu_to_be16(mlen);

	/* BOLT #8:
	 *
	 *   * Encrypt `l` using `ChaChaPoly-1305`, `sn`, and `sk` to obtain `lc`
	 *     (`18-bytes`)
	 *     * The nonce `sn` is encoded as a 96-bit little-endian number.
	 *      As our decoded nonces a 64-bit, we encode the 96-bit nonce as
	 *      follows: 32-bits of leading zeroes followed by a 64-bit value.
	 * 	* The nonce `sn` MUST be incremented after this step.
	 *     * A zero-length byte slice is to be passed as the AD
	 */
	le64_nonce(npub, cs->sn++);
	ret = crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen,
							(unsigned char *)
							memcheck(&l, sizeof(l)),
							sizeof(l),
							NULL, 0,
							NULL, npub,
							cs->sk.u.u8);
	assert(ret == 0);
	assert(clen == sizeof(l) + 16);
#ifdef SUPERVERBOSE
	status_trace("# encrypt l: cleartext=0x%s, AD=NULL, sn=0x%s, sk=0x%s => 0x%s",
		     tal_hexstr(trc, &l, sizeof(l)),
		     tal_hexstr(trc, npub, sizeof(npub)),
		     tal_hexstr(trc, &cs->sk, sizeof(cs->sk)),
		     tal_hexstr(trc, out, clen));
#endif

	/* BOLT #8:
	 *
	 *   * Finally encrypt the message itself (`m`) using the same
	 *     procedure used to encrypt the length prefix. Let
	 *     encrypted ciphertext be known as `c`.
	 *
	 *     * The nonce `sn` MUST be incremented after this step.
	 */
	le64_nonce(npub, cs->sn++);
	ret = crypto_aead_chacha20poly1305_ietf_encrypt(out + clen, &clen,
							memcheck(msg, mlen),
							mlen,
							NULL, 0,
							NULL, npub,
							cs->sk.u.u8);
	assert(ret == 0);
	assert(clen == mlen + 16);
#ifdef SUPERVERBOSE
	status_trace("# encrypt m: cleartext=0x%s, AD=NULL, sn=0x%s, sk=0x%s => 0x%s",
		     tal_hexstr(trc, msg, mlen),
		     tal_hexstr(trc, npub, sizeof(npub)),
		     tal_hexstr(trc, &cs->sk, sizeof(cs->sk)),
		     tal_hexstr(trc, out + 18, clen));
#endif

	maybe_rotate_key(&cs->sn, &cs->sk, &cs->s_ck);

	return out;
}

struct io_plan *peer_write_message(struct io_conn *conn,
				   struct crypto_state *cs,
				   const u8 *msg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *))
{
	assert(!cs->out);

	cs->out = cryptomsg_encrypt_msg(cs, cs, msg);
	cs->next_out = next;

	/* BOLT #8:
	 *   * Send `lc || c` over the network buffer.
	 */
	return io_write(conn, cs->out, tal_count(cs->out), peer_write_done, cs);
}

struct crypto_state *crypto_state(struct peer *peer,
				  const struct sha256 *sk,
				  const struct sha256 *rk,
				  const struct sha256 *rck,
				  const struct sha256 *sck,
				  u64 rn, u64 sn)
{
	struct crypto_state *cs = tal(peer, struct crypto_state);

	cs->rn = rn;
	cs->sn = sn;
	cs->sk = *sk;
	cs->rk = *rk;
	cs->s_ck = *sck;
	cs->r_ck = *rck;
	cs->peer = peer;
	cs->out = cs->in = NULL;

	return cs;
}

void towire_crypto_state(u8 **ptr, const struct crypto_state *cs)
{
	towire_u64(ptr, cs->rn);
	towire_u64(ptr, cs->sn);
	towire_sha256(ptr, &cs->sk);
	towire_sha256(ptr, &cs->rk);
	towire_sha256(ptr, &cs->s_ck);
	towire_sha256(ptr, &cs->r_ck);
}

void fromwire_crypto_state(const u8 **ptr, size_t *max, struct crypto_state *cs)
{
	cs->rn = fromwire_u64(ptr, max);
	cs->sn = fromwire_u64(ptr, max);
	fromwire_sha256(ptr, max, &cs->sk);
	fromwire_sha256(ptr, max, &cs->rk);
	fromwire_sha256(ptr, max, &cs->s_ck);
	fromwire_sha256(ptr, max, &cs->r_ck);
}
