#include <assert.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <ccan/short_types/short_types.h>
#include <ccan/take/take.h>
#include <lightningd/cryptomsg.h>
#include <lightningd/dev_disconnect.h>
#include <lightningd/status.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <utils.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_io.h>

static void hkdf_two_keys(struct secret *out1, struct secret *out2,
			  const struct secret *in1,
			  const struct secret *in2)
{
	/* BOLT #8:
	 *
	 *   * `HKDF(salt,ikm)`: a function is defined in [3](#reference-3),
	 *      evaluated with a zero-length `info` field.
	 *      * All invocations of the `HKDF` implicitly return `64-bytes`
	 *        of cryptographic randomness using the extract-and-expand
	 *        component of the `HKDF`.
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
						      npub, cs->rk.data) != 0) {
		/* FIXME: Report error! */
		return tal_free(decrypted);
	}
	assert(mlen == tal_count(decrypted));

	maybe_rotate_key(&cs->rn, &cs->rk, &cs->r_ck);
	return decrypted;
}

static struct io_plan *peer_decrypt_body(struct io_conn *conn,
					 struct peer_crypto_state *pcs)
{
	struct io_plan *plan;
	u8 *in, *decrypted;

	decrypted = cryptomsg_decrypt_body(pcs->in, &pcs->cs, pcs->in);
	if (!decrypted)
		return io_close(conn);

	/* BOLT #1:
	 *
	 * A node MUST ignore a received message of unknown type, if that type
	 * is odd.
	 */
	if (unlikely(is_unknown_msg_discardable(decrypted))) {
		pcs->in = tal_free(pcs->in);
		return peer_read_message(conn, pcs, pcs->next_in);
	}

	/* Steal cs->in: we free it after, and decrypted too unless
	 * they steal but be careful not to touch anything after
	 * next_in (could free itself) */
	in = tal_steal(NULL, pcs->in);
	pcs->in = NULL;

	plan = pcs->next_in(conn, pcs->peer, decrypted);
	tal_free(in);
	return plan;
}

bool cryptomsg_decrypt_header(struct crypto_state *cs, u8 hdr[18], u16 *lenp)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen;
	be16 len;

	le64_nonce(npub, cs->rn++);

	/* BOLT #8:
	 *
	 *  * Let the encrypted length prefix be known as `lc`
	 *
	 *  * Decrypt `lc` using `ChaCha20-Poly1305`, `rn`, and `rk` to
	 *    obtain size of the encrypted packet `l`.
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

static struct io_plan *peer_decrypt_header(struct io_conn *conn,
					   struct peer_crypto_state *pcs)
{
	u16 len;

	if (!cryptomsg_decrypt_header(&pcs->cs, pcs->in, &len))
		return io_close(conn);

	tal_free(pcs->in);

	/* BOLT #8:
	 *
	 * * Read _exactly_ `l+16` bytes from the network buffer, let
	 *   the bytes be known as `c`.
	 */
	pcs->in = tal_arr(conn, u8, (u32)len + 16);
	return io_read(conn, pcs->in, tal_count(pcs->in), peer_decrypt_body,
		       pcs);
}

struct io_plan *peer_read_message(struct io_conn *conn,
				  struct peer_crypto_state *pcs,
				  struct io_plan *(*next)(struct io_conn *,
							  struct peer *,
							  u8 *msg))
{
	assert(!pcs->in);
	/* BOLT #8:
	 *
	 * ### Decrypting Messages
	 *
	 * In order to decrypt the _next_ message in the network
	 * stream, the following is done:
	 *
	 *  * Read _exactly_ `18-bytes` from the network buffer.
	 */
	pcs->in = tal_arr(conn, u8, 18);
	pcs->next_in = next;
	return io_read(conn, pcs->in, 18, peer_decrypt_header, pcs);
}

static struct io_plan *peer_write_done(struct io_conn *conn,
				       struct peer_crypto_state *pcs)
{
	pcs->out = tal_free(pcs->out);
	return pcs->next_out(conn, pcs->peer);
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
							cs->sk.data);
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

	if (taken(msg))
		tal_free(msg);
	return out;
}

static struct io_plan *peer_write_postclose(struct io_conn *conn,
					    struct peer_crypto_state *pcs)
{
	pcs->out = tal_free(pcs->out);
	dev_sabotage_fd(io_conn_fd(conn));
	return pcs->next_out(conn, pcs->peer);
}

struct io_plan *peer_write_message(struct io_conn *conn,
				   struct peer_crypto_state *pcs,
				   const u8 *msg,
				   struct io_plan *(*next)(struct io_conn *,
							   struct peer *))
{
	struct io_plan *(*post)(struct io_conn *, struct peer_crypto_state *);
	int type = fromwire_peektype(msg);
	assert(!pcs->out);

	pcs->out = cryptomsg_encrypt_msg(conn, &pcs->cs, msg);
	pcs->next_out = next;

	post = peer_write_done;

	switch (dev_disconnect(type)) {
	case DEV_DISCONNECT_BEFORE:
		return io_close(conn);
	case DEV_DISCONNECT_DROPPKT:
		pcs->out = NULL; /* FALL THRU */
	case DEV_DISCONNECT_AFTER:
		post = peer_write_postclose;
		break;
	default:
		break;
	}

	/* BOLT #8:
	 *   * Send `lc || c` over the network buffer.
	 */
	return io_write(conn, pcs->out, tal_count(pcs->out), post, pcs);
}

void init_peer_crypto_state(struct peer *peer, struct peer_crypto_state *pcs)
{
	pcs->peer = peer;
	pcs->out = pcs->in = NULL;
}

void towire_crypto_state(u8 **ptr, const struct crypto_state *cs)
{
	towire_u64(ptr, cs->rn);
	towire_u64(ptr, cs->sn);
	towire_secret(ptr, &cs->sk);
	towire_secret(ptr, &cs->rk);
	towire_secret(ptr, &cs->s_ck);
	towire_secret(ptr, &cs->r_ck);
}

void fromwire_crypto_state(const u8 **ptr, size_t *max, struct crypto_state *cs)
{
	cs->rn = fromwire_u64(ptr, max);
	cs->sn = fromwire_u64(ptr, max);
	fromwire_secret(ptr, max, &cs->sk);
	fromwire_secret(ptr, max, &cs->rk);
	fromwire_secret(ptr, max, &cs->s_ck);
	fromwire_secret(ptr, max, &cs->r_ck);
}
