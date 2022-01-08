#include "config.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/io/io.h>
#include <ccan/mem/mem.h>
#include <common/crypto_state.h>
#include <common/ecdh.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <connectd/handshake.h>
#include <errno.h>
#include <secp256k1_ecdh.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/randombytes.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

enum bolt8_side {
	INITIATOR,
	RESPONDER
};

/* BOLT #8:
 *
 * Act One is sent from initiator to responder. During Act One, the
 * initiator attempts to satisfy an implicit challenge by the responder. To
 * complete this challenge, the initiator must know the static public key of
 * the responder.
 */
struct act_one {
	u8 v;
	u8 pubkey[PUBKEY_CMPR_LEN];
	u8 tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
};

/* BOLT #8: The handshake message is _exactly_ 50 bytes */
#define ACT_ONE_SIZE 50 /* ARM's stupid ABI adds padding. */

static inline void check_act_one(const struct act_one *act1)
{
	/* BOLT #8:
	 *
	 * : 1 byte for the handshake version, 33 bytes for the compressed
	 * ephemeral public key of the initiator, and 16 bytes for the
	 * `poly1305` tag.
	 */
	BUILD_ASSERT(sizeof(act1->v) == 1);
	BUILD_ASSERT(sizeof(act1->pubkey) == 33);
	BUILD_ASSERT(sizeof(act1->tag) == 16);
}

/* BOLT #8:
 *
 * Act Two is sent from the responder to the initiator. Act Two will
 * _only_ take place if Act One was successful. Act One was successful if
 * the responder was able to properly decrypt and check the MAC of the tag
 * sent at the end of Act One.
 */
struct act_two {
	u8 v;
	u8 pubkey[PUBKEY_CMPR_LEN];
	u8 tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
};

/* BOLT #8: The handshake is _exactly_ 50 bytes: */
#define ACT_TWO_SIZE 50 /* ARM's stupid ABI adds padding. */

static inline void check_act_two(const struct act_two *act2)
{
	/* BOLT #8:
	 * 1 byte for the handshake version,
	 * 33 bytes for the compressed ephemeral public key of the initiator, and
	 * 16 bytes for the `poly1305` tag.
	 */
	BUILD_ASSERT(sizeof(act2->v) == 1);
	BUILD_ASSERT(sizeof(act2->pubkey) == 33);
	BUILD_ASSERT(sizeof(act2->tag) == 16);
}

/* BOLT #8:
 *
 * Act Three is the final phase in the authenticated key agreement described
 * in this section. This act is sent from the initiator to the responder as a
 * concluding step. Act Three is executed  _if and only if_  Act Two was
 * successful.  During Act Three, the initiator transports its static public
 * key to the responder encrypted with _strong_ forward secrecy, using the
 * accumulated `HKDF` derived secret key at this point of the handshake.
 */
struct act_three {
	u8 v;
	u8 ciphertext[PUBKEY_CMPR_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES];
	u8 tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
};

/* BOLT #8: The handshake is _exactly_ 66 bytes */
#define ACT_THREE_SIZE 66 /* ARM's stupid ABI adds padding. */

static inline void check_act_three(const struct act_three *act3)
{
	/* BOLT #8:
	 *
	 * 1 byte for the handshake version, 33 bytes for the
	 * compressed ephemeral public key of the initiator, and 16
	 * bytes for the `poly1305` tag.
	 */
	BUILD_ASSERT(sizeof(act3->v) == 1);
	BUILD_ASSERT(sizeof(act3->ciphertext) == 33 + 16);
	BUILD_ASSERT(sizeof(act3->tag) == 16);
}

/* BOLT #8:
 *
 *  * `generateKey()`: generates and returns a fresh `secp256k1` keypair
 *      * Where the object returned by `generateKey` has two attributes:
 *          * `.pub`, which returns an abstract object representing the
 *            public key
 *          * `.priv`, which represents the private key used to generate the
 *            public key
 */
struct keypair {
	struct pubkey pub;
	struct privkey priv;
};

/* BOLT #8:
 *
 * Throughout the handshake process, each side maintains these variables:
 *
 *  * `ck`: the **chaining key**. This value is the accumulated hash of all
 *    previous ECDH outputs. At the end of the handshake, `ck` is used to derive
 *    the encryption keys for Lightning messages.
 *
 *  * `h`: the **handshake hash**. This value is the accumulated hash of _all_
 *    handshake data that has been sent and received so far during the handshake
 *    process.
 *
 *  * `temp_k1`, `temp_k2`, `temp_k3`: the **intermediate keys**. These are used to
 *    encrypt and decrypt the zero-length AEAD payloads at the end of each handshake
 *    message.
 *
 *  * `e`: a party's **ephemeral keypair**. For each session, a node MUST generate a
 *    new ephemeral key with strong cryptographic randomness.
 *
 *  * `s`: a party's **static keypair** (`ls` for local, `rs` for remote)
 */
struct handshake {
	struct secret ck;
	struct secret temp_k;
	struct sha256 h;
	struct keypair e;
	struct secret *ss;

	/* Used between the Acts */
	struct pubkey re;
	struct act_one act1;
	struct act_two act2;
	struct act_three act3;

	/* Where is connection from/to */
	struct wireaddr_internal addr;

	/* Who we are */
	struct pubkey my_id;
	/* Who they are: set already if we're initiator. */
	struct pubkey their_id;

	/* Are we initiator or responder. */
	enum bolt8_side side;

	/* Timeout timer if we take too long. */
	struct oneshot *timeout;

	/* Function to call once handshake complete. */
	struct io_plan *(*cb)(struct io_conn *conn,
			      const struct pubkey *their_id,
			      const struct wireaddr_internal *wireaddr,
			      struct crypto_state *cs,
			      struct oneshot *timeout,
			      void *cbarg);
	void *cbarg;
};

static struct keypair generate_key(void)
{
	struct keypair k;

	do {
		randombytes_buf(k.priv.secret.data, sizeof(k.priv.secret.data));
	} while (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					     &k.pub.pubkey, k.priv.secret.data));
	return k;
}

/* h = SHA-256(h || data) */
static void sha_mix_in(struct sha256 *h, const void *data, size_t len)
{
	struct sha256_ctx shactx;

	sha256_init(&shactx);
	sha256_update(&shactx, h, sizeof(*h));
	sha256_update(&shactx, data, len);
	sha256_done(&shactx, h);
}

/* h = SHA-256(h || pub.serializeCompressed()) */
static void sha_mix_in_key(struct sha256 *h, const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];
	size_t len = sizeof(der);

	secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &len, &key->pubkey,
				      SECP256K1_EC_COMPRESSED);
	assert(len == sizeof(der));
	sha_mix_in(h, der, sizeof(der));
}

/* out1, out2 = HKDF(in1, in2)` */
static void hkdf_two_keys(struct secret *out1, struct secret *out2,
			  const struct secret *in1,
			  const void *in2, size_t in2_size)
{
	/* BOLT #8:
	 *
	 *   * `HKDF(salt,ikm)`: a function defined in `RFC 5869`<sup>[3](#reference-3)</sup>,
	 *      evaluated with a zero-length `info` field
	 *      * All invocations of `HKDF` implicitly return 64 bytes
	 *        of cryptographic randomness using the extract-and-expand
	 *        component of the `HKDF`.
	 */
	struct secret okm[2];

	SUPERVERBOSE("# HKDF(0x%s,%s%s)",
		     tal_hexstr(tmpctx, in1, sizeof(*in1)),
		     in2_size ? "0x" : "zero",
		     tal_hexstr(tmpctx, in2, in2_size));
	BUILD_ASSERT(sizeof(okm) == 64);
	hkdf_sha256(okm, sizeof(okm), in1, sizeof(*in1), in2, in2_size,
		    NULL, 0);
	*out1 = okm[0];
	*out2 = okm[1];
}

static void le64_nonce(unsigned char *npub, u64 nonce)
{
	/* BOLT #8:
	 *
	 * ...with nonce `n` encoded as 32 zero bits, followed by a
	 * *little-endian* 64-bit value. Note: this follows the Noise
	 * Protocol convention, rather than our normal endian
	 */
	le64 le_nonce = cpu_to_le64(nonce);
	const size_t zerolen = crypto_aead_chacha20poly1305_ietf_NPUBBYTES - sizeof(le_nonce);

	BUILD_ASSERT(crypto_aead_chacha20poly1305_ietf_NPUBBYTES >= sizeof(le_nonce));
	/* First part is 0, followed by nonce. */
	memset(npub, 0, zerolen);
	memcpy(npub + zerolen, &le_nonce, sizeof(le_nonce));
}

/* BOLT #8:
 *   * `encryptWithAD(k, n, ad, plaintext)`: outputs `encrypt(k, n, ad,
 *      plaintext)`
 *      * Where `encrypt` is an evaluation of `ChaCha20-Poly1305` (IETF
 *	  variant) with the passed arguments, with nonce `n`
 */
static void encrypt_ad(const struct secret *k, u64 nonce,
		       const void *additional_data, size_t additional_data_len,
		       const void *plaintext, size_t plaintext_len,
		       void *output, size_t outputlen)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long clen;
	int ret;

	assert(outputlen == plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
	le64_nonce(npub, nonce);
	BUILD_ASSERT(sizeof(*k) == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
	SUPERVERBOSE("# encryptWithAD(0x%s, 0x%s, 0x%s, %s%s)",
		     tal_hexstr(tmpctx, k, sizeof(*k)),
		     tal_hexstr(tmpctx, npub, sizeof(npub)),
		     tal_hexstr(tmpctx, additional_data, additional_data_len),
		     plaintext_len ? "0x" : "<empty>",
		     tal_hexstr(tmpctx, plaintext, plaintext_len));

	ret = crypto_aead_chacha20poly1305_ietf_encrypt(output, &clen,
						   memcheck(plaintext, plaintext_len),
						   plaintext_len,
						   additional_data, additional_data_len,
							NULL, npub, k->data);
	assert(ret == 0);
	assert(clen == plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES);
}

/* BOLT #8:
 *    * `decryptWithAD(k, n, ad, ciphertext)`: outputs `decrypt(k, n, ad,
 *       ciphertext)`
 *      * Where `decrypt` is an evaluation of `ChaCha20-Poly1305` (IETF
 *        variant) with the passed arguments, with nonce `n`
 */
static bool decrypt(const struct secret *k, u64 nonce,
		    const void *additional_data, size_t additional_data_len,
		    const void *ciphertext, size_t ciphertext_len,
		    void *output, size_t outputlen)
{
	unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
	unsigned long long mlen;

	assert(outputlen == ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);

	le64_nonce(npub, nonce);
	BUILD_ASSERT(sizeof(*k) == crypto_aead_chacha20poly1305_ietf_KEYBYTES);
	SUPERVERBOSE("# decryptWithAD(0x%s, 0x%s, 0x%s, 0x%s)",
		     tal_hexstr(tmpctx, k, sizeof(*k)),
		     tal_hexstr(tmpctx, npub, sizeof(npub)),
		     tal_hexstr(tmpctx, additional_data, additional_data_len),
		     tal_hexstr(tmpctx, ciphertext, ciphertext_len));
	if (crypto_aead_chacha20poly1305_ietf_decrypt(output, &mlen, NULL,
						 memcheck(ciphertext, ciphertext_len),
						 ciphertext_len,
						 additional_data, additional_data_len,
						 npub, k->data) != 0)
		return false;

	assert(mlen == ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
	return true;
}

static struct io_plan *handshake_failed_(struct io_conn *conn,
					 struct handshake *h,
					 const char *function, int line)
{
	status_debug("%s: handshake failed %s:%u",
		     h->side == RESPONDER ? "Responder" : "Initiator",
		     function, line);
	errno = EPROTO;
	return io_close(conn);
}
#define handshake_failed(conn, h) \
	handshake_failed_((conn), (h), __func__, __LINE__)

static struct io_plan *handshake_succeeded(struct io_conn *conn,
					   struct handshake *h)
{
	struct crypto_state cs;
	struct io_plan *(*cb)(struct io_conn *conn,
			      const struct pubkey *their_id,
			      const struct wireaddr_internal *addr,
			      struct crypto_state *cs,
			      struct oneshot *timeout,
			      void *cbarg);
	void *cbarg;
	struct pubkey their_id;
	struct wireaddr_internal addr;
	struct oneshot *timeout;

	/* BOLT #8:
	 *
	 * 9. `rk, sk = HKDF(ck, zero)`
	 *      * where `zero` is a zero-length plaintext, `rk` is the key to
	 *        be used by the responder to decrypt the messages sent by the
	 *        initiator, and `sk` is the key to be used by the responder
	 *        to encrypt messages to the initiator
	 *
	 *      * The final encryption keys, to be used for sending and
	 *        receiving messages for the duration of the session, are
	 *        generated.
	 */
	if (h->side == RESPONDER)
		hkdf_two_keys(&cs.rk, &cs.sk, &h->ck, NULL, 0);
	else
		hkdf_two_keys(&cs.sk, &cs.rk, &h->ck, NULL, 0);

	cs.rn = cs.sn = 0;
	cs.r_ck = cs.s_ck = h->ck;

	cb = h->cb;
	cbarg = h->cbarg;
	their_id = h->their_id;
	addr = h->addr;
	timeout = h->timeout;

	tal_free(h);
	return cb(conn, &their_id, &addr, &cs, timeout, cbarg);
}

static struct handshake *new_handshake(const tal_t *ctx,
				       const struct pubkey *responder_id)
{
	struct handshake *handshake = tal(ctx, struct handshake);

	/* BOLT #8:
	 *
	 * Before the start of Act One, both sides initialize their
	 * per-sessions state as follows:
	 *
	 *  1. `h = SHA-256(protocolName)`
	 *   *  where `protocolName = "Noise_XK_secp256k1_ChaChaPoly_SHA256"`
	 *      encoded as an ASCII string
	 */
	sha256(&handshake->h, "Noise_XK_secp256k1_ChaChaPoly_SHA256",
	       strlen("Noise_XK_secp256k1_ChaChaPoly_SHA256"));

	/* BOLT #8:
	 *
	 * 2. `ck = h`
	 */
	BUILD_ASSERT(sizeof(handshake->h) == sizeof(handshake->ck));
	memcpy(&handshake->ck, &handshake->h, sizeof(handshake->ck));
	SUPERVERBOSE("# ck=%s",
		     tal_hexstr(tmpctx, &handshake->ck, sizeof(handshake->ck)));

	/* BOLT #8:
	 *
	 * 3. `h = SHA-256(h || prologue)`
	 *    *  where `prologue` is the ASCII string: `lightning`
	 */
	sha_mix_in(&handshake->h, "lightning", strlen("lightning"));

	/* BOLT #8:
	 *
	 * As a concluding step, both sides mix the responder's public key
	 * into the handshake digest:
	 *
	 * * The initiating node mixes in the responding node's static public
	 *    key serialized in Bitcoin's compressed format:
	 *    * `h = SHA-256(h || rs.pub.serializeCompressed())`
	 *
	 * * The responding node mixes in their local static public key
	 *   serialized in Bitcoin's compressed format:
	 *    * `h = SHA-256(h || ls.pub.serializeCompressed())`
	 */
	sha_mix_in_key(&handshake->h, responder_id);
	SUPERVERBOSE("# h=%s",
		     tal_hexstr(tmpctx, &handshake->h, sizeof(handshake->h)));

	return handshake;
}

static struct io_plan *act_three_initiator(struct io_conn *conn,
					   struct handshake *h)
{
	u8 spub[PUBKEY_CMPR_LEN];
	size_t len = sizeof(spub);

	SUPERVERBOSE("Initiator: Act 3");

	/* BOLT #8:
	 * 1. `c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())`
	 *     * where `s` is the static public key of the initiator
	 */
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, spub, &len,
				      &h->my_id.pubkey,
				      SECP256K1_EC_COMPRESSED);
	encrypt_ad(&h->temp_k, 1, &h->h, sizeof(h->h), spub, sizeof(spub),
		   h->act3.ciphertext, sizeof(h->act3.ciphertext));
	SUPERVERBOSE("# c=0x%s",
		     tal_hexstr(tmpctx,
				h->act3.ciphertext, sizeof(h->act3.ciphertext)));

	/* BOLT #8:
	 * 2. `h = SHA-256(h || c)`
	 */
	sha_mix_in(&h->h, h->act3.ciphertext, sizeof(h->act3.ciphertext));
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 3. `se = ECDH(s.priv, re)`
	 *     * where `re` is the ephemeral public key of the responder
	 */
	h->ss = tal(h, struct secret);
	ecdh(&h->re, h->ss);
	SUPERVERBOSE("# ss=0x%s", tal_hexstr(tmpctx, h->ss, sizeof(*h->ss)));

	/* BOLT #8:
	 *
	 * 4. `ck, temp_k3 = HKDF(ck, se)`
	 *     * The final intermediate shared secret is mixed into the running chaining key.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, h->ss, sizeof(*h->ss));
	SUPERVERBOSE("# ck,temp_k3=0x%s,0x%s",
		     tal_hexstr(tmpctx, &h->ck, sizeof(h->ck)),
		     tal_hexstr(tmpctx, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 * 5. `t = encryptWithAD(temp_k3, 0, h, zero)`
	 *      * where `zero` is a zero-length plaintext
	 *
	 */
	encrypt_ad(&h->temp_k, 0, &h->h, sizeof(h->h), NULL, 0,
		   h->act3.tag, sizeof(h->act3.tag));
	SUPERVERBOSE("# t=0x%s",
		     tal_hexstr(tmpctx, h->act3.tag, sizeof(h->act3.tag)));

	/* BOLT #8:
	 *
	 * 8.  Send `m = 0 || c || t` over the network buffer.
	 *
	 */
	h->act3.v = 0;

	SUPERVERBOSE("output: 0x%s", tal_hexstr(tmpctx, &h->act3, ACT_THREE_SIZE));
	return io_write(conn, &h->act3, ACT_THREE_SIZE, handshake_succeeded, h);
}

static struct io_plan *act_two_initiator2(struct io_conn *conn,
					 struct handshake *h)
{
	SUPERVERBOSE("input: 0x%s", tal_hexstr(tmpctx, &h->act2, ACT_TWO_SIZE));

	/* BOLT #8:
	 *
	 * 3. If `v` is an unrecognized handshake version, then the responder
	 *     MUST abort the connection attempt.
	 */
	if (h->act2.v != 0)
		return handshake_failed(conn, h);

	/* BOLT #8:
	 *
	 *     * The raw bytes of the remote party's ephemeral public key
	 *       (`re`) are to be deserialized into a point on the curve using
	 *       affine coordinates as encoded by the key's serialized
	 *       composed format.
	 */
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &h->re.pubkey,
				      h->act2.pubkey, sizeof(h->act2.pubkey)) != 1)
		return handshake_failed(conn, h);

	SUPERVERBOSE("# re=0x%s", type_to_string(tmpctx, struct pubkey, &h->re));

	/* BOLT #8:
	 *
	 * 4. `h = SHA-256(h || re.serializeCompressed())`
	 */
	sha_mix_in_key(&h->h, &h->re);
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 5. `es = ECDH(s.priv, re)`
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss->data, &h->re.pubkey,
			    h->e.priv.secret.data, NULL, NULL))
		return handshake_failed(conn, h);

	SUPERVERBOSE("# ss=0x%s", tal_hexstr(tmpctx, h->ss, sizeof(*h->ss)));

	/* BOLT #8:
	 *
	 * 6. `ck, temp_k2 = HKDF(ck, ee)`
	 *      * A new temporary encryption key is generated, which is
	 *        used to generate the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, h->ss, sizeof(*h->ss));
	SUPERVERBOSE("# ck,temp_k2=0x%s,0x%s",
		     tal_hexstr(tmpctx, &h->ck, sizeof(h->ck)),
		     tal_hexstr(tmpctx, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 * 7. `p = decryptWithAD(temp_k2, 0, h, c)`
	 *     * If the MAC check in this operation fails, then the initiator
	 *       MUST terminate the connection without any further messages.
	 */
	if (!decrypt(&h->temp_k, 0, &h->h, sizeof(h->h),
		     h->act2.tag, sizeof(h->act2.tag), NULL, 0))
		return handshake_failed(conn, h);

	/* BOLT #8:
	 *
	 * 8. `h = SHA-256(h || c)`
	 *     * The received ciphertext is mixed into the handshake digest.
	 *       This step serves to ensure the payload wasn't modified by a
	 *       MITM.
	 */
	sha_mix_in(&h->h, h->act2.tag, sizeof(h->act2.tag));
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	return act_three_initiator(conn, h);
}

static struct io_plan *act_two_initiator(struct io_conn *conn,
					 struct handshake *h)
{
	SUPERVERBOSE("Initiator: Act 2");

	/* BOLT #8:
	 *
	 * 1. Read _exactly_ 50 bytes from the network buffer.
	 *
	 * 2. Parse the read message (`m`) into `v`, `re`, and `c`:
	 *    * where `v` is the _first_ byte of `m`, `re` is the next 33
	 *      bytes of `m`, and `c` is the last 16 bytes of `m`.
	 */
	return io_read(conn, &h->act2, ACT_TWO_SIZE, act_two_initiator2, h);
}

static struct io_plan *act_one_initiator(struct io_conn *conn,
					 struct handshake *h)
{
	size_t len;

	SUPERVERBOSE("Initiator: Act 1");

	/* BOLT #8:
	 *
	 * **Sender Actions:**
	 *
	 * 1. `e = generateKey()`
	 */
	h->e = generate_key();
	SUPERVERBOSE("e.priv: 0x%s",
		     tal_hexstr(tmpctx, &h->e.priv, sizeof(h->e.priv)));
	SUPERVERBOSE("e.pub: 0x%s",
		     type_to_string(tmpctx, struct pubkey, &h->e.pub));

	/* BOLT #8:
	 *
	 * 2. `h = SHA-256(h || e.pub.serializeCompressed())`
	 *     * The newly generated ephemeral key is accumulated into the
	 *       running handshake digest.
	 */
	sha_mix_in_key(&h->h, &h->e.pub);
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 3. `es = ECDH(e.priv, rs)`
	 *      * The initiator performs an ECDH between its newly generated ephemeral
	 *        key and the remote node's static public key.
	 */
	h->ss = tal(h, struct secret);
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss->data,
			    &h->their_id.pubkey, h->e.priv.secret.data,
			    NULL, NULL))
		return handshake_failed(conn, h);

	SUPERVERBOSE("# ss=0x%s", tal_hexstr(tmpctx, h->ss->data, sizeof(h->ss->data)));

	/* BOLT #8:
	 *
	 * 4. `ck, temp_k1 = HKDF(ck, es)`
	 *      * A new temporary encryption key is generated, which is
	 *        used to generate the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, h->ss, sizeof(*h->ss));
	SUPERVERBOSE("# ck,temp_k1=0x%s,0x%s",
		     tal_hexstr(tmpctx, &h->ck, sizeof(h->ck)),
		     tal_hexstr(tmpctx, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 * 5. `c = encryptWithAD(temp_k1, 0, h, zero)`
	 *     * where `zero` is a zero-length plaintext
	 */
	encrypt_ad(&h->temp_k, 0, &h->h, sizeof(h->h), NULL, 0,
		   h->act1.tag, sizeof(h->act1.tag));
	SUPERVERBOSE("# c=%s",
		     tal_hexstr(tmpctx, h->act1.tag, sizeof(h->act1.tag)));

	/* BOLT #8:
	 * 6. `h = SHA-256(h || c)`
	 *     * Finally, the generated ciphertext is accumulated into the
	 *       authenticating handshake digest.
	 */
	sha_mix_in(&h->h, h->act1.tag, sizeof(h->act1.tag));
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 7. Send `m = 0 || e.pub.serializeCompressed() || c` to the responder over the network buffer.
	 */
	h->act1.v = 0;
	len = sizeof(h->act1.pubkey);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, h->act1.pubkey, &len,
				      &h->e.pub.pubkey,
				      SECP256K1_EC_COMPRESSED);
	SUPERVERBOSE("output: 0x%s", tal_hexstr(tmpctx, &h->act1, ACT_ONE_SIZE));

	check_act_one(&h->act1);
	return io_write(conn, &h->act1, ACT_ONE_SIZE, act_two_initiator, h);
}

static struct io_plan *act_three_responder2(struct io_conn *conn,
					    struct handshake *h)
{
	u8 der[PUBKEY_CMPR_LEN];

	SUPERVERBOSE("input: 0x%s", tal_hexstr(tmpctx, &h->act3, ACT_THREE_SIZE));

	/* BOLT #8:
	 *
	 * 2. Parse the read message (`m`) into `v`, `c`, and `t`:
	 *    * where `v` is the _first_ byte of `m`, `c` is the next 49
	 *      bytes of `m`, and `t` is the last 16 bytes of `m`
	 */

	/* BOLT #8:
	 *
	 * 3. If `v` is an unrecognized handshake version, then the responder
	 *    MUST abort the connection attempt.
	 */
	if (h->act3.v != 0)
		return handshake_failed(conn, h);

	/* BOLT #8:
	 *
	 * 4. `rs = decryptWithAD(temp_k2, 1, h, c)`
	 *      * At this point, the responder has recovered the static public
	 *        key of the initiator.
	 */
	if (!decrypt(&h->temp_k, 1, &h->h, sizeof(h->h),
		     h->act3.ciphertext, sizeof(h->act3.ciphertext),
		     der, sizeof(der)))
		return handshake_failed(conn, h);

	SUPERVERBOSE("# rs=0x%s", tal_hexstr(tmpctx, der, sizeof(der)));

	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &h->their_id.pubkey,
				      der, sizeof(der)) != 1)
		return handshake_failed(conn, h);

	/* BOLT #8:
	 *
	 * 5. `h = SHA-256(h || c)`
	 *
	 */
	sha_mix_in(&h->h, h->act3.ciphertext, sizeof(h->act3.ciphertext));
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 6. `se = ECDH(e.priv, rs)`
	 *      * where `e` is the responder's original ephemeral key
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss->data, &h->their_id.pubkey,
			    h->e.priv.secret.data, NULL, NULL))
		return handshake_failed(conn, h);

	SUPERVERBOSE("# ss=0x%s", tal_hexstr(tmpctx, h->ss, sizeof(*h->ss)));

	/* BOLT #8:
	 * 7. `ck, temp_k3 = HKDF(ck, se)`
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, h->ss, sizeof(*h->ss));
	SUPERVERBOSE("# ck,temp_k3=0x%s,0x%s",
		     tal_hexstr(tmpctx, &h->ck, sizeof(h->ck)),
		     tal_hexstr(tmpctx, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 * 8. `p = decryptWithAD(temp_k3, 0, h, t)`
	 *      * If the MAC check in this operation fails, then the responder
	 *        MUST terminate the connection without any further messages.
	 *
	 */
	if (!decrypt(&h->temp_k, 0, &h->h, sizeof(h->h),
		     h->act3.tag, sizeof(h->act3.tag), NULL, 0))
		return handshake_failed(conn, h);

	check_act_three(&h->act3);
	return handshake_succeeded(conn, h);
}

static struct io_plan *act_three_responder(struct io_conn *conn,
					   struct handshake *h)
{
	SUPERVERBOSE("Responder: Act 3");

	/* BOLT #8:
	 *
	 * **Receiver Actions:**
	 *
	 * 1. Read _exactly_ 66 bytes from the network buffer.
	 */
	return io_read(conn, &h->act3, ACT_THREE_SIZE, act_three_responder2, h);
}

static struct io_plan *act_two_responder(struct io_conn *conn,
					 struct handshake *h)
{
	size_t len;

	SUPERVERBOSE("Responder: Act 2");

	/* BOLT #8:
	 *
	 * **Sender Actions:**
	 *
	 * 1. `e = generateKey()`
	 */
	h->e = generate_key();
	SUPERVERBOSE("# e.pub=0x%s e.priv=0x%s",
		     type_to_string(tmpctx, struct pubkey, &h->e.pub),
		     tal_hexstr(tmpctx, &h->e.priv, sizeof(h->e.priv)));

	/* BOLT #8:
	 *
	 * 2. `h = SHA-256(h || e.pub.serializeCompressed())`
	 *      * The newly generated ephemeral key is accumulated into the
	 *        running handshake digest.
	 */
	sha_mix_in_key(&h->h, &h->e.pub);
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 3. `ee = ECDH(e.priv, re)`
	 *      * where `re` is the ephemeral key of the initiator, which was received
	 *        during Act One
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss->data, &h->re.pubkey,
			    h->e.priv.secret.data, NULL, NULL))
		return handshake_failed(conn, h);
	SUPERVERBOSE("# ss=0x%s", tal_hexstr(tmpctx, h->ss, sizeof(*h->ss)));

	/* BOLT #8:
	 *
	 * 4. `ck, temp_k2 = HKDF(ck, ee)`
	 *      * A new temporary encryption key is generated, which is
	 *       used to generate the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, h->ss, sizeof(*h->ss));
	SUPERVERBOSE("# ck,temp_k2=0x%s,0x%s",
		     tal_hexstr(tmpctx, &h->ck, sizeof(h->ck)),
		     tal_hexstr(tmpctx, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 * 5. `c = encryptWithAD(temp_k2, 0, h, zero)`
	 *      * where `zero` is a zero-length plaintext
	 */
	encrypt_ad(&h->temp_k, 0, &h->h, sizeof(h->h), NULL, 0,
		   h->act2.tag, sizeof(h->act2.tag));
	SUPERVERBOSE("# c=0x%s", tal_hexstr(tmpctx, h->act2.tag, sizeof(h->act2.tag)));

	/* BOLT #8:
	 *
	 * 6. `h = SHA-256(h || c)`
	 *      * Finally, the generated ciphertext is accumulated into the
	 *        authenticating handshake digest.
	 */
	sha_mix_in(&h->h, h->act2.tag, sizeof(h->act2.tag));
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 7. Send `m = 0 || e.pub.serializeCompressed() || c` to the initiator over the network buffer.
	 */
	h->act2.v = 0;
	len = sizeof(h->act2.pubkey);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, h->act2.pubkey, &len,
				      &h->e.pub.pubkey,
				      SECP256K1_EC_COMPRESSED);
	SUPERVERBOSE("output: 0x%s", tal_hexstr(tmpctx, &h->act2, ACT_TWO_SIZE));

	check_act_two(&h->act2);
	return io_write(conn, &h->act2, ACT_TWO_SIZE, act_three_responder, h);
}

static struct io_plan *act_one_responder2(struct io_conn *conn,
					 struct handshake *h)
{
	/* BOLT #8:
	 *
	 * 3. If `v` is an unrecognized handshake version, then the responder
	 *     MUST abort the connection attempt.
	 */
	if (h->act1.v != 0)
		return handshake_failed(conn, h);

	/* BOLT #8:
	 *
	 *     * The raw bytes of the remote party's ephemeral public key
	 *       (`re`) are to be deserialized into a point on the curve using
	 *       affine coordinates as encoded by the key's serialized
	 *       composed format.
	 */
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &h->re.pubkey,
				      h->act1.pubkey, sizeof(h->act1.pubkey)) != 1)
		return handshake_failed(conn, h);

	SUPERVERBOSE("# re=0x%s", type_to_string(tmpctx, struct pubkey, &h->re));

	/* BOLT #8:
	 *
	 * 4. `h = SHA-256(h || re.serializeCompressed())`
	 *    * The responder accumulates the initiator's ephemeral key into the
	 *      authenticating handshake digest.
	 */
	sha_mix_in_key(&h->h, &h->re);
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * 5. `es = ECDH(s.priv, re)`
	 *    * The responder performs an ECDH between its static private key and
	 *      the initiator's ephemeral public key.
	 */
	h->ss = tal(h, struct secret);
	ecdh(&h->re, h->ss);
	SUPERVERBOSE("# ss=0x%s", tal_hexstr(tmpctx, h->ss, sizeof(*h->ss)));

	/* BOLT #8:
	 *
	 * 6. `ck, temp_k1 = HKDF(ck, es)`
	 *     * A new temporary encryption key is generated, which will
	 *       shortly be used to check the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, h->ss, sizeof(*h->ss));
	SUPERVERBOSE("# ck,temp_k1=0x%s,0x%s",
		     tal_hexstr(tmpctx, &h->ck, sizeof(h->ck)),
		     tal_hexstr(tmpctx, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 * 7. `p = decryptWithAD(temp_k1, 0, h, c)`
	 *     * If the MAC check in this operation fails, then the initiator
	 *       does _not_ know the responder's static public key. If this
	 *       is the case, then the responder MUST terminate the connection
	 *       without any further messages.
	 */
	if (!decrypt(&h->temp_k, 0, &h->h, sizeof(h->h),
		     h->act1.tag, sizeof(h->act1.tag), NULL, 0))
		return handshake_failed(conn, h);

	/* BOLT #8:
	 *
	 * 8. `h = SHA-256(h || c)`
	 *     * The received ciphertext is mixed into the handshake digest.
	 *       This step serves to ensure the payload wasn't modified by a
	 *       MITM.
	 */
	sha_mix_in(&h->h, h->act1.tag, sizeof(h->act1.tag));
	SUPERVERBOSE("# h=0x%s", tal_hexstr(tmpctx, &h->h, sizeof(h->h)));

	return act_two_responder(conn, h);
}

static struct io_plan *act_one_responder(struct io_conn *conn,
					 struct handshake *h)
{

	SUPERVERBOSE("Responder: Act 1");

	/* BOLT #8:
	 *
	 * 1. Read _exactly_ 50 bytes from the network buffer.
	 *
	 * 2. Parse the read message (`m`) into `v`, `re`, and `c`:
	 *     * where `v` is the _first_ byte of `m`, `re` is the next 33
	 *       bytes of `m`, and `c` is the last 16 bytes of `m`.
	 */
	return io_read(conn, &h->act1, ACT_ONE_SIZE, act_one_responder2, h);
}

struct io_plan *responder_handshake_(struct io_conn *conn,
				     const struct pubkey *my_id,
				     const struct wireaddr_internal *addr,
				     struct oneshot *timeout,
				     struct io_plan *(*cb)(struct io_conn *,
							   const struct pubkey *,
							   const struct wireaddr_internal *,
							   struct crypto_state *,
							   struct oneshot *,
							   void *cbarg),
				     void *cbarg)
{
	struct handshake *h = new_handshake(conn, my_id);

	h->side = RESPONDER;
	h->my_id = *my_id;
	h->addr = *addr;
	h->cbarg = cbarg;
	h->cb = cb;
	h->timeout = timeout;

	return act_one_responder(conn, h);
}

struct io_plan *initiator_handshake_(struct io_conn *conn,
				     const struct pubkey *my_id,
				     const struct pubkey *their_id,
				     const struct wireaddr_internal *addr,
				     struct oneshot *timeout,
				     struct io_plan *(*cb)(struct io_conn *,
							   const struct pubkey *,
							   const struct wireaddr_internal *,
							   struct crypto_state *,
							   struct oneshot *timeout,
							   void *cbarg),
				     void *cbarg)
{
	struct handshake *h = new_handshake(conn, their_id);

	h->side = INITIATOR;
	h->my_id = *my_id;
	h->their_id = *their_id;
	h->addr = *addr;
	h->cbarg = cbarg;
	h->cb = cb;
	h->timeout = timeout;

	return act_one_initiator(conn, h);
}
