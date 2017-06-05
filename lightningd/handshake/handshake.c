#include "type_to_string.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <ccan/build_assert/build_assert.h>
#include <ccan/crypto/hkdf_sha256/hkdf_sha256.h>
#include <ccan/endian/endian.h>
#include <ccan/fdpass/fdpass.h>
#include <ccan/mem/mem.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/short_types/short_types.h>
#include <errno.h>
#include <lightningd/crypto_sync.h>
#include <lightningd/debug.h>
#include <lightningd/handshake/gen_handshake_wire.h>
#include <lightningd/hsm/client.h>
#include <lightningd/status.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/randombytes.h>
#include <stdio.h>
#include <unistd.h>
#include <version.h>
#include <wire/peer_wire.h>
#include <wire/wire.h>
#include <wire/wire_sync.h>

#define REQ_FD STDIN_FILENO

/* BOLT #8:
 *
 *  * `generateKey()`
 *      * where generateKey generates and returns a fresh `secp256k1` keypair
 *      * the object returned by `generateKey` has two attributes:
 *          * `.pub`: which returns an abstract object representing the
 *            public key
 *          * `.priv`: which represents the private key used to generate the
 *            public key
 */
struct keypair {
	struct pubkey pub;
	struct privkey priv;
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

/* BOLT #8:
 *
 * Throughout the handshake process, each side maintains these variables:
 *
 *  * `ck`: The **chaining key**. This value is the accumulated hash of all
 *    previous ECDH outputs. At the end of the handshake, `ck` is used to
 *    derive the encryption keys for lightning messages.
 *
 *  * `h`: The **handshake hash**. This value is the accumulated hash of _all_
 *    handshake data that has been sent and received so far during the
 *    handshake process.
 *
 * * `temp_k1`, `temp_k2`, `temp_k3`: **intermediate keys** used to
 *    encrypt/decrypt the zero-length AEAD payloads at the end of each
 *    handshake message.
 *
 *  * `e`: A party's **ephemeral keypair**. For each session a node MUST
 *    generate a new ephemeral key with strong cryptographic randomness.
 *
 *  * `s`: A party's **static public key** (`ls` for local, `rs` for remote)
 */
struct handshake {
	struct secret ck;
	struct secret temp_k;
	struct sha256 h;
	struct keypair e;
	struct secret ss;
};

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
	u8 der[PUBKEY_DER_LEN];
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
	 *   * `HKDF(salt,ikm)`: a function is defined in [3](#reference-3),
	 *      evaluated with a zero-length `info` field.
	 *      * All invocations of the `HKDF` implicitly return `64-bytes`
	 *        of cryptographic randomness using the extract-and-expand
	 *        component of the `HKDF`.
	 */
	struct secret okm[2];

	status_trace("# HKDF(0x%s,%s%s)",
		     tal_hexstr(trc, in1, sizeof(*in1)),
		     in2_size ? "0x" : "zero",
		     tal_hexstr(trc, in2, in2_size));
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

/* BOLT #8:
 *   * `encryptWithAD(k, n, ad, plaintext)`: outputs `encrypt(k, n, ad,
 *      plaintext)`
 *      * where `encrypt` is an evaluation of `ChaCha20-Poly1305` (IETF
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
	status_trace("# encryptWithAD(0x%s, 0x%s, 0x%s, %s%s)",
		     tal_hexstr(trc, k, sizeof(*k)),
		     tal_hexstr(trc, npub, sizeof(npub)),
		     tal_hexstr(trc, additional_data, additional_data_len),
		     plaintext_len ? "0x" : "<empty>",
		     tal_hexstr(trc, plaintext, plaintext_len));

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
 *      * where `decrypt` is an evaluation of `ChaCha20-Poly1305` (IETF
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
	status_trace("# decryptWithAD(0x%s, 0x%s, 0x%s, 0x%s)",
		     tal_hexstr(trc, k, sizeof(*k)),
		     tal_hexstr(trc, npub, sizeof(npub)),
		     tal_hexstr(trc, additional_data, additional_data_len),
		     tal_hexstr(trc, ciphertext, ciphertext_len));
	if (crypto_aead_chacha20poly1305_ietf_decrypt(output, &mlen, NULL,
						 memcheck(ciphertext, ciphertext_len),
						 ciphertext_len,
						 additional_data, additional_data_len,
						 npub, k->data) != 0)
		return false;

	assert(mlen == ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES);
	return true;
}

static struct handshake *new_handshake(const tal_t *ctx,
				       const struct pubkey *id)
{
	struct handshake *handshake = tal(ctx, struct handshake);

	/* BOLT #8:
	 *
	 * Before the start of the first act, both sides initialize their
	 * per-sessions state as follows:
	 *
	 *  1. `h = SHA-256(protocolName)`
	 *   *  where `protocolName = "Noise_XK_secp256k1_ChaChaPoly_SHA256"`
	 *      encoded as an ASCII string.
	 */
	sha256(&handshake->h, "Noise_XK_secp256k1_ChaChaPoly_SHA256",
	       strlen("Noise_XK_secp256k1_ChaChaPoly_SHA256"));

	/* BOLT #8:
	 *
	 * 2. `ck = h`
	 */
	BUILD_ASSERT(sizeof(handshake->h) == sizeof(handshake->ck));
	memcpy(&handshake->ck, &handshake->h, sizeof(handshake->ck));
	status_trace("# ck=%s",
		     tal_hexstr(trc, &handshake->ck, sizeof(handshake->ck)));

	/* BOLT #8:
	 *
	 * 3. `h = SHA-256(h || prologue)`
	 *    *  where `prologue` is the ASCII string: `lightning`.
	 */
	sha_mix_in(&handshake->h, "lightning", strlen("lightning"));

	/* BOLT #8:
	 *
	 * As a concluding step, both sides mix the responder's public key
	 * into the handshake digest:
	 *
	 * * The initiating node mixes in the responding node's static public
	 *    key serialized in Bitcoin's DER compressed format:
	 *    * `h = SHA-256(h || rs.pub.serializeCompressed())`
	 *
	 * * The responding node mixes in their local static public key
	 *   serialized in Bitcoin's DER compressed format:
	 *    * `h = SHA-256(h || ls.pub.serializeCompressed())`
	 */
	sha_mix_in_key(&handshake->h, id);
	status_trace("# h=%s",
		     tal_hexstr(trc, &handshake->h, sizeof(handshake->h)));

	return handshake;
}

/* BOLT #8:
 *
 * Act One is sent from initiator to responder. During `Act One`, the
 * initiator attempts to satisfy an implicit challenge by the responder. To
 * complete this challenge, the initiator _must_ know the static public key of
 * the responder.
 */
struct act_one {
	u8 v;
	u8 pubkey[PUBKEY_DER_LEN];
	u8 tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
};

/* BOLT #8: The handshake message is _exactly_ `50 bytes` */
#define ACT_ONE_SIZE 50 /* ARM's stupid ABI adds padding. */

static inline void check_act_one(const struct act_one *act1)
{
	/* BOLT #8:
	 *
	 * : `1 byte` for the handshake version, `33 bytes` for the compressed
	 * ephemeral public key of the initiator, and `16 bytes` for the
	 * `poly1305` tag.
	 */
	BUILD_ASSERT(sizeof(act1->v) == 1);
	BUILD_ASSERT(sizeof(act1->pubkey) == 33);
	BUILD_ASSERT(sizeof(act1->tag) == 16);
}

static void act_one_initiator(struct handshake *h, int fd,
			      const struct pubkey *their_id)
{
	struct act_one act1;
	size_t len;

	status_send_sync(towire_initr_act_one(h));

	/* BOLT #8:
	 *
	 * **Sender Actions:**
	 *
	 *  * `e = generateKey()`
	 */
	h->e = generate_key();
	status_trace("e.priv: 0x%s",
		     tal_hexstr(trc, &h->e.priv, sizeof(h->e.priv)));
	status_trace("e.pub: 0x%s",
		     type_to_string(trc, struct pubkey, &h->e.pub));

	/* BOLT #8:
	 *
	 *  * `h = SHA-256(h || e.pub.serializeCompressed())`
	 *     * The newly generated ephemeral key is accumulated into our
	 *       running handshake digest.
	 */
	sha_mix_in_key(&h->h, &h->e.pub);
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 *  * `ss = ECDH(rs, e.priv)`
	 *     * The initiator performs a `ECDH` between its newly generated
	 *       ephemeral key with the remote node's static public key.
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss.data,
			    &their_id->pubkey, h->e.priv.secret.data))
		status_failed(WIRE_INITR_ACT1_BAD_ECDH_FOR_SS, "%s", "");
	status_trace("# ss=0x%s", tal_hexstr(trc, h->ss.data, sizeof(h->ss.data)));

	/* BOLT #8:
	 *
	 *  * `ck, temp_k1 = HKDF(ck, ss)`
	 *     * This phase generates a new temporary encryption key
	 *       which is used to generate the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, &h->ss, sizeof(h->ss));
	status_trace("# ck,temp_k1=0x%s,0x%s",
		     tal_hexstr(trc, &h->ck, sizeof(h->ck)),
		     tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 *  * `c = encryptWithAD(temp_k1, 0, h, zero)`
	 *     * where `zero` is a zero-length plaintext
	 */
	encrypt_ad(&h->temp_k, 0, &h->h, sizeof(h->h), NULL, 0,
		   act1.tag, sizeof(act1.tag));
	status_trace("# c=%s", tal_hexstr(trc, act1.tag, sizeof(act1.tag)));

	/* BOLT #8:
	 *
	 *  * `h = SHA-256(h || c)`
	 *     * Finally, the generated ciphertext is accumulated into the
	 *       authenticating handshake digest.
	 */
	sha_mix_in(&h->h, act1.tag, sizeof(act1.tag));
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 *  * Send `m = 0 || e.pub.serializeCompressed() || c` to the responder over the network buffer.
	 */
	act1.v = 0;
	len = sizeof(act1.pubkey);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, act1.pubkey, &len,
				      &h->e.pub.pubkey,
				      SECP256K1_EC_COMPRESSED);
	status_trace("output: 0x%s", tal_hexstr(trc, &act1, ACT_ONE_SIZE));
	if (!write_all(fd, &act1, ACT_ONE_SIZE))
		status_failed(WIRE_INITR_ACT1_WRITE_FAILED,
			      "%s", strerror(errno));
}

static void act_one_responder(struct handshake *h, int fd, struct pubkey *re)
{
	struct act_one act1;

	status_send_sync(towire_respr_act_one(h));

	/* BOLT #8:
	 *
	 *   * Read _exactly_ `50-bytes` from the network buffer.
	 *
	 *   * Parse out the read message (`m`) into `v = m[0]`, `re =
	 *     m[1:33]` and `c = m[34:]`
	 *     * where `m[0]` is the _first_ byte of `m`, `m[1:33]` are the
	 *       next `33` bytes of `m` and `m[34:]` is the last 16 bytes of
	 *       `m`
	 */
	if (!read_all(fd, &act1, ACT_ONE_SIZE))
		status_failed(WIRE_RESPR_ACT1_READ_FAILED,
			      "%s", strerror(errno));
	status_trace("input: 0x%s", tal_hexstr(trc, &act1, ACT_ONE_SIZE));

	/* BOLT #8:
	 *
	 *   * If `v` is an unrecognized handshake version, then the responder
	 *     MUST abort the connection attempt.
	 */
	if (act1.v != 0)
		status_failed(WIRE_RESPR_ACT1_BAD_VERSION, "%u", act1.v);

	/* BOLT #8:
	 *     * The raw bytes of the remote party's ephemeral public key
	 *       (`e`) are to be deserialized into a point on the curve using
	 *       affine coordinates as encoded by the key's serialized
	 *       composed format.
	 */
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &re->pubkey,
				      act1.pubkey, sizeof(act1.pubkey)) != 1)
		status_failed(WIRE_RESPR_ACT1_BAD_PUBKEY, "%s",
			      tal_hexstr(trc, &act1.pubkey,
					 sizeof(act1.pubkey)));
	status_trace("# re=0x%s", type_to_string(trc, struct pubkey, re));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || re.serializeCompressed())`
	 *     * Accumulate the initiator's ephemeral key into the
	 *       authenticating handshake digest.
	 */
	sha_mix_in_key(&h->h, re);
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *   * `ss = ECDH(re, s.priv)`
	 *     * The responder performs an `ECDH` between its static public
	 *       key and the initiator's ephemeral public key.
	 */
	if (!hsm_do_ecdh(&h->ss, re))
		status_failed(WIRE_RESPR_ACT1_BAD_HSM_ECDH,
			      "re=%s",
			      type_to_string(trc, struct pubkey, re));
	status_trace("# ss=0x%s", tal_hexstr(trc, &h->ss, sizeof(h->ss)));

	/* BOLT #8:
	 *
	 *   * `ck, temp_k1 = HKDF(ck, ss)`
	 *     * This phase generates a new temporary encryption key
	 *       which will be used to shortly check the
	 *       authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, &h->ss, sizeof(h->ss));
	status_trace("# ck,temp_k1=0x%s,0x%s",
		     tal_hexstr(trc, &h->ck, sizeof(h->ck)),
		     tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 *   * `p = decryptWithAD(temp_k1, 0, h, c)`
	 *     * If the MAC check in this operation fails, then the initiator
	 *       does _not_ know our static public key. If so, then the
	 *       responder MUST terminate the connection without any further
	 *       messages.
	 */
	if (!decrypt(&h->temp_k, 0, &h->h, sizeof(h->h),
		     act1.tag, sizeof(act1.tag), NULL, 0))
		status_failed(WIRE_RESPR_ACT1_BAD_TAG, "re=%s ss=%s tag=%s",
			      type_to_string(trc, struct pubkey, re),
			      tal_hexstr(trc, &h->ss, sizeof(h->ss)),
			      tal_hexstr(trc, act1.tag, sizeof(act1.tag)));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || c)`
	 *      * Mix the received ciphertext into the handshake digest. This
	 *        step serves to ensure the payload wasn't modified by a MiTM.
	 */
	sha_mix_in(&h->h, act1.tag, sizeof(act1.tag));
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));
}

/* BOLT #8:
 *
 * `Act Two` is sent from the responder to the initiator. `Act Two` will
 * _only_ take place if `Act One` was successful. `Act One` was successful if
 * the responder was able to properly decrypt and check the `MAC` of the tag
 * sent at the end of `Act One`.
 */
struct act_two {
	u8 v;
	u8 pubkey[PUBKEY_DER_LEN];
	u8 tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
};

/* BOLT #8: The handshake is _exactly_ `50 bytes:` */
#define ACT_TWO_SIZE 50 /* ARM's stupid ABI adds padding. */

static inline void check_act_two(const struct act_two *act2)
{
	/* BOLT #8:
	 * `1 byte` for the handshake version,
	 * `33 bytes` for the compressed ephemeral public key of the initiator, and
	 * `16 bytes` for the `poly1305` tag.
	 */
	BUILD_ASSERT(sizeof(act2->v) == 1);
	BUILD_ASSERT(sizeof(act2->pubkey) == 33);
	BUILD_ASSERT(sizeof(act2->tag) == 16);
}

static void act_two_responder(struct handshake *h, int fd,
			      const struct pubkey *re)
{
	struct act_two act2;
	size_t len;

	status_send_sync(towire_respr_act_two(h));

	/* BOLT #8:
	 *
	 * **Sender Actions:**
	 *
	 *   * `e = generateKey()`
	 */
	h->e = generate_key();
	status_trace("# e.pub=0x%s e.priv=0x%s",
		     type_to_string(trc, struct pubkey, &h->e.pub),
		     tal_hexstr(trc, &h->e.priv, sizeof(h->e.priv)));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || e.pub.serializeCompressed())`
	 *      * The newly generated ephemeral key is accumulated into our
	 *        running handshake digest.
	 */
	sha_mix_in_key(&h->h, &h->e.pub);
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 *   * `ss = ECDH(re, e.priv)`
	 *      * where `re` is the ephemeral key of the initiator which was
	 *        received during `ActOne`.
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss.data, &re->pubkey,
			    h->e.priv.secret.data))
		status_failed(WIRE_RESPR_ACT2_BAD_ECDH_FOR_SS, "re=%s e.priv=%s",
			      type_to_string(trc, struct pubkey, re),
			      tal_hexstr(trc, &h->e.priv, sizeof(h->e.priv)));
	status_trace("# ss=0x%s", tal_hexstr(trc, &h->ss, sizeof(h->ss)));

	/* BOLT #8:
	 *
	 *   * `ck, temp_k2 = HKDF(ck, ss)`
	 *      * This phase generates a new temporary encryption key
	 *        which is used to generate the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, &h->ss, sizeof(h->ss));
	status_trace("# ck,temp_k2=0x%s,0x%s",
		     tal_hexstr(trc, &h->ck, sizeof(h->ck)),
		     tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 *   * `c = encryptWithAD(temp_k2, 0, h, zero)`
	 *      * where `zero` is a zero-length plaintext
	 */
	encrypt_ad(&h->temp_k, 0, &h->h, sizeof(h->h), NULL, 0,
		   act2.tag, sizeof(act2.tag));
	status_trace("# c=0x%s", tal_hexstr(trc, act2.tag, sizeof(act2.tag)));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || c)`
	 *      * Finally, the generated ciphertext is accumulated into the
	 *        authenticating handshake digest.
	 */
	sha_mix_in(&h->h, act2.tag, sizeof(act2.tag));
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 * * Send `m = 0 || e.pub.serializeCompressed() || c` to the initiator over the network buffer.
	 */
	act2.v = 0;
	len = sizeof(act2.pubkey);
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, act2.pubkey, &len,
				      &h->e.pub.pubkey,
				      SECP256K1_EC_COMPRESSED);
	status_trace("output: 0x%s", tal_hexstr(trc, &act2, ACT_TWO_SIZE));
	if (!write_all(fd, &act2, ACT_TWO_SIZE))
		status_failed(WIRE_RESPR_ACT2_WRITE_FAILED,
			      "%s", strerror(errno));
}

static void act_two_initiator(struct handshake *h, int fd, struct pubkey *re)
{
	struct act_two act2;

	status_send_sync(towire_initr_act_two(h));

	/* BOLT #8:
	 *
	 *   * Read _exactly_ `50-bytes` from the network buffer.
	 *
	 *   * Parse out the read message (`m`) into `v = m[0]`, `re = m[1:33]`
	 *     and `c = m[34:]`
	 *     * where `m[0]` is the _first_ byte of `m`, `m[1:33]` are the
	 *       next `33` bytes of `m` and `m[34:]` is the last 16 bytes of
	 *       `m`
	 */
	if (!read_all(fd, &act2, ACT_TWO_SIZE))
		status_failed(WIRE_INITR_ACT2_READ_FAILED,
			      "%s", strerror(errno));
	status_trace("input: 0x%s", tal_hexstr(trc, &act2, ACT_TWO_SIZE));

	/* BOLT #8:
	 *
	 *   * If `v` is an unrecognized handshake version, then the responder
	 *     MUST abort the connection attempt.
	 */
	if (act2.v != 0)
		status_failed(WIRE_INITR_ACT2_BAD_VERSION, "%u", act2.v);

	/* BOLT #8:
	 *
	 *     * The raw bytes of the remote party's ephemeral public key
	 *       (`re`) are to be deserialized into a point on the curve using
	 *       affine coordinates as encoded by the key's serialized
	 *       composed format.
	 */
	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &re->pubkey,
				      act2.pubkey, sizeof(act2.pubkey)) != 1)
		status_failed(WIRE_INITR_ACT2_BAD_PUBKEY, "%s",
			      tal_hexstr(trc, &act2.pubkey,
					 sizeof(act2.pubkey)));
	status_trace("# re=0x%s", type_to_string(trc, struct pubkey, re));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || re.serializeCompressed())`
	 */
	sha_mix_in_key(&h->h, re);
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 *   * `ss = ECDH(re, e.priv)`
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss.data, &re->pubkey,
			    h->e.priv.secret.data))
		status_failed(WIRE_INITR_ACT2_BAD_ECDH_FOR_SS, "re=%s e.priv=%s",
			      type_to_string(trc, struct pubkey, re),
			      tal_hexstr(trc, &h->e.priv, sizeof(h->e.priv)));
	status_trace("# ss=0x%s", tal_hexstr(trc, &h->ss, sizeof(h->ss)));

	/* BOLT #8:
	 *
	 *   * `ck, temp_k2 = HKDF(ck, ss)`
	 *      * This phase generates a new temporary encryption key
	 *        which is used to generate the authenticating MAC.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, &h->ss, sizeof(h->ss));
	status_trace("# ck,temp_k2=0x%s,0x%s",
		     tal_hexstr(trc, &h->ck, sizeof(h->ck)),
		     tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 *   * `p = decryptWithAD(temp_k2, 0, h, c)`
	 *     * If the MAC check in this operation fails, then the initiator
	 *       MUST terminate the connection without any further messages.
	 */
	if (!decrypt(&h->temp_k, 0, &h->h, sizeof(h->h),
		     act2.tag, sizeof(act2.tag), NULL, 0))
		status_failed(WIRE_INITR_ACT2_BAD_TAG, "c=%s",
			      tal_hexstr(trc, act2.tag, sizeof(act2.tag)));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || c)`
	 *      * Mix the received ciphertext into the handshake digest. This
	 *        step serves to ensure the payload wasn't modified by a MiTM.
	 */
	sha_mix_in(&h->h, act2.tag, sizeof(act2.tag));
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));
}

/* BOLT #8:
 *
 * `Act Three` is the final phase in the authenticated key agreement described
 * in this section. This act is sent from the initiator to the responder as a
 * final concluding step. `Act Three` is only executed `iff` `Act Two` was
 * successful.  During `Act Three`, the initiator transports its static public
 * key to the responder encrypted with _strong_ forward secrecy using the
 * accumulated `HKDF` derived secret key at this point of the handshake.
 */
struct act_three {
	u8 v;
	u8 ciphertext[PUBKEY_DER_LEN + crypto_aead_chacha20poly1305_ietf_ABYTES];
	u8 tag[crypto_aead_chacha20poly1305_ietf_ABYTES];
};

/* BOLT #8: The handshake is _exactly_ `66 bytes` */
#define ACT_THREE_SIZE 66 /* ARM's stupid ABI adds padding. */

static inline void check_act_three(const struct act_three *act3)
{
	/* BOLT #8:
	 *
	 * `1 byte` for the handshake version, `33 bytes` for the ephemeral
	 * public key encrypted with the `ChaCha20` stream cipher, `16 bytes`
	 * for the encrypted public key's tag generated via the `AEAD`
	 * construction, and `16 bytes` for a final authenticating tag.
	 */
	BUILD_ASSERT(sizeof(act3->v) == 1);
	BUILD_ASSERT(sizeof(act3->ciphertext) == 33 + 16);
	BUILD_ASSERT(sizeof(act3->tag) == 16);
}

static void act_three_initiator(struct handshake *h, int fd,
				const struct pubkey *re,
				const struct pubkey *my_id)
{
	struct act_three act3;
	u8 spub[PUBKEY_DER_LEN];
	size_t len = sizeof(spub);

	status_send_sync(towire_initr_act_three(h));

	/* BOLT #8:
	 *   * `c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())`
	 *     * where `s` is the static public key of the initiator.
	 */
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, spub, &len,
				      &my_id->pubkey,
				      SECP256K1_EC_COMPRESSED);
	encrypt_ad(&h->temp_k, 1, &h->h, sizeof(h->h), spub, sizeof(spub),
		   act3.ciphertext, sizeof(act3.ciphertext));
	status_trace("# c=0x%s",
		     tal_hexstr(trc,act3.ciphertext,sizeof(act3.ciphertext)));

	/* BOLT #8:
	 *   * `h = SHA-256(h || c)`
	 */
	sha_mix_in(&h->h, act3.ciphertext, sizeof(act3.ciphertext));
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 *   * `ss = ECDH(re, s.priv)`
	 *     * where `re` is the ephemeral public key of the responder.
	 *
	 */
	if (!hsm_do_ecdh(&h->ss, re))
		status_failed(WIRE_INITR_ACT3_BAD_HSM_ECDH,
			      "re=%s",
			      type_to_string(trc, struct pubkey, re));
	status_trace("# ss=0x%s", tal_hexstr(trc, &h->ss, sizeof(h->ss)));

	/* BOLT #8:
	 *
	 *   * `ck, temp_k3 = HKDF(ck, ss)`
	 *     * Mix the final intermediate shared secret into the running chaining key.
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, &h->ss, sizeof(h->ss));
	status_trace("# ck,temp_k3=0x%s,0x%s",
		     tal_hexstr(trc, &h->ck, sizeof(h->ck)),
		     tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *
	 *   * `t = encryptWithAD(temp_k3, 0, h, zero)`
	 *      * where `zero` is a zero-length plaintext
	 *
	 */
	encrypt_ad(&h->temp_k, 0, &h->h, sizeof(h->h), NULL, 0,
		   act3.tag, sizeof(act3.tag));
	status_trace("# t=0x%s",
		     tal_hexstr(trc, act3.tag, sizeof(act3.tag)));

	/* BOLT #8:
	 *
	 *   * Send `m = 0 || c || t` over the network buffer.
	 *
	 */
	act3.v = 0;

	status_trace("output: 0x%s", tal_hexstr(trc, &act3, ACT_THREE_SIZE));
	if (!write_all(fd, &act3, ACT_THREE_SIZE))
		status_failed(WIRE_INITR_ACT3_WRITE_FAILED,
			      "%s", strerror(errno));
}

static void act_three_responder(struct handshake *h, int fd,
				struct pubkey *their_id)
{
	struct act_three act3;
	u8 der[PUBKEY_DER_LEN];

	status_send_sync(towire_respr_act_three(h));

	/* BOLT #8:
	 *
	 * **Receiver Actions:**
	 *
	 *   * Read _exactly_ `66-bytes` from the network buffer.
	 */
	if (!read_all(fd, &act3, ACT_THREE_SIZE))
		status_failed(WIRE_RESPR_ACT3_READ_FAILED,
			      "%s", strerror(errno));
	status_trace("input: 0x%s", tal_hexstr(trc, &act3, ACT_THREE_SIZE));

	/* BOLT #8:
	 *
	 *   * Parse out the read message (`m`) into `v = m[0]`, `c = m[1:49]` and `t = m[50:]`
	 */

	/* BOLT #8:
	 *
	 *   * If `v` is an unrecognized handshake version, then the responder MUST
	 *     abort the connection attempt.
	 */
	if (act3.v != 0)
		status_failed(WIRE_RESPR_ACT3_BAD_VERSION, "%u", act3.v);

	/* BOLT #8:
	 *
	 *   * `rs = decryptWithAD(temp_k2, 1, h, c)`
	 *      * At this point, the responder has recovered the static public key of the
	 *        initiator.
	 */
	if (!decrypt(&h->temp_k, 1, &h->h, sizeof(h->h),
		     act3.ciphertext, sizeof(act3.ciphertext),
		     der, sizeof(der)))
		status_failed(WIRE_RESPR_ACT3_BAD_CIPHERTEXT,
			      "ciphertext=%s",
			      tal_hexstr(trc, act3.ciphertext,
					 sizeof(act3.ciphertext)));
	status_trace("# rs=0x%s", tal_hexstr(trc, der, sizeof(der)));

	if (secp256k1_ec_pubkey_parse(secp256k1_ctx, &their_id->pubkey,
				      der, sizeof(der)) != 1)
		status_failed(WIRE_RESPR_ACT3_BAD_PUBKEY, "%s",
			      tal_hexstr(trc, &der, sizeof(der)));

	/* BOLT #8:
	 *
	 *   * `h = SHA-256(h || c)`
	 *
	 */
	sha_mix_in(&h->h, act3.ciphertext, sizeof(act3.ciphertext));
	status_trace("# h=0x%s", tal_hexstr(trc, &h->h, sizeof(h->h)));

	/* BOLT #8:
	 *
	 *   * `ss = ECDH(rs, e.priv)`
	 *      * where `e` is the responder's original ephemeral key
	 */
	if (!secp256k1_ecdh(secp256k1_ctx, h->ss.data, &their_id->pubkey,
			    h->e.priv.secret.data))
		status_failed(WIRE_RESPR_ACT3_BAD_ECDH_FOR_SS, "rs=%s e.priv=%s",
			      type_to_string(trc, struct pubkey, their_id),
			      tal_hexstr(trc, &h->e.priv, sizeof(h->e.priv)));
	status_trace("# ss=0x%s", tal_hexstr(trc, &h->ss, sizeof(h->ss)));

	/* BOLT #8:
	 *   * `ck, temp_k3 = HKDF(ck, ss)`
	 */
	hkdf_two_keys(&h->ck, &h->temp_k, &h->ck, &h->ss, sizeof(h->ss));
	status_trace("# ck,temp_k3=0x%s,0x%s",
		     tal_hexstr(trc, &h->ck, sizeof(h->ck)),
		     tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)));

	/* BOLT #8:
	 *   * `p = decryptWithAD(temp_k3, 0, h, t)`
	 *      * If the MAC check in this operation fails, then the responder MUST
	 *        terminate the connection without any further messages.
	 *
	 */
	if (!decrypt(&h->temp_k, 0, &h->h, sizeof(h->h),
		     act3.tag, sizeof(act3.tag), NULL, 0))
		status_failed(WIRE_RESPR_ACT3_BAD_TAG, "temp_k3=%s h=%s t=%s",
			      tal_hexstr(trc, &h->temp_k, sizeof(h->temp_k)),
			      tal_hexstr(trc, &h->h, sizeof(h->h)),
			      tal_hexstr(trc, act3.tag, sizeof(act3.tag)));
}

static void initiator(int fd, const struct pubkey *my_id,
		      const struct pubkey *their_id,
		      struct secret *ck, struct secret *sk, struct secret *rk)
{
	const tal_t *tmpctx = tal_tmpctx(NULL);
	struct handshake *h = new_handshake(tmpctx, their_id);
	struct pubkey re;

	act_one_initiator(h, fd, their_id);
	act_two_initiator(h, fd, &re);
	act_three_initiator(h, fd, &re, my_id);

	/* We need this for re-keying */
	*ck = h->ck;

	/* BOLT #8:
	 *
	 *   * `sk, rk = HKDF(ck, zero)`
	 *
	 *      * where `zero` is a zero-length plaintext, `sk` is the key to
	 *        be used by the initiator to encrypt messages to the
	 *        responder, and `rk` is the key to be used by the initiator
	 *        to decrypt messages sent by the responder.
	 *
	 *      * This step generates the final encryption keys to be used for
	 *        sending and receiving messages for the duration of the
	 *        session.
	 */
	hkdf_two_keys(sk, rk, ck, NULL, 0);
	status_trace("output: sk,rk=0x%s,0x%s",
		     tal_hexstr(trc, sk, sizeof(*sk)),
		     tal_hexstr(trc, rk, sizeof(*rk)));
	tal_free(tmpctx);
}

static void responder(int fd,
		      const struct pubkey *my_id,
		      struct pubkey *their_id,
		      struct secret *ck, struct secret *sk, struct secret *rk)
{
	const tal_t *tmpctx = tal_tmpctx(NULL);
	struct handshake *h = new_handshake(tmpctx, my_id);
	struct pubkey re;

	act_one_responder(h, fd, &re);
	act_two_responder(h, fd, &re);
	act_three_responder(h, fd, their_id);

	/* We need this for re-keying */
	*ck = h->ck;

	/* BOLT #8:
	 *
	 *   * `rk, sk = HKDF(ck, zero)`
	 *      * where `zero` is a zero-length plaintext, `rk` is the key to
	 *        be used by the responder to decrypt the messages sent by the
	 *        initiator, and `sk` is the key to be used by the responder
	 *        to encrypt messages to the initiator,
	 *
	 *      * This step generates the final encryption keys to be used for
	 *        sending and receiving messages for the duration of the
	 *        session.
	 */
	hkdf_two_keys(rk, sk, ck, NULL, 0);
	status_trace("output: rk,sk=0x%s,0x%s",
		     tal_hexstr(trc, rk, sizeof(*rk)),
		     tal_hexstr(trc, sk, sizeof(*sk)));
	tal_free(tmpctx);
}

#ifndef TESTING
static void exchange_init(int fd, struct crypto_state *cs,
			  u8 **gfeatures, u8 **lfeatures)
{
	/* BOLT #1:
	 *
	 * The sending node SHOULD use the minimum lengths required to
	 * represent the feature fields.
	 *
	 * The sender MUST set feature bits as defined in [BOLT
	 * #9](09-features.md), and MUST set to zero any feature bits that are
	 * not defined.
	 */
	u8 *msg = towire_init(NULL, NULL, NULL);

	if (!sync_crypto_write(cs, fd, msg))
		status_failed(WIRE_INITMSG_WRITE_FAILED, "%s", strerror(errno));

	/* BOLT #1:
	 *
	 * Each node MUST wait to receive `init` before sending any other
	 * messages.
	 */
	msg = sync_crypto_read(NULL, cs, fd);
	if (!msg)
		status_failed(WIRE_INITMSG_READ_FAILED, "%s", strerror(errno));

	if (!fromwire_init(msg, msg, NULL, gfeatures, lfeatures))
		status_failed(WIRE_INITMSG_READ_FAILED, "bad init: %s",
			      tal_hex(msg, msg));
}

/* We expect hsmfd as fd 3, clientfd as 4 */
int main(int argc, char *argv[])
{
	u8 *msg;
	struct pubkey my_id, their_id;
	int hsmfd = 3, clientfd = 4;
	struct secret ck, rk, sk;
	struct crypto_state cs;
	u8 *gfeatures, *lfeatures;

	if (argc == 2 && streq(argv[1], "--version")) {
		printf("%s\n", version());
		exit(0);
	}

	subdaemon_debug(argc, argv);
	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY
						 | SECP256K1_CONTEXT_SIGN);
	status_setup_sync(REQ_FD);

	hsm_setup(hsmfd);

	msg = wire_sync_read(NULL, REQ_FD);
	if (!msg)
		status_failed(WIRE_HANDSHAKE_BAD_COMMAND, "%s", strerror(errno));

	if (fromwire_handshake_responder(msg, NULL, &my_id)) {
		responder(clientfd, &my_id, &their_id, &ck, &sk, &rk);

		cs.rn = cs.sn = 0;
		cs.sk = sk;
		cs.rk = rk;
		cs.r_ck = cs.s_ck = ck;
		exchange_init(clientfd, &cs, &gfeatures, &lfeatures);
		wire_sync_write(REQ_FD,
				towire_handshake_responder_reply(msg,
								 &their_id,
								 &cs,
								 gfeatures,
								 lfeatures));
	} else if (fromwire_handshake_initiator(msg, NULL, &my_id,
						&their_id)) {
		initiator(clientfd, &my_id, &their_id, &ck, &sk, &rk);
		cs.rn = cs.sn = 0;
		cs.sk = sk;
		cs.rk = rk;
		cs.r_ck = cs.s_ck = ck;
		exchange_init(clientfd, &cs, &gfeatures, &lfeatures);
		wire_sync_write(REQ_FD,
				towire_handshake_initiator_reply(msg, &cs,
								 gfeatures,
								 lfeatures));
	} else
		status_failed(WIRE_HANDSHAKE_BAD_COMMAND, "%i",
			      fromwire_peektype(msg));

	/* Hand back the fd. */
	fdpass_send(REQ_FD, clientfd);

	tal_free(msg);
	return 0;
}
#endif /* TESTING */
