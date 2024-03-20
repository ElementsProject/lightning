#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/cast/cast.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/bolt11.h>
#include <common/hmac.h>
#include <secp256k1_ecdh.h>
#include <sodium.h>
#include <wire/onion_wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* Blinds node_id and calculates next blinding factor. */
static bool blind_node(const struct privkey *blinding,
		       const struct secret *ss,
		       const struct pubkey *node,
		       struct pubkey *node_alias,
		       struct privkey *next_blinding)
{
	struct pubkey blinding_pubkey;
	struct sha256 h;

	if (!blindedpath_get_alias(ss, node, node_alias))
		return false;
	SUPERVERBOSE("\t\"blinded_node_id\": \"%s\",\n",
		     fmt_pubkey(tmpctx, node_alias));

	/* BOLT #4:
	 *  - `E(i+1) = SHA256(E(i) || ss(i)) * E(i)`
	 *     (NB: `N(i)` MUST NOT learn `e(i)`)
	 */
	if (!pubkey_from_privkey(blinding, &blinding_pubkey))
		return false;
	SUPERVERBOSE("\t\"E\": \"%s\",\n",
		     fmt_pubkey(tmpctx, &blinding_pubkey));

	/* BOLT #4:
	 *  - `e(i+1) = SHA256(E(i) || ss(i)) * e(i)`
	 *     (blinding ephemeral private key, only known by `N(r)`)
	 */
	blinding_hash_e_and_ss(&blinding_pubkey, ss, &h);
	SUPERVERBOSE("\t\"H(E || ss)\": \"%s\",\n",
		     fmt_sha256(tmpctx, &h));
	blinding_next_privkey(blinding, &h, next_blinding);
	SUPERVERBOSE("\t\"next_e\": \"%s\",\n",
		     fmt_privkey(tmpctx, next_blinding));

	return true;
}

static u8 *enctlv_from_encmsg_raw(const tal_t *ctx,
				  const struct privkey *blinding,
				  const struct pubkey *node,
				  const u8 *raw_encmsg TAKES,
				  struct privkey *next_blinding,
				  struct pubkey *node_alias)
{
	struct secret ss, rho;
	u8 *ret;
	int ok;
	/* All-zero npub */
	static const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

	/* BOLT #4:
	 *     - `ss(i) = SHA256(e(i) * N(i)) = SHA256(k(i) * E(i))`
	 *        (ECDH shared secret known only by `N(r)` and `N(i)`)
	 */
	if (secp256k1_ecdh(secp256k1_ctx, ss.data,
			   &node->pubkey, blinding->secret.data,
			   NULL, NULL) != 1)
		return NULL;
	SUPERVERBOSE("\t\"ss\": \"%s\",\n",
		     fmt_secret(tmpctx, &ss));

	/* This calculates the node's alias, and next blinding */
	if (!blind_node(blinding, &ss, node, node_alias, next_blinding))
		return NULL;

	ret = tal_dup_talarr(ctx, u8, raw_encmsg);

	/* BOLT #4:
	 * - `rho(i) = HMAC256("rho", ss(i))`
	 *    (key used to encrypt the payload for `N(i)` by `N(r)`)
	 */
	subkey_from_hmac("rho", &ss, &rho);
	SUPERVERBOSE("\t\"rho\": \"%s\",\n",
		     fmt_secret(tmpctx, &rho));

	/* BOLT #4:
	 * - MUST encrypt each `encrypted_data_tlv(i)` with ChaCha20-Poly1305 using
	 *   the corresponding `rho(i)` key and an all-zero nonce to produce
	 *   `encrypted_recipient_data(i)`
	 */
	/* Encrypt in place */
	towire_pad(&ret, crypto_aead_chacha20poly1305_ietf_ABYTES);
	ok = crypto_aead_chacha20poly1305_ietf_encrypt(ret, NULL,
						       ret,
						       tal_bytelen(ret)
						       - crypto_aead_chacha20poly1305_ietf_ABYTES,
						       NULL, 0,
						       NULL, npub,
						       rho.data);
	assert(ok == 0);

	return ret;
}

u8 *encrypt_tlv_encrypted_data(const tal_t *ctx,
			       const struct privkey *blinding,
			       const struct pubkey *node,
			       const struct tlv_encrypted_data_tlv *encmsg,
			       struct privkey *next_blinding,
			       struct pubkey *node_alias)
{
	struct privkey unused;
	u8 *encmsg_raw = tal_arr(NULL, u8, 0);
	towire_tlv_encrypted_data_tlv(&encmsg_raw, encmsg);

	/* last hop doesn't care about next_blinding */
	if (!next_blinding)
		next_blinding = &unused;
	return enctlv_from_encmsg_raw(ctx, blinding, node, take(encmsg_raw),
				      next_blinding, node_alias);
}

bool unblind_onion(const struct pubkey *blinding,
		   void (*ecdh)(const struct pubkey *point, struct secret *ss),
		   struct pubkey *onion_key,
		   struct secret *ss)
{
	struct secret hmac;

	/* BOLT #4:
	 * A reader:
	 *...
	 * - MUST compute:
	 *   - `ss(i) = SHA256(k(i) * E(i))` (standard ECDH)
	 *   - `b(i) = HMAC256("blinded_node_id", ss(i)) * k(i)`
	 */
	ecdh(blinding, ss);
	subkey_from_hmac("blinded_node_id", ss, &hmac);

	/* We instead tweak the *ephemeral* key from the onion and use
	 * our normal privkey: since hsmd knows only how to ECDH with
	 * our real key.  IOW: */
	/* BOLT #4:
	 * - MUST use `b(i)` instead of its private key `k(i)` to decrypt the onion. Note
	 *   that the node may instead tweak the onion ephemeral key with
	 *   `HMAC256("blinded_node_id", ss(i))` which achieves the same result.
	 */
	return secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					     &onion_key->pubkey,
					     hmac.data) == 1;
}

static u8 *decrypt_encmsg_raw(const tal_t *ctx,
			      const struct pubkey *blinding,
			      const struct secret *ss,
			      const u8 *enctlv)
{
	struct secret rho;
	u8 *dec;
	/* All-zero npub */
	static const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

	/* BOLT #4:
	 * A reader:
	 *...
	 *- MUST decrypt the `encrypted_data` field using `rho(i)` and use
	 *  the decrypted fields to locate the next node
	 */
	subkey_from_hmac("rho", ss, &rho);

	/* BOLT-onion-message #4:
	 *- If the `encrypted_data` field is missing or cannot
	 *  be decrypted:
	 *   - MUST return an error
	 */
	/* Too short? */
	if (tal_bytelen(enctlv) < crypto_aead_chacha20poly1305_ietf_ABYTES)
		return NULL;

	dec = tal_arr(ctx, u8, tal_bytelen(enctlv)
		      - crypto_aead_chacha20poly1305_ietf_ABYTES);
	if (crypto_aead_chacha20poly1305_ietf_decrypt(dec, NULL,
						      NULL,
						      enctlv, tal_bytelen(enctlv),
						      NULL, 0,
						      npub,
						      rho.data) != 0)
		return tal_free(dec);

	return dec;
}

struct tlv_encrypted_data_tlv *decrypt_encrypted_data(const tal_t *ctx,
						      const struct pubkey *blinding,
						      const struct secret *ss,
						      const u8 *enctlv)
{
	const u8 *cursor = decrypt_encmsg_raw(tmpctx, blinding, ss, enctlv);
	size_t maxlen = tal_bytelen(cursor);

	/* BOLT-onion-message #4:
	 *
	 * - MUST return an error if `encrypted_recipient_data` does not decrypt
	 *   using the blinding point as described in
	 *   [Route Blinding](#route-blinding).
	 */
	/* Note: our parser consider nothing is a valid TLV, but decrypt_encmsg_raw
	 * returns NULL if it couldn't decrypt. */
	if (!cursor)
		return NULL;
	return fromwire_tlv_encrypted_data_tlv(ctx, &cursor, &maxlen);
}

bool blindedpath_get_alias(const struct secret *ss,
			   const struct pubkey *my_id,
			   struct pubkey *alias)
{
	struct secret node_id_blinding;

	/* BOLT #4:
	 * - `B(i) = HMAC256("blinded_node_id", ss(i)) * N(i)`
	 *   (blinded `node_id` for `N(i)`, private key known only by `N(i)`)
	 */
	subkey_from_hmac("blinded_node_id", ss, &node_id_blinding);
	SUPERVERBOSE("\t\"HMAC256('blinded_node_id', ss)\": \"%s\",\n",
		     fmt_secret(tmpctx, &node_id_blinding));

	*alias = *my_id;
	return secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					     &alias->pubkey,
					     node_id_blinding.data) == 1;
}

void blindedpath_next_blinding(const struct tlv_encrypted_data_tlv *enc,
			       const struct pubkey *blinding,
			       const struct secret *ss,
			       struct pubkey *next_blinding)
{
	/* BOLT #4:
	 *   - `E(i+1) = SHA256(E(i) || ss(i)) * E(i)`
	 * ...
	 * - If `encrypted_data` contains a `next_blinding_override`:
	 *   - MUST use it as the next blinding point instead of `E(i+1)`
	 *   - Otherwise:
	 *     - MUST use `E(i+1)` as the next blinding point
	 */
	if (enc->next_blinding_override)
		*next_blinding = *enc->next_blinding_override;
	else {
		/* E(i-1) = H(E(i) || ss(i)) * E(i) */
		struct sha256 h;
		blinding_hash_e_and_ss(blinding, ss, &h);
		blinding_next_pubkey(blinding, &h, next_blinding);
	}
}
