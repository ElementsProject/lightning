#include "config.h"
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
		     type_to_string(tmpctx, struct pubkey, node_alias));

	/* BOLT-route-blinding #4:
	 *  - `E(i+1) = SHA256(E(i) || ss(i)) * E(i)`
	 *     (NB: `N(i)` MUST NOT learn `e(i)`)
	 */
	if (!pubkey_from_privkey(blinding, &blinding_pubkey))
		return false;
	SUPERVERBOSE("\t\"E\": \"%s\",\n",
		     type_to_string(tmpctx, struct pubkey, &blinding_pubkey));

	/* BOLT-route-blinding #4:
	 *  - `e(i+1) = SHA256(E(i) || ss(i)) * e(i)`
	 *     (blinding ephemeral private key, only known by `N(r)`)
	 */
	blinding_hash_e_and_ss(&blinding_pubkey, ss, &h);
	SUPERVERBOSE("\t\"H(E || ss)\": \"%s\",\n",
		     type_to_string(tmpctx, struct sha256, &h));
	blinding_next_privkey(blinding, &h, next_blinding);
	SUPERVERBOSE("\t\"next_e\": \"%s\",\n",
		     type_to_string(tmpctx, struct privkey, next_blinding));

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

	/* BOLT-route-blinding #4:
	 *     - `ss(i) = SHA256(e(i) * N(i)) = SHA256(k(i) * E(i))`
	 *        (ECDH shared secret known only by `N(r)` and `N(i)`)
	 */
	if (secp256k1_ecdh(secp256k1_ctx, ss.data,
			   &node->pubkey, blinding->secret.data,
			   NULL, NULL) != 1)
		return NULL;
	SUPERVERBOSE("\t\"ss\": \"%s\",\n",
		     type_to_string(tmpctx, struct secret, &ss));

	/* This calculates the node's alias, and next blinding */
	if (!blind_node(blinding, &ss, node, node_alias, next_blinding))
		return NULL;

	ret = tal_dup_talarr(ctx, u8, raw_encmsg);

	/* BOLT-route-blinding #4:
	 * - `rho(i) = HMAC256("rho", ss(i))`
	 *    (key used to encrypt the payload for `N(i)` by `N(r)`)
	 */
	subkey_from_hmac("rho", &ss, &rho);
	SUPERVERBOSE("\t\"rho\": \"%s\",\n",
		     type_to_string(tmpctx, struct secret, &rho));

	/* BOLT-route-blinding #4:
	 * - MUST encrypt them with ChaCha20-Poly1305 using the `rho(i)` key
	 *   and an all-zero nonce
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

static u8 *enctlv_from_encmsg(const tal_t *ctx,
			      const struct privkey *blinding,
			      const struct pubkey *node,
			      const struct tlv_encrypted_data_tlv *encmsg,
			      struct privkey *next_blinding,
			      struct pubkey *node_alias)
{
	u8 *encmsg_raw = tal_arr(NULL, u8, 0);
	towire_tlv_encrypted_data_tlv(&encmsg_raw, encmsg);
	return enctlv_from_encmsg_raw(ctx, blinding, node, take(encmsg_raw),
				      next_blinding, node_alias);
}

bool unblind_onion(const struct pubkey *blinding,
		   void (*ecdh)(const struct pubkey *point, struct secret *ss),
		   struct pubkey *onion_key,
		   struct secret *ss)
{
	struct secret hmac;

	/* BOLT-route-blinding #4:
	 * An intermediate node in the blinded route:
	 *
	 * - MUST compute:
	 *   - `ss(i) = SHA256(k(i) * E(i))` (standard ECDH)
	 *   - `b(i) = HMAC256("blinded_node_id", ss(i)) * k(i)`
	 */
	ecdh(blinding, ss);
	subkey_from_hmac("blinded_node_id", ss, &hmac);

	/* We instead tweak the *ephemeral* key from the onion and use
	 * our normal privkey: since hsmd knows only how to ECDH with
	 * our real key.  IOW: */
	/* BOLT-route-blinding #4:
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

	/* BOLT-route-blinding #4:
	 * - If an `encrypted_data` field is provided:
	 *   - MUST decrypt it using `rho(r)`
	 */
	subkey_from_hmac("rho", ss, &rho);

	/* BOLT-onion-message #4:
	 *   - if `enctlv` is not present, or does not decrypt with the
	 *     shared secret from the given `blinding` parameter:
	 *   - MUST drop the message.
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
	 * - if the `enctlv` is not a valid TLV...
	 *   - MUST drop the message.
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

	/* BOLT-route-blinding #4:
	 * - `B(i) = HMAC256("blinded_node_id", ss(i)) * N(i)`
	 *   (blinded `node_id` for `N(i)`, private key known only by `N(i)`)
	 */
	subkey_from_hmac("blinded_node_id", ss, &node_id_blinding);
	SUPERVERBOSE("\t\"HMAC256('blinded_node_id', ss)\": \"%s\",\n",
		     type_to_string(tmpctx, struct secret,
				    &node_id_blinding));

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
	/* BOLT-route
	 *   - `E(1) = SHA256(E(0) || ss(0)) * E(0)`
	 * ...
	 * - If `encrypted_data` contains a `next_blinding_override`:
	 *   - MUST use it as the next blinding point instead of `E(1)`
	 *   - Otherwise:
	 *     - MUST use `E(1)` as the next blinding point
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

u8 *create_enctlv(const tal_t *ctx,
		  const struct privkey *blinding,
		  const struct pubkey *node,
		  const struct pubkey *next_node,
		  const struct short_channel_id *next_scid,
		  size_t padlen,
		  const struct pubkey *next_blinding_override,
		  const struct tlv_encrypted_data_tlv_payment_relay *payment_relay TAKES,
		  const struct tlv_encrypted_data_tlv_payment_constraints *payment_constraints TAKES,
		  const u8 *allowed_features TAKES,
		  struct privkey *next_blinding,
		  struct pubkey *node_alias)
{
	struct tlv_encrypted_data_tlv *encmsg = tlv_encrypted_data_tlv_new(tmpctx);
	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	encmsg->next_node_id = cast_const(struct pubkey *, next_node);
	encmsg->next_blinding_override = cast_const(struct pubkey *, next_blinding_override);
	encmsg->payment_relay = tal_dup_or_null(encmsg, struct tlv_encrypted_data_tlv_payment_relay,
						payment_relay);
	encmsg->payment_constraints = tal_dup_or_null(encmsg, struct tlv_encrypted_data_tlv_payment_constraints,
						      payment_constraints);
	encmsg->allowed_features = tal_dup_talarr(encmsg, u8, allowed_features);

	return enctlv_from_encmsg(ctx, blinding, node, encmsg,
				  next_blinding, node_alias);
}

u8 *create_final_enctlv(const tal_t *ctx,
			const struct privkey *blinding,
			const struct pubkey *final_node,
			size_t padlen,
			const struct secret *path_id,
			const u8 *allowed_features TAKES,
			struct pubkey *node_alias)
{
	struct tlv_encrypted_data_tlv *encmsg = tlv_encrypted_data_tlv_new(tmpctx);
	struct privkey unused_next_blinding;

	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	if (path_id)
		encmsg->path_id = (u8 *)tal_dup(encmsg, struct secret, path_id);
	encmsg->allowed_features = tal_dup_talarr(encmsg, u8, allowed_features);

	return enctlv_from_encmsg(ctx, blinding, final_node, encmsg,
				  &unused_next_blinding, node_alias);
}
