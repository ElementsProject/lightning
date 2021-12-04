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
	struct secret node_id_blinding;
	struct pubkey blinding_pubkey;
	struct sha256 h;

	/*
	 * Blinded node_id for N(i), private key known only by N(i):
	 *   B(i) = HMAC256("blinded_node_id", ss(i)) * P(i)
	 */
	subkey_from_hmac("blinded_node_id", ss, &node_id_blinding);
	SUPERVERBOSE("\t\"HMAC256('blinded_node_id', ss)\": \"%s\",\n",
		     type_to_string(tmpctx, struct secret,
				    &node_id_blinding));

	*node_alias = *node;
	if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &node_alias->pubkey,
					  node_id_blinding.data) != 1)
		return false;
	SUPERVERBOSE("\t\"blinded_node_id\": \"%s\",\n",
		     type_to_string(tmpctx, struct pubkey, node_alias));

	/*
	 * Ephemeral private key, only known by N(r):
	 *   e(i+1) = H(E(i) || ss(i)) * e(i)
	 */
	if (!pubkey_from_privkey(blinding, &blinding_pubkey))
		return false;
	SUPERVERBOSE("\t\"E\": \"%s\",\n",
		     type_to_string(tmpctx, struct pubkey, &blinding_pubkey));

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
	/* https://github.com/lightningnetwork/lightning-rfc/blob/route-blinding/proposals/route-blinding.md */
	struct secret ss, rho;
	u8 *ret;
	int ok;
	/* All-zero npub */
	static const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

	/*
	 * shared secret known only by N(r) and N(i):
	 *   ss(i) = H(e(i) * P(i)) = H(k(i) * E(i))
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
	SUPERVERBOSE("\t\"encmsg_hex\": \"%s\",\n", tal_hex(tmpctx, ret));

	/*
	 * Key used to encrypt payload for N(i) by N(r):
	 *  rho(i) = HMAC256("rho", ss(i))
	 */
	subkey_from_hmac("rho", &ss, &rho);
	SUPERVERBOSE("\t\"rho\": \"%s\",\n",
		     type_to_string(tmpctx, struct secret, &rho));

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

static u8 *enctlv_from_obs2_encmsg(const tal_t *ctx,
				   const struct privkey *blinding,
				   const struct pubkey *node,
				   const struct tlv_obs2_encmsg_tlvs *encmsg,
				   struct privkey *next_blinding,
				   struct pubkey *node_alias)
{
	u8 *encmsg_raw = tal_arr(NULL, u8, 0);
	towire_obs2_encmsg_tlvs(&encmsg_raw, encmsg);
	return enctlv_from_encmsg_raw(ctx, blinding, node, take(encmsg_raw),
				      next_blinding, node_alias);
}

static u8 *enctlv_from_encmsg(const tal_t *ctx,
			      const struct privkey *blinding,
			      const struct pubkey *node,
			      const struct tlv_encrypted_data_tlv *encmsg,
			      struct privkey *next_blinding,
			      struct pubkey *node_alias)
{
	u8 *encmsg_raw = tal_arr(NULL, u8, 0);
	towire_encrypted_data_tlv(&encmsg_raw, encmsg);
	return enctlv_from_encmsg_raw(ctx, blinding, node, take(encmsg_raw),
				      next_blinding, node_alias);
}

bool unblind_onion(const struct pubkey *blinding,
		   void (*ecdh)(const struct pubkey *point, struct secret *ss),
		   struct pubkey *onion_key,
		   struct secret *ss)
{
	struct secret hmac;

	/* E(i) */
	ecdh(blinding, ss);

	/* b(i) = HMAC256("blinded_node_id", ss(i)) * k(i) */
	subkey_from_hmac("blinded_node_id", ss, &hmac);

	/* We instead tweak the *ephemeral* key from the onion and use
	 * our normal privkey: since hsmd knows only how to ECDH with
	 * our real key */
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

	/* We need this to decrypt enctlv */
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

static struct tlv_obs2_encmsg_tlvs *decrypt_obs2_encmsg(const tal_t *ctx,
							const struct pubkey *blinding,
							const struct secret *ss,
							const u8 *enctlv)
{
	struct tlv_obs2_encmsg_tlvs *encmsg;
	const u8 *cursor = decrypt_encmsg_raw(tmpctx, blinding, ss, enctlv);
	size_t maxlen = tal_bytelen(cursor);

	/* BOLT-onion-message #4:
	 *
	 * - if the `enctlv` is not a valid TLV...
	 *   - MUST drop the message.
	 */
	encmsg = tlv_obs2_encmsg_tlvs_new(ctx);
	if (!fromwire_obs2_encmsg_tlvs(&cursor, &maxlen, encmsg)
	    || !tlv_fields_valid(encmsg->fields, NULL, NULL))
		return tal_free(encmsg);

	return encmsg;
}

static struct tlv_encrypted_data_tlv *decrypt_encmsg(const tal_t *ctx,
						     const struct pubkey *blinding,
						     const struct secret *ss,
						     const u8 *enctlv)
{
	struct tlv_encrypted_data_tlv *encmsg;
	const u8 *cursor = decrypt_encmsg_raw(tmpctx, blinding, ss, enctlv);
	size_t maxlen = tal_bytelen(cursor);

	/* BOLT-onion-message #4:
	 *
	 * - if the `enctlv` is not a valid TLV...
	 *   - MUST drop the message.
	 */
	encmsg = tlv_encrypted_data_tlv_new(ctx);
	if (!fromwire_encrypted_data_tlv(&cursor, &maxlen, encmsg)
	    || !tlv_fields_valid(encmsg->fields, NULL, NULL))
		return tal_free(encmsg);

	return encmsg;
}

bool decrypt_enctlv(const struct pubkey *blinding,
		    const struct secret *ss,
		    const u8 *enctlv,
		    struct pubkey *next_node,
		    struct pubkey *next_blinding)
{
	struct tlv_encrypted_data_tlv *encmsg;

	encmsg = decrypt_encmsg(tmpctx, blinding, ss, enctlv);
	if (!encmsg)
		return false;

	/* BOLT-onion-message #4:
	 *
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `enctlv` ... does not contain
	 *      `next_node_id`:
	 *      - MUST drop the message.
	 */
	if (!encmsg->next_node_id)
		return false;

	/* BOLT-onion-message #4:
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `enctlv` contains `path_id`:
	 *      - MUST drop the message.
	 */
	if (encmsg->path_id)
		return false;

	/* BOLT-onion-message #4:
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if `blinding` is specified in the `enctlv`:
	 *       - MUST pass that as `blinding` in the `onion_message`
	 *    - otherwise:
	 *       - MUST pass `blinding` derived as in
	 *         [Route Blinding][route-blinding] (i.e.
	 *         `E(i+1) = H(E(i) || ss(i)) * E(i)`).
	 */
	*next_node = *encmsg->next_node_id;
	if (encmsg->next_blinding_override)
		*next_blinding = *encmsg->next_blinding_override;
	else {
		/* E(i-1) = H(E(i) || ss(i)) * E(i) */
		struct sha256 h;
		blinding_hash_e_and_ss(blinding, ss, &h);
		blinding_next_pubkey(blinding, &h, next_blinding);
	}
	return true;
}

bool decrypt_final_enctlv(const tal_t *ctx,
			  const struct pubkey *blinding,
			  const struct secret *ss,
			  const u8 *enctlv,
			  const struct pubkey *my_id,
			  struct pubkey *alias,
			  struct secret **path_id)
{
	struct tlv_encrypted_data_tlv *encmsg;
	struct secret node_id_blinding;

	/* Repeat the tweak to get the alias it was using for us */
	subkey_from_hmac("blinded_node_id", ss, &node_id_blinding);
	*alias = *my_id;
	if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &alias->pubkey,
					  node_id_blinding.data) != 1)
		return false;

	encmsg = decrypt_encmsg(tmpctx, blinding, ss, enctlv);
	if (!encmsg)
		return false;

	if (tal_bytelen(encmsg->path_id) == sizeof(**path_id)) {
		*path_id = tal(ctx, struct secret);
		memcpy(*path_id, encmsg->path_id, sizeof(**path_id));
	} else
		*path_id = NULL;

	return true;
}

u8 *create_enctlv(const tal_t *ctx,
		  const struct privkey *blinding,
		  const struct pubkey *node,
		  const struct pubkey *next_node,
		  size_t padlen,
		  const struct pubkey *next_blinding_override,
		  struct privkey *next_blinding,
		  struct pubkey *node_alias)
{
	struct tlv_encrypted_data_tlv *encmsg = tlv_encrypted_data_tlv_new(tmpctx);
	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	encmsg->next_node_id = cast_const(struct pubkey *, next_node);
	encmsg->next_blinding_override = cast_const(struct pubkey *, next_blinding_override);

	return enctlv_from_encmsg(ctx, blinding, node, encmsg,
				  next_blinding, node_alias);
}

u8 *create_final_enctlv(const tal_t *ctx,
			const struct privkey *blinding,
			const struct pubkey *final_node,
			size_t padlen,
			const struct secret *path_id,
			struct pubkey *node_alias)
{
	struct tlv_encrypted_data_tlv *encmsg = tlv_encrypted_data_tlv_new(tmpctx);
	struct privkey unused_next_blinding;

	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	if (path_id)
		encmsg->path_id = (u8 *)tal_dup(encmsg, struct secret, path_id);

	return enctlv_from_encmsg(ctx, blinding, final_node, encmsg,
				  &unused_next_blinding, node_alias);
}

/* Obsolete variants */
bool decrypt_obs2_enctlv(const struct pubkey *blinding,
			 const struct secret *ss,
			 const u8 *enctlv,
			 struct pubkey *next_node,
			 struct pubkey *next_blinding)
{
	struct tlv_obs2_encmsg_tlvs *encmsg;

	encmsg = decrypt_obs2_encmsg(tmpctx, blinding, ss, enctlv);
	if (!encmsg)
		return false;

	/* BOLT-onion-message #4:
	 *
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `enctlv` ... does not contain
	 *      `next_node_id`:
	 *      - MUST drop the message.
	 */
	if (!encmsg->next_node_id)
		return false;

	/* BOLT-onion-message #4:
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if the `enctlv` contains `self_id`:
	 *      - MUST drop the message.
	 */
	if (encmsg->self_id)
		return false;

	/* BOLT-onion-message #4:
	 * The reader:
	 *  - if it is not the final node according to the onion encryption:
	 *...
	 *    - if `blinding` is specified in the `enctlv`:
	 *       - MUST pass that as `blinding` in the `onion_message`
	 *    - otherwise:
	 *       - MUST pass `blinding` derived as in
	 *         [Route Blinding][route-blinding] (i.e.
	 *         `E(i+1) = H(E(i) || ss(i)) * E(i)`).
	 */
	*next_node = *encmsg->next_node_id;
	if (encmsg->next_blinding)
		*next_blinding = *encmsg->next_blinding;
	else {
		/* E(i-1) = H(E(i) || ss(i)) * E(i) */
		struct sha256 h;
		blinding_hash_e_and_ss(blinding, ss, &h);
		blinding_next_pubkey(blinding, &h, next_blinding);
	}
	return true;
}

bool decrypt_obs2_final_enctlv(const tal_t *ctx,
			       const struct pubkey *blinding,
			       const struct secret *ss,
			       const u8 *enctlv,
			       const struct pubkey *my_id,
			       struct pubkey *alias,
			       struct secret **self_id)
{
	struct tlv_obs2_encmsg_tlvs *encmsg;
	struct secret node_id_blinding;

	/* Repeat the tweak to get the alias it was using for us */
	subkey_from_hmac("blinded_node_id", ss, &node_id_blinding);
	*alias = *my_id;
	if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &alias->pubkey,
					  node_id_blinding.data) != 1)
		return false;

	encmsg = decrypt_obs2_encmsg(tmpctx, blinding, ss, enctlv);
	if (!encmsg)
		return false;

	if (tal_bytelen(encmsg->self_id) == sizeof(**self_id)) {
		*self_id = tal(ctx, struct secret);
		memcpy(*self_id, encmsg->self_id, sizeof(**self_id));
	} else
		*self_id = NULL;

	return true;
}

u8 *create_obs2_enctlv(const tal_t *ctx,
		       const struct privkey *blinding,
		       const struct pubkey *node,
		       const struct pubkey *next_node,
		       size_t padlen,
		       const struct pubkey *override_blinding,
		       struct privkey *next_blinding,
		       struct pubkey *node_alias)
{
	struct tlv_obs2_encmsg_tlvs *encmsg = tlv_obs2_encmsg_tlvs_new(tmpctx);
	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	encmsg->next_node_id = cast_const(struct pubkey *, next_node);
	encmsg->next_blinding = cast_const(struct pubkey *, override_blinding);

	return enctlv_from_obs2_encmsg(ctx, blinding, node, encmsg,
				       next_blinding, node_alias);
}

u8 *create_obs2_final_enctlv(const tal_t *ctx,
			     const struct privkey *blinding,
			     const struct pubkey *final_node,
			     size_t padlen,
			     const struct secret *self_id,
			     struct pubkey *node_alias)
{
	struct tlv_obs2_encmsg_tlvs *encmsg = tlv_obs2_encmsg_tlvs_new(tmpctx);
	struct privkey unused_next_blinding;

	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	if (self_id)
		encmsg->self_id = (u8 *)tal_dup(encmsg, struct secret, self_id);

	return enctlv_from_obs2_encmsg(ctx, blinding, final_node, encmsg,
				       &unused_next_blinding, node_alias);
}
