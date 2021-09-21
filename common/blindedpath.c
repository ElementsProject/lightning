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

/* Obsolete version: use enctlv() helper. */
struct onionmsg_path **make_blindedpath(const tal_t *ctx,
					const struct pubkey *route,
					struct pubkey *initial_blinding,
					struct pubkey *final_blinding)
{
	struct privkey e;
	struct pubkey *pk_e, *b;
	struct secret *rho;
	struct onionmsg_path **path;
	size_t num = tal_count(route);

	if (!num)
		abort();

	/* E(i) */
	pk_e = tal_arr(tmpctx, struct pubkey, num);
	/* B(i) */
	b = tal_arr(tmpctx, struct pubkey, num);
	/* rho(i) */
	rho = tal_arr(tmpctx, struct secret, num);

	randombytes_buf(&e, sizeof(e));
	if (!pubkey_from_privkey(&e, &pk_e[0]))
		abort();

	for (size_t i = 0; i < num; i++) {
		struct secret ss;
		struct secret hmac;
		struct sha256 h;

		if (secp256k1_ecdh(secp256k1_ctx, ss.data,
				   &route[i].pubkey, e.secret.data,
				   NULL, NULL) != 1)
				abort();

		subkey_from_hmac("blinded_node_id", &ss, &hmac);
		b[i] = route[i];
		if (i != 0) {
			if (secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					  &b[i].pubkey, hmac.data) != 1)
				abort();
		}
		subkey_from_hmac("rho", &ss, &rho[i]);
		blinding_hash_e_and_ss(&pk_e[i], &ss, &h);
		if (i != num-1)
			blinding_next_pubkey(&pk_e[i], &h, &pk_e[i+1]);
		blinding_next_privkey(&e, &h, &e);
	}

	*initial_blinding = pk_e[0];
	*final_blinding = pk_e[num-1];

	path = tal_arr(ctx, struct onionmsg_path *, num);
	for (size_t i = 0; i < num; i++) {
		path[i] = tal(path, struct onionmsg_path);
		path[i]->node_id = b[i];
	}

	for (size_t i = 0; i < num - 1; i++) {
		const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		struct tlv_encmsg_tlvs *inner;
		int ret;

		/* Inner is encrypted */
		inner = tlv_encmsg_tlvs_new(tmpctx);
		/* FIXME: We could support scids, too */
		inner->next_node_id = cast_const(struct pubkey *, &route[i+1]);

		path[i]->enctlv = tal_arr(path, u8, 0);
		towire_encmsg_tlvs(&path[i]->enctlv, inner);
		towire_pad(&path[i]->enctlv,
			   crypto_aead_chacha20poly1305_ietf_ABYTES);

		ret = crypto_aead_chacha20poly1305_ietf_encrypt(path[i]->enctlv, NULL,
								path[i]->enctlv,
								tal_bytelen(path[i]->enctlv) - crypto_aead_chacha20poly1305_ietf_ABYTES,
								NULL, 0,
								NULL, npub,
								rho[i].data);
		assert(ret == 0);
	}

	/* Final one has no enctlv */
	path[num-1]->enctlv = NULL;

	return path;
}

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

static u8 *enctlv_from_encmsg(const tal_t *ctx,
			      const struct privkey *blinding,
			      const struct pubkey *node,
			      const struct tlv_encmsg_tlvs *encmsg,
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

	/* Marshall */
	ret = tal_arr(ctx, u8, 0);
	towire_encmsg_tlvs(&ret, encmsg);
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

static struct tlv_encmsg_tlvs *decrypt_encmsg(const tal_t *ctx,
					      const struct pubkey *blinding,
					      const struct secret *ss,
					      const u8 *enctlv)
{
	struct secret rho;
	u8 *dec;
	const u8 *cursor;
	size_t maxlen;
	struct tlv_encmsg_tlvs *encmsg;
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

	dec = tal_arr(tmpctx, u8, tal_bytelen(enctlv)
		      - crypto_aead_chacha20poly1305_ietf_ABYTES);
	if (crypto_aead_chacha20poly1305_ietf_decrypt(dec, NULL,
						      NULL,
						      enctlv, tal_bytelen(enctlv),
						      NULL, 0,
						      npub,
						      rho.data) != 0)
		return NULL;

	cursor = dec;
	maxlen = tal_bytelen(dec);

	/* BOLT-onion-message #4:
	 *
	 * - if the `enctlv` is not a valid TLV...
	 *   - MUST drop the message.
	 */
	encmsg = tlv_encmsg_tlvs_new(ctx);
	if (!fromwire_encmsg_tlvs(&cursor, &maxlen, encmsg)
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
	struct tlv_encmsg_tlvs *encmsg;

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

bool decrypt_final_enctlv(const tal_t *ctx,
			  const struct pubkey *blinding,
			  const struct secret *ss,
			  const u8 *enctlv,
			  const struct pubkey *my_id,
			  struct pubkey *alias,
			  struct secret **self_id)
{
	struct tlv_encmsg_tlvs *encmsg;
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

	if (tal_bytelen(encmsg->self_id) == sizeof(**self_id)) {
		*self_id = tal(ctx, struct secret);
		memcpy(*self_id, encmsg->self_id, sizeof(**self_id));
	} else
		*self_id = NULL;

	return true;
}

u8 *create_enctlv(const tal_t *ctx,
		  const struct privkey *blinding,
		  const struct pubkey *node,
		  const struct pubkey *next_node,
		  size_t padlen,
		  const struct pubkey *override_blinding,
		  struct privkey *next_blinding,
		  struct pubkey *node_alias)
{
	struct tlv_encmsg_tlvs *encmsg = tlv_encmsg_tlvs_new(tmpctx);
	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	encmsg->next_node_id = cast_const(struct pubkey *, next_node);
	encmsg->next_blinding = cast_const(struct pubkey *, override_blinding);

	return enctlv_from_encmsg(ctx, blinding, node, encmsg,
				  next_blinding, node_alias);
}

u8 *create_final_enctlv(const tal_t *ctx,
			const struct privkey *blinding,
			const struct pubkey *final_node,
			size_t padlen,
			const struct secret *self_id,
			struct pubkey *node_alias)
{
	struct tlv_encmsg_tlvs *encmsg = tlv_encmsg_tlvs_new(tmpctx);
	struct privkey unused_next_blinding;

	if (padlen)
		encmsg->padding = tal_arrz(encmsg, u8, padlen);
	if (self_id)
		encmsg->self_id = (u8 *)tal_dup(encmsg, struct secret, self_id);

	return enctlv_from_encmsg(ctx, blinding, final_node, encmsg,
				  &unused_next_blinding, node_alias);
}
