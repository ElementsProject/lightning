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
static bool blind_node(const struct privkey *path_privkey,
		       const struct secret *ss,
		       const struct pubkey *node,
		       struct pubkey *node_alias,
		       struct privkey *next_path_privkey)
{
	struct pubkey path_pubkey;
	struct sha256 h;

	if (!blindedpath_get_alias(ss, node, node_alias))
		return false;
	SUPERVERBOSE("\t\"blinded_node_id\": \"%s\",\n",
		     fmt_pubkey(tmpctx, node_alias));

	/* BOLT #4:
	 *  - $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$
	 *     (`path_key`. NB: $`N_i`$ MUST NOT learn $`e_i`$)
	 */
	if (!pubkey_from_privkey(path_privkey, &path_pubkey))
		return false;
	SUPERVERBOSE("\t\"E\": \"%s\",\n",
		     fmt_pubkey(tmpctx, &path_pubkey));

	/* BOLT #4:
	 *  - $`e_{i+1} = SHA256(E_i || ss_i) * e_i`$
	 *     (ephemeral private path key, only known by $`N_r`$)
	 */
	blinding_hash_e_and_ss(&path_pubkey, ss, &h);
	SUPERVERBOSE("\t\"H(E || ss)\": \"%s\",\n",
		     fmt_sha256(tmpctx, &h));
	blinding_next_path_privkey(path_privkey, &h, next_path_privkey);
	SUPERVERBOSE("\t\"next_e\": \"%s\",\n",
		     fmt_privkey(tmpctx, next_path_privkey));

	return true;
}

static u8 *enctlv_from_encmsg_raw(const tal_t *ctx,
				  const struct privkey *path_privkey,
				  const struct pubkey *node,
				  const u8 *raw_encmsg TAKES,
				  struct privkey *next_path_privkey,
				  struct pubkey *node_alias)
{
	struct secret ss, rho;
	u8 *ret;
	int ok;
	/* All-zero npub */
	static const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

	/* BOLT #4:
	 *     - $`ss_i = SHA256(e_i * N_i) = SHA256(k_i * E_i)`$
	 *        (ECDH shared secret known only by $`N_r`$ and $`N_i`$)
	 */
	if (secp256k1_ecdh(secp256k1_ctx, ss.data,
			   &node->pubkey, path_privkey->secret.data,
			   NULL, NULL) != 1)
		return NULL;
	SUPERVERBOSE("\t\"ss\": \"%s\",\n",
		     fmt_secret(tmpctx, &ss));

	/* This calculates the node's alias, and next path_key */
	if (!blind_node(path_privkey, &ss, node, node_alias, next_path_privkey))
		return NULL;

	ret = tal_dup_talarr(ctx, u8, raw_encmsg);

	/* BOLT #4:
	 * - $`rho_i = HMAC256(\text{"rho"}, ss_i)`$
	 *    (key used to encrypt `encrypted_recipient_data` for $`N_i`$ by $`N_r`$)
	 */
	subkey_from_hmac("rho", &ss, &rho);
	SUPERVERBOSE("\t\"rho\": \"%s\",\n",
		     fmt_secret(tmpctx, &rho));

	/* BOLT #4:
	 * - MUST encrypt each `encrypted_data_tlv[i]` with ChaCha20-Poly1305 using
	 *   the corresponding $`rho_i`$ key and an all-zero nonce to produce
	 *   `encrypted_recipient_data[i]`
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
			       const struct privkey *path_privkey,
			       const struct pubkey *node,
			       const struct tlv_encrypted_data_tlv *tlv,
			       struct privkey *next_path_privkey,
			       struct pubkey *node_alias)
{
	struct privkey unused;
	u8 *tlv_wire = tal_arr(NULL, u8, 0);
	towire_tlv_encrypted_data_tlv(&tlv_wire, tlv);

	/* last hop doesn't care about next path_key */
	if (!next_path_privkey)
		next_path_privkey = &unused;
	return enctlv_from_encmsg_raw(ctx, path_privkey, node, take(tlv_wire),
				      next_path_privkey, node_alias);
}

bool unblind_onion(const struct pubkey *path_key,
		   void (*ecdh)(const struct pubkey *point, struct secret *ss),
		   struct pubkey *onion_key,
		   struct secret *ss)
{
	struct secret hmac;

	/* BOLT #4:
	 * A reader:
	 *...
	 * - if `path_key` is specified:
	 *    - Calculate the `blinding_ss` as ECDH(`path_key`, `node_privkey`).
	 *    - Either:
	 *      - Tweak `public_key` by multiplying by $`HMAC256(\text{"blinded\_node\_id"}, blinding\_ss)`$.
	 *    - or (equivalently):
	 *      - Tweak its own `node_privkey` below by multiplying by $`HMAC256(\text{"blinded\_node\_id"}, blinding\_ss)`$.
	 */
	ecdh(path_key, ss);
	subkey_from_hmac("blinded_node_id", ss, &hmac);

	/* We tweak the *ephemeral* key from the onion and use
	 * our normal privkey: since hsmd knows only how to ECDH with
	 * our real key. */
	return secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					     &onion_key->pubkey,
					     hmac.data) == 1;
}

u8 *decrypt_encmsg_raw(const tal_t *ctx,
		       const struct secret *ss,
		       const u8 *enctlv)
{
	struct secret rho;
	u8 *dec;
	/* All-zero npub */
	static const unsigned char npub[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

	/* BOLT #4:
	 * The reader of the `encrypted_recipient_data`:
	 *...
	 *- $`rho_i = HMAC256(\text{"rho"}, ss_i)`$
	 *- MUST decrypt the `encrypted_recipient_data` field using $`rho_i`$
         *  as a key using ChaCha20-Poly1305 and an all-zero nonce key.
	 */
	subkey_from_hmac("rho", ss, &rho);

	/* BOLT #4:
	 * - If the `encrypted_recipient_data` field is missing, cannot be
         *   decrypted into an `encrypted_data_tlv` or contains unknown even
         *   fields:
	 *    - MUST return an error
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
						      const struct secret *ss,
						      const u8 *enctlv)
{
	const u8 *cursor = decrypt_encmsg_raw(tmpctx, ss, enctlv);
	size_t maxlen = tal_bytelen(cursor);

	/* BOLT #4:
	 * - If the `encrypted_recipient_data` field is missing, cannot be
         *   decrypted into an `encrypted_data_tlv` or contains unknown even
         *   fields:
	 *    - MUST return an error
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
	 * - $`B_i = HMAC256(\text{"blinded\_node\_id"}, ss_i) * N_i`$
	 *   (blinded `node_id` for $`N_i`$, private key known only by $`N_i`$)
	 */
	subkey_from_hmac("blinded_node_id", ss, &node_id_blinding);
	SUPERVERBOSE("\t\"HMAC256('blinded_node_id', ss)\": \"%s\",\n",
		     fmt_secret(tmpctx, &node_id_blinding));

	*alias = *my_id;
	return secp256k1_ec_pubkey_tweak_mul(secp256k1_ctx,
					     &alias->pubkey,
					     node_id_blinding.data) == 1;
}

void blindedpath_next_path_key(const struct tlv_encrypted_data_tlv *enc,
			       const struct pubkey *path_key,
			       const struct secret *ss,
			       struct pubkey *next_path_key)
{
	/* BOLT #4:
	 *   - $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$
	 * ...
	 * - If `encrypted_data` contains a `next_path_key_override`:
	 *   - MUST use it as the next `path_key`.
	 * - Otherwise:
	 *  - MUST use $`E_{i+1} = SHA256(E_i || ss_i) * E_i`$ as the next `path_key`
	 */
	if (enc->next_path_key_override)
		*next_path_key = *enc->next_path_key_override;
	else {
		struct sha256 h;
		blinding_hash_e_and_ss(path_key, ss, &h);
		blinding_next_path_key(path_key, &h, next_path_key);
	}
}
