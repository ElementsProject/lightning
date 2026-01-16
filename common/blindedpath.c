#include "config.h"
#include <string.h>
#include <bitcoin/tx.h>
#include <ccan/endian/endian.h>
#include <common/blindedpath.h>
#include <common/blinding.h>
#include <common/bolt11.h>
#include <common/hmac.h>
#include <common/utils.h>
#include <secp256k1_ecdh.h>
#include <sodium.h>
#include <wire/onion_wiregen.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/*
 * The `first_path_privkey` (`e_0`) is derived using
 * `e_0 = HMAC256(\text{"first_path_privkey"}, SHA256(path_id || N_0 || path_index))`,
 * where `path_id` is from the offer's `encrypted_data_tlv` that is only known by the
 * payee, where `N_0` is the `first_node_id` of the path and where `path_index`
 * is a big-endian 64-bit integer containing the path's index, to
 * differentiate potential multiple paths using the same `first_node_id`.
 * The deterministic generation of e_0 allows for the recovery of the offer paths.
 */
void derive_first_path_privkey(const struct secret *path_id, const struct pubkey *first_node, const size_t path_index, struct privkey *first_path_privkey)
{
	u8 der[PUBKEY_CMPR_LEN];
	struct sha256_ctx shactx;
	struct secret sha;
	uint64_t wire_path_index = cpu_to_be64(path_index);

	pubkey_to_der(der, first_node);
	sha256_init(&shactx);
	sha256_update(&shactx, path_id->data, sizeof(path_id->data));
	sha256_update(&shactx, der, sizeof(der));

	sha256_update(&shactx, (u8*)&wire_path_index, sizeof(wire_path_index));
	assert(sizeof(sha.data) == sizeof(struct sha256));
	sha256_done(&shactx, (struct sha256*)sha.data);
	subkey_from_hmac("first_path_privkey", &sha, &first_path_privkey->secret);
}

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
	 * - If the `encrypted_data_tlv` contains a `next_path_key_override`:
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

/*
 * The blinded path node ids and the path_pubkey of the last used hop are
 * calculated given a set of blinded paths, the used blinded_node_id and the
 * path_id (secret). The index of the used path is returned, unless an error
 * occurred, in which case a negative value is returned.
 */
ssize_t unblind_paths(const tal_t *ctx,
				struct blinded_path * const * const paths,
				struct pubkey const * const blinded_node_id,
				struct secret const * const path_id,
				struct pubkey *** const node_ids,
				struct pubkey ** const path_pubkey
				)
{
	struct privkey path_privkey, next_path_privkey;
	struct secret ss;
	struct pubkey node_alias;
	struct pubkey* last_node_id = NULL;
	struct tlv_encrypted_data_tlv *encmsg;
	size_t nhops;
	ssize_t i, j;
	ssize_t used_index = -1;
	const size_t npaths = tal_count(paths);

	if (npaths == 0) return -1;

	*node_ids = tal_arr(ctx, struct pubkey*, npaths);

	/* Loop over all blinded_paths */
	for (i = 0; i < npaths; ++i) {
		nhops = tal_count(paths[i]->path);

		/* There must be at least one hop */
		if (nhops == 0) return -1;

		/* Generated offers by us are assumed to only use pubkeys as
		 * first_node_id (Maybe not always true when using dev_paths?)*/
		if (!paths[i]->first_node_id.is_pubkey) return -1;
		(*node_ids)[i] = tal_arrz(ctx, struct pubkey, nhops);

		(*node_ids)[i][0] = paths[i]->first_node_id.pubkey;
		derive_first_path_privkey(path_id,
				(*node_ids)[i],
				i, &path_privkey);

		for (j = 0;; ++j) {

			if (!paths[i]->path[j]->encrypted_recipient_data)
				return -1;

			/* BOLT #4:
			 *     - $`ss_i = SHA256(e_i * N_i) = SHA256(k_i * E_i)`$
			 *        (ECDH shared secret known only by $`N_r`$ and $`N_i`$)
			 */
			if (secp256k1_ecdh(secp256k1_ctx, ss.data,
						&(*node_ids)[i][j].pubkey, path_privkey.secret.data,
						NULL, NULL) != 1)
				return -1;
			SUPERVERBOSE("\t\"ss\": \"%s\",\n",
					fmt_secret(tmpctx, &ss));

			/* This calculates the node's alias, and next path_key */
			if (!blind_node(&path_privkey, &ss, (*node_ids)[i]+j,
						&node_alias, &next_path_privkey))
				return -1;

			/* Verify that the blinded node id calculated by
			 * tweaking the node id using path_privkey matches the
			 * one provided in the path
			 * */
			if (pubkey_cmp(&paths[i]->path[j]->blinded_node_id, &node_alias)) return -1;
			encmsg = decrypt_encrypted_data(ctx, &ss, paths[i]->path[j]->encrypted_recipient_data);

			if (!encmsg)
				return -1;

			if (!encmsg->next_node_id) {

				if (j != nhops - 1)
				  return -1;

				if (!encmsg->path_id || tal_count(encmsg->path_id) != sizeof(path_id->data))
					return -1;

				/* Verify that we generated the path by
				 * verifying the stored secret
				 */
				if (memcmp(encmsg->path_id, path_id->data, sizeof(path_id->data)))
					return -1;

				if (last_node_id) {

					/* Verify that the last hop of each blinded path points to the
					 * same node id */
					if (pubkey_cmp((*node_ids)[i] + j, last_node_id))
						return -1;
				} else last_node_id = (*node_ids)[i] + j;

				/* Check if this is the path that contains blinded_node_id */
				if (!pubkey_cmp(&paths[i]->path[j]->blinded_node_id, blinded_node_id)) {
					used_index = i;
					*path_pubkey = tal(ctx, struct pubkey);

					if (!pubkey_from_privkey(&path_privkey, *path_pubkey))
						return -1;
				}
				/* Only the last hop has next_node_id unset */
				break;
			}

			/* The last hop cannot have next_node_id set */
			if (j == nhops - 1) return -1;
			(*node_ids)[i][j+1] = *encmsg->next_node_id;
			path_privkey = next_path_privkey;
		}
	}
	return used_index;
}
