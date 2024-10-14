#ifndef LIGHTNING_COMMON_BLINDEDPATH_H
#define LIGHTNING_COMMON_BLINDEDPATH_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct route_info;
struct pubkey;
struct privkey;
struct secret;
struct short_channel_id;
struct tlv_encrypted_data_tlv;
struct tlv_encrypted_data_tlv_payment_constraints;
struct tlv_encrypted_data_tlv_payment_relay;

/**
 * encrypt_tlv_encrypted_data - Encrypt a tlv_encrypted_data_tlv.
 * @ctx: tal context
 * @path_privkey: e(i), the path key
 * @node: the pubkey of the node to encrypt for
 * @tlv: the message to encrypt.
 * @next_path_privkey: (out) e(i+1), the next blinding secret (optional)
 * @node_alias: (out) the blinded pubkey of the node to tell the recipient.
 *
 * You create a blinding secret using randombytes_buf(), then call this
 * iteratively for each node in the path.
 */
u8 *encrypt_tlv_encrypted_data(const tal_t *ctx,
			       const struct privkey *path_privkey,
			       const struct pubkey *node,
			       const struct tlv_encrypted_data_tlv *tlv,
			       struct privkey *next_path_privkey,
			       struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 4, 6);

/**
 * unblind_onion - tweak onion epheremeral key so we can decode it with ours.
 * @path_key: E(i), the blinding pubkey the previous peer gave us.
 * @ecdh: the ecdh routine (usually ecdh from common/ecdh_hsmd).
 * @onion_key: (in, out) the onionpacket->ephemeralkey to tweak.
 * @ss: (out) the shared secret we gained from blinding pubkey.
 *
 * The shared secret is needed to decrypt the enctlv we expect to find, too.
 */
bool unblind_onion(const struct pubkey *path_key,
		   void (*ecdh)(const struct pubkey *point, struct secret *ss),
		   struct pubkey *onion_key,
		   struct secret *ss)
	NO_NULL_ARGS;

/**
 * blindedpath_get_alias - tweak our id to see alias they used.
 * @ss: the shared secret from unblind_onion
 * @my_id: my node_id
 * @alias: (out) the alias.
 *
 * Returns false on ECDH fail.
 */
bool blindedpath_get_alias(const struct secret *ss,
			   const struct pubkey *my_id,
			   struct pubkey *alias);

/**
 * decrypt_encrypted_data - Decrypt an encmsg to form an tlv_encrypted_data_tlv.
 * @ctx: the context to allocate off.
 * @ss: the blinding secret from unblind_onion().
 * @enctlv: the enctlv from the onion (tal, may be NULL).
 *
 * Returns NULL if decryption failed or encmsg was malformed.
 */
struct tlv_encrypted_data_tlv *decrypt_encrypted_data(const tal_t *ctx,
						      const struct secret *ss,
						      const u8 *enctlv)
	NON_NULL_ARGS(2, 3);

/* Low-level accessor */
u8 *decrypt_encmsg_raw(const tal_t *ctx,
		       const struct secret *ss,
		       const u8 *enctlv);

/**
 * blindedpath_next_path_key - Calculate or extract next blinding pubkey
 */
void blindedpath_next_path_key(const struct tlv_encrypted_data_tlv *enc,
			       const struct pubkey *path_key,
			       const struct secret *ss,
			       struct pubkey *next_path_key);

#endif /* LIGHTNING_COMMON_BLINDEDPATH_H */
