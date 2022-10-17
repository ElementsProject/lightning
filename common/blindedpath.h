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
struct tlv_encrypted_data_tlv_payment_constraints;
struct tlv_encrypted_data_tlv_payment_relay;

/**
 * create_enctlv - Encrypt an encmsg to form an enctlv.
 * @ctx: tal context
 * @blinding: e(i), the blinding secret
 * @node: the pubkey of the node to encrypt for
 * @next_node: the pubkey of the next node, to place in enctlv
 * @next_scid: the short_channel_id to the next node, to place in enctlv
 * @padlen: if non-zero, the bytes of padding to add (also adds 2 byte padding hdr)
 * @next_blinding_override: the optional blinding point to place in enctlv
 * @payment_relay: optional payment_relay tlv
 * @payment_constraints: optional payment_constraints tlv
 * @allowed_features: optional allowed_features array
 * @next_blinding: (out) e(i+1), the next blinding secret.
 * @node_alias: (out) the blinded pubkey of the node to tell the recipient.
 *
 * Exactly one of next_node and next_scid must be non-NULL.
 * Returns the enctlv blob, or NULL if the secret is invalid.
 */
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
	NON_NULL_ARGS(2, 3, 11, 12);

/**
 * create_final_enctlv - Encrypt an encmsg to form the final enctlv.
 * @ctx: tal context
 * @blinding: e(i), the blinding secret
 * @final_node: the pubkey of the node to encrypt for
 * @padlen: if non-zero, the bytes of padding to add (also adds 2 byte padding hdr)
 * @allowed_features: optional allowed_features array
 * @path_id: secret to include in enctlv, if not NULL.
 * @node_alias: (out) the blinded pubkey of the node to tell the recipient.
 *
 * If it fails, it means one of the privkeys is bad.
 */
u8 *create_final_enctlv(const tal_t *ctx,
			const struct privkey *blinding,
			const struct pubkey *final_node,
			size_t padlen,
			const struct secret *path_id,
			const u8 *allowed_features TAKES,
			struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 7);

/**
 * unblind_onion - tweak onion epheremeral key so we can decode it with ours.
 * @blinding: E(i), the blinding pubkey the previous peer gave us.
 * @ecdh: the ecdh routine (usually ecdh from common/ecdh_hsmd).
 * @onion_key: (in, out) the onionpacket->ephemeralkey to tweak.
 * @ss: (out) the shared secret we gained from blinding pubkey.
 *
 * The shared secret is needed to decrypt the enctlv we expect to find, too.
 */
bool unblind_onion(const struct pubkey *blinding,
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
 * @blinding: E(i), the blinding pubkey the previous peer gave us.
 * @ss: the blinding secret from unblind_onion().
 * @enctlv: the enctlv from the onion (tal, may be NULL).
 *
 * Returns NULL if decryption failed or encmsg was malformed.
 */
struct tlv_encrypted_data_tlv *decrypt_encrypted_data(const tal_t *ctx,
						      const struct pubkey *blinding,
						      const struct secret *ss,
						      const u8 *enctlv)
	NON_NULL_ARGS(2, 3);

/**
 * blindedpath_next_blinding - Calculate or extract next blinding pubkey
 */
void blindedpath_next_blinding(const struct tlv_encrypted_data_tlv *enc,
			       const struct pubkey *blinding,
			       const struct secret *ss,
			       struct pubkey *next_blinding);

#endif /* LIGHTNING_COMMON_BLINDEDPATH_H */
