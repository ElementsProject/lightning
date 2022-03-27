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

/**
 * create_enctlv - Encrypt an encmsg to form an enctlv.
 * @ctx: tal context
 * @blinding: e(i), the blinding secret
 * @node: the pubkey of the node to encrypt for
 * @next_node: the pubkey of the next node, to place in enctlv
 * @padlen: if non-zero, the bytes of padding to add (also adds 2 byte padding hdr)
 * @next_blinding_override: the optional blinding point to place in enctlv
 * @next_blinding: (out) e(i+1), the next blinding secret.
 * @node_alias: (out) the blinded pubkey of the node to tell the recipient.
 *
 * Returns the enctlv blob, or NULL if the secret is invalid.
 */
u8 *create_enctlv(const tal_t *ctx,
		  const struct privkey *blinding,
		  const struct pubkey *node,
		  const struct pubkey *next_node,
		  size_t padlen,
		  const struct pubkey *next_blinding_override,
		  struct privkey *next_blinding,
		  struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 4, 7, 8);

/**
 * create_final_enctlv - Encrypt an encmsg to form the final enctlv.
 * @ctx: tal context
 * @blinding: e(i), the blinding secret
 * @final_node: the pubkey of the node to encrypt for
 * @padlen: if non-zero, the bytes of padding to add (also adds 2 byte padding hdr)
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
			struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 6);

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
 * decrypt_enctlv - Decrypt an encmsg to form an enctlv.
 * @blinding: E(i), the blinding pubkey the previous peer gave us.
 * @ss: the blinding secret from unblind_onion().
 * @enctlv: the enctlv from the onion (tal, may be NULL).
 * @next_node: (out) the next node_id.
 * @next_blinding: (out) the next blinding E(i+1).
 *
 * Returns false if decryption failed or encmsg was malformed.
 */
bool decrypt_enctlv(const struct pubkey *blinding,
		    const struct secret *ss,
		    const u8 *enctlv,
		    struct pubkey *next_node,
		    struct pubkey *next_blinding)
	NON_NULL_ARGS(1, 2, 4, 5);

/**
 * decrypt_final_enctlv - Decrypt an encmsg to form an enctlv.
 * @ctx: tal context for @path_id
 * @blinding: E(i), the blinding pubkey the previous peer gave us.
 * @ss: the blinding secret from unblind_onion().
 * @enctlv: the enctlv from the onion (tal, may be NULL).
 * @my_id: the pubkey of this node.
 * @alias: (out) the node_id this was addressed to.
 * @path_id: (out) the secret contained in the enctlv, if any (NULL if invalid or unset)
 *
 * Returns false if decryption failed or encmsg was malformed.
 */
bool decrypt_final_enctlv(const tal_t *ctx,
			  const struct pubkey *blinding,
			  const struct secret *ss,
			  const u8 *enctlv,
			  const struct pubkey *my_id,
			  struct pubkey *alias,
			  struct secret **path_id)
	NON_NULL_ARGS(1, 2, 4, 5);

/* Obsolete variants */
u8 *create_obs2_enctlv(const tal_t *ctx,
		       const struct privkey *blinding,
		       const struct pubkey *node,
		       const struct pubkey *next_node,
		       size_t padlen,
		       const struct pubkey *override_blinding,
		       struct privkey *next_blinding,
		       struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 4, 7, 8);
u8 *create_obs2_final_enctlv(const tal_t *ctx,
			     const struct privkey *blinding,
			     const struct pubkey *final_node,
			     size_t padlen,
			     const struct secret *self_id,
			     struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 6);
bool decrypt_obs2_enctlv(const struct pubkey *blinding,
			 const struct secret *ss,
			 const u8 *enctlv,
			 struct pubkey *next_node,
			 struct pubkey *next_blinding)
	NON_NULL_ARGS(1, 2, 4, 5);
bool decrypt_obs2_final_enctlv(const tal_t *ctx,
			       const struct pubkey *blinding,
			       const struct secret *ss,
			       const u8 *enctlv,
			       const struct pubkey *my_id,
			       struct pubkey *alias,
			       struct secret **self_id)
	NON_NULL_ARGS(1, 2, 4, 5);

#endif /* LIGHTNING_COMMON_BLINDEDPATH_H */
