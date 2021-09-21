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

/* Fills in *initial_blinding and *final_blinding and returns
 * onionmsg_path array for this route */
struct onionmsg_path **make_blindedpath(const tal_t *ctx,
					const struct pubkey *route,
					struct pubkey *initial_blinding,
					struct pubkey *final_blinding);

/**
 * create_enctlv - Encrypt an encmsg to form an enctlv.
 * @ctx: tal context
 * @blinding: e(i), the blinding secret
 * @node: the pubkey of the node to encrypt for
 * @next_node: the pubkey of the next node, to place in enctlv
 * @padlen: if non-zero, the bytes of padding to add (also adds 2 byte padding hdr)
 * @override_blinding: the optional blinding point to place in enctlv
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
		  const struct pubkey *override_blinding,
		  struct privkey *next_blinding,
		  struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 4, 7, 8);

/**
 * create_final_enctlv - Encrypt an encmsg to form the final enctlv.
 * @ctx: tal context
 * @blinding: e(i), the blinding secret
 * @final_node: the pubkey of the node to encrypt for
 * @padlen: if non-zero, the bytes of padding to add (also adds 2 byte padding hdr)
 * @self_id: secret to include in enctlv, if not NULL.
 * @node_alias: (out) the blinded pubkey of the node to tell the recipient.
 *
 * If it fails, it means one of the privkeys is bad.
 */
u8 *create_final_enctlv(const tal_t *ctx,
			const struct privkey *blinding,
			const struct pubkey *final_node,
			size_t padlen,
			const struct secret *self_id,
			struct pubkey *node_alias)
	NON_NULL_ARGS(2, 3, 6);

#endif /* LIGHTNING_COMMON_BLINDEDPATH_H */
