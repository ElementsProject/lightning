#ifndef LIGHTNING_COMMON_BOLT12_ID_H
#define LIGHTNING_COMMON_BOLT12_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct secret;
struct sha256;

/* String to use with makesecret to get the bolt12 base secret */
#define BOLT12_ID_BASE_STRING "bolt12-invoice-base"

/* String to use with makesecret to get node aliases */
#define NODE_ALIAS_BASE_STRING "node-alias-base"

/**
 * bolt12_path_secret: generate the "path_" field for the tlv_encrypted_data_tlv
 * @base_secret: the node-specific secret makesecret(BOLT12_ID_BASE_STRING)
 * @payment_hash: the invoice payment hash
 * @path_secret: the path_secret to populate.
 *
 * Receiving a blinded, encrypted tlv_encrypted_data_tlv containing
 * the correct path_id is how we know this blinded path is the correct
 * one for this invoice payment.
 *
 * It's exposed here as plugins may want to generate blinded paths.
 */
void bolt12_path_secret(const struct secret *base_secret,
			const struct sha256 *payment_hash,
			struct secret *path_secret);

/* This variant gives the result as a u8 talarr, as expected by
 * the tlv interface */
u8 *bolt12_path_id(const tal_t *ctx,
		   const struct secret *base_secret,
		   const struct sha256 *payment_hash);

/**
 * bolt12_alias_tweak: generate a tweak to disguise our node id for this offer/invoice_request
 * @base_secret: the node-specific secret makesecret(NODE_ALIAS_BASE_STRING)
 * @input: the byte array to use to generate the tweak.
 * @input_len: the length of @input.
 * @tweak: the resulting tweak.
 *
 * We use this tweak to disguise our node_id when we want a temporary id for a specific
 * purpose.  The "input" can be shared publicly, as the base_secret prevents
 * others from linking the tweak (or the resulting pubkey) to us.
 */
void bolt12_alias_tweak(const struct secret *base_secret,
			const void *input,
			size_t input_len,
			struct sha256 *tweak);

#endif /* LIGHTNING_COMMON_BOLT12_ID_H */
