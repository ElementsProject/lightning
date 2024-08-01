#ifndef LIGHTNING_COMMON_BOLT12_ID_H
#define LIGHTNING_COMMON_BOLT12_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct secret;
struct sha256;

/* String to use with makesecret to get the bolt12 base secret */
#define BOLT12_ID_BASE_STRING "bolt12-invoice-base"

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

#endif /* LIGHTNING_COMMON_BOLT12_ID_H */
