#ifndef LIGHTNING_COMMON_INVOICE_PATH_ID_H
#define LIGHTNING_COMMON_INVOICE_PATH_ID_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

struct secret;
struct sha256;

/* String to use with makesecret to get the invoice base secret */
#define INVOICE_PATH_BASE_STRING "bolt12-invoice-base"

/**
 * invoice_path_id: generate the "path_id" field for the tlv_encrypted_data_tlv
 * @ctx: tal context
 * @payment_hash: the invoice payment hash
 * @base_secret: the node-specific secret makesecret("bolt12-invoice-base")
 *
 * Receiving a blinded, encrypted tlv_encrypted_data_tlv containing
 * the correct path_id is how we know this blinded path is the correct
 * one for this invoice payment.
 *
 * It's exposed here as plugins may want to generate blinded paths.
 */
u8 *invoice_path_id(const tal_t *ctx,
		    const struct secret *base_secret,
		    const struct sha256 *payment_hash);

#endif /* LIGHTNING_COMMON_INVOICE_PATH_ID_H */
