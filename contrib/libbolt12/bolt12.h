/* libbolt12 - Standalone BOLT12 offer/invoice decode and verification library.
 *
 * Built on top of Core Lightning's bolt12 implementation.
 * Provides a clean C API with no CLN internal types exposed.
 *
 * Usage:
 *   #include "bolt12.h"
 *   if (bolt12_init() != 0) { ... }
 *   int rc = bolt12_verify_offer_payment(offer_str, invoice_str, preimage_hex, &err);
 *   bolt12_cleanup();
 *
 * Link against libbolt12.a + libcommon.a + libccan.a + -lsecp256k1
 * -lsodium -lwallycore -lm (or use the bundled libbolt12-fat.a which
 * combines the three CLN archives).
 *
 * THREAD-SAFETY: libbolt12 is NOT thread-safe. It uses process-global
 * state (secp256k1 context, tal temporary context). Serialize calls
 * from a single thread, or protect with an external mutex.
 *
 * SPDX-License-Identifier: BSD-MIT
 */
#ifndef LIGHTNING_CONTRIB_LIBBOLT12_BOLT12_H
#define LIGHTNING_CONTRIB_LIBBOLT12_BOLT12_H
#include "config.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Opaque types --- */
typedef struct bolt12_offer bolt12_offer_t;
typedef struct bolt12_invoice bolt12_invoice_t;

/* --- Error handling --- */
typedef struct {
	int code;		/* 0 = success, non-zero = error category */
	char message[512];	/* Human-readable error description */
} bolt12_error_t;

/* Error codes */
#define BOLT12_OK		0
#define BOLT12_ERR_DECODE	1  /* Failed to decode offer/invoice */
#define BOLT12_ERR_SIGNATURE	2  /* Signature verification failed */
#define BOLT12_ERR_MISMATCH	3  /* Offer/invoice fields don't match */
#define BOLT12_ERR_PREIMAGE	4  /* Proof of payment failed */
#define BOLT12_ERR_INIT		5  /* Library not initialized */
#define BOLT12_ERR_MISSING	6  /* Required field missing */

/* --- Fixed-size public types --- */
typedef struct { uint8_t data[32]; } bolt12_sha256_t;
typedef struct { uint8_t data[33]; } bolt12_pubkey_t;	 /* compressed secp256k1 */
typedef struct { uint8_t data[64]; } bolt12_signature_t; /* BIP-340 schnorr */

/* --- Library lifecycle --- */

/**
 * bolt12_init - Initialize the library.
 *
 * Must be called once before any other function.
 * Initializes libsecp256k1, libsodium, and libwally contexts.
 *
 * Returns 0 on success, -1 on failure.
 */
int bolt12_init(void);

/**
 * bolt12_cleanup - Release library resources.
 *
 * Call when done with the library. After this, no other
 * libbolt12 functions may be called (except bolt12_init again).
 */
void bolt12_cleanup(void);

/* --- Decode --- */

/**
 * bolt12_offer_decode - Decode a BOLT12 offer from "lno1..." bech32 string.
 *
 * @offer_str: the offer string (NUL-terminated).
 * @err: if non-NULL and decode fails, populated with error details.
 *
 * Returns opaque offer handle, or NULL on failure.
 * Caller must free with bolt12_offer_free().
 */
bolt12_offer_t *bolt12_offer_decode(const char *offer_str,
				    bolt12_error_t *err);

/**
 * bolt12_offer_free - Free a decoded offer.
 */
void bolt12_offer_free(bolt12_offer_t *offer);

/**
 * bolt12_invoice_decode - Decode a BOLT12 invoice from "lni1..." bech32 string.
 *
 * @invoice_str: the invoice string (NUL-terminated).
 * @err: if non-NULL and decode fails, populated with error details.
 *
 * Returns opaque invoice handle, or NULL on failure.
 * Caller must free with bolt12_invoice_free().
 *
 * Note: this performs structural validation and signature verification
 * as per BOLT #12.
 */
bolt12_invoice_t *bolt12_invoice_decode(const char *invoice_str,
					bolt12_error_t *err);

/**
 * bolt12_invoice_free - Free a decoded invoice.
 */
void bolt12_invoice_free(bolt12_invoice_t *invoice);

/* --- Accessors: Offer --- */

/**
 * bolt12_offer_id - Compute the offer_id (SHA256 of offer TLV fields).
 *
 * Returns 0 on success, -1 on failure.
 */
int bolt12_offer_id(const bolt12_offer_t *offer, bolt12_sha256_t *id);

/**
 * bolt12_offer_issuer_signing_pubkey - Get the explicit issuer_signing_pubkey.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_offer_issuer_signing_pubkey(const bolt12_offer_t *offer,
				       bolt12_pubkey_t *pubkey);

/**
 * bolt12_offer_path_signing_pubkey - Get signing pubkey from blinded paths.
 *
 * Falls back to the last hop's blinded_node_id of the first path.
 * Returns 0 on success, -1 if no paths or empty paths.
 */
int bolt12_offer_path_signing_pubkey(const bolt12_offer_t *offer,
				     bolt12_pubkey_t *pubkey);

/**
 * bolt12_offer_effective_signing_pubkey - Get the "best" signing pubkey.
 *
 * Returns issuer_signing_pubkey if present, otherwise path_signing_pubkey.
 * Returns 0 on success, -1 if neither is available.
 */
int bolt12_offer_effective_signing_pubkey(const bolt12_offer_t *offer,
					  bolt12_pubkey_t *pubkey);

/**
 * bolt12_offer_description - Get the offer description string.
 *
 * @offer: decoded offer.
 * @out: buffer to write the NUL-terminated description into.
 * @out_len: size of @out buffer.
 *
 * Returns the length of the description (excluding NUL), or -1 if not present.
 * If the description is longer than out_len-1, it is truncated.
 */
int bolt12_offer_description(const bolt12_offer_t *offer,
			     char *out, size_t out_len);

/**
 * bolt12_offer_issuer - Get the offer issuer string.
 *
 * Returns the length of the issuer string (excluding NUL), or -1 if not present.
 */
int bolt12_offer_issuer(const bolt12_offer_t *offer,
			char *out, size_t out_len);

/**
 * bolt12_offer_amount_msat - Get the offer amount in millisatoshi.
 *
 * @offer: decoded offer.
 * @amount_msat: output. Set to the amount if present.
 *
 * Returns 0 on success, -1 if no amount is set.
 * Note: if offer_currency is set, this is in that currency's minor unit,
 * not millisatoshi.
 */
int bolt12_offer_amount(const bolt12_offer_t *offer, uint64_t *amount);

/**
 * bolt12_offer_currency - Get the offer currency (e.g. "USD").
 *
 * Returns the length of the currency string (excluding NUL), or -1 if not present.
 * If not present, the amount is in millisatoshi.
 */
int bolt12_offer_currency(const bolt12_offer_t *offer,
			  char *out, size_t out_len);

/**
 * bolt12_offer_absolute_expiry - Get the absolute expiry timestamp.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_offer_absolute_expiry(const bolt12_offer_t *offer,
				 uint64_t *expiry);

/**
 * bolt12_offer_quantity_max - Get the maximum quantity allowed.
 *
 * Returns 0 on success, -1 if not present (no quantity limit).
 */
int bolt12_offer_quantity_max(const bolt12_offer_t *offer,
			      uint64_t *quantity_max);

/**
 * bolt12_offer_chains - Get the chain hashes the offer is valid for.
 *
 * @offer: decoded offer.
 * @chains: output array of 32-byte chain hashes.
 * @max_chains: maximum number of chains to write.
 *
 * Returns the number of chains written, or -1 on error.
 * Returns 0 if no chains are specified (implies bitcoin only).
 */
int bolt12_offer_chains(const bolt12_offer_t *offer,
			bolt12_sha256_t *chains, size_t max_chains);

/**
 * bolt12_offer_num_paths - Get the number of blinded paths in the offer.
 *
 * Returns the count, or 0 if no paths.
 */
size_t bolt12_offer_num_paths(const bolt12_offer_t *offer);

/* --- Accessors: Invoice --- */

/**
 * bolt12_invoice_signing_pubkey - Get the invoice's node_id (signing pubkey).
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_signing_pubkey(const bolt12_invoice_t *invoice,
				  bolt12_pubkey_t *pubkey);

/**
 * bolt12_invoice_offer_id - Get the offer_id embedded in the invoice.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_offer_id(const bolt12_invoice_t *invoice,
			    bolt12_sha256_t *id);

/**
 * bolt12_invoice_payment_hash - Get the payment hash.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_payment_hash(const bolt12_invoice_t *invoice,
				bolt12_sha256_t *hash);

/**
 * bolt12_invoice_amount_msat - Get the invoice amount in millisatoshi.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_amount(const bolt12_invoice_t *invoice, uint64_t *amount);

/**
 * bolt12_invoice_description - Get the invoice description (inherited from offer).
 *
 * Returns the length of the description (excluding NUL), or -1 if not present.
 */
int bolt12_invoice_description(const bolt12_invoice_t *invoice,
			       char *out, size_t out_len);

/**
 * bolt12_invoice_created_at - Get the invoice creation timestamp.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_created_at(const bolt12_invoice_t *invoice,
			      uint64_t *created_at);

/**
 * bolt12_invoice_expiry - Get the absolute expiry timestamp.
 *
 * Combines invoice_created_at + invoice_relative_expiry (default 7200s).
 * Returns UINT64_MAX if it would overflow.
 * Returns 0 on success, -1 if invoice_created_at is not present.
 */
int bolt12_invoice_expiry(const bolt12_invoice_t *invoice,
			  uint64_t *expiry);

/**
 * bolt12_invoice_signature - Get the invoice BIP-340 signature.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_signature(const bolt12_invoice_t *invoice,
			     bolt12_signature_t *sig);

/**
 * bolt12_invoice_payer_note - Get the payer's note (if present).
 *
 * Returns the length of the note (excluding NUL), or -1 if not present.
 */
int bolt12_invoice_payer_note(const bolt12_invoice_t *invoice,
			      char *out, size_t out_len);

/**
 * bolt12_invoice_quantity - Get the quantity requested.
 *
 * Returns 0 on success, -1 if not present.
 */
int bolt12_invoice_quantity(const bolt12_invoice_t *invoice,
			    uint64_t *quantity);

/**
 * bolt12_invoice_num_paths - Get the number of blinded payment paths.
 *
 * Returns the count, or 0 if no paths.
 */
size_t bolt12_invoice_num_paths(const bolt12_invoice_t *invoice);

/**
 * bolt12_invoice_features - Get the raw feature bits.
 *
 * @invoice: decoded invoice.
 * @out: buffer to write the feature bytes into.
 * @out_len: size of @out buffer.
 *
 * Returns the number of feature bytes written, or -1 if not present.
 */
int bolt12_invoice_features(const bolt12_invoice_t *invoice,
			    uint8_t *out, size_t out_len);

/* --- Verification --- */

/**
 * bolt12_verify_invoice_signature - Verify the invoice's Schnorr signature.
 *
 * Verifies the BIP-340 signature over the merkle root of the invoice TLV,
 * using the invoice_node_id as the public key.
 *
 * Returns 0 if valid, -1 on failure (err set if non-NULL).
 */
int bolt12_verify_invoice_signature(const bolt12_invoice_t *invoice,
				    bolt12_error_t *err);

/**
 * bolt12_verify_proof_of_payment - Verify that SHA256(preimage) == payment_hash.
 *
 * @invoice: decoded invoice.
 * @preimage_hex: 64-character hex string (32 bytes).
 * @err: populated on failure if non-NULL.
 *
 * Returns 0 if valid, -1 on failure.
 */
int bolt12_verify_proof_of_payment(const bolt12_invoice_t *invoice,
				   const char *preimage_hex,
				   bolt12_error_t *err);

/**
 * bolt12_compare_offer_id - Check that offer and invoice share the same offer_id.
 *
 * Returns 0 if they match, -1 if they don't (err set if non-NULL).
 */
int bolt12_compare_offer_id(const bolt12_offer_t *offer,
			    const bolt12_invoice_t *invoice,
			    bolt12_error_t *err);

/**
 * bolt12_compare_signing_pubkeys - Check that signing pubkeys match.
 *
 * Compares the offer's effective signing pubkey with the invoice's
 * signing pubkey (invoice_node_id).
 *
 * Returns 0 if they match, -1 if they don't (err set if non-NULL).
 */
int bolt12_compare_signing_pubkeys(const bolt12_offer_t *offer,
				   const bolt12_invoice_t *invoice,
				   bolt12_error_t *err);

/* --- Convenience: Full verification --- */

/**
 * bolt12_verify_offer_payment - All-in-one offer payment verification.
 *
 * Performs the complete verification pipeline:
 *   1. Decode offer and invoice
 *   2. Compare signing pubkeys
 *   3. Compare offer_ids
 *   4. Verify invoice signature
 *   5. Verify proof of payment (preimage)
 *
 * @offer_str: "lno1..." offer string.
 * @invoice_str: "lni1..." invoice string.
 * @preimage_hex: 64-char hex preimage string.
 * @err: populated on first failure if non-NULL.
 *
 * Returns 0 if everything checks out, -1 on first failure.
 */
int bolt12_verify_offer_payment(const char *offer_str,
				const char *invoice_str,
				const char *preimage_hex,
				bolt12_error_t *err);

#ifdef __cplusplus
}
#endif

#endif /* LIGHTNING_CONTRIB_LIBBOLT12_BOLT12_H */
