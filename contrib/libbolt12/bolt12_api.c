/* libbolt12 - Public API implementation.
 *
 * Wraps CLN's internal bolt12 functions behind a clean C interface.
 * All CLN/tal types are hidden; the public API uses only standard C types.
 *
 * SPDX-License-Identifier: BSD-MIT
 */
#include "config.h"
#include "contrib/libbolt12/bolt12.h"
#include "contrib/libbolt12/bolt12_internal.h"
#include <bitcoin/pubkey.h>
#include <ccan/crypto/sha256/sha256.h>
#include <ccan/tal/str/str.h>
#include <common/bolt12_merkle.h>
#include <common/utils.h>
#include <secp256k1.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool libbolt12_initialized = false;

/* We declare this here since common/utils.h declares it extern; libbolt12
 * owns the lifetime instead of relying on common_setup()/wally. */
extern secp256k1_context *secp256k1_ctx;

/* --- Library lifecycle --- */

/* Deliberately avoids common_setup():
 *   - common_setup() mutates process-global state (locale, env, progname)
 *     which is surprising in a library context.
 *   - common_setup() calls errx(1, ...) on libsodium/libwally init failures,
 *     which would kill a host application. A library must never do that.
 * We only need secp256k1_ctx (for verify) and tmpctx. That's it. */
int bolt12_init(void)
{
	if (libbolt12_initialized)
		return 0;

	secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	if (!secp256k1_ctx)
		return -1;

	/* setup_tmpctx() asserts if tmpctx is already set, so only
	 * call it on the first init. A later cleanup()/init() cycle
	 * keeps the existing tmpctx (see bolt12_cleanup). */
	if (!tmpctx)
		setup_tmpctx();
	libbolt12_initialized = true;
	return 0;
}

void bolt12_cleanup(void)
{
	if (!libbolt12_initialized)
		return;

	/* Drop any transient allocations but leave tmpctx itself in
	 * place: CLN's convention (enforced by check-tmpctx) is that
	 * tmpctx is process-global and never freed. A subsequent
	 * bolt12_init() is therefore a no-op for tmpctx setup. */
	clean_tmpctx();

	secp256k1_context_destroy(secp256k1_ctx);
	secp256k1_ctx = NULL;

	libbolt12_initialized = false;
}

/* --- Internal helpers --- */

/* Serialize a secp256k1_pubkey to 33-byte compressed form. */
static void pubkey_to_compressed(const struct pubkey *pk, bolt12_pubkey_t *out)
{
	size_t len = 33;
	secp256k1_ec_pubkey_serialize(secp256k1_ctx, out->data, &len,
				      &pk->pubkey,
				      SECP256K1_EC_COMPRESSED);
}

/* Convert a hex character to its value. Returns -1 on invalid input. */
static int hex_val(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

/* Decode a hex string into a byte buffer. Returns false on invalid input. */
static bool hex_decode(const char *hex, size_t hexlen,
		       uint8_t *buf, size_t buflen)
{
	if (hexlen != buflen * 2)
		return false;

	for (size_t i = 0; i < buflen; i++) {
		int hi = hex_val(hex[i * 2]);
		int lo = hex_val(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0)
			return false;
		buf[i] = (hi << 4) | lo;
	}
	return true;
}

/* --- Decode --- */

bolt12_offer_t *bolt12_offer_decode(const char *offer_str,
				    bolt12_error_t *err)
{
	bolt12_offer_t *offer;
	char *fail;

	if (!libbolt12_initialized) {
		set_error(err, BOLT12_ERR_INIT,
			  "Library not initialized. Call bolt12_init() first.");
		return NULL;
	}

	offer = calloc(1, sizeof(*offer));
	if (!offer) {
		set_error(err, BOLT12_ERR_DECODE, "Out of memory");
		return NULL;
	}

	offer->ctx = tal(NULL, char);

	/* Pass NULL for features and chain to skip validation --
	 * we only care about structural decode + field extraction. */
	offer->tlv = offer_decode(offer->ctx, offer_str, strlen(offer_str),
				  NULL, NULL, &fail);
	if (!offer->tlv) {
		set_error(err, BOLT12_ERR_DECODE,
			  "Failed to decode offer: %s", fail);
		tal_free(offer->ctx);
		free(offer);
		return NULL;
	}

	clean_tmpctx();
	return offer;
}

void bolt12_offer_free(bolt12_offer_t *offer)
{
	if (!offer)
		return;
	tal_free(offer->ctx);
	free(offer);
}

bolt12_invoice_t *bolt12_invoice_decode(const char *invoice_str,
					bolt12_error_t *err)
{
	bolt12_invoice_t *invoice;
	char *fail;

	if (!libbolt12_initialized) {
		set_error(err, BOLT12_ERR_INIT,
			  "Library not initialized. Call bolt12_init() first.");
		return NULL;
	}

	invoice = calloc(1, sizeof(*invoice));
	if (!invoice) {
		set_error(err, BOLT12_ERR_DECODE, "Out of memory");
		return NULL;
	}

	invoice->ctx = tal(NULL, char);

	/* Use invoice_decode which does full validation + signature check.
	 * Pass NULL for features/chain to skip those checks. */
	invoice->tlv = invoice_decode(invoice->ctx, invoice_str,
				      strlen(invoice_str),
				      NULL, NULL, &fail);
	if (!invoice->tlv) {
		set_error(err, BOLT12_ERR_DECODE,
			  "Failed to decode invoice: %s", fail);
		tal_free(invoice->ctx);
		free(invoice);
		return NULL;
	}

	clean_tmpctx();
	return invoice;
}

void bolt12_invoice_free(bolt12_invoice_t *invoice)
{
	if (!invoice)
		return;
	tal_free(invoice->ctx);
	free(invoice);
}

/* --- Accessors: Offer --- */

int bolt12_offer_id(const bolt12_offer_t *offer, bolt12_sha256_t *id)
{
	struct sha256 sha;

	if (!offer || !offer->tlv || !id)
		return -1;

	offer_offer_id(offer->tlv, &sha);
	memcpy(id->data, sha.u.u8, 32);

	clean_tmpctx();
	return 0;
}

int bolt12_offer_issuer_signing_pubkey(const bolt12_offer_t *offer,
				       bolt12_pubkey_t *pubkey)
{
	if (!offer || !offer->tlv || !pubkey)
		return -1;

	if (!offer->tlv->offer_issuer_id)
		return -1;

	pubkey_to_compressed(offer->tlv->offer_issuer_id, pubkey);
	return 0;
}

int bolt12_offer_path_signing_pubkey(const bolt12_offer_t *offer,
				     bolt12_pubkey_t *pubkey)
{
	if (!offer || !offer->tlv || !pubkey)
		return -1;

	/* Walk the offer's blinded paths, find the last hop's
	 * blinded_node_id of the first path that has hops. */
	for (size_t i = 0; i < tal_count(offer->tlv->offer_paths); i++) {
		const struct blinded_path *path = offer->tlv->offer_paths[i];
		size_t nhops = tal_count(path->path);

		if (nhops == 0)
			continue;

		/* The last hop's blinded_node_id is used as the
		 * "effective" signing key when no issuer_id is present. */
		pubkey_to_compressed(&path->path[nhops - 1]->blinded_node_id,
				     pubkey);
		return 0;
	}

	return -1;
}

int bolt12_offer_effective_signing_pubkey(const bolt12_offer_t *offer,
					  bolt12_pubkey_t *pubkey)
{
	if (bolt12_offer_issuer_signing_pubkey(offer, pubkey) == 0)
		return 0;
	return bolt12_offer_path_signing_pubkey(offer, pubkey);
}

/* Helper to copy a tal UTF-8 string into a caller-provided buffer. */
static int copy_tal_str(const char *src, char *out, size_t out_len)
{
	size_t len;

	if (!src)
		return -1;

	len = tal_bytelen(src);
	/* tal strings may or may not include a NUL, but UTF-8 fields
	 * from the wire are raw bytes without NUL. */
	if (out && out_len > 0) {
		size_t copy = len < out_len - 1 ? len : out_len - 1;
		memcpy(out, src, copy);
		out[copy] = '\0';
	}
	return (int)len;
}

int bolt12_offer_description(const bolt12_offer_t *offer,
			     char *out, size_t out_len)
{
	if (!offer || !offer->tlv)
		return -1;
	return copy_tal_str(offer->tlv->offer_description, out, out_len);
}

int bolt12_offer_issuer(const bolt12_offer_t *offer,
			char *out, size_t out_len)
{
	if (!offer || !offer->tlv)
		return -1;
	return copy_tal_str(offer->tlv->offer_issuer, out, out_len);
}

int bolt12_offer_amount(const bolt12_offer_t *offer, uint64_t *amount)
{
	if (!offer || !offer->tlv || !amount)
		return -1;
	if (!offer->tlv->offer_amount)
		return -1;
	*amount = *offer->tlv->offer_amount;
	return 0;
}

int bolt12_offer_currency(const bolt12_offer_t *offer,
			  char *out, size_t out_len)
{
	if (!offer || !offer->tlv)
		return -1;
	return copy_tal_str(offer->tlv->offer_currency, out, out_len);
}

int bolt12_offer_absolute_expiry(const bolt12_offer_t *offer,
				 uint64_t *expiry)
{
	if (!offer || !offer->tlv || !expiry)
		return -1;
	if (!offer->tlv->offer_absolute_expiry)
		return -1;
	*expiry = *offer->tlv->offer_absolute_expiry;
	return 0;
}

int bolt12_offer_quantity_max(const bolt12_offer_t *offer,
			      uint64_t *quantity_max)
{
	if (!offer || !offer->tlv || !quantity_max)
		return -1;
	if (!offer->tlv->offer_quantity_max)
		return -1;
	*quantity_max = *offer->tlv->offer_quantity_max;
	return 0;
}

int bolt12_offer_chains(const bolt12_offer_t *offer,
			bolt12_sha256_t *chains, size_t max_chains)
{
	size_t n;

	if (!offer || !offer->tlv)
		return -1;
	if (!offer->tlv->offer_chains)
		return 0; /* No chains = bitcoin only */

	n = tal_count(offer->tlv->offer_chains);
	if (n > max_chains)
		n = max_chains;

	/* FIXME: reaches into struct bitcoin_blkid layout. If CLN adds a
	 * stable bitcoin_blkid_to_bytes() helper we should use it instead. */
	for (size_t i = 0; i < n; i++)
		memcpy(chains[i].data,
		       offer->tlv->offer_chains[i].shad.sha.u.u8, 32);
	return (int)n;
}

size_t bolt12_offer_num_paths(const bolt12_offer_t *offer)
{
	if (!offer || !offer->tlv || !offer->tlv->offer_paths)
		return 0;
	return tal_count(offer->tlv->offer_paths);
}

/* --- Accessors: Invoice --- */

int bolt12_invoice_signing_pubkey(const bolt12_invoice_t *invoice,
				  bolt12_pubkey_t *pubkey)
{
	if (!invoice || !invoice->tlv || !pubkey)
		return -1;

	if (!invoice->tlv->invoice_node_id)
		return -1;

	pubkey_to_compressed(invoice->tlv->invoice_node_id, pubkey);
	return 0;
}

int bolt12_invoice_offer_id(const bolt12_invoice_t *invoice,
			    bolt12_sha256_t *id)
{
	struct sha256 sha;

	if (!invoice || !invoice->tlv || !id)
		return -1;

	/* The invoice contains the offer fields; compute offer_id
	 * from them the same way CLN does. */
	invoice_offer_id(invoice->tlv, &sha);
	memcpy(id->data, sha.u.u8, 32);

	clean_tmpctx();
	return 0;
}

int bolt12_invoice_payment_hash(const bolt12_invoice_t *invoice,
				bolt12_sha256_t *hash)
{
	if (!invoice || !invoice->tlv || !hash)
		return -1;

	if (!invoice->tlv->invoice_payment_hash)
		return -1;

	memcpy(hash->data, invoice->tlv->invoice_payment_hash->u.u8, 32);
	return 0;
}

int bolt12_invoice_amount(const bolt12_invoice_t *invoice, uint64_t *amount)
{
	if (!invoice || !invoice->tlv || !amount)
		return -1;
	if (!invoice->tlv->invoice_amount)
		return -1;
	*amount = *invoice->tlv->invoice_amount;
	return 0;
}

int bolt12_invoice_description(const bolt12_invoice_t *invoice,
			       char *out, size_t out_len)
{
	if (!invoice || !invoice->tlv)
		return -1;
	return copy_tal_str(invoice->tlv->offer_description, out, out_len);
}

int bolt12_invoice_created_at(const bolt12_invoice_t *invoice,
			      uint64_t *created_at)
{
	if (!invoice || !invoice->tlv || !created_at)
		return -1;
	if (!invoice->tlv->invoice_created_at)
		return -1;
	*created_at = *invoice->tlv->invoice_created_at;
	return 0;
}

int bolt12_invoice_expiry(const bolt12_invoice_t *invoice, uint64_t *expiry)
{
	if (!invoice || !invoice->tlv || !expiry)
		return -1;
	/* Reuse CLN's invoice_expiry() which handles
	 * relative_expiry and overflow correctly. */
	*expiry = invoice_expiry(invoice->tlv);
	return 0;
}

int bolt12_invoice_signature(const bolt12_invoice_t *invoice,
			     bolt12_signature_t *sig)
{
	if (!invoice || !invoice->tlv || !sig)
		return -1;
	if (!invoice->tlv->signature)
		return -1;
	memcpy(sig->data, invoice->tlv->signature->u8, 64);
	return 0;
}

int bolt12_invoice_payer_note(const bolt12_invoice_t *invoice,
			      char *out, size_t out_len)
{
	if (!invoice || !invoice->tlv)
		return -1;
	return copy_tal_str(invoice->tlv->invreq_payer_note, out, out_len);
}

int bolt12_invoice_quantity(const bolt12_invoice_t *invoice,
			    uint64_t *quantity)
{
	if (!invoice || !invoice->tlv || !quantity)
		return -1;
	if (!invoice->tlv->invreq_quantity)
		return -1;
	*quantity = *invoice->tlv->invreq_quantity;
	return 0;
}

size_t bolt12_invoice_num_paths(const bolt12_invoice_t *invoice)
{
	if (!invoice || !invoice->tlv || !invoice->tlv->invoice_paths)
		return 0;
	return tal_count(invoice->tlv->invoice_paths);
}

int bolt12_invoice_features(const bolt12_invoice_t *invoice,
			    uint8_t *out, size_t out_len)
{
	size_t len;

	if (!invoice || !invoice->tlv)
		return -1;
	if (!invoice->tlv->invoice_features)
		return -1;

	len = tal_bytelen(invoice->tlv->invoice_features);
	if (len > out_len)
		len = out_len;
	if (out && len > 0)
		memcpy(out, invoice->tlv->invoice_features, len);
	return (int)len;
}

/* --- Verification --- */

int bolt12_verify_invoice_signature(const bolt12_invoice_t *invoice,
				    bolt12_error_t *err)
{
	if (!invoice || !invoice->tlv) {
		set_error(err, BOLT12_ERR_MISSING, "No invoice provided");
		return -1;
	}

	if (!invoice->tlv->invoice_node_id) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Invoice missing invoice_node_id");
		return -1;
	}

	if (!invoice->tlv->signature) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Invoice missing signature");
		return -1;
	}

	if (!bolt12_check_signature(invoice->tlv->fields,
				    "invoice", "signature",
				    invoice->tlv->invoice_node_id,
				    invoice->tlv->signature)) {
		set_error(err, BOLT12_ERR_SIGNATURE,
			  "Invoice signature verification failed");
		return -1;
	}

	return 0;
}

int bolt12_verify_proof_of_payment(const bolt12_invoice_t *invoice,
				   const char *preimage_hex,
				   bolt12_error_t *err)
{
	uint8_t preimage[32];
	struct sha256 computed_hash;
	size_t hexlen;

	if (!invoice || !invoice->tlv) {
		set_error(err, BOLT12_ERR_MISSING, "No invoice provided");
		return -1;
	}

	if (!invoice->tlv->invoice_payment_hash) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Invoice missing payment_hash");
		return -1;
	}

	if (!preimage_hex) {
		set_error(err, BOLT12_ERR_PREIMAGE, "No preimage provided");
		return -1;
	}

	hexlen = strlen(preimage_hex);
	if (!hex_decode(preimage_hex, hexlen, preimage, sizeof(preimage))) {
		set_error(err, BOLT12_ERR_PREIMAGE,
			  "Invalid preimage: must be 64 hex chars (32 bytes), "
			  "got %zu chars", hexlen);
		return -1;
	}

	/* SHA256(preimage) should equal the invoice payment_hash */
	sha256(&computed_hash, preimage, sizeof(preimage));

	if (memcmp(computed_hash.u.u8,
		   invoice->tlv->invoice_payment_hash->u.u8, 32) != 0) {
		set_error(err, BOLT12_ERR_PREIMAGE,
			  "Proof of payment failed: SHA256(preimage) does not "
			  "match invoice payment_hash");
		return -1;
	}

	return 0;
}

int bolt12_compare_offer_id(const bolt12_offer_t *offer,
			    const bolt12_invoice_t *invoice,
			    bolt12_error_t *err)
{
	bolt12_sha256_t offer_id, invoice_oid;

	if (bolt12_offer_id(offer, &offer_id) != 0) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Failed to compute offer_id from offer");
		return -1;
	}

	if (bolt12_invoice_offer_id(invoice, &invoice_oid) != 0) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Invoice does not contain offer fields");
		return -1;
	}

	if (memcmp(offer_id.data, invoice_oid.data, 32) != 0) {
		set_error(err, BOLT12_ERR_MISMATCH,
			  "Offer ID and invoice offer ID do not match");
		return -1;
	}

	return 0;
}

int bolt12_compare_signing_pubkeys(const bolt12_offer_t *offer,
				   const bolt12_invoice_t *invoice,
				   bolt12_error_t *err)
{
	bolt12_pubkey_t offer_pk, invoice_pk;

	if (bolt12_offer_effective_signing_pubkey(offer, &offer_pk) != 0) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Offer has no signing pubkey (no issuer_id or paths)");
		return -1;
	}

	if (bolt12_invoice_signing_pubkey(invoice, &invoice_pk) != 0) {
		set_error(err, BOLT12_ERR_MISSING,
			  "Invoice missing invoice_node_id");
		return -1;
	}

	if (memcmp(offer_pk.data, invoice_pk.data, 33) != 0) {
		set_error(err, BOLT12_ERR_MISMATCH,
			  "Offer and invoice signing pubkeys do not match");
		return -1;
	}

	return 0;
}

/* --- Convenience: Full verification --- */

int bolt12_verify_offer_payment(const char *offer_str,
				const char *invoice_str,
				const char *preimage_hex,
				bolt12_error_t *err)
{
	bolt12_offer_t *offer = NULL;
	bolt12_invoice_t *invoice = NULL;
	int rc = -1;

	offer = bolt12_offer_decode(offer_str, err);
	if (!offer)
		goto out;

	invoice = bolt12_invoice_decode(invoice_str, err);
	if (!invoice)
		goto out;

	/* Step 1: Compare signing pubkeys */
	if (bolt12_compare_signing_pubkeys(offer, invoice, err) != 0)
		goto out;

	/* Step 2: Compare offer_ids */
	if (bolt12_compare_offer_id(offer, invoice, err) != 0)
		goto out;

	/* Step 3: Verify invoice signature (redundant since invoice_decode
	 * already checks this, but included for completeness) */
	if (bolt12_verify_invoice_signature(invoice, err) != 0)
		goto out;

	/* Step 4: Verify proof of payment */
	if (bolt12_verify_proof_of_payment(invoice, preimage_hex, err) != 0)
		goto out;

	rc = 0;

out:
	bolt12_invoice_free(invoice);
	bolt12_offer_free(offer);
	return rc;
}
