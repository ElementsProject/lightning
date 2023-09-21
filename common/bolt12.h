#ifndef LIGHTNING_COMMON_BOLT12_H
#define LIGHTNING_COMMON_BOLT12_H
#include "config.h"
#include <wire/bolt12_wiregen.h>

struct feature_set;

/* BOLT-offers #12:
 * - if `invoice_relative_expiry` is present:
 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
 *     is greater than `invoice_created_at` plus `seconds_from_creation`.
 *  - otherwise:
 *    - MUST reject the invoice if the current time since 1970-01-01 UTC
 *      is greater than `invoice_created_at` plus 7200.
 */
#define BOLT12_DEFAULT_REL_EXPIRY 7200

/**
 * offer_encode - encode this complete bolt12 offer TLV into text.
 */
char *offer_encode(const tal_t *ctx, const struct tlv_offer *bolt12_tlv);

/**
 * offer_decode - decode this complete bolt12 text into a TLV.
 * @ctx: the context to allocate return or *@fail off.
 * @b12: the offer string
 * @b12len: the offer string length
 * @our_features: if non-NULL, feature set to check against.
 * @must_be_chain: if non-NULL, chain to enforce.
 * @fail: pointer to descriptive error string, set if this returns NULL.
 */
struct tlv_offer *offer_decode(const tal_t *ctx, const char *b12, size_t b12len,
			       const struct feature_set *our_features,
			       const struct chainparams *must_be_chain,
			       char **fail);

/**
 * invrequest_encode - encode this complete bolt12 invreq TLV into text.
 */
char *invrequest_encode(const tal_t *ctx,
			const struct tlv_invoice_request *bolt12_tlv);

/**
 * invrequest_decode - decode this complete bolt12 text into a TLV.
 * @ctx: the context to allocate return or *@fail off.
 * @b12: the invreq string
 * @b12len: the invreq string length
 * @our_features: if non-NULL, feature set to check against.
 * @must_be_chain: if non-NULL, chain to enforce.
 * @fail: pointer to descriptive error string, set if this returns NULL.
 *
 * Note: invreq doesn't always have a signature, so no checking is done!
 */
struct tlv_invoice_request *invrequest_decode(const tal_t *ctx,
					      const char *b12, size_t b12len,
					      const struct feature_set *our_features,
					      const struct chainparams *must_be_chain,
					      char **fail);

/**
 * invoice_encode - encode this complete bolt12 invoice TLV into text.
 */
char *invoice_encode(const tal_t *ctx, const struct tlv_invoice *bolt12_tlv);

/**
 * invoice_decode - decode this complete bolt12 text into a TLV.
 * @ctx: the context to allocate return or *@fail off.
 * @b12: the invoice string
 * @b12len: the invoice string length
 * @our_features: if non-NULL, feature set to check against.
 * @must_be_chain: if non-NULL, chain to enforce.
 * @fail: pointer to descriptive error string, set if this returns NULL.
 *
 * Note: checks signature!
 */
struct tlv_invoice *invoice_decode(const tal_t *ctx,
				   const char *b12, size_t b12len,
				   const struct feature_set *our_features,
				   const struct chainparams *must_be_chain,
				   char **fail);

/* Variant which does not check signature */
struct tlv_invoice *invoice_decode_nosig(const tal_t *ctx,
					 const char *b12, size_t b12len,
					 const struct feature_set *our_features,
					 const struct chainparams *must_be_chain,
					 char **fail);

/* Check a bolt12-style signature. */
bool bolt12_check_signature(const struct tlv_field *fields,
			    const char *messagename,
			    const char *fieldname,
			    const struct pubkey *key,
			    const struct bip340sig *sig);

/* Given a single bolt12 chain, does it match?  (NULL == bitcoin) */
bool bolt12_chain_matches(const struct bitcoin_blkid *chain,
			  const struct chainparams *must_be_chain);

/* Given an array of max_num_chains chains (or NULL == bitcoin), does
 * it match? */
bool bolt12_chains_match(const struct bitcoin_blkid *chains,
			 size_t max_num_chains,
			 const struct chainparams *must_be_chain);

/* Given a basetime, when does period N start? */
u64 offer_period_start(u64 basetime, size_t n,
		       const struct recurrence *recurrence);

/* Get the start and end of the payment window for period N. */
void offer_period_paywindow(const struct recurrence *recurrence,
			    const struct recurrence_paywindow *recurrence_paywindow,
			    const struct recurrence_base *recurrence_base,
			    u64 basetime, u64 period_idx,
			    u64 *period_start, u64 *period_end);


/**
 * Preliminary prefix check to see if the string might be a bolt12 string.
 */
bool bolt12_has_prefix(const char *str);

/**
 * tlv_span: Find span of this inclusive range of tlv types
 * @tlvstream: the tlv stream
 * @minfield: lowest field to find
 * @maxfield: highest field to find
 * @start: (out) optional offset of start.
 *
 * Returns length, so 0 means nothing found.
*/
size_t tlv_span(const u8 *tlvstream, u64 minfield, u64 maxfield,
		size_t *start);

/* Get offer_id referred to by various structures. */
void offer_offer_id(const struct tlv_offer *offer, struct sha256 *id);
void invreq_offer_id(const struct tlv_invoice_request *invreq, struct sha256 *id);
void invoice_offer_id(const struct tlv_invoice *invoice, struct sha256 *id);

/* Get invreq_id: this is used to match incoming invoices to invoice_requests
 * we publish. */
void invreq_invreq_id(const struct tlv_invoice_request *invreq, struct sha256 *id);
void invoice_invreq_id(const struct tlv_invoice *invoice, struct sha256 *id);

/**
 * Prepare a new invoice_request based on an offer.
 */
struct tlv_invoice_request *invoice_request_for_offer(const tal_t *ctx,
						      const struct tlv_offer *offer);

/**
 * Prepare a new invoice based on an invoice_request.
 */
struct tlv_invoice *invoice_for_invreq(const tal_t *ctx,
				       const struct tlv_invoice_request *invreq);

#endif /* LIGHTNING_COMMON_BOLT12_H */
