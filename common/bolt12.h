#ifndef LIGHTNING_COMMON_BOLT12_H
#define LIGHTNING_COMMON_BOLT12_H
#include "config.h"
#include <wire/bolt12_exp_wiregen.h>

struct feature_set;

/* BOLT-offers #12:
 * - if `relative_expiry` is present:
 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
 *     is greater than `timestamp` plus `seconds_from_timestamp`.
 *  - otherwise:
 *    - MUST reject the invoice if the current time since 1970-01-01 UTC
 *      is greater than `timestamp` plus 7200.
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
 *
 * Note: checks signature!
 */
struct tlv_offer *offer_decode(const tal_t *ctx, const char *b12, size_t b12len,
			       const struct feature_set *our_features,
			       const struct chainparams *must_be_chain,
			       char **fail);

/* Variant which does not check signature */
struct tlv_offer *offer_decode_nosig(const tal_t *ctx,
				     const char *b12, size_t b12len,
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
 * @b12: the invoice_request string
 * @b12len: the invoice_request string length
 * @our_features: if non-NULL, feature set to check against.
 * @must_be_chain: if non-NULL, chain to enforce.
 * @fail: pointer to descriptive error string, set if this returns NULL.
 *
 * Note: invoice_request doesn't always have a signature, so no checking is done!
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
			    const struct pubkey32 *key,
			    const struct bip340sig *sig)
	NO_NULL_ARGS;

/* Given a tal_arr of chains, does it contain this chain? */
bool bolt12_chains_match(const struct bitcoin_blkid *chains,
			 const struct chainparams *must_be_chain);

/* Given a basetime, when does period N start? */
u64 offer_period_start(u64 basetime, size_t n,
		       const struct tlv_offer_recurrence *recurrence);

/* Get the start and end of the payment window for period N. */
void offer_period_paywindow(const struct tlv_offer_recurrence *recurrence,
			    const struct tlv_offer_recurrence_paywindow *recurrence_paywindow,
			    const struct tlv_offer_recurrence_base *recurrence_base,
			    u64 basetime, u64 period_idx,
			    u64 *period_start, u64 *period_end);

#endif /* LIGHTNING_COMMON_BOLT12_H */
