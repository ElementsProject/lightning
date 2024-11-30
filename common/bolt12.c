#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/tal/str/str.h>
#include <ccan/time/time.h>
#include <common/bech32_util.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/features.h>
#include <common/overflows.h>
#include <inttypes.h>
#include <secp256k1_schnorrsig.h>
#include <time.h>

/* If chains is NULL, max_num_chains is ignored */
bool bolt12_chains_match(const struct bitcoin_blkid *chains,
			 size_t max_num_chains,
			 const struct chainparams *must_be_chain)
{
	/* BOLT-offers #12:
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `offer_chains` the offer is valid for.
	 *   - otherwise:
	 *     - MAY omit `offer_chains`, implying that bitcoin is only chain.
	 */
	/* BOLT-offers #12:
	 * A reader of an offer:
	 *...
	 *  - if `offer_chains` is not set:
	 *    - if the node does not accept bitcoin invoices:
	 *      - MUST NOT respond to the offer
	 *  - otherwise: (`offer_chains` is set):
	 *    - if the node does not accept invoices for any of the `chains`:
	 *      - MUST NOT respond to the offer
	 */
	if (!chains) {
		max_num_chains = 1;
		chains = &chainparams_for_network("bitcoin")->genesis_blockhash;
	}

	for (size_t i = 0; i < max_num_chains; i++) {
		if (bitcoin_blkid_eq(&chains[i],
				     &must_be_chain->genesis_blockhash))
			return true;
	}

	return false;
}

bool bolt12_chain_matches(const struct bitcoin_blkid *chain,
			  const struct chainparams *must_be_chain)
{
	return bolt12_chains_match(chain, 1, must_be_chain);
}

static char *check_features_and_chain(const tal_t *ctx,
				      const struct feature_set *our_features,
				      const struct chainparams *must_be_chain,
				      const u8 *features,
				      enum feature_place fplace,
				      const struct bitcoin_blkid *chains,
				      size_t num_chains)
{
	if (must_be_chain) {
		if (!bolt12_chains_match(chains, num_chains, must_be_chain))
			return tal_fmt(ctx, "wrong chain");
	}

	if (our_features) {
		int badf = features_unsupported(our_features, features, fplace);
		if (badf != -1)
			return tal_fmt(ctx, "unknown feature bit %i", badf);
	}

	return NULL;
}

bool bolt12_check_signature(const struct tlv_field *fields,
			    const char *messagename,
			    const char *fieldname,
			    const struct pubkey *key,
			    const struct bip340sig *sig)
{
	struct sha256 m, shash;

	merkle_tlv(fields, &m);
	sighash_from_merkle(messagename, fieldname, &m, &shash);

	return check_schnorr_sig(&shash, &key->pubkey, sig);
}

static char *check_signature(const tal_t *ctx,
			     const struct tlv_field *fields,
			     const char *messagename,
			     const char *fieldname,
			     const struct pubkey *node_id,
			     const struct bip340sig *sig)
{
	if (!node_id)
		return tal_fmt(ctx, "Missing node_id");
	if (!sig)
		return tal_fmt(ctx, "Missing signature");

	if (!bolt12_check_signature(fields,
				    messagename, fieldname, node_id, sig))
		return tal_fmt(ctx, "Invalid signature");
	return NULL;
}

static const u8 *string_to_data(const tal_t *ctx,
				const char *str,
				size_t str_len,
				const char *hrp_expected,
				size_t *dlen,
				char **fail)
{
	char *hrp;
	u8 *data;
	char *bech32;
	size_t bech32_len;
	bool have_plus = false;

	/* First we collapse +\s*, except at start/end. */
	bech32 = tal_arr(tmpctx, char, str_len);
	bech32_len = 0;
	for (size_t i = 0; i < str_len; i++) {
		if (i != 0 && i+1 != str_len && !have_plus && str[i] == '+') {
			have_plus = true;
			continue;
		}
		if (have_plus && cisspace(str[i]))
			continue;
		have_plus = false;
		bech32[bech32_len++] = str[i];
	}

	if (have_plus) {
		*fail = tal_fmt(ctx, "unfinished string");
		return NULL;
	}

	if (!from_bech32_charset(ctx, bech32, bech32_len, &hrp, &data)) {
		*fail = tal_fmt(ctx, "invalid bech32 string");
		return NULL;
	}
	if (!streq(hrp, hrp_expected)) {
		*fail = tal_fmt(ctx, "unexpected prefix %s", hrp);
		data = tal_free(data);
	} else
		*dlen = tal_bytelen(data);

	tal_free(hrp);
	return data;
}

char *offer_encode(const tal_t *ctx, const struct tlv_offer *offer_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_offer(&wire, offer_tlv);

	return to_bech32_charset(ctx, "lno", wire);
}

struct tlv_offer *offer_decode(const tal_t *ctx,
			       const char *b12, size_t b12len,
			       const struct feature_set *our_features,
			       const struct chainparams *must_be_chain,
			       char **fail)
{
	struct tlv_offer *offer;
	const u8 *data;
	size_t dlen;
	const struct tlv_field *badf;

	data = string_to_data(tmpctx, b12, b12len, "lno", &dlen, fail);
	if (!data)
		return NULL;;

	offer = fromwire_tlv_offer(ctx, &data, &dlen);
	if (!offer) {
		*fail = tal_fmt(ctx, "invalid offer data");
		return NULL;
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 offer->offer_features,
					 BOLT12_OFFER_FEATURE,
					 offer->offer_chains,
					 tal_count(offer->offer_chains));
	if (*fail)
		return tal_free(offer);

	/* BOLT-offers #12:
	 * A reader of an offer:
	 * - if the offer contains any TLV fields outside the inclusive ranges: 1 to 79 and 1000000000 to 1999999999:
	 *   - MUST NOT respond to the offer.
	 * - if `offer_features` contains unknown _odd_ bits that are non-zero:
	 *     - MUST ignore the bit.
	 * - if `offer_features` contains unknown _even_ bits that are non-zero:
	 *   - MUST NOT respond to the offer.
	 *   - SHOULD indicate the unknown bit to the user.
	 */
	badf = any_field_outside_range(offer->fields, false,
				       1, 79,
				       1000000000, 1999999999);
	if (badf) {
		*fail = tal_fmt(ctx,
				"Offer %"PRIu64" field outside offer range",
				badf->numtype);
		return tal_free(offer);
	}

	/* BOLT-offers #12:
	 *
	 * - if `offer_amount` is set and `offer_description` is not set:
	 *    - MUST NOT respond to the offer.
	 */
	if (!offer->offer_description && offer->offer_amount) {
		*fail = tal_strdup(ctx, "Offer does not contain a description, but contains an amount");
		return tal_free(offer);
	}

	/* BOLT-offers #12:
	 *
	 *   - if neither `offer_issuer_id` nor `offer_paths` are set:
	 *     - MUST NOT respond to the offer.
	 */
	if (!offer->offer_issuer_id && !offer->offer_paths) {
		*fail = tal_strdup(ctx, "Offer does not contain an issuer_id or paths");
		return tal_free(offer);
	}

	/* BOLT-offers #12:
	 *   - if `num_hops` is 0 in any `blinded_path` in `offer_paths`:
	 *     - MUST NOT respond to the offer.
	 */
	for (size_t i = 0; i < tal_count(offer->offer_paths); i++) {
		if (tal_count(offer->offer_paths[i]->path) == 0) {
			*fail = tal_strdup(ctx, "Offer contains an empty offer_path");
			return tal_free(offer);
		}
	}

	return offer;
}

char *invrequest_encode(const tal_t *ctx, const struct tlv_invoice_request *invrequest_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_invoice_request(&wire, invrequest_tlv);

	return to_bech32_charset(ctx, "lnr", wire);
}

struct tlv_invoice_request *invrequest_decode(const tal_t *ctx,
					      const char *b12, size_t b12len,
					      const struct feature_set *our_features,
					      const struct chainparams *must_be_chain,
					      char **fail)
{
	struct tlv_invoice_request *invrequest;
	const u8 *data;
	size_t dlen;
	const struct tlv_field *badf;

	data = string_to_data(tmpctx, b12, b12len, "lnr", &dlen, fail);
	if (!data)
		return NULL;

	invrequest = fromwire_tlv_invoice_request(ctx, &data, &dlen);
	if (!invrequest) {
		*fail = tal_fmt(ctx, "invalid invreq data");
		return NULL;
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 invrequest->invreq_features,
					 BOLT12_INVREQ_FEATURE,
					 invrequest->invreq_chain, 1);
	if (*fail)
		return tal_free(invrequest);

	/* BOLT-offers #12:
	 * The reader:
	 *...
	 *  - MUST fail the request if any non-signature TLV fields are outside the inclusive ranges: 0 to 159 and 1000000000 to 2999999999
	 */
	badf = any_field_outside_range(invrequest->fields, true,
				       0, 159,
				       1000000000, 2999999999);
	if (badf) {
		*fail = tal_fmt(ctx,
				"Invoice request %"PRIu64" field outside invoice request range",
				badf->numtype);
		return tal_free(invrequest);
	}

	/* BOLT-offers #12:
	 *   - if `num_hops` is 0 in any `blinded_path` in `invreq_paths`:
	 *     - MUST fail the request.
	 */
	for (size_t i = 0; i < tal_count(invrequest->invreq_paths); i++) {
		if (tal_count(invrequest->invreq_paths[i]->path) == 0) {
			*fail = tal_strdup(ctx, "Invoice request contains an empty invreq_path");
			return tal_free(invrequest);
		}
	}

	return invrequest;
}

char *invoice_encode(const tal_t *ctx, const struct tlv_invoice *invoice_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_invoice(&wire, invoice_tlv);

	return to_bech32_charset(ctx, "lni", wire);
}

struct tlv_invoice *invoice_decode_minimal(const tal_t *ctx,
					   const char *b12, size_t b12len,
					   const struct feature_set *our_features,
					   const struct chainparams *must_be_chain,
					   char **fail)
{
	struct tlv_invoice *invoice;
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lni", &dlen, fail);
	if (!data)
		return NULL;

	invoice = fromwire_tlv_invoice(ctx, &data, &dlen);
	if (!invoice) {
		*fail = tal_fmt(ctx, "invalid invoice data");
		return NULL;
	}

	/* BOLT-offers #12:
	 * - if `invreq_chain` is not present:
	 *    - MUST fail the request if bitcoin is not a supported chain.
	 *  - otherwise:
	 *    - MUST fail the request if `invreq_chain`.`chain` is not a
	 *      supported chain.
	 * - if `invoice_features` contains unknown _odd_ bits that are non-zero:
	 *  - MUST ignore the bit.
	 * - if `invoice_features` contains unknown _even_ bits that are non-zero:
	 *  - MUST reject the invoice.
	 */
	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 invoice->invoice_features,
					 BOLT12_INVOICE_FEATURE,
					 invoice->invreq_chain, 1);
	if (*fail)
		return tal_free(invoice);

	return invoice;
}

static void add_days(struct tm *tm, u32 number)
{
	tm->tm_mday += number;
}

static void add_months(struct tm *tm, u32 number)
{
	tm->tm_mon += number;
}

static void add_years(struct tm *tm, u32 number)
{
	tm->tm_year += number;
}

static u64 time_change(u64 prevstart, u32 number,
		       void (*add_time)(struct tm *tm, u32 number),
		       bool day_const)
{
	struct tm tm;
	time_t prev = prevstart, ret;

	tm = *gmtime(&prev);

	for (;;) {
		struct tm new_tm = tm;
		add_time(&new_tm, number);
		ret = mktime(&new_tm);

		if (ret == (time_t)-1)
			return 0;

		/* If we overflowed that month, try one less. */
		if (!day_const || new_tm.tm_mday == tm.tm_mday)
			break;
		tm.tm_mday--;
	}

	return ret;
}

u64 offer_period_start(u64 basetime, size_t n,
		       const struct recurrence *recur)
{
	/* BOLT-offers-recurrence #12:
	 * 1. A `time_unit` defining 0 (seconds), 1 (days), 2 (months),
	 *    3 (years).
	 */
	switch (recur->time_unit) {
	case 0:
		return basetime + recur->period * n;
	case 1:
		return time_change(basetime, recur->period * n, add_days, false);
	case 2:
		return time_change(basetime, recur->period * n, add_months, true);
	case 3:
		return time_change(basetime, recur->period * n, add_years, true);
	default:
		/* This is our offer, how did we get here? */
		return 0;
	}
}

void offer_period_paywindow(const struct recurrence *recurrence,
			    const struct recurrence_paywindow *recurrence_paywindow,
			    const struct recurrence_base *recurrence_base,
			    u64 basetime, u64 period_idx,
			    u64 *start, u64 *end)
{
	/* BOLT-offers-recurrence #12:
	 * - if the offer contains `recurrence_paywindow`:
	 */
	if (recurrence_paywindow) {
		u64 pstart = offer_period_start(basetime, period_idx,
						recurrence);
		/* BOLT-offers-recurrence #12:
		 * - if the offer has a `recurrence_basetime` or the
		 *    `recurrence_counter` is non-zero:
		 *   - SHOULD NOT send an `invreq` for a period prior to
		 *     `seconds_before` seconds before that period start.
		 *   - SHOULD NOT send an `invreq` for a period later
		 *     than `seconds_after` seconds past that period start.
		 */
		*start = pstart - recurrence_paywindow->seconds_before;
		*end = pstart + recurrence_paywindow->seconds_after;

		/* First payment without recurrence_base, we give
		 * ourselves 60 seconds, since period will start
		 * now */
		if (!recurrence_base && period_idx == 0
		    && recurrence_paywindow->seconds_after < 60)
			*end = pstart + 60;
	} else {
		/* BOLT-offers-recurrence #12:
		 * - otherwise:
		 *   - SHOULD NOT send an `invreq` with
		 *     `recurrence_counter` is non-zero for a period whose
		 *     immediate predecessor has not yet begun.
		 */
		if (period_idx == 0)
			*start = 0;
		else
			*start = offer_period_start(basetime, period_idx-1,
						    recurrence);

		/* BOLT-offers-recurrence #12:
		 *     - SHOULD NOT send an `invreq` for a period which
		 *       has already passed.
		 */
		*end = offer_period_start(basetime, period_idx+1,
					  recurrence) - 1;
	}
}

struct tlv_invoice *invoice_decode(const tal_t *ctx,
				   const char *b12, size_t b12len,
				   const struct feature_set *our_features,
				   const struct chainparams *must_be_chain,
				   char **fail)
{
	struct tlv_invoice *invoice;

	invoice = invoice_decode_minimal(ctx, b12, b12len, our_features,
					 must_be_chain, fail);
	if (!invoice)
		return NULL;

	*fail = check_signature(ctx, invoice->fields,
				"invoice", "signature",
				invoice->invoice_node_id,
				invoice->signature);
	if (*fail)
		return tal_free(invoice);

	/* BOLT-offers #12:
	 * A reader of an invoice:
	 *   - MUST reject the invoice if `invoice_amount` is not present.
	 *   - MUST reject the invoice if `invoice_created_at` is not present.
	 *   - MUST reject the invoice if `invoice_payment_hash` is not present.
	 *   - MUST reject the invoice if `invoice_node_id` is not present.
	 */
	if (!invoice->invoice_amount) {
		*fail = tal_strdup(ctx, "missing invoice_amount");
		return tal_free(invoice);
	}
	if (!invoice->invoice_created_at) {
		*fail = tal_strdup(ctx, "missing invoice_created_at");
		return tal_free(invoice);
	}
	if (!invoice->invoice_payment_hash) {
		*fail = tal_strdup(ctx, "missing invoice_payment_hash");
		return tal_free(invoice);
	}
	if (!invoice->invoice_node_id) {
		*fail = tal_strdup(ctx, "missing invoicenode_id");
		return tal_free(invoice);
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `invoice_paths` is not present or is
	 *   empty. */
	if (tal_count(invoice->invoice_paths) == 0) {
		*fail = tal_strdup(ctx, "missing/empty invoice_paths");
		return tal_free(invoice);
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `num_hops` is 0 in any
         *   `blinded_path` in `invoice_paths`.
	 */
	for (size_t i = 0; i < tal_count(invoice->invoice_paths); i++) {
		if (tal_count(invoice->invoice_paths[i]->path) != 0)
			continue;
		*fail = tal_fmt(ctx, "zero num_hops in path %zu/%zu",
				i, tal_count(invoice->invoice_paths));
		return tal_free(invoice);
	}

	/* BOLT-offers #12:
	 * - MUST reject the invoice if `invoice_blindedpay` is not present.
	 * - MUST reject the invoice if `invoice_blindedpay` does not contain exactly one `blinded_payinfo` per `invoice_paths`.`blinded_path`.
	 */
	if (tal_count(invoice->invoice_blindedpay)
	    != tal_count(invoice->invoice_paths)) {
		*fail = tal_fmt(ctx, "expected %zu payinfo but found %zu",
				tal_count(invoice->invoice_paths),
				tal_count(invoice->invoice_blindedpay));
		return tal_free(invoice);
	}

	return invoice;
}

u64 invoice_expiry(const struct tlv_invoice *invoice)
{
	u64 expiry;

	/* BOLT-offers #12:
	 * - if `invoice_relative_expiry` is present:
	 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
	 *     is greater than `invoice_created_at` plus `seconds_from_creation`.
	 * - otherwise:
	 *   - MUST reject the invoice if the current time since 1970-01-01 UTC
	 *     is greater than `invoice_created_at` plus 7200.
	 */
	if (invoice->invoice_relative_expiry)
		expiry = *invoice->invoice_relative_expiry;
	else
		expiry = 7200;

	/* If it overflows, it's forever */
	if (add_overflows_u64(*invoice->invoice_created_at, expiry))
		return UINT64_MAX;

	return *invoice->invoice_created_at + expiry;
}

static bool bolt12_has_invoice_prefix(const char *str)
{
	return strstarts(str, "lni1") || strstarts(str, "LNI1");
}

static bool bolt12_has_request_prefix(const char *str)
{
	return strstarts(str, "lnr1") || strstarts(str, "LNR1");
}

static bool bolt12_has_offer_prefix(const char *str)
{
	return strstarts(str, "lno1") || strstarts(str, "LNO1");
}

bool bolt12_has_prefix(const char *str)
{
	return bolt12_has_invoice_prefix(str) || bolt12_has_offer_prefix(str) ||
	       bolt12_has_request_prefix(str);
}

/* Inclusive span of tlv range >= minfield and <= maxfield */
size_t tlv_span(const u8 *tlvstream, u64 minfield, u64 maxfield,
		size_t *startp)
{
	const u8 *cursor = tlvstream;
	size_t tlvlen = tal_bytelen(tlvstream);
	const u8 *start, *end;

	start = end = NULL;
	while (tlvlen) {
		const u8 *before = cursor;
		bigsize_t type = fromwire_bigsize(&cursor, &tlvlen);
		bigsize_t len = fromwire_bigsize(&cursor, &tlvlen);
		if (type >= minfield && start == NULL)
			start = before;
		if (type > maxfield)
			break;
		fromwire_pad(&cursor, &tlvlen, len);
		end = cursor;
	}
	if (!start)
		start = end;

	if (startp)
		*startp = start - tlvstream;
	return end - start;
}

static void calc_offer(const u8 *tlvstream, struct sha256 *id)
{
	size_t start1, len1, start2, len2;
	struct sha256_ctx ctx;

	/* BOLT-offers #12:
	 * A writer of an offer:
	 * - MUST NOT set any TLV fields outside the inclusive ranges: 1 to 79 and 1000000000 to 1999999999.
	 */
	len1 = tlv_span(tlvstream, 1, 79, &start1);
	len2 = tlv_span(tlvstream, 1000000000, 1999999999, &start2);

	sha256_init(&ctx);
	sha256_update(&ctx, tlvstream + start1, len1);
	sha256_update(&ctx, tlvstream + start2, len2);
	sha256_done(&ctx, id);
}

void offer_offer_id(const struct tlv_offer *offer, struct sha256 *id)
{
	u8 *wire = tal_arr(tmpctx, u8, 0);

	towire_tlv_offer(&wire, offer);
	calc_offer(wire, id);
}

void invreq_offer_id(const struct tlv_invoice_request *invreq, struct sha256 *id)
{
	u8 *wire = tal_arr(tmpctx, u8, 0);

	towire_tlv_invoice_request(&wire, invreq);
	calc_offer(wire, id);
}

void invoice_offer_id(const struct tlv_invoice *invoice, struct sha256 *id)
{
	u8 *wire = tal_arr(tmpctx, u8, 0);

	towire_tlv_invoice(&wire, invoice);
	calc_offer(wire, id);
}

static void calc_invreq(const u8 *tlvstream, struct sha256 *id)
{
	size_t start1, len1, start2, len2;
	struct sha256_ctx ctx;

	/* BOLT-offers #12:
	 * The writer:
	 *...
	 *   - MUST NOT set any non-signature TLV fields outside the inclusive ranges: 0 to 159 and 1000000000 to 2999999999
	 */
	len1 = tlv_span(tlvstream, 0, 159, &start1);
	len2 = tlv_span(tlvstream, 1000000000, 2999999999, &start2);

	sha256_init(&ctx);
	sha256_update(&ctx, tlvstream + start1, len1);
	sha256_update(&ctx, tlvstream + start2, len2);
	sha256_done(&ctx, id);
}

void invreq_invreq_id(const struct tlv_invoice_request *invreq, struct sha256 *id)
{
	u8 *wire = tal_arr(tmpctx, u8, 0);

	towire_tlv_invoice_request(&wire, invreq);
	calc_invreq(wire, id);
}

void invoice_invreq_id(const struct tlv_invoice *invoice, struct sha256 *id)
{
	u8 *wire = tal_arr(tmpctx, u8, 0);

	towire_tlv_invoice(&wire, invoice);
	calc_invreq(wire, id);
}


/* BOLT-offers #12:
 * ## Requirements for Invoice Requests
 *
 * The writer:
 *   - if it is responding to an offer:
 *     - MUST copy all fields from the offer (including unknown fields).
 */
struct tlv_invoice_request *invoice_request_for_offer(const tal_t *ctx,
						      const struct tlv_offer *offer)
{
	const u8 *cursor;
	size_t max;
	u8 *wire = tal_arr(tmpctx, u8, 0);
	towire_tlv_offer(&wire, offer);

	cursor = wire;
	max = tal_bytelen(wire);
	return fromwire_tlv_invoice_request(ctx, &cursor, &max);
}

/**
 * Prepare a new invoice based on an invoice_request.
 */
struct tlv_invoice *invoice_for_invreq(const tal_t *ctx,
				       const struct tlv_invoice_request *invreq)
{
	const u8 *cursor;
	size_t start1, len1, start2, len2;
	u8 *wire = tal_arr(tmpctx, u8, 0);

	towire_tlv_invoice_request(&wire, invreq);

	/* BOLT-offers #12:
	 * A writer of an invoice:
	 *...
	 * - if the invoice is in response to an `invoice_request`:
	 *   - MUST copy all non-signature fields from the `invoice_request` (including
	 *     unknown fields).
	 */
	len1 = tlv_span(wire, 0, 159, &start1);
	len2 = tlv_span(wire, 1000000000, 2999999999, &start2);

	/* Move second span adjacent first span */
	memmove(wire + start1 + len1, wire + start2, len2);

	/* Unmarshal combined result */
	len1 = len1 + len2;
	cursor = wire + start1;
	return fromwire_tlv_invoice(ctx, &cursor, &len1);
}

bool is_bolt12_signature_field(u64 typenum)
{
	/* BOLT-offers #12:
	 * Each form is signed using one or more *signature TLV elements*: TLV
	 * types 240 through 1000 (inclusive). */
	return typenum >= 240 && typenum <= 1000;
}

static bool in_ranges(u64 numtype,
		      u64 r1_start, u64 r1_end,
		      u64 r2_start, u64 r2_end)
{
	if (numtype >= r1_start && numtype <= r1_end)
		return true;
	if (numtype >= r2_start && numtype <= r2_end)
		return true;
	return false;
}

const struct tlv_field *any_field_outside_range(const struct tlv_field *fields,
						bool ignore_signature_fields,
						size_t r1_start, size_t r1_end,
						size_t r2_start, size_t r2_end)
{
	for (size_t i = 0; i < tal_count(fields); i++) {
		if (ignore_signature_fields
		    && is_bolt12_signature_field(fields[i].numtype))
			continue;
		if (!in_ranges(fields[i].numtype,
			       r1_start, r1_end,
			       r2_start, r2_end))
			return &fields[i];
	}
	return NULL;
}
