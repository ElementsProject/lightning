#include "config.h"
#include <bitcoin/chainparams.h>
#include <ccan/tal/str/str.h>
#include <common/bech32_util.h>
#include <common/bolt12.h>
#include <common/bolt12_merkle.h>
#include <common/configdir.h>
#include <common/features.h>
#include <secp256k1_schnorrsig.h>
#include <time.h>

/* If chains is NULL, max_num_chains is ignored */
static bool bolt12_chains_match(const struct bitcoin_blkid *chains,
				size_t max_num_chains,
				const struct chainparams *must_be_chain)
{
	/* BOLT-offers #12:
	 *   - if the chain for the invoice is not solely bitcoin:
	 *     - MUST specify `chains` the offer is valid for.
	 *   - otherwise:
	 *     - the bitcoin chain is implied as the first and only entry.
	 */
	/* BOLT-offers #12:
	 * The reader of an invoice_request:
	 *...
	 *  - if `chain` is not present:
	 *    - MUST fail the request if bitcoin is not a supported chain.
	 *  - otherwise:
	 *    - MUST fail the request if `chain` is not a supported chain.
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
				      const struct bitcoin_blkid *chains,
				      size_t num_chains)
{
	if (must_be_chain) {
		if (!bolt12_chains_match(chains, num_chains, must_be_chain))
			return tal_fmt(ctx, "wrong chain");
	}

	if (our_features) {
		int badf = features_unsupported(our_features, features,
						BOLT11_FEATURE);
		if (badf != -1)
			return tal_fmt(ctx, "unknown feature bit %i", badf);
	}

	return NULL;
}

bool bolt12_check_signature(const struct tlv_field *fields,
			    const char *messagename,
			    const char *fieldname,
			    const struct point32 *key,
			    const struct bip340sig *sig)
{
	struct sha256 m, shash;

	merkle_tlv(fields, &m);
	sighash_from_merkle(messagename, fieldname, &m, &shash);
	return secp256k1_schnorrsig_verify(secp256k1_ctx,
					   sig->u8,
					   shash.u.u8,
					   &key->pubkey) == 1;
}

static char *check_signature(const tal_t *ctx,
			     const struct tlv_field *fields,
			     const char *messagename,
			     const char *fieldname,
			     const struct point32 *node_id,
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
	towire_offer(&wire, offer_tlv);

	return to_bech32_charset(ctx, "lno", wire);
}

struct tlv_offer *offer_decode(const tal_t *ctx,
			       const char *b12, size_t b12len,
			       const struct feature_set *our_features,
			       const struct chainparams *must_be_chain,
			       char **fail)
{
	struct tlv_offer *offer = tlv_offer_new(ctx);
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lno", &dlen, fail);
	if (!data)
		return tal_free(offer);

	if (!fromwire_offer(&data, &dlen, offer)) {
		*fail = tal_fmt(ctx, "invalid offer data");
		return tal_free(offer);
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 offer->features,
					 offer->chains,
					 tal_count(offer->chains));
	if (*fail)
		return tal_free(offer);

	/* BOLT-offers #12:
	 * - if `signature` is present, but is not a valid signature using
	 *   `node_id` as described in [Signature Calculation](#signature-calculation):
	 *   - MUST NOT respond to the offer.
	 */
	if (offer->signature) {
		*fail = check_signature(ctx, offer->fields,
					"offer", "signature",
					offer->node_id, offer->signature);
		if (*fail)
			return tal_free(offer);
	}

	return offer;
}

char *invrequest_encode(const tal_t *ctx, const struct tlv_invoice_request *invrequest_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_invoice_request(&wire, invrequest_tlv);

	return to_bech32_charset(ctx, "lnr", wire);
}

struct tlv_invoice_request *invrequest_decode(const tal_t *ctx,
					      const char *b12, size_t b12len,
					      const struct feature_set *our_features,
					      const struct chainparams *must_be_chain,
					      char **fail)
{
	struct tlv_invoice_request *invrequest = tlv_invoice_request_new(ctx);
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lnr", &dlen, fail);
	if (!data)
		return tal_free(invrequest);

	if (!fromwire_invoice_request(&data, &dlen, invrequest)) {
		*fail = tal_fmt(ctx, "invalid invoice_request data");
		return tal_free(invrequest);
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 invrequest->features,
					 invrequest->chain, 1);
	if (*fail)
		return tal_free(invrequest);

	return invrequest;
}

char *invoice_encode(const tal_t *ctx, const struct tlv_invoice *invoice_tlv)
{
	u8 *wire;

	wire = tal_arr(tmpctx, u8, 0);
	towire_invoice(&wire, invoice_tlv);

	return to_bech32_charset(ctx, "lni", wire);
}

struct tlv_invoice *invoice_decode_nosig(const tal_t *ctx,
					 const char *b12, size_t b12len,
					 const struct feature_set *our_features,
					 const struct chainparams *must_be_chain,
					 char **fail)
{
	struct tlv_invoice *invoice = tlv_invoice_new(ctx);
	const u8 *data;
	size_t dlen;

	data = string_to_data(tmpctx, b12, b12len, "lni", &dlen, fail);
	if (!data)
		return tal_free(invoice);

	if (!fromwire_invoice(&data, &dlen, invoice)) {
		*fail = tal_fmt(ctx, "invalid invoice data");
		return tal_free(invoice);
	}

	*fail = check_features_and_chain(ctx,
					 our_features, must_be_chain,
					 invoice->features,
					 invoice->chain, 1);
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
		       const struct tlv_offer_recurrence *recur)
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

void offer_period_paywindow(const struct tlv_offer_recurrence *recurrence,
			    const struct tlv_offer_recurrence_paywindow *recurrence_paywindow,
			    const struct tlv_offer_recurrence_base *recurrence_base,
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
		 *   - SHOULD NOT send an `invoice_request` for a period prior to
		 *     `seconds_before` seconds before that period start.
		 *   - SHOULD NOT send an `invoice_request` for a period later
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
		 *   - SHOULD NOT send an `invoice_request` with
		 *     `recurrence_counter` is non-zero for a period whose
		 *     immediate predecessor has not yet begun.
		 */
		if (period_idx == 0)
			*start = 0;
		else
			*start = offer_period_start(basetime, period_idx-1,
						    recurrence);

		/* BOLT-offers-recurrence #12:
		 *     - SHOULD NOT send an `invoice_request` for a period which
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

	invoice = invoice_decode_nosig(ctx, b12, b12len, our_features,
				       must_be_chain, fail);
	if (invoice) {
		*fail = check_signature(ctx, invoice->fields,
					"invoice", "signature",
					invoice->node_id, invoice->signature);
		if (*fail)
			invoice = tal_free(invoice);
	}
	return invoice;
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
