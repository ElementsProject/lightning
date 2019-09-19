#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/amount.h>
#include <common/overflows.h>
#include <common/type_to_string.h>
#include <common/utils.h>
#include <inttypes.h>

bool amount_sat_to_msat(struct amount_msat *msat,
			struct amount_sat sat)
{
	if (mul_overflows_u64(sat.satoshis, MSAT_PER_SAT))
		return false;
	msat->millisatoshis = sat.satoshis * MSAT_PER_SAT;
	return true;
}

/* You can always truncate millisatoshis->satoshis. */
struct amount_sat amount_msat_to_sat_round_down(struct amount_msat msat)
{
	struct amount_sat sat;

	sat.satoshis = msat.millisatoshis / MSAT_PER_SAT;
	return sat;
}

/* Different formatting by amounts: btc, sat and msat */
const char *fmt_amount_msat_btc(const tal_t *ctx,
				const struct amount_msat *msat,
				bool append_unit)
{
	return tal_fmt(ctx, "%"PRIu64".%011"PRIu64"%s",
		       msat->millisatoshis / MSAT_PER_BTC,
		       msat->millisatoshis % MSAT_PER_BTC,
		       append_unit ? "btc" : "");
}

const char *fmt_amount_msat(const tal_t *ctx, const struct amount_msat *msat)
{
	return tal_fmt(ctx, "%"PRIu64"msat", msat->millisatoshis);
}
REGISTER_TYPE_TO_STRING(amount_msat, fmt_amount_msat);

const char *fmt_amount_sat_btc(const tal_t *ctx,
			       const struct amount_sat *sat,
			       bool append_unit)
{
	return tal_fmt(ctx, "%"PRIu64".%08"PRIu64"%s",
		       sat->satoshis / SAT_PER_BTC,
		       sat->satoshis % SAT_PER_BTC,
		       append_unit ? "btc" : "");
}

const char *fmt_amount_sat(const tal_t *ctx, const struct amount_sat *sat)
{
	return tal_fmt(ctx, "%"PRIu64"sat", sat->satoshis);
}
REGISTER_TYPE_TO_STRING(amount_sat, fmt_amount_sat);

static bool breakup(const char *str, size_t slen,
		    /* Length of first numeric part. */
		    size_t *whole_number_len,
		    /* Pointer to post-decimal part, or NULL */
		    const char **post_decimal_ptr,
		    size_t *post_decimal_len,
		    /* Pointer to suffix, or NULL */
		    const char **suffix_ptr,
		    size_t *suffix_len)
{
	size_t i;

	*whole_number_len = 0;
	*post_decimal_len = 0;
	*post_decimal_ptr = NULL;
	*suffix_ptr = NULL;
	*suffix_len = 0;

	for (i = 0;; i++) {
		if (i >= slen)
			return i != 0;
		if (cisdigit(str[i]))
			(*whole_number_len)++;
		else
			break;
	}

	if (str[i] == '.') {
		i++;
		*post_decimal_ptr = str + i;
		for (;; i++) {
			/* True if > 0 decimals. */
			if (i >= slen)
				return str + i != *post_decimal_ptr;
			if (cisdigit(str[i]))
				(*post_decimal_len)++;
			else
				break;
		}
	}

	*suffix_ptr = str + i;
	*suffix_len = slen - i;
	return true;
}

static bool from_number(u64 *res, const char *s, size_t len, int tens_factor)
{
	if (len == 0)
		return false;

	*res = 0;
	for (size_t i = 0; i < len; i++) {
		if (mul_overflows_u64(*res, 10))
			return false;
		*res *= 10;
		assert(cisdigit(s[i]));
		if (add_overflows_u64(*res, s[i] - '0'))
			return false;
		*res += s[i] - '0';
	}
	while (tens_factor > 0) {
		if (mul_overflows_u64(*res, 10))
			return false;
		*res *= 10;
		tens_factor--;
	}
	return true;
}

static bool from_numbers(u64 *res,
			 const char *s1, size_t len1, int tens_factor,
			 const char *s2, size_t len2)
{
	u64 p1, p2;
	if (len2 > tens_factor)
		return false;

	if (!from_number(&p1, s1, len1, tens_factor)
	    || !from_number(&p2, s2, len2, tens_factor - len2))
		return false;

	if (add_overflows_u64(p1, p2))
		return false;

	*res = p1 + p2;
	return true;
}

/* Valid strings:
 *  [0-9]+ => millisatoshi.
 *  [0-9]+msat => millisatoshi.
 *  [0-9]+sat => *1000 -> millisatopshi.
 *  [0-9]+.[0-9]{1,11}btc => millisatoshi.
 */
bool parse_amount_msat(struct amount_msat *msat, const char *s, size_t slen)
{
	size_t whole_number_len, post_decimal_len, suffix_len;
	const char *post_decimal_ptr, *suffix_ptr;

	if (!breakup(s, slen, &whole_number_len,
		     &post_decimal_ptr, &post_decimal_len,
		     &suffix_ptr, &suffix_len))
		return false;

	if (!post_decimal_ptr && !suffix_ptr)
		return from_number(&msat->millisatoshis, s, whole_number_len, 0);
	if (!post_decimal_ptr && memeqstr(suffix_ptr, suffix_len, "msat"))
		return from_number(&msat->millisatoshis, s, whole_number_len, 0);
	if (!post_decimal_ptr && memeqstr(suffix_ptr, suffix_len, "sat"))
		return from_number(&msat->millisatoshis, s, whole_number_len, 3);
	if (post_decimal_ptr && memeqstr(suffix_ptr, suffix_len, "btc"))
		return from_numbers(&msat->millisatoshis,
				    s, whole_number_len, 11,
				    post_decimal_ptr, post_decimal_len);
	return false;
}

/* Valid strings:
 *  [0-9]+ => satoshi.
 *  [0-9]+sat => satoshi.
 *  [0-9]+000msat => satoshi.
 *  0msat => 0 satoshi
 *  [0-9]+.[0-9]{1,8}btc => satoshi.
 */
bool parse_amount_sat(struct amount_sat *sat, const char *s, size_t slen)
{
	size_t whole_number_len, post_decimal_len, suffix_len;
	const char *post_decimal_ptr, *suffix_ptr;

	if (!breakup(s, slen, &whole_number_len,
		     &post_decimal_ptr, &post_decimal_len,
		     &suffix_ptr, &suffix_len))
		return false;

	if (!post_decimal_ptr && !suffix_ptr)
		return from_number(&sat->satoshis, s, whole_number_len, 0);
	if (!post_decimal_ptr && memeqstr(suffix_ptr, suffix_len, "sat"))
		return from_number(&sat->satoshis, s, whole_number_len, 0);
	if (!post_decimal_ptr && memeqstr(suffix_ptr, suffix_len, "msat")) {
		if (!memends(s, whole_number_len, "000", strlen("000"))) {
			if (memeqstr(s, whole_number_len, "0"))
				return from_number(&sat->satoshis, s,
						   whole_number_len, 0);
			return false;
		}
		return from_number(&sat->satoshis, s, whole_number_len - 3, 0);
	}
	if (post_decimal_ptr && memeqstr(suffix_ptr, suffix_len, "btc"))
		return from_numbers(&sat->satoshis,
				    s, whole_number_len, 8,
				    post_decimal_ptr, post_decimal_len);

	return false;
}

WARN_UNUSED_RESULT bool amount_msat_add(struct amount_msat *val,
					struct amount_msat a,
					struct amount_msat b)
{
	if (add_overflows_u64(a.millisatoshis, b.millisatoshis))
		return false;

	val->millisatoshis = a.millisatoshis + b.millisatoshis;
	return true;
}

WARN_UNUSED_RESULT bool amount_msat_sub(struct amount_msat *val,
					struct amount_msat a,
					struct amount_msat b)
{
	if (a.millisatoshis < b.millisatoshis)
		return false;

	val->millisatoshis = a.millisatoshis - b.millisatoshis;
	return true;
}

WARN_UNUSED_RESULT bool amount_sat_add(struct amount_sat *val,
				       struct amount_sat a,
				       struct amount_sat b)
{
	if (add_overflows_u64(a.satoshis, b.satoshis))
		return false;

	val->satoshis = a.satoshis + b.satoshis;
	return true;
}

WARN_UNUSED_RESULT bool amount_sat_sub(struct amount_sat *val,
				       struct amount_sat a,
				       struct amount_sat b)
{
	if (a.satoshis < b.satoshis)
		return false;

	val->satoshis = a.satoshis - b.satoshis;
	return true;
}

WARN_UNUSED_RESULT bool amount_msat_sub_sat(struct amount_msat *val,
					    struct amount_msat a,
					    struct amount_sat b)
{
	struct amount_msat msatb;

	if (!amount_sat_to_msat(&msatb, b))
		return false;

	return amount_msat_sub(val, a, msatb);
}

WARN_UNUSED_RESULT bool amount_sat_sub_msat(struct amount_msat *val,
					    struct amount_sat a,
					    struct amount_msat b)
{
	struct amount_msat msata;

	if (!amount_sat_to_msat(&msata, a))
		return false;

	return amount_msat_sub(val, msata, b);
}

WARN_UNUSED_RESULT bool amount_msat_add_sat(struct amount_msat *val,
					    struct amount_msat a,
					    struct amount_sat b)
{
	struct amount_msat msatb;

	if (!amount_sat_to_msat(&msatb, b))
		return false;

	return amount_msat_add(val, a, msatb);
}

bool amount_sat_eq(struct amount_sat a, struct amount_sat b)
{
	return a.satoshis == b.satoshis;
}

bool amount_msat_eq(struct amount_msat a, struct amount_msat b)
{
	return a.millisatoshis == b.millisatoshis;
}

bool amount_sat_greater(struct amount_sat a, struct amount_sat b)
{
	return a.satoshis > b.satoshis;
}

bool amount_msat_greater(struct amount_msat a, struct amount_msat b)
{
	return a.millisatoshis > b.millisatoshis;
}

bool amount_sat_greater_eq(struct amount_sat a, struct amount_sat b)
{
	return a.satoshis >= b.satoshis;
}

bool amount_msat_greater_eq(struct amount_msat a, struct amount_msat b)
{
	return a.millisatoshis >= b.millisatoshis;
}

bool amount_sat_less(struct amount_sat a, struct amount_sat b)
{
	return a.satoshis < b.satoshis;
}

bool amount_msat_less(struct amount_msat a, struct amount_msat b)
{
	return a.millisatoshis < b.millisatoshis;
}

bool amount_sat_less_eq(struct amount_sat a, struct amount_sat b)
{
	return a.satoshis <= b.satoshis;
}

bool amount_msat_less_eq(struct amount_msat a, struct amount_msat b)
{
	return a.millisatoshis <= b.millisatoshis;
}

bool amount_msat_greater_sat(struct amount_msat msat, struct amount_sat sat)
{
	struct amount_msat msat_from_sat;

	if (!amount_sat_to_msat(&msat_from_sat, sat))
		return false;
	return msat.millisatoshis > msat_from_sat.millisatoshis;
}

bool amount_msat_greater_eq_sat(struct amount_msat msat, struct amount_sat sat)
{
	struct amount_msat msat_from_sat;

	if (!amount_sat_to_msat(&msat_from_sat, sat))
		return false;
	return msat.millisatoshis >= msat_from_sat.millisatoshis;
}

bool amount_msat_less_sat(struct amount_msat msat, struct amount_sat sat)
{
	struct amount_msat msat_from_sat;

	if (!amount_sat_to_msat(&msat_from_sat, sat))
		return false;
	return msat.millisatoshis < msat_from_sat.millisatoshis;
}

bool amount_msat_less_eq_sat(struct amount_msat msat, struct amount_sat sat)
{
	struct amount_msat msat_from_sat;

	if (!amount_sat_to_msat(&msat_from_sat, sat))
		return false;
	return msat.millisatoshis <= msat_from_sat.millisatoshis;
}

bool amount_msat_to_u32(struct amount_msat msat, u32 *millisatoshis)
{
	if (amount_msat_greater_eq(msat, AMOUNT_MSAT(0x100000000)))
		return false;
	*millisatoshis = msat.millisatoshis;
	return true;
}

void amount_msat_from_u64(struct amount_msat *msat, u64 millisatoshis)
{
	msat->millisatoshis = millisatoshis;
}

WARN_UNUSED_RESULT bool amount_msat_from_sat_u64(struct amount_msat *msat, u64 satoshis)
{
	if (mul_overflows_u64(satoshis, MSAT_PER_SAT))
		return false;
	msat->millisatoshis = satoshis * MSAT_PER_SAT;
	return true;
}

bool amount_msat_fee(struct amount_msat *fee,
		     struct amount_msat amt,
		     u32 fee_base_msat,
		     u32 fee_proportional_millionths)
{
	struct amount_msat fee_base, fee_prop;

	/* BOLT #7:
	 *
	 *   - SHOULD accept HTLCs that pay a fee equal to or greater than:
	 *    - fee_base_msat + ( amount_to_forward * fee_proportional_millionths / 1000000 )
	 */
	fee_base.millisatoshis = fee_base_msat;

	if (mul_overflows_u64(amt.millisatoshis, fee_proportional_millionths))
		return false;
	fee_prop.millisatoshis = amt.millisatoshis * fee_proportional_millionths
		/ 1000000;

	return amount_msat_add(fee, fee_base, fee_prop);
}

bool amount_msat_add_fee(struct amount_msat *amt,
			 u32 fee_base_msat,
			 u32 fee_proportional_millionths)
{
	struct amount_msat fee;

	if (!amount_msat_fee(&fee, *amt,
			     fee_base_msat, fee_proportional_millionths))
		return false;
	return amount_msat_add(amt, *amt, fee);
}

struct amount_sat amount_tx_fee(u32 fee_per_kw, size_t weight)
{
	struct amount_sat fee;

	/* If this overflows, weight must be > 2^32, which is not a real tx */
	assert(!mul_overflows_u64(fee_per_kw, weight));
	fee.satoshis = (u64)fee_per_kw * weight / 1000;

	return fee;
}

bool amount_asset_is_main(struct amount_asset *amount)
{
	/* If we're not on elements, there is only one asset. */
	if (!chainparams->is_elements)
		return true;

	/* If we are on elements we better check against the chainparams. */
	return memeq(amount->asset, sizeof(amount->asset),
		     chainparams->fee_asset_tag, sizeof(amount->asset));
}

/* Convert from a generic asset to the fee-paying asset if possible. */
struct amount_sat amount_asset_to_sat(struct amount_asset *amount)
{
	struct amount_sat sats;
	assert(amount_asset_is_main(amount));
	sats.satoshis = amount->value; /* Raw: low-level conversion */
	return sats;
}
