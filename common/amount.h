#ifndef LIGHTNING_COMMON_AMOUNT_H
#define LIGHTNING_COMMON_AMOUNT_H
#include "config.h"
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>

#define MSAT_PER_SAT ((u64)1000)
#define SAT_PER_BTC ((u64)100000000)
#define MSAT_PER_BTC (MSAT_PER_SAT * SAT_PER_BTC)

/* Use these to wrap amounts, for typesafety.  Please use ops where possible,
 * rather than accessing the members directly. */
struct amount_sat {
	/* Amount in satoshis. */
	u64 satoshis;
};

struct amount_msat {
	/* Amount in millisatoshis. */
	u64 millisatoshis;
};

struct amount_asset {
	u64 value;
	u8 asset[33]; /* 1 version byte + 32 byte asset_tag */
};

/* For constants only: others must be built from primitives! */
#if HAVE_BUILTIN_CONSTANT_P
#define AMOUNT_MUST_BE_CONST(c) BUILD_ASSERT_OR_ZERO(IS_COMPILE_CONSTANT(c))
#else
#define AMOUNT_MUST_BE_CONST(c) 0
#endif

/* GCC 4.8.5 (Centos 7.6!) thinks struct casts are not constants, so we
 * need to not use a cast for static initializations. */
#define AMOUNT_MSAT_INIT(msat)		\
	{ .millisatoshis = (msat) }
#define AMOUNT_SAT_INIT(sat)		\
	{ .satoshis = (sat) }

#define AMOUNT_MSAT(constant)						\
	((struct amount_msat){(constant) + AMOUNT_MUST_BE_CONST(constant)})

#define AMOUNT_SAT(constant)						\
	((struct amount_sat){(constant) + AMOUNT_MUST_BE_CONST(constant)})

/* We do sometimes need to import from raw types, eg. wally or wire fmt */
struct amount_msat amount_msat(u64 millisatoshis);
struct amount_sat amount_sat(u64 satoshis);

/* You may not always be able to convert satoshis->millisatoshis. */
WARN_UNUSED_RESULT bool amount_sat_to_msat(struct amount_msat *msat,
					   struct amount_sat sat);

/* You may not always be able to convert millisatoshis->satoshis without rounding. */
WARN_UNUSED_RESULT bool amount_msat_to_sat(struct amount_sat *sat,
					   struct amount_msat msat);

/* You can always truncate millisatoshis->satoshis. */
struct amount_sat amount_msat_to_sat_round_down(struct amount_msat msat);

/* The msats truncated by `amount_msat_to_sat_round_down` */
struct amount_msat amount_msat_to_sat_remainder(struct amount_msat msat);

/* Simple operations: val = a + b, val = a - b. */
WARN_UNUSED_RESULT bool amount_msat_add(struct amount_msat *val,
					struct amount_msat a,
					struct amount_msat b);
WARN_UNUSED_RESULT bool amount_msat_sub(struct amount_msat *val,
					struct amount_msat a,
					struct amount_msat b);
WARN_UNUSED_RESULT bool amount_sat_add(struct amount_sat *val,
				       struct amount_sat a,
				       struct amount_sat b);
WARN_UNUSED_RESULT bool amount_sat_sub(struct amount_sat *val,
				       struct amount_sat a,
				       struct amount_sat b);
WARN_UNUSED_RESULT bool amount_msat_sub_sat(struct amount_msat *val,
					    struct amount_msat a,
					    struct amount_sat b);
WARN_UNUSED_RESULT bool amount_msat_add_sat(struct amount_msat *val,
					    struct amount_msat a,
					    struct amount_sat b);
WARN_UNUSED_RESULT bool amount_sat_sub_msat(struct amount_msat *val,
					    struct amount_sat a,
					    struct amount_msat b);
WARN_UNUSED_RESULT bool amount_msat_scale(struct amount_msat *val,
					  struct amount_msat msat,
					  double scale);
WARN_UNUSED_RESULT bool amount_sat_scale(struct amount_sat *val,
					 struct amount_sat sat,
					 double scale);

WARN_UNUSED_RESULT bool amount_msat_add_sat_s64(struct amount_msat *val,
						struct amount_msat a,
						s64 b);

WARN_UNUSED_RESULT bool amount_sat_add_sat_s64(struct amount_sat *val,
					       struct amount_sat a,
					       s64 b);

struct amount_msat amount_msat_div(struct amount_msat msat, u64 div);
struct amount_sat amount_sat_div(struct amount_sat sat, u64 div);

bool amount_sat_mul(struct amount_sat *res, struct amount_sat sat, u64 mul);
bool amount_msat_mul(struct amount_msat *res, struct amount_msat msat, u64 mul);

/* Is a == b? */
bool amount_sat_eq(struct amount_sat a, struct amount_sat b);
bool amount_msat_eq(struct amount_msat a, struct amount_msat b);

/* Is a zero? */
bool amount_sat_zero(struct amount_sat a);
bool amount_msat_zero(struct amount_msat a);

/* Is a > b? */
bool amount_sat_greater(struct amount_sat a, struct amount_sat b);
bool amount_msat_greater(struct amount_msat a, struct amount_msat b);

/* Is a >= b */
bool amount_sat_greater_eq(struct amount_sat a, struct amount_sat b);
bool amount_msat_greater_eq(struct amount_msat a, struct amount_msat b);

/* Is a < b? */
bool amount_sat_less(struct amount_sat a, struct amount_sat b);
bool amount_msat_less(struct amount_msat a, struct amount_msat b);

/* Is a <= b? */
bool amount_sat_less_eq(struct amount_sat a, struct amount_sat b);
bool amount_msat_less_eq(struct amount_msat a, struct amount_msat b);

/* Is msat > sat? */
bool amount_msat_greater_sat(struct amount_msat msat, struct amount_sat sat);
/* Is msat >= sat? */
bool amount_msat_greater_eq_sat(struct amount_msat msat, struct amount_sat sat);
/* Is msat < sat? */
bool amount_msat_less_sat(struct amount_msat msat, struct amount_sat sat);
/* Is msat <= sat? */
bool amount_msat_less_eq_sat(struct amount_msat msat, struct amount_sat sat);
/* Is msat == sat? */
bool amount_msat_eq_sat(struct amount_msat msat, struct amount_sat sat);

/* a / b */
double amount_msat_ratio(struct amount_msat a, struct amount_msat b);

/* min(a,b) and max(a,b) */
static inline struct amount_msat amount_msat_min(struct amount_msat a,
						 struct amount_msat b)
{
	return amount_msat_less(a, b) ? a : b;
}

static inline struct amount_msat amount_msat_max(struct amount_msat a,
						 struct amount_msat b)
{
	return amount_msat_greater(a, b) ? a : b;
}

/* Check whether this asset is actually the main / fee-paying asset of the
 * current chain. */
bool amount_asset_is_main(struct amount_asset *asset);

/* Convert an amount_sat to an amount_asset */
struct amount_asset amount_sat_to_asset(struct amount_sat *sat, const u8 *asset);

/* amount_asset_extract_value -Prefix the amount_asset's value
 * to have the 'explicit' marker. Returns NULL if the
 * asset was originally blinded.
 * FIXME: pass through blinded amounts */
u8 *amount_asset_extract_value(const tal_t *ctx, struct amount_asset *asset);

/* Convert from a generic asset to the fee-paying asset if possible. */
struct amount_sat amount_asset_to_sat(struct amount_asset *asset);

/* Returns true if msat fits in a u32 value. */
WARN_UNUSED_RESULT bool amount_msat_to_u32(struct amount_msat msat,
					   u32 *millisatoshis);

/* Common operation: what is the HTLC fee for given feerate?  Can overflow! */
WARN_UNUSED_RESULT bool amount_msat_fee(struct amount_msat *fee,
					struct amount_msat amt,
					u32 fee_base_msat,
					u32 fee_proportional_millionths);

/* Same, but add into amt. */
WARN_UNUSED_RESULT bool amount_msat_add_fee(struct amount_msat *amt,
					    u32 fee_base_msat,
					    u32 fee_proportional_millionths);

/* Reversed: what is the largest possible output for a given input and fee? */
struct amount_msat amount_msat_sub_fee(struct amount_msat input,
				       u32 fee_base_msat,
				       u32 fee_proportional_millionths);

/* What is the fee for this tx weight? */
struct amount_sat amount_tx_fee(u32 fee_per_kw, size_t weight);

/* What is the feerate given this fee and (non-zero!) weight? */
WARN_UNUSED_RESULT bool amount_feerate(u32 *feerate, struct amount_sat fee, size_t weight);

/* Different formatting by amounts: btc, sat and msat */
/* => 1.23456789012btc (11 decimals!) */
const char *fmt_amount_msat_btc(const tal_t *ctx,
				struct amount_msat msat,
				bool append_unit);
/* => 1234msat */
char *fmt_amount_msat(const tal_t *ctx, struct amount_msat msat);

/* => 1.23456789btc (8 decimals!) */
const char *fmt_amount_sat_btc(const tal_t *ctx,
			       struct amount_sat sat,
			       bool append_unit);
/* => 1234sat */
char *fmt_amount_sat(const tal_t *ctx, struct amount_sat sat);

/* Valid strings:
 *  [0-9]+ => millisatoshi.
 *  [0-9]+msat => millisatoshi.
 *  [0-9]+sat => *1000 -> millisatopshi.
 *  [0-9]+.[0-9]{1,11}btc => millisatoshi.
 */
bool parse_amount_msat(struct amount_msat *msat, const char *s, size_t slen);

/* Valid strings:
 *  [0-9]+ => satoshi.
 *  [0-9]+sat => satoshi.
 *  [0-9]+000msat => satoshi.
 *  [0-9]+.[0-9]{1,8}btc => satoshi.
 */
bool parse_amount_sat(struct amount_sat *sat, const char *s, size_t slen);

/* Marshal/unmarshal functions */
struct amount_msat fromwire_amount_msat(const u8 **cursor, size_t *max);
struct amount_sat fromwire_amount_sat(const u8 **cursor, size_t *max);
void towire_amount_msat(u8 **pptr, const struct amount_msat msat);
void towire_amount_sat(u8 **pptr, const struct amount_sat sat);
#endif /* LIGHTNING_COMMON_AMOUNT_H */
