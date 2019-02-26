#ifndef LIGHTNING_COMMON_AMOUNT_H
#define LIGHTNING_COMMON_AMOUNT_H
#include "config.h"
#include <ccan/build_assert/build_assert.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/tal.h>
#include <stdbool.h>

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

/* You may not always be able to convert satoshis->millisatoshis. */
WARN_UNUSED_RESULT bool amount_sat_to_msat(struct amount_msat *msat,
					   struct amount_sat sat);

/* You can always truncate millisatoshis->satoshis. */
struct amount_sat amount_msat_to_sat_round_down(struct amount_msat msat);

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
WARN_UNUSED_RESULT bool amount_sat_sub_msat(struct amount_msat *val,
					    struct amount_sat a,
					    struct amount_msat b);

/* Is a == b? */
bool amount_sat_eq(struct amount_sat a, struct amount_sat b);
bool amount_msat_eq(struct amount_msat a, struct amount_msat b);

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

/* Common operation: what is the HTLC fee for given feerate?  Can overflow! */
WARN_UNUSED_RESULT bool amount_msat_fee(struct amount_msat *fee,
					struct amount_msat amt,
					u32 fee_base_msat,
					u32 fee_proportional_millionths);

/* Same, but add into amt. */
WARN_UNUSED_RESULT bool amount_msat_add_fee(struct amount_msat *amt,
					    u32 fee_base_msat,
					    u32 fee_proportional_millionths);

/* What is the fee for this tx weight? */
struct amount_sat amount_tx_fee(u32 fee_per_kw, size_t weight);

/* Different formatting by amounts: btc, sat and msat */
/* => 1.23456789012btc (11 decimals!) */
const char *fmt_amount_msat_btc(const tal_t *ctx,
				const struct amount_msat *msat,
				bool append_unit);
/* => 1234msat */
const char *fmt_amount_msat(const tal_t *ctx, const struct amount_msat *msat);

/* => 1.23456789btc (8 decimals!) */
const char *fmt_amount_sat_btc(const tal_t *ctx,
			       const struct amount_sat *sat,
			       bool append_unit);
/* => 1234sat */
const char *fmt_amount_sat(const tal_t *ctx, const struct amount_sat *sat);

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

#endif /* LIGHTNING_COMMON_AMOUNT_H */
