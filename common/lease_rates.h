#ifndef LIGHTNING_COMMON_LEASE_RATES_H
#define LIGHTNING_COMMON_LEASE_RATES_H
#include "config.h"
#include <stdbool.h>

struct amount_msat;
struct amount_sat;
struct lease_rates;
struct pubkey;
struct sha256;

#define LEASE_RATE_DURATION 4032

bool lease_rates_empty(struct lease_rates *rates);

void lease_rates_get_commitment(struct pubkey *pubkey,
				u32 lease_expiry,
				u32 chan_fee_msat,
				u16 chan_fee_ppt,
				struct sha256 *sha);

bool lease_rates_eq(struct lease_rates *l1,
		    struct lease_rates *l2);

bool lease_rates_calc_fee(struct lease_rates *rates,
			  struct amount_sat accept_funding_sats,
			  struct amount_sat requested_sats,
			  u32 onchain_feerate,
			  struct amount_sat *fee);

WARN_UNUSED_RESULT bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates, struct amount_msat amt);

WARN_UNUSED_RESULT bool lease_rates_set_lease_fee_sat(struct lease_rates *rates, struct amount_sat amt);

/* Convert 'lease_rates' into a hexstring */
char *lease_rates_tohex(const tal_t *ctx, const struct lease_rates *rates);

/* Convert 'lease_rates' from a hexstring */
bool lease_rates_fromhex(const tal_t *ctx,
			 const char *hexdata, size_t len,
			 struct lease_rates **rates);

/* Format a string describing the passed in lease_rates */
char *lease_rates_fmt(const tal_t *ctx, const struct lease_rates *rates);
#endif /* LIGHTNING_COMMON_LEASE_RATES_H */
