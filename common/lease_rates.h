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

WARN_UNUSED_RESULT bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates, struct amount_msat amt);

WARN_UNUSED_RESULT bool lease_rates_set_lease_fee_sat(struct lease_rates *rates, struct amount_sat amt);
#endif /* LIGHTNING_COMMON_LEASE_RATES_H */
