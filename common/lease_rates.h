#ifndef LIGHTNING_COMMON_LEASE_RATES_H
#define LIGHTNING_COMMON_LEASE_RATES_H
#include "config.h"
#include <stdbool.h>

struct amount_msat;
struct amount_sat;
struct lease_rates;

bool lease_rates_empty(struct lease_rates *rates);

WARN_UNUSED_RESULT bool lease_rates_set_chan_fee_base_msat(struct lease_rates *rates, struct amount_msat amt);

WARN_UNUSED_RESULT bool lease_rates_set_lease_fee_sat(struct lease_rates *rates, struct amount_sat amt);
#endif /* LIGHTNING_COMMON_LEASE_RATES_H */
