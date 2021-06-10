#ifndef LIGHTNING_COMMON_LEASE_RATES_H
#define LIGHTNING_COMMON_LEASE_RATES_H
#include "config.h"
#include <stdbool.h>

struct lease_rates;

bool lease_rates_empty(struct lease_rates *rates);
#endif /* LIGHTNING_COMMON_LEASE_RATES_H */
