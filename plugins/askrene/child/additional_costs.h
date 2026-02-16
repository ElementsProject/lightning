#ifndef LIGHTNING_PLUGINS_ASKRENE_CHILD_ADDITIONAL_COSTS_H
#define LIGHTNING_PLUGINS_ASKRENE_CHILD_ADDITIONAL_COSTS_H
#include "config.h"
#include <ccan/htable/htable_type.h>
#include <ccan/tal/tal.h>

/* "spendable" for a channel assumes a single HTLC: for additional HTLCs,
 * the need to pay for fees (if we're the owner) reduces it */
struct per_htlc_cost {
	struct short_channel_id_dir scidd;
	struct amount_msat per_htlc_cost;
};

static inline const struct short_channel_id_dir *
per_htlc_cost_key(const struct per_htlc_cost *phc)
{
	return &phc->scidd;
}

static inline bool per_htlc_cost_eq_key(const struct per_htlc_cost *phc,
					const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &phc->scidd);
}

HTABLE_DEFINE_NODUPS_TYPE(struct per_htlc_cost,
			  per_htlc_cost_key,
			  hash_scidd,
			  per_htlc_cost_eq_key,
			  additional_cost_htable);

#endif /* LIGHTNING_PLUGINS_ASKRENE_CHILD_ADDITIONAL_COSTS_H */
