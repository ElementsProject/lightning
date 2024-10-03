#ifndef LIGHTNING_PLUGINS_ASKRENE_RESERVE_H
#define LIGHTNING_PLUGINS_ASKRENE_RESERVE_H
/* We have to know what payments are in progress, so we can take into
 * account the reduced capacity of channels.  We do this by telling
 * everyone to reserve / unreserve paths as they use them. */
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <common/amount.h>
#include <common/fp16.h>

/* Initialize hash table for reservations */
struct reserve_htable *new_reserve_htable(const tal_t *ctx);

struct reserve_hop {
	struct short_channel_id_dir scidd;
	struct amount_msat amount;
};

/* Add a reservation */
void reserve_add(struct reserve_htable *reserved,
		 const struct reserve_hop *rhop,
		 const char *cmd_id TAKES);

/* Try to remove a reservation, if it exists. */
bool reserve_remove(struct reserve_htable *reserved,
		    const struct reserve_hop *rhop);

/* Clear capacities array where we have reserves */
void reserves_clear_capacities(struct reserve_htable *reserved,
			       const struct gossmap *gossmap,
			       fp16_t *capacities);

/* Subtract any reserves for scidd from this amount */
void reserve_sub(const struct reserve_htable *reserved,
		 const struct short_channel_id_dir *scidd,
		 struct amount_msat *amount);

/* Scan for memleaks */
void reserve_memleak_mark(struct askrene *askrene, struct htable *memtable);
#endif /* LIGHTNING_PLUGINS_ASKRENE_RESERVE_H */
