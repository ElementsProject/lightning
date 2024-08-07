#ifndef LIGHTNING_PLUGINS_ASKRENE_RESERVE_H
#define LIGHTNING_PLUGINS_ASKRENE_RESERVE_H
/* We have to know what payments are in progress, so we can take into
 * account the reduced capacity of channels.  We do this by telling
 * everyone to reserve / unreserve paths as they use them. */
#include "config.h"
#include <bitcoin/short_channel_id.h>
#include <common/amount.h>

/* We reserve a path being used.  This records how many and how much */
struct reserve {
	size_t num_htlcs;
	struct short_channel_id_dir scidd;
	struct amount_msat amount;
};

/* Initialize hash table for reservations */
struct reserve_hash *new_reserve_hash(const tal_t *ctx);

/* Find a reservation for this scidd (if any!) */
const struct reserve *find_reserve(const struct reserve_hash *reserved,
				   const struct short_channel_id_dir *scidd);

/* Atomically add to reserves, or fail.
 * Returns offset of failure, or num on success */
size_t reserves_add(struct reserve_hash *reserved,
		    const struct short_channel_id_dir *scidds,
		    const struct amount_msat *amounts,
		    size_t num);

/* Atomically remove from reserves, to fail.
 * Returns offset of failure or tal_count(scidds) */
size_t reserves_remove(struct reserve_hash *reserved,
		       const struct short_channel_id_dir *scidds,
		       const struct amount_msat *amounts,
		       size_t num);

#endif /* LIGHTNING_PLUGINS_ASKRENE_RESERVE_H */
