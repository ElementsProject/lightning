#include "config.h"
#include <assert.h>
#include <ccan/htable/htable_type.h>
#include <common/gossmap.h>
#include <common/memleak.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/reserve.h>

/* Hash table for reservations */
static const struct short_channel_id_dir *
reserve_scidd(const struct reserve *r)
{
	return &r->scidd;
}

static size_t hash_scidd(const struct short_channel_id_dir *scidd)
{
	/* scids cost money to generate, so simple hash works here */
	return (scidd->scid.u64 >> 32) ^ (scidd->scid.u64 >> 16) ^ (scidd->scid.u64 << 1) ^ scidd->dir;
}

static bool reserve_eq_scidd(const struct reserve *r,
			     const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &r->scidd);
}

HTABLE_DEFINE_TYPE(struct reserve, reserve_scidd, hash_scidd,
		   reserve_eq_scidd, reserve_htable);

struct reserve_htable *new_reserve_htable(const tal_t *ctx)
{
	struct reserve_htable *reserved = tal(ctx, struct reserve_htable);
	reserve_htable_init(reserved);
	return reserved;
}

/* Find a reservation for this scidd (if any!) */
const struct reserve *find_reserve(const struct reserve_htable *reserved,
				   const struct short_channel_id_dir *scidd)
{
	return reserve_htable_get(reserved, scidd);
}

/* Create a new (empty) reservation */
static struct reserve *new_reserve(struct reserve_htable *reserved,
				   const struct short_channel_id_dir *scidd)
{
	struct reserve *r = tal(reserved, struct reserve);

	r->num_htlcs = 0;
	r->amount = AMOUNT_MSAT(0);
	r->scidd = *scidd;

	reserve_htable_add(reserved, r);
	return r;
}

static void del_reserve(struct reserve_htable *reserved, struct reserve *r)
{
	assert(r->num_htlcs == 0);

	reserve_htable_del(reserved, r);
	tal_free(r);
}

/* Add to existing reservation (false if would overflow). */
static bool add(struct reserve *r, struct amount_msat amount)
{
	if (!amount_msat_accumulate(&r->amount, amount))
		return false;
	r->num_htlcs++;
	return true;
}

static bool remove(struct reserve *r, struct amount_msat amount)
{
	if (r->num_htlcs == 0)
		return false;
	if (!amount_msat_sub(&r->amount, r->amount, amount))
		return false;
	r->num_htlcs--;
	return true;
}

/* Atomically add to reserves, or fail.
 * Returns offset of failure, or num on success */
size_t reserves_add(struct reserve_htable *reserved,
		    const struct short_channel_id_dir *scidds,
		    const struct amount_msat *amounts,
		    size_t num)
{
	for (size_t i = 0; i < num; i++) {
		struct reserve *r = reserve_htable_get(reserved, &scidds[i]);
		if (!r)
			r = new_reserve(reserved, &scidds[i]);
		if (!add(r, amounts[i])) {
			reserves_remove(reserved, scidds, amounts, i);
			return i;
		}
	}
	return num;
}

/* Atomically remove from reserves, to fail.
 * Returns offset of failure or tal_count(scidds) */
size_t reserves_remove(struct reserve_htable *reserved,
		       const struct short_channel_id_dir *scidds,
		       const struct amount_msat *amounts,
		       size_t num)
{
	for (size_t i = 0; i < num; i++) {
		struct reserve *r = reserve_htable_get(reserved, &scidds[i]);
		if (!r || !remove(r, amounts[i])) {
			reserves_add(reserved, scidds, amounts, i);
			return i;
		}
		if (r->num_htlcs == 0)
			del_reserve(reserved, r);
	}
	return num;
}

void reserves_clear_capacities(struct reserve_htable *reserved,
			       const struct gossmap *gossmap,
			       fp16_t *capacities)
{
	struct reserve *r;
	struct reserve_htable_iter rit;

	for (r = reserve_htable_first(reserved, &rit);
	     r;
	     r = reserve_htable_next(reserved, &rit)) {
		struct gossmap_chan *c = gossmap_find_chan(gossmap, &r->scidd.scid);
		size_t idx;
		if (!c)
			continue;
		idx = gossmap_chan_idx(gossmap, c);
		if (idx < tal_count(capacities))
			capacities[idx] = 0;
	}
}

void reserve_memleak_mark(struct askrene *askrene, struct htable *memtable)
{
	memleak_scan_htable(memtable, &askrene->reserved->raw);
}
