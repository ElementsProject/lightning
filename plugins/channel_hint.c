#include "config.h"
#include <common/memleak.h>
#include <plugins/channel_hint.h>

size_t channel_hint_hash(const struct short_channel_id_dir *out)
{
	struct siphash24_ctx ctx;
	siphash24_init(&ctx, siphash_seed());
	siphash24_update(&ctx, &out->scid.u64, sizeof(u64));
	siphash24_update(&ctx, &out->dir, sizeof(int));
	return siphash24_done(&ctx);
}

const struct short_channel_id_dir *channel_hint_keyof(const struct channel_hint *out)
{
	return &out->scid;
}

bool channel_hint_eq(const struct channel_hint *a,
		     const struct short_channel_id_dir *b)
{
	return short_channel_id_eq(a->scid.scid, b->scid) &&
		a->scid.dir == b->dir;
}

static void memleak_help_channel_hint_map(struct htable *memtable,
					 struct channel_hint_map *channel_hints)
{
	memleak_scan_htable(memtable, &channel_hints->raw);
}

void channel_hint_to_json(const char *name, const struct channel_hint *hint,
			  struct json_stream *dest)
{
	json_object_start(dest, name);
	json_add_u32(dest, "timestamp", hint->timestamp);
	json_add_short_channel_id_dir(dest, "scid", hint->scid);
	json_add_amount_msat(dest, "estimated_capacity_msat",
			     hint->estimated_capacity);
	json_add_amount_msat(dest, "total_capacity_msat", hint->capacity);
	json_add_bool(dest, "enabled", hint->enabled);
	json_object_end(dest);
}

/* How long until even a channel whose estimate is down at 0msat will
 * be considered fully refilled. The refill rate is the inverse of
 * this times the channel size. The refilling is a linear
 * approximation, with a small hysteresis applied in order to prevent
 * a single payment relaxing its own constraints thus causing it to
 * prematurely retry an already attempted channel.
 */
#define PAY_REFILL_TIME 7200

/* Add an artificial delay before accepting updates. This ensures we
 * don't actually end up relaxing a tight constraint inbetween the
 * attempt that added it and the next retry. If we were to relax right
 * away, then we could end up retrying the exact same path we just
 * failed at.  If the `time_between_attempts * refill > 1msat`, we'd
 * end up not actually constraining at all, because we set the
 * estimate to `attempt - 1msat`. This also results in the updates
 * being limited to once every minute, and causes a stairway
 * pattern. The hysteresis has to be >60s otherwise a single payment
 * can already end up retrying a previously excluded channel.
 */
#define PAY_REFILL_HYSTERESIS 60
/**
 * Update the `channel_hint` in place, return whether it should be kept.
 *
 * This computes the refill-rate based on the overall capacity, and
 * the time elapsed since the last update and relaxes the upper bound
 * on the capacity, and resets the enabled flag if appropriate. If the
 * hint is no longer useful, i.e., it does not provide any additional
 * information on top of the structural information we've learned from
 * the gossip, then we return `false` to signal that the
 * `channel_hint` may be removed.
 */
bool channel_hint_update(const struct timeabs now, struct channel_hint *hint)
{
	/* Precision is not required here, so integer division is good
	 * enough. But keep the order such that we do not round down
	 * too much. We do so by first multiplying, before
	 * dividing. The formula is `current = last + delta_t *
	 * overall / refill_rate`.
	 */
	struct amount_msat refill;
	struct amount_msat capacity = hint->capacity;

	if (now.ts.tv_sec < hint->timestamp + PAY_REFILL_HYSTERESIS)
		return true;

	u64 seconds = now.ts.tv_sec - hint->timestamp;
	if (!amount_msat_mul(&refill, capacity, seconds))
		abort();

	refill = amount_msat_div(refill, PAY_REFILL_TIME);
	if (!amount_msat_add(&hint->estimated_capacity,
			     hint->estimated_capacity, refill))
		abort();

	/* Clamp the value to the `overall_capacity` */
	if (amount_msat_greater(hint->estimated_capacity, capacity))
		hint->estimated_capacity = capacity;

	/* TODO This is rather coarse. We could map the disabled flag
	to having 0msat capacity, and then relax from there. But it'd
	likely be too slow of a relaxation.*/
	if (seconds > 60)
		hint->enabled = true;

	/* Since we update in-place we should make sure that we can
	 * just call update again and the result is stable, if no time
	 * has passed. */
	hint->timestamp = now.ts.tv_sec;

	/* We report this hint as useless, if the hint does not
	 * restrict the channel, i.e., if it is enabled and the
	 * estimate is the same as the overall capacity. */
	return !hint->enabled ||
	       amount_msat_greater(capacity, hint->estimated_capacity);
}

struct channel_hint *channel_hint_set_find(const struct channel_hint_set *self,
					   const struct short_channel_id_dir *scidd)
{
	return channel_hint_map_get(self->hints, scidd);
}

/* See header */
struct channel_hint *
channel_hint_set_add(struct channel_hint_set *self, u32 timestamp,
		     const struct short_channel_id_dir *scidd, bool enabled,
		     const struct amount_msat *estimated_capacity,
		     const struct amount_msat capacity, u16 *htlc_budget)
{
	struct channel_hint *copy, *old, *newhint;

	/* If the channel is marked as enabled it must have an estimate. */
	assert(!enabled || estimated_capacity != NULL);

	/* If there was no hint, add the new one, if there was one,
	 * pick the one with the newer timestamp. */
	old = channel_hint_set_find(self, scidd);
	copy = tal_dup(tmpctx, struct channel_hint, old);
	if (old == NULL) {
		newhint = tal(self, struct channel_hint);
		newhint->enabled = enabled;
		newhint->scid = *scidd;
		newhint->capacity = capacity;
		if (estimated_capacity != NULL)
			newhint->estimated_capacity = *estimated_capacity;
		newhint->local = NULL;
		newhint->timestamp = timestamp;
		channel_hint_map_add(self->hints, newhint);
		return newhint;
	} else if (old->timestamp <= timestamp) {
		/* `local` is kept, since we do not pass in those
		 * annotations here. */
		old->enabled = enabled;
		old->timestamp = timestamp;
		if (estimated_capacity != NULL)
			old->estimated_capacity = *estimated_capacity;

		/* We always pick the larger of the capacities we are
		 * being told. This is because in some cases, such as
		 * routehints, we're not actually being told the total
		 * capacity, just lower values. */
		if (amount_msat_greater(capacity, old->capacity))
			old->capacity = capacity;

		return copy;
	} else {
		return NULL;
	}
}

/**
 * Load a channel_hint from its JSON representation.
 *
 * @return The initialized `channel_hint` or `NULL` if we encountered a parsing
 *         error.
 */
struct channel_hint *channel_hint_from_json(const tal_t *ctx,
					    const char *buffer,
					    const jsmntok_t *toks)
{
	const char *ret;
	const jsmntok_t *payload = json_get_member(buffer, toks, "payload"),
			*jhint =
			    json_get_member(buffer, payload, "channel_hint");
	struct channel_hint *hint = tal(ctx, struct channel_hint);

	ret = json_scan(ctx, buffer, jhint,
			"{timestamp:%,scid:%,estimated_capacity_msat:%,total_capacity_msat:%,enabled:%}",
			JSON_SCAN(json_to_u32, &hint->timestamp),
			JSON_SCAN(json_to_short_channel_id_dir, &hint->scid),
			JSON_SCAN(json_to_msat, &hint->estimated_capacity),
			JSON_SCAN(json_to_msat, &hint->capacity),
			JSON_SCAN(json_to_bool, &hint->enabled));

	if (ret != NULL)
		hint = tal_free(hint);
	return hint;
}

struct channel_hint_set *channel_hint_set_new(const tal_t *ctx)
{
	struct channel_hint_set *set = tal(ctx, struct channel_hint_set);
	set->hints = tal(set, struct channel_hint_map);
	channel_hint_map_init(set->hints);
	memleak_add_helper(set->hints, memleak_help_channel_hint_map);
	return set;
}

void channel_hint_set_update(struct channel_hint_set *set,
			     const struct timeabs now)
{
	struct channel_hint *hint;
	struct channel_hint_map_iter iter;
	for (hint = channel_hint_map_first(set->hints, &iter);
	     hint;
	     hint = channel_hint_map_next(set->hints, &iter))
		channel_hint_update(now, hint);
}

size_t channel_hint_set_count(const struct channel_hint_set *set)
{
	return channel_hint_map_count(set->hints);
}
