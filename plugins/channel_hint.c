#include "config.h"
#include <plugins/channel_hint.h>

void channel_hint_to_json(const char *name, const struct channel_hint *hint,
			  struct json_stream *dest)
{
	json_object_start(dest, name);
	json_add_u32(dest, "timestamp", hint->timestamp);
	json_add_short_channel_id_dir(dest, "scid", hint->scid);
	json_add_amount_msat(dest, "estimated_capacity_msat",
			     hint->estimated_capacity);
	json_add_amount_msat(dest, "capacity_msat",
			     hint->capacity);
	json_add_bool(dest, "enabled", hint->enabled);
	json_object_end(dest);
}

#define PAY_REFILL_TIME 7200

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
	u64 seconds = now.ts.tv_sec - hint->timestamp;
	if (!amount_msat_mul(&refill, hint->capacity, seconds))
		abort();

	refill = amount_msat_div(refill, PAY_REFILL_TIME);
	if (!amount_msat_add(&hint->estimated_capacity,
			     hint->estimated_capacity, refill))
		abort();

	/* Clamp the value to the `overall_capacity` */
	if (amount_msat_greater(hint->estimated_capacity,
				hint->capacity))
		hint->estimated_capacity = hint->capacity;

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
	return !hint->enabled || amount_msat_greater(hint->capacity,
						     hint->estimated_capacity);
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
	struct channel_hint *hint = tal(ctx, struct channel_hint);
	ret = json_scan(ctx, buffer, toks,
			"{timestamp:%,scid:%,estimated_capacity_msat:%,capacity_msat:%,enabled:%}",
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
	set->hints = tal_arr(set, struct channel_hint, 0);
	return set;
}

void channel_hint_set_add(struct channel_hint_set *set, const struct channel_hint *hint)
{
	abort();
}

/* Find the position of a routehint in the hints list. Allows for
 * in-place updates in some cases. */
static bool channel_hint_set_find_index(struct channel_hint_set *set,
					struct short_channel_id_dir *scidd,
					size_t *index)
{
	struct channel_hint *hint;
	for (size_t i = 0; i < tal_count(set->hints); index++) {
		hint = &set->hints[i];
		if (short_channel_id_dir_eq(scidd, &hint->scid)) {
			*index = i;
			return true;
		}
	}
	return false;
}

struct channel_hint *channel_hint_set_find(struct channel_hint_set *set,
					   struct short_channel_id_dir *scidd)
{
	size_t index;

	if (!channel_hint_set_find_index(set, scidd, &index))
		return NULL;

	return &set->hints[index];
}

void channel_hint_set_update(struct channel_hint_set *set,
			     const struct timeabs now)
{
	for (size_t i = 0; i < tal_count(set->hints); i++)
		channel_hint_update(now, &set->hints[i]);
}

bool channel_hint_set_add(struct channel_hint_set *self,
			  struct channel_hint *hint)
{
	/* Start by checking if we already have a channel_hint, update
	 * it if yes. */
	struct channel_hint *old = channel_hint_set_find(self, &hint->scid);
	struct timeabs now = time_now();
	if (old != NULL) {
		/* Start by projecting both to now, so we can compare and merge
		 * them. */
		channel_hint_update(now, old);
		channel_hint_update(now, hint);
		assert(hint->timestamp == old->timestamp);

		/* If either indicate this channel is disabled, keep
		 * it disabled. */
		/* Evaluate: A newer observation may mark this as
		 * enabled, however we likely won't ever try that
		 * channel until the hint expires anyway, so this
		 * simple logic may be sufficient already. */
		old->enabled = hint->enabled && old->enabled;

		/* Keep the more restrictive one. */
		old->estimated_capacity = amount_msat_min(
		    old->estimated_capacity, hint->estimated_capacity);

		/* If we don't have exact channel sizes we
		 * approximate. These can be off. Always take the
		 * least restrictive as the best estimate. */
		old->overall_capacity = amount_msat_max(old->overall_capacity, hint->overall_capacity);
		return false;
	} else {
		/* OK, this is the simple case, just add it to the end
		 * of the tal_arr. */
		tal_arr_expand(&self->hints, *hint);
		return true;
	}
}
