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
	json_add_amount_msat(dest, "overall_capacity_msat",
			     hint->overall_capacity);
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
	if (!amount_msat_mul(&refill, hint->overall_capacity, seconds))
		abort();

	refill = amount_msat_div(refill, PAY_REFILL_TIME);
	if (!amount_msat_add(&hint->estimated_capacity,
			     hint->estimated_capacity, refill))
		abort();

	/* Clamp the value to the `overall_capacity` */
	if (amount_msat_greater(hint->estimated_capacity,
				hint->overall_capacity))
		hint->estimated_capacity = hint->overall_capacity;

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
	return !hint->enabled || amount_msat_greater(hint->overall_capacity,
						     hint->estimated_capacity);
}

/**
 * Load a channel_hint from its JSON representation.
 *
 * @return The initialized `channel_hint` or `NULL` if we encountered a parsing
 *         error.
 */
/*
struct channel_hint *channel_hint_from_json(const tal_t *ctx,
						   const char *buffer,
						   const jsmntok_t *toks)
{
	const char *ret;
	const jsmntok_t *payload = json_get_member(buffer, toks, "payload"),
			*jhint =
			    json_get_member(buffer, payload, "channel_hint");
	struct channel_hint *hint = tal(ctx, struct channel_hint);
	ret = json_scan(ctx, buffer, toks,
			"{timestamp:%,scid:%,estimated_capacity_msat:%,overall_capacity_msat:%,enabled:%}",
			JSON_SCAN(json_to_u32, &hint->timestamp),
			JSON_SCAN(json_to_short_channel_id_dir, &hint->scid),
			JSON_SCAN(json_to_msat, &hint->estimated_capacity),
			JSON_SCAN(json_to_bool, &hint->enabled));

	if (ret != NULL)
		hint = tal_free(hint);
	return hint;
}
*/
