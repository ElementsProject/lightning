#include "config.h"
#include <assert.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/str/str.h>
#include <common/gossmap.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <plugins/askrene/askrene.h>
#include <plugins/askrene/reserve.h>

/* Note!  We can have multiple of these! */
struct reserve {
	/* What */
	struct reserve_hop rhop;
	/* When */
	struct timemono timestamp;
	/* ID of command which reserved it */
	const char *cmd_id;
};

/* Hash table for reservations */
static const struct short_channel_id_dir *
reserve_scidd(const struct reserve *r)
{
	return &r->rhop.scidd;
}

static bool reserve_eq_scidd(const struct reserve *r,
			     const struct short_channel_id_dir *scidd)
{
	return short_channel_id_dir_eq(scidd, &r->rhop.scidd);
}

HTABLE_DEFINE_DUPS_TYPE(struct reserve, reserve_scidd, hash_scidd,
			reserve_eq_scidd, reserve_htable);

struct reserve_htable *new_reserve_htable(const tal_t *ctx)
{
	struct reserve_htable *reserved = tal(ctx, struct reserve_htable);
	reserve_htable_init(reserved);
	return reserved;
}

void reserve_add(struct reserve_htable *reserved,
		 const struct reserve_hop *rhop,
		 const char *cmd_id TAKES)
{
	struct reserve *r = tal(reserved, struct reserve);
	r->rhop = *rhop;
	r->timestamp = time_mono();
	r->cmd_id = tal_strdup(r, cmd_id);

	reserve_htable_add(reserved, r);
}

bool reserve_remove(struct reserve_htable *reserved,
		    const struct reserve_hop *rhop)
{
	struct reserve *r;
	struct reserve_htable_iter rit;

	/* Note!  This may remove the "wrong" one, but since they're only
	 * differentiated for debugging, that's OK */
	for (r = reserve_htable_getfirst(reserved, &rhop->scidd, &rit);
	     r;
	     r = reserve_htable_getnext(reserved, &rhop->scidd, &rit)) {
		if (!amount_msat_eq(r->rhop.amount, rhop->amount))
			continue;

		reserve_htable_del(reserved, r);
		tal_free(r);
		return true;
	}
	return false;
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
		struct gossmap_chan *c = gossmap_find_chan(gossmap, &r->rhop.scidd.scid);
		size_t idx;
		if (!c)
			continue;
		idx = gossmap_chan_idx(gossmap, c);
		if (idx < tal_count(capacities))
			capacities[idx] = 0;
	}
}

void reserve_sub(const struct reserve_htable *reserved,
		 const struct short_channel_id_dir *scidd,
		 struct amount_msat *amount)
{
	struct reserve *r;
	struct reserve_htable_iter rit;

	for (r = reserve_htable_getfirst(reserved, scidd, &rit);
	     r;
	     r = reserve_htable_getnext(reserved, scidd, &rit)) {
		if (!amount_msat_sub(amount, *amount, r->rhop.amount))
			*amount = AMOUNT_MSAT(0);
	}
}

bool reserve_accumulate(const struct reserve_htable *reserved,
			const struct short_channel_id_dir *scidd,
			struct amount_msat *amount)
{
	struct reserve *r;
	struct reserve_htable_iter rit;

	for (r = reserve_htable_getfirst(reserved, scidd, &rit);
	     r;
	     r = reserve_htable_getnext(reserved, scidd, &rit)) {
		if (!amount_msat_add(amount, *amount, r->rhop.amount))
			return false;
	}
	return true;
}

void json_add_reservations(struct json_stream *js,
			   const struct reserve_htable *reserved,
			   const char *fieldname)
{
	struct reserve *r;
	struct reserve_htable_iter rit;

	json_array_start(js, fieldname);
	for (r = reserve_htable_first(reserved, &rit);
	     r;
	     r = reserve_htable_next(reserved, &rit)) {
		json_object_start(js, NULL);
		json_add_short_channel_id_dir(js,
					      "short_channel_id_dir",
					      r->rhop.scidd);
		json_add_amount_msat(js,
				     "amount_msat",
				     r->rhop.amount);
		json_add_u64(js, "age_in_seconds",
			     timemono_between(time_mono(), r->timestamp).ts.tv_sec);
		json_add_string(js, "command_id", r->cmd_id);
		json_object_end(js);
	}
	json_array_end(js);
}

const char *fmt_reservations(const tal_t *ctx,
			     const struct reserve_htable *reserved,
			     const struct short_channel_id_dir *scidd)
{
	struct reserve *r;
	struct reserve_htable_iter rit;
	char *ret = NULL;

	for (r = reserve_htable_getfirst(reserved, scidd, &rit);
	     r;
	     r = reserve_htable_getnext(reserved, scidd, &rit)) {
		u64 seconds;
		if (!ret)
			ret = tal_strdup(ctx, "");
		else
			tal_append_fmt(&ret, ", ");
		tal_append_fmt(&ret, "%s by command %s",
			       fmt_amount_msat(tmpctx, r->rhop.amount), r->cmd_id);
		seconds = timemono_between(time_mono(), r->timestamp).ts.tv_sec;
		/* Add a note if it's old */
		if (seconds > 0)
			tal_append_fmt(&ret, " (%"PRIu64" seconds ago)", seconds);
	}
	return ret;
}

void reserve_memleak_mark(struct askrene *askrene, struct htable *memtable)
{
	memleak_scan_htable(memtable, &askrene->reserved->raw);
}
