/* LGPL (v2.1 or any later version) - see LICENSE file for details */
#include <ccan/timer/timer.h>
#include <ccan/array_size/array_size.h>
#include <ccan/ilog/ilog.h>
#include <stdlib.h>
#include <stdio.h>

#define PER_LEVEL (1ULL << TIMER_LEVEL_BITS)

struct timer_level {
	struct list_head list[PER_LEVEL];
};

static uint64_t time_to_grains(struct timemono t)
{
	return t.ts.tv_sec * ((uint64_t)1000000000 / TIMER_GRANULARITY)
		+ (t.ts.tv_nsec / TIMER_GRANULARITY);
}

static struct timemono grains_to_time(uint64_t grains)
{
	struct timemono t;

	t.ts.tv_sec = grains / (1000000000 / TIMER_GRANULARITY);
	t.ts.tv_nsec = (grains % (1000000000 / TIMER_GRANULARITY))
		* TIMER_GRANULARITY;
	return t;
}

void timers_init(struct timers *timers, struct timemono start)
{
	unsigned int i;

	list_head_init(&timers->far);
	timers->base = time_to_grains(start);
	timers->first = -1ULL;
	memset(timers->firsts, 0xFF, sizeof(timers->firsts));
	for (i = 0; i < ARRAY_SIZE(timers->level); i++)
		timers->level[i] = NULL;
}

static unsigned int level_of(const struct timers *timers, uint64_t time)
{
	uint64_t diff;

	/* Level depends how far away it is. */
	diff = time - timers->base;
	return ilog64(diff / 2) / TIMER_LEVEL_BITS;
}

static void timer_add_raw(struct timers *timers, struct timer *t)
{
	struct list_head *l;
	unsigned int level = level_of(timers, t->time);
	uint64_t *first;

	if (!timers->level[level]) {
		l = &timers->far;
		first = &timers->firsts[ARRAY_SIZE(timers->level)];
	} else {
		int off = (t->time >> (level*TIMER_LEVEL_BITS)) & (PER_LEVEL-1);
		l = &timers->level[level]->list[off];
		first = &timers->firsts[level];
	}

	list_add_tail(l, &t->list);
	if (t->time < *first)
		*first = t->time;
}

void timer_init(struct timer *t)
{
	list_node_init(&t->list);
}

static bool list_node_initted(const struct list_node *n)
{
	return n->prev == n;
}

void timer_addrel(struct timers *timers, struct timer *t, struct timerel rel)
{
	assert(list_node_initted(&t->list));

	t->time = time_to_grains(timemono_add(time_mono(), rel));

#if TIME_HAVE_MONOTONIC
	assert(t->time >= timers->base);
#else
	/* Added in the past?  Treat it as imminent. */
	if (t->time < timers->base)
		t->time = timers->base;
#endif
	if (t->time < timers->first)
		timers->first = t->time;

	timer_add_raw(timers, t);
}

void timer_addmono(struct timers *timers, struct timer *t, struct timemono when)
{
	assert(list_node_initted(&t->list));

	t->time = time_to_grains(when);

	/* Added in the past?  Treat it as imminent. */
	if (t->time < timers->base)
		t->time = timers->base;
	if (t->time < timers->first)
		timers->first = t->time;

	timer_add_raw(timers, t);
}

/* FIXME: inline */
void timer_del(struct timers *timers UNNEEDED, struct timer *t)
{
	list_del_init(&t->list);
}

static void timers_far_get(struct timers *timers,
			   struct list_head *list,
			   uint64_t when)
{
	struct timer *i, *next;

	list_for_each_safe(&timers->far, i, next, list) {
		if (i->time <= when) {
			list_del_from(&timers->far, &i->list);
			list_add_tail(list, &i->list);
		}
	}
}

static void add_level(struct timers *timers, unsigned int level)
{
	struct timer_level *l;
	struct timer *t;
	unsigned int i;
	struct list_head from_far;

	l = malloc(sizeof(*l));
	if (!l)
		return;

	for (i = 0; i < ARRAY_SIZE(l->list); i++)
		list_head_init(&l->list[i]);
	timers->level[level] = l;

	list_head_init(&from_far);
	timers_far_get(timers, &from_far,
		       timers->base + (1ULL << ((level+1)*TIMER_LEVEL_BITS)) - 1);

	while ((t = list_pop(&from_far, struct timer, list)) != NULL)
		timer_add_raw(timers, t);
}

/* We don't need to search past the first at level 0, since the
 * bucket range is 1; they're all the same. */
static const struct timer *find_first(const struct list_head *list,
				      unsigned int level,
				      const struct timer *prev)
{
	struct timer *t;

	list_for_each(list, t, list) {
		if (!prev || t->time < prev->time)
			prev = t;
		if (level == 0)
			break;
	}
	return prev;
}

/* Update level's first watermark, and return overall first. */
static const struct timer *first_for_level(struct timers *timers,
					   size_t level,
					   const struct timer *level_first,
					   const struct timer *first)
{
	if (level_first) {
		timers->firsts[level] = level_first->time;
		if (!first || level_first->time < first->time)
			first = level_first;
	} else {
		timers->firsts[level] = -1ULL;
	}
	return first;
}

static bool level_may_beat(const struct timers *timers, size_t level,
			   const struct timer *first)
{
	return !first || timers->firsts[level] < first->time;
}

/* FIXME: Suboptimal */
static const struct timer *brute_force_first(struct timers *timers)
{
	unsigned int l, i;
	const struct timer *found = NULL;

	for (l = 0; l < ARRAY_SIZE(timers->level) && timers->level[l]; l++) {
		const struct timer *t = NULL;

		/* Do we know they don't have a better one? */
		if (!level_may_beat(timers, l, found))
			continue;

		/* Find first timer on this level. */
		for (i = 0; i < PER_LEVEL; i++)
			t = find_first(&timers->level[l]->list[i], l, t);

		found = first_for_level(timers, l, t, found);
	}

	/* Check (and update) far list if there's a chance. */
	l = ARRAY_SIZE(timers->level);
	if (level_may_beat(timers, l, found)) {
		const struct timer *t = find_first(&timers->far, l, NULL);
		found = first_for_level(timers, l, t, found);
	}

	return found;
}

static const struct timer *get_first(struct timers *timers)
{
	/* We can have just far timers, for example. */
	if (timers->level[0]) {
		/* First search rest of lower buckets; we've already spilled
		 * so if we find one there we don't need to search further. */
		unsigned int i, off = timers->base % PER_LEVEL;

		for (i = off; i < PER_LEVEL; i++) {
			struct list_head *h = &timers->level[0]->list[i];
			if (!list_empty(h))
				return find_first(h, 0, NULL);
		}
	}

	/* From here on, we're searching non-normalized parts of the
	 * data structure, which is much subtler.
	 *
	 * So we brute force. */
	return brute_force_first(timers);
}

static bool update_first(struct timers *timers)
{
	const struct timer *found = get_first(timers);

	if (!found) {
		timers->first = -1ULL;
		return false;
 	}

	timers->first = found->time;
	return true;
}

bool timer_earliest(struct timers *timers, struct timemono *first)
{
	if (!update_first(timers))
		return false;

	*first = grains_to_time(timers->first);
	return true;
}

/* Assume no timers before 'time', cascade down and update base time. */
static void timer_fast_forward(struct timers *timers, uint64_t time)
{
	unsigned int level, changed;
	int need_level = -1;
	struct list_head list;
	struct timer *i;

	/* How many bits changed between base and time?
	 * Each time we wrap, we need to empty buckets from above. */
	if (time == timers->base)
		return;

	changed = ilog64_nz(time ^ timers->base);
	level = (changed - 1) / TIMER_LEVEL_BITS;

	/* Buckets always empty downwards, so we could cascade manually,
	 * but it's rarely very many so we just remove and re-add */
	list_head_init(&list);

	do {
		if (!timers->level[level]) {
			/* We need any which belong on this level. */
			timers_far_get(timers, &list,
				       timers->base
				       + (1ULL << ((level+1)*TIMER_LEVEL_BITS))-1);
			need_level = level;
		} else {
			unsigned src;

			/* Get all timers from this bucket. */
			src = (time >> (level * TIMER_LEVEL_BITS)) % PER_LEVEL;
			list_append_list(&list,
					 &timers->level[level]->list[src]);
		}
	} while (level--);

	/* Did we hit the last level?  If so, add. */
	if (need_level != -1)
		add_level(timers, need_level);

	/* Fast-forward the time, and re-add everyone. */
	timers->base = time;
	while ((i = list_pop(&list, struct timer, list)) != NULL)
		timer_add_raw(timers, i);
}

/* Returns an expired timer. */
struct timer *timers_expire(struct timers *timers, struct timemono expire)
{
	uint64_t now = time_to_grains(expire);
	unsigned int off;
	struct timer *t;

	assert(now >= timers->base);

	if (!timers->level[0]) {
		if (list_empty(&timers->far))
			return NULL;
		add_level(timers, 0);
	}

	do {
		if (timers->first > now) {
			timer_fast_forward(timers, now);
			return NULL;
		}

		timer_fast_forward(timers, timers->first);
		off = timers->base % PER_LEVEL;

		/* This *may* be NULL, if we deleted the first timer */
		t = list_pop(&timers->level[0]->list[off], struct timer, list);
		if (t)
			list_node_init(&t->list);
	} while (!t && update_first(timers));

	return t;
}

static bool timer_list_check(const struct list_head *l,
			     uint64_t min, uint64_t max, uint64_t first,
			     const char *abortstr)
{
	const struct timer *t;

	if (!list_check(l, abortstr))
		return false;

	list_for_each(l, t, list) {
		if (t->time < min || t->time > max) {
			if (abortstr) {
				fprintf(stderr,
					"%s: timer %p %llu not %llu-%llu\n",
					abortstr, t, (long long)t->time,
					(long long)min, (long long)max);
				abort();
			}
			return false;
		}
		if (t->time < first) {
			if (abortstr) {
				fprintf(stderr,
					"%s: timer %p %llu < minimum %llu\n",
					abortstr, t, (long long)t->time,
					(long long)first);
				abort();
			}
			return false;
		}
	}
	return true;
}

struct timers *timers_check(const struct timers *timers, const char *abortstr)
{
	unsigned int l, i, off;
	uint64_t base;

	l = 0;
	if (!timers->level[0])
		goto past_levels;

	/* First level is simple. */
	off = timers->base % PER_LEVEL;
	for (i = 0; i < PER_LEVEL; i++) {
		struct list_head *h;

		h = &timers->level[l]->list[(i+off) % PER_LEVEL];
		if (!timer_list_check(h, timers->base + i, timers->base + i,
				      timers->firsts[l], abortstr))
			return NULL;
	}

	/* For other levels, "current" bucket has been emptied, and may contain
	 * entries for the current + level_size bucket. */
	for (l = 1; l < ARRAY_SIZE(timers->level) && timers->level[l]; l++) {
		uint64_t per_bucket = 1ULL << (TIMER_LEVEL_BITS * l);

		off = ((timers->base >> (l*TIMER_LEVEL_BITS)) % PER_LEVEL);
		/* We start at *next* bucket. */
		base = (timers->base & ~(per_bucket - 1)) + per_bucket;

		for (i = 1; i <= PER_LEVEL; i++) {
			struct list_head *h;

			h = &timers->level[l]->list[(i+off) % PER_LEVEL];
			if (!timer_list_check(h, base, base + per_bucket - 1,
					      timers->firsts[l], abortstr))
				return NULL;
			base += per_bucket;
		}
	}

past_levels:
	base = (timers->base & ~((1ULL << (TIMER_LEVEL_BITS * l)) - 1))
		+ (1ULL << (TIMER_LEVEL_BITS * l)) - 1;
	if (!timer_list_check(&timers->far, base, -1ULL,
			      timers->firsts[ARRAY_SIZE(timers->level)],
			      abortstr))
		return NULL;

	return (struct timers *)timers;
}

#ifdef CCAN_TIMER_DEBUG
static void dump_bucket_stats(FILE *fp, const struct list_head *h)
{
	unsigned long long min, max, num;
	struct timer *t;

	if (list_empty(h)) {
		printf("\n");
		return;
	}

	min = -1ULL;
	max = 0;
	num = 0;
	list_for_each(h, t, list) {
		if (t->time < min)
			min = t->time;
		if (t->time > max)
			max = t->time;
		num++;
	}
	fprintf(fp, " %llu (%llu-%llu)\n",
		num, min, max);
}

void timers_dump(const struct timers *timers, FILE *fp)
{
	unsigned int l, i, off;
	unsigned long long base;

	if (!fp)
		fp = stderr;

	fprintf(fp, "Base: %llu\n", (unsigned long long)timers->base);

	if (!timers->level[0])
		goto past_levels;

	fprintf(fp, "Level 0:\n");

	/* First level is simple. */
	off = timers->base % PER_LEVEL;
	for (i = 0; i < PER_LEVEL; i++) {
		const struct list_head *h;

		fprintf(fp, "  Bucket %llu (%lu):",
			(i+off) % PER_LEVEL, timers->base + i);
		h = &timers->level[0]->list[(i+off) % PER_LEVEL];
		dump_bucket_stats(fp, h);
	}

	/* For other levels, "current" bucket has been emptied, and may contain
	 * entries for the current + level_size bucket. */
	for (l = 1; l < ARRAY_SIZE(timers->level) && timers->level[l]; l++) {
		uint64_t per_bucket = 1ULL << (TIMER_LEVEL_BITS * l);

		off = ((timers->base >> (l*TIMER_LEVEL_BITS)) % PER_LEVEL);
		/* We start at *next* bucket. */
		base = (timers->base & ~(per_bucket - 1)) + per_bucket;

		fprintf(fp, "Level %u:\n", l);
		for (i = 1; i <= PER_LEVEL; i++) {
			const struct list_head *h;

			fprintf(fp, "  Bucket %llu (%llu - %llu):",
				(i+off) % PER_LEVEL,
				base, base + per_bucket - 1);

			h = &timers->level[l]->list[(i+off) % PER_LEVEL];
			dump_bucket_stats(fp, h);
			base += per_bucket;
		}
	}

past_levels:
	if (!list_empty(&timers->far)) {
		fprintf(fp, "Far timers:");
		dump_bucket_stats(fp, &timers->far);
	}
}
#endif

void timers_cleanup(struct timers *timers)
{
	unsigned int l;

	for (l = 0; l < ARRAY_SIZE(timers->level); l++)
		free(timers->level[l]);
}
