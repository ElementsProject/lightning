/* CC0 (Public domain) - see LICENSE file for details. */
#ifdef CCAN_LIKELY_DEBUG
#include <ccan/likely/likely.h>
#include <ccan/hash/hash.h>
#include <ccan/htable/htable_type.h>
#include <stdlib.h>
#include <stdio.h>
struct trace {
	const char *condstr;
	const char *file;
	unsigned int line;
	bool expect;
	unsigned long count, right;
};

static size_t hash_trace(const struct trace *trace)
{
	return hash(trace->condstr, strlen(trace->condstr),
		    hash(trace->file, strlen(trace->file),
			 trace->line + trace->expect));
}

static bool trace_eq(const struct trace *t1, const struct trace *t2)
{
	return t1->condstr == t2->condstr
		&& t1->file == t2->file
		&& t1->line == t2->line
		&& t1->expect == t2->expect;
}

/* struct thash */
HTABLE_DEFINE_TYPE(struct trace, (const struct trace *), hash_trace, trace_eq,
		   thash);

static struct thash htable
= { HTABLE_INITIALIZER(htable.raw, thash_hash, NULL) };

static void init_trace(struct trace *trace,
		       const char *condstr, const char *file, unsigned int line,
		       bool expect)
{
	trace->condstr = condstr;
	trace->file = file;
	trace->line = line;
	trace->expect = expect;
	trace->count = trace->right = 0;
}

static struct trace *add_trace(const struct trace *t)
{
	struct trace *trace = malloc(sizeof(*trace));
	*trace = *t;
	thash_add(&htable, trace);
	return trace;
}

long _likely_trace(bool cond, bool expect,
		   const char *condstr,
		   const char *file, unsigned int line)
{
	struct trace *p, trace;

	init_trace(&trace, condstr, file, line, expect);
	p = thash_get(&htable, &trace);
	if (!p)
		p = add_trace(&trace);

	p->count++;
	if (cond == expect)
		p->right++;

	return cond;
}

static double right_ratio(const struct trace *t)
{
	return (double)t->right / t->count;
}

char *likely_stats(unsigned int min_hits, unsigned int percent)
{
	struct trace *worst;
	double worst_ratio;
	struct thash_iter i;
	char *ret;
	struct trace *t;

	worst = NULL;
	worst_ratio = 2;

	/* This is O(n), but it's not likely called that often. */
	for (t = thash_first(&htable, &i); t; t = thash_next(&htable, &i)) {
		if (t->count >= min_hits) {
			if (right_ratio(t) < worst_ratio) {
				worst = t;
				worst_ratio = right_ratio(t);
			}
		}
	}

	if (worst_ratio * 100 > percent)
		return NULL;

	ret = malloc(strlen(worst->condstr) +
		     strlen(worst->file) +
		     sizeof(long int) * 8 +
		     sizeof("%s:%u:%slikely(%s) correct %u%% (%lu/%lu)"));
	sprintf(ret, "%s:%u:%slikely(%s) correct %u%% (%lu/%lu)",
		worst->file, worst->line,
		worst->expect ? "" : "un", worst->condstr,
		(unsigned)(worst_ratio * 100),
		worst->right, worst->count);

	thash_del(&htable, worst);
	free(worst);

	return ret;
}

void likely_stats_reset(void)
{
	struct thash_iter i;
	struct trace *t;

	/* This is a bit better than O(n^2), but we have to loop since
	 * first/next during delete is unreliable. */
	while ((t = thash_first(&htable, &i)) != NULL) {
		for (; t; t = thash_next(&htable, &i)) {
			thash_del(&htable, t);
			free(t);
		}
	}

	thash_clear(&htable);
}
#endif /*CCAN_LIKELY_DEBUG*/
