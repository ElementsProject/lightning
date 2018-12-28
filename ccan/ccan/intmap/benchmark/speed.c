/* Test speed of intmap */
#include <ccan/time/time.h>
#include <ccan/intmap/intmap.h>
#include <ccan/isaac/isaac64.h>
#include <ccan/htable/htable_type.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

/* hack to let us gather span. */
struct node {
	/* These point to strings or nodes. */
	struct intmap child[2];
	/* Encoding both prefix and critbit: 1 is appended to prefix. */
	intmap_index_t prefix_and_critbit;
};

static void update_span(const void *p, size_t s, uintptr_t *min, uintptr_t *max)
{
	if ((uintptr_t)p < *min)
		*min = (uintptr_t)p;
	if ((uintptr_t)p + s > *max)
		*max = (uintptr_t)p + s;
}

static void getspan(const struct intmap *m, uintptr_t *min, uintptr_t *max)
{
	struct node *n;
	/* Leaf node? */
	if (m->v)
		return;

	n = m->u.n;
	update_span(n, sizeof(*n), min, max);
	getspan(&n->child[0], min, max);
	getspan(&n->child[1], min, max);
}

struct htable_elem {
	uint64_t index;
	uint64_t *v;
};

static struct siphash_seed sipseed;

static uint64_t keyof(const struct htable_elem *elem)
{
	return elem->index;
}

static size_t hashfn(const uint64_t index)
{
	return siphash24(&sipseed, &index, sizeof(index));
}

static bool eqfn(const struct htable_elem *elem, const uint64_t index)
{
	return elem->index == index;
}
HTABLE_DEFINE_TYPE(struct htable_elem, keyof, hashfn, eqfn, hash);

static bool check_val(intmap_index_t i, uint64_t *v, uint64_t *expected)
{
	if (v != expected)
		abort();
	return true;
}

int main(int argc, char *argv[])
{
	uint64_t i, total = 0, seed, *v;
	size_t max = argv[1] ? atol(argv[1]) : 100000000;
	isaac64_ctx isaac;
	struct timeabs start, end;
	UINTMAP(uint64_t *) map;
	struct hash hash;
	struct htable_elem *e;
	struct hash_iter it;
	uintptr_t span_min, span_max;

	uintmap_init(&map);
	hash_init(&hash);

	/* We don't want our randomness function to dominate the time,
	 * nor deal with duplicates (just abort, that's v. unlikely) */
	seed = time_now().ts.tv_sec + time_now().ts.tv_nsec;
	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));

	start = time_now();
	for (i = 0; i < max; i++)
		total += isaac64_next_uint64(&isaac);
	end = time_now();
	printf("%zu,random generation (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (i = 0; i < max; i++) {
		if (!uintmap_add(&map, isaac64_next_uint64(&isaac), &i))
			abort();
	}
	end = time_now();
	printf("%zu,critbit insert (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (i = 0; i < max; i++) {
		if (uintmap_get(&map, isaac64_next_uint64(&isaac)) != &i)
			abort();
	}
	end = time_now();
	printf("%zu,critbit successful lookup (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	start = time_now();
	for (i = 0; i < max; i++) {
		if (uintmap_get(&map, isaac64_next_uint64(&isaac)))
			abort();
	}
	end = time_now();
	printf("%zu,critbit failed lookup (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (v = uintmap_first(&map, &i); v; v = uintmap_after(&map, &i)) {
		if (v != &i)
			abort();
	}
	end = time_now();
	printf("%zu,critbit iteration (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	start = time_now();
	uintmap_iterate(&map, check_val, &i);
	end = time_now();
	printf("%zu,critbit callback iteration (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	span_min = -1ULL;
	span_max = 0;
	getspan(uintmap_unwrap_(&map), &span_min, &span_max);
	printf("%zu,critbit memory (bytes),%zu\n",
	       max, (size_t)(span_max - span_min + max / 2) / max);

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (i = 0; i < max; i++) {
		if (!uintmap_del(&map, isaac64_next_uint64(&isaac)))
			abort();
	}
	end = time_now();
	printf("%zu,critbit delete (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	/* Fill with consecutive values */
	for (i = 0; i < max; i++) {
		if (!uintmap_add(&map, i, &i))
			abort();
	}
	start = time_now();
	for (v = uintmap_first(&map, &i); v; v = uintmap_after(&map, &i)) {
		if (v != &i)
			abort();
	}
	end = time_now();
	printf("%zu,critbit consecutive iteration (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	start = time_now();
	uintmap_iterate(&map, check_val, &i);
	end = time_now();
	printf("%zu,critbit consecutive callback iteration (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	sipseed.u.u64[0] = isaac64_next_uint64(&isaac);
	sipseed.u.u64[1] = isaac64_next_uint64(&isaac);

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (i = 0; i < max; i++) {
		e = malloc(sizeof(*e));
		e->v = &i;
		e->index = isaac64_next_uint64(&isaac);
		hash_add(&hash, e);
	}
	end = time_now();
	printf("%zu,hash insert (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (i = 0; i < max; i++) {
		if (hash_get(&hash, isaac64_next_uint64(&isaac))->v != &i)
			abort();
	}
	end = time_now();
	printf("%zu,hash successful lookup (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	start = time_now();
	for (i = 0; i < max; i++) {
		if (hash_get(&hash, isaac64_next_uint64(&isaac)))
			abort();
	}
	end = time_now();
	printf("%zu,hash failed lookup (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (e = hash_first(&hash, &it); e; e = hash_next(&hash, &it)) {
		if (e->v != &i)
			abort();
	}
	end = time_now();
	printf("%zu,hash iteration (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	span_min = -1ULL;
	span_max = 0;
	for (e = hash_first(&hash, &it); e; e = hash_next(&hash, &it))
		update_span(e, sizeof(*e), &span_min, &span_max);
	/* table itself tends to be allocated in separate memory. */
	span_max += (sizeof(uintptr_t) << hash.raw.bits);
	printf("%zu,hash memory (bytes),%zu\n",
	       max, (size_t)(span_max - span_min + max / 2) / max);

	isaac64_init(&isaac, (unsigned char *)&seed, sizeof(seed));
	start = time_now();
	for (i = 0; i < max; i++) {
		e = hash_get(&hash, isaac64_next_uint64(&isaac));
		if (!hash_del(&hash, e))
			abort();
		free(e);
	}
	end = time_now();
	printf("%zu,hash delete (nsec),%"PRIu64"\n", max,
	       time_to_nsec(time_divide(time_between(end, start), max)));

	/* Use total, but "never happens". */
	return (total == 0);
}
