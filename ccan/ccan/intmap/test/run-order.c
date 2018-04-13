#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

#define NUM 1000

typedef UINTMAP(unsigned int *) umap;
typedef SINTMAP(int *) smap;

static bool uint_iterate_check(intmap_index_t i, unsigned int *v, int64_t *prev)
{
	if ((int64_t)i <= *prev)
		return false;
	if (*v != i)
		return false;
	*prev = i;
	return true;
}

static bool check_umap(const umap *map)
{
	/* This is a larger type than unsigned, and allows negative */
	int64_t prev;
	uint64_t i, last_idx;
	unsigned int *v;
	bool last = true;

	/* Must be in order, must contain value. */
	prev = -1;
	for (v = uintmap_first(map, &i); v; v = uintmap_after(map, &i)) {
		if ((int64_t)i <= prev)
			return false;
		if (*v != i)
			return false;
		prev = i;
		last = (uintmap_last(map, &last_idx) == v);
	}

	if (!last)
		return false;

	prev = -1;
	return uintmap_iterate(map, uint_iterate_check, &prev);
}

static bool sint_iterate_check(sintmap_index_t i, int *v, int64_t *prev)
{
	if (i <= *prev)
		return false;
	if (*v != i)
		return false;
	*prev = i;
	return true;
}

static bool check_smap(const smap *map)
{
	/* This is a larger type than int, and allows negative */
	int64_t prev, i, last_idx;
	int *v;
	bool last = true;

	/* Must be in order, must contain value. */
	prev = -0x80000001ULL;
	for (v = sintmap_first(map, &i); v; v = sintmap_after(map, &i)) {
		if (i <= prev)
			return false;
		if (*v != i)
			return false;
		last = (sintmap_last(map, &last_idx) == v);
		prev = i;
	}

	if (!last)
		return false;

	prev = -1;
	return sintmap_iterate(map, sint_iterate_check, &prev);
}

int main(void)
{
	umap umap;
	smap smap;
	int i;
	unsigned int urandoms[NUM];
	int srandoms[NUM];

	plan_tests(6 * NUM + 2);
	uintmap_init(&umap);
	sintmap_init(&smap);

	for (i = 0; i < NUM; i++) {
		urandoms[i] = random();
		srandoms[i] = random();
	}
	for (i = 0; i < NUM; i++) {
		/* In case we have duplicates. */
		while (!uintmap_add(&umap, urandoms[i], urandoms+i))
			urandoms[i] = random();
		ok1(check_umap(&umap));
	}
	for (i = 0; i < NUM; i++) {
		ok1(uintmap_del(&umap, urandoms[i]) == urandoms+i);
		ok1(check_umap(&umap));
	}
	ok1(uintmap_empty(&umap));

	for (i = 0; i < NUM; i++) {
		/* In case we have duplicates. */
		while (!sintmap_add(&smap, srandoms[i], srandoms+i))
			srandoms[i] = random();
		ok1(check_smap(&smap));
	}
	for (i = 0; i < NUM; i++) {
		ok1(sintmap_del(&smap, srandoms[i]) == srandoms+i);
		ok1(check_smap(&smap));
	}
	ok1(sintmap_empty(&smap));

	/* This exits depending on whether all tests passed */
	return exit_status();
}
