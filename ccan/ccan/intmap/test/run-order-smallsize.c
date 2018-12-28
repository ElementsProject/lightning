#define intmap_index_t uint8_t
#define sintmap_index_t int8_t

#include <ccan/intmap/intmap.c>
#include <ccan/tap/tap.h>
#include <stdio.h>

#define NUM 100

typedef UINTMAP(uint8_t *) umap;
typedef SINTMAP(int8_t *) smap;

static bool check_umap(const umap *map)
{
	/* This is a larger type than unsigned, and allows negative */
	int64_t prev;
	intmap_index_t i, last_idx;
	uint8_t *v;
	bool last = true;

	/* Must be in order, must contain value. */
	prev = -1;
	for (v = uintmap_first(map, &i); v; v = uintmap_after(map, &i)) {
		if (i <= prev)
			return false;
		if (*v != i)
			return false;
		prev = i;
		last = (uintmap_last(map, &last_idx) == v);
	}
	return last;
}

static bool check_smap(const smap *map)
{
	/* This is a larger type than int, and allows negative */
	int64_t prev;
	sintmap_index_t i, last_idx;
	int8_t *v;
	bool last = true;

	/* Must be in order, must contain value. */
	prev = -0x80000001ULL;
	for (v = sintmap_first(map, &i); v; v = sintmap_after(map, &i)) {
		if (i <= prev)
			return false;
		if (*v != i)
			return false;
		prev = i;
		last = (sintmap_last(map, &last_idx) == v);
	}
	return last;
}

int main(void)
{
	umap umap;
	smap smap;
	int i;
	uint8_t urandoms[NUM];
	int8_t srandoms[NUM];

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
