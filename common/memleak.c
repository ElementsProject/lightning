#include <ccan/cast/cast.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable.h>
#include <ccan/tal/tal.h>
#include <common/memleak.h>

#if DEVELOPER
static const void **notleaks;

void *notleak_(const void *ptr)
{
	size_t nleaks;

	/* If we're not tracking, don't do anything. */
	if (!notleaks)
		return cast_const(void *, ptr);

	/* FIXME: Doesn't work with reallocs, but tal_steal breaks lifetimes */
	nleaks = tal_count(notleaks);
	tal_resize(&notleaks, nleaks+1);
	notleaks[nleaks] = ptr;
	return cast_const(void *, ptr);
}

/* This only works if all objects have tal_len() */
#ifndef CCAN_TAL_DEBUG
#error CCAN_TAL_DEBUG must be set
#endif

static size_t hash_ptr(const void *elem, void *unused UNNEEDED)
{
	static struct siphash_seed seed;
	return siphash24(&seed, &elem, sizeof(elem));
}

static bool pointer_referenced(struct htable *memtable, const void *p)
{
	return htable_del(memtable, hash_ptr(p, NULL), p);
}

static void children_into_htable(const void *exclude,
				 struct htable *memtable, const tal_t *p)
{
	const tal_t *i;

	for (i = tal_first(p); i; i = tal_next(i)) {
		if (p == exclude)
			continue;
		htable_add(memtable, hash_ptr(i, NULL), i);
		children_into_htable(exclude, memtable, i);
	}
}

struct htable *memleak_enter_allocations(const tal_t *ctx, const void *exclude)
{
	struct htable *memtable = tal(ctx, struct htable);
	htable_init(memtable, hash_ptr, NULL);

	/* First, add all pointers off NULL to table. */
	children_into_htable(exclude, memtable, NULL);

	tal_add_destructor(memtable, htable_clear);
	return memtable;
}

static void scan_for_pointers(struct htable *memtable, const tal_t *p)
{
	size_t i, n;

	/* Search for (aligned) pointers. */
	n = tal_len(p) / sizeof(void *);
	for (i = 0; i < n; i++) {
		void *ptr;

		memcpy(&ptr, (char *)p + i * sizeof(void *), sizeof(ptr));
		if (pointer_referenced(memtable, ptr))
			scan_for_pointers(memtable, ptr);
	}
}

void memleak_scan_region(struct htable *memtable, const void *ptr)
{
	pointer_referenced(memtable, ptr);
	scan_for_pointers(memtable, ptr);
}

void memleak_remove_referenced(struct htable *memtable, const void *root)
{
	/* Now delete the ones which are referenced. */
	memleak_scan_region(memtable, root);
	memleak_scan_region(memtable, notleaks);

	/* Remove memtable itself */
	pointer_referenced(memtable, memtable);
}

static void remove_with_children(struct htable *memtable, const tal_t *p)
{
	const tal_t *i;

	pointer_referenced(memtable, p);
	for (i = tal_first(p); i; i = tal_next(i))
		remove_with_children(memtable, i);
}

static bool ptr_match(const void *candidate, void *ptr)
{
	return candidate == ptr;
}

const void *memleak_get(struct htable *memtable)
{
	struct htable_iter it;
	const tal_t *i, *p;

	i = htable_first(memtable, &it);
	if (!i)
		return NULL;

	/* Delete from table (avoids parenting loops) */
	htable_delval(memtable, &it);

	/* Find ancestor, which is probably source of leak. */
	for (p = tal_parent(i);
	     htable_get(memtable, hash_ptr(p, NULL), ptr_match, p);
	     i = p, p = tal_parent(i));

	/* Delete all children */
	remove_with_children(memtable, i);

	return i;
}

void memleak_init(const tal_t *root)
{
	notleaks = tal_arr(NULL, const void *, 0);
}

void memleak_cleanup(void)
{
	notleaks = tal_free(notleaks);
}
#endif /* DEVELOPER */
