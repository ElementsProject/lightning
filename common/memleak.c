#include <assert.h>
#include <backtrace.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable.h>
#include <common/memleak.h>

#if DEVELOPER
static struct backtrace_state *backtrace_state;
static const void **notleaks;
static bool *notleak_children;

static size_t find_notleak(const tal_t *ptr)
{
	size_t i, nleaks = tal_count(notleaks);

	for (i = 0; i < nleaks; i++)
		if (notleaks[i] == ptr)
			return i;
	abort();
}

static void notleak_change(tal_t *ctx,
			   enum tal_notify_type type,
			   void *info)
{
	size_t i;

	if (type == TAL_NOTIFY_FREE) {
		i = find_notleak(ctx);
		memmove(notleaks + i, notleaks + i + 1,
			sizeof(*notleaks) * (tal_count(notleaks) - i - 1));
		memmove(notleak_children + i, notleak_children + i + 1,
			sizeof(*notleak_children)
			* (tal_count(notleak_children) - i - 1));
		tal_resize(&notleaks, tal_count(notleaks) - 1);
		tal_resize(&notleak_children, tal_count(notleak_children) - 1);
	} else if (type == TAL_NOTIFY_MOVE) {
		i = find_notleak(info);
		notleaks[i] = ctx;
	}
}

void *notleak_(const void *ptr, bool plus_children)
{
	size_t nleaks;

	/* If we're not tracking, don't do anything. */
	if (!notleaks)
		return cast_const(void *, ptr);

	nleaks = tal_count(notleaks);
	tal_resize(&notleaks, nleaks+1);
	tal_resize(&notleak_children, nleaks+1);
	notleaks[nleaks] = ptr;
	notleak_children[nleaks] = plus_children;

	tal_add_notifier(ptr, TAL_NOTIFY_FREE|TAL_NOTIFY_MOVE, notleak_change);
	return cast_const(void *, ptr);
}

static size_t hash_ptr(const void *elem, void *unused UNNEEDED)
{
	static struct siphash_seed seed;
	return siphash24(&seed, &elem, sizeof(elem));
}

static bool pointer_referenced(struct htable *memtable, const void *p)
{
	return htable_del(memtable, hash_ptr(p, NULL), p);
}

static void children_into_htable(const void *exclude1, const void *exclude2,
				 struct htable *memtable, const tal_t *p)
{
	const tal_t *i;

	for (i = tal_first(p); i; i = tal_next(i)) {
		const char *name = tal_name(i);

		if (p == exclude1 || p == exclude2)
			continue;

		if (name) {
			/* Don't add backtrace objects. */
			if (streq(name, "backtrace"))
				continue;

			/* Don't add tal_link objects */
			if (strends(name, "struct link")
			    || strends(name, "struct linkable"))
				continue;

			/* ccan/io allocates pollfd array. */
			if (strends(name, "struct pollfd[]") && !tal_parent(i))
				continue;

			/* Don't add tmpctx. */
			if (streq(name, "tmpctx"))
				continue;
		}
		htable_add(memtable, hash_ptr(i, NULL), i);
		children_into_htable(exclude1, exclude2, memtable, i);
	}
}

struct htable *memleak_enter_allocations(const tal_t *ctx,
					 const void *exclude1,
					 const void *exclude2)
{
	struct htable *memtable = tal(ctx, struct htable);
	htable_init(memtable, hash_ptr, NULL);

	/* First, add all pointers off NULL to table. */
	children_into_htable(exclude1, exclude2, memtable, NULL);

	tal_add_destructor(memtable, htable_clear);
	return memtable;
}

static void scan_for_pointers(struct htable *memtable, const tal_t *p)
{
	size_t i, n;

	/* Search for (aligned) pointers. */
	n = tal_bytelen(p) / sizeof(void *);
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

static void remove_with_children(struct htable *memtable, const tal_t *p)
{
	const tal_t *i;

	pointer_referenced(memtable, p);
	for (i = tal_first(p); i; i = tal_next(i))
		remove_with_children(memtable, i);
}

void memleak_remove_referenced(struct htable *memtable, const void *root)
{
	size_t i;

	/* Now delete the ones which are referenced. */
	memleak_scan_region(memtable, root);
	memleak_scan_region(memtable, notleaks);

	/* Those who asked tal children to be removed, do so. */
	for (i = 0; i < tal_count(notleaks); i++)
		if (notleak_children[i])
			remove_with_children(memtable, notleaks[i]);

	/* notleak_children array is not a leak */
	pointer_referenced(memtable, notleak_children);

	/* Remove memtable itself */
	pointer_referenced(memtable, memtable);
}

static bool ptr_match(const void *candidate, void *ptr)
{
	return candidate == ptr;
}

const void *memleak_get(struct htable *memtable, const uintptr_t **backtrace)
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

	/* Does it have a child called "backtrace"? */
	for (*backtrace = tal_first(i);
	     *backtrace;
	     *backtrace = tal_next(*backtrace)) {
		if (tal_name(*backtrace)
		    && streq(tal_name(*backtrace), "backtrace"))
			break;
	}

	return i;
}

static int append_bt(void *data, uintptr_t pc)
{
	uintptr_t *bt = data;

	if (bt[0] == 32)
		return 1;

	bt[bt[0]++] = pc;
	return 0;
}

static void add_backtrace(tal_t *parent UNUSED, enum tal_notify_type type UNNEEDED,
			  void *child)
{
	uintptr_t *bt = tal_arrz_label(child, uintptr_t, 32, "backtrace");

	/* First serves as counter. */
	bt[0] = 1;
	backtrace_simple(backtrace_state, 2, append_bt, NULL, bt);
	tal_add_notifier(child, TAL_NOTIFY_ADD_CHILD, add_backtrace);
}

void memleak_init(const tal_t *root, struct backtrace_state *bstate)
{
	assert(!notleaks);
	backtrace_state = bstate;
	notleaks = tal_arr(NULL, const void *, 0);
	notleak_children = tal_arr(notleaks, bool, 0);

	if (backtrace_state)
		tal_add_notifier(root, TAL_NOTIFY_ADD_CHILD, add_backtrace);
}

void memleak_cleanup(void)
{
	notleaks = tal_free(notleaks);
}
#endif /* DEVELOPER */
