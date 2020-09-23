#include <assert.h>
#include <backtrace.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable.h>
#include <ccan/intmap/intmap.h>
#include <common/daemon.h>
#include <common/memleak.h>
#include <common/utils.h>

struct backtrace_state *backtrace_state;

#if DEVELOPER
static bool memleak_track;

struct memleak_notleak {
	bool plus_children;
};

struct memleak_helper {
	void (*cb)(struct htable *memtable, const tal_t *);
};

void *notleak_(const void *ptr, bool plus_children)
{
	struct memleak_notleak *notleak;

	/* If we're not tracking, don't do anything. */
	if (!memleak_track)
		return cast_const(void *, ptr);

	notleak = tal(ptr, struct memleak_notleak);
	notleak->plus_children = plus_children;
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

		if (i == exclude1 || i == exclude2)
			return;

		if (name) {
			/* Don't add backtrace objects. */
			if (streq(name, "backtrace"))
				continue;

			/* Don't add our own memleak_helpers or notleak() */
			if (strends(name, "struct memleak_helper")
			    || strends(name, "struct memleak_notleak"))
				continue;

			/* Don't add tal_link objects */
			if (strends(name, "struct link")
			    || strends(name, "struct linkable"))
				continue;

			/* ccan/io allocates pollfd array, always array. */
			if (strends(name, "struct pollfd[]") && !tal_parent(i))
				continue;

			if (strends(name, "struct io_plan *[]") && !tal_parent(i))
				continue;

			/* Don't add tmpctx. */
			if (streq(name, "tmpctx"))
				continue;
		}
		htable_add(memtable, hash_ptr(i, NULL), i);
		children_into_htable(exclude1, exclude2, memtable, i);
	}
}

static void scan_for_pointers(struct htable *memtable,
			      const tal_t *p, size_t bytelen)
{
	size_t i, n;

	/* Search for (aligned) pointers. */
	n = bytelen / sizeof(void *);
	for (i = 0; i < n; i++) {
		void *ptr;

		memcpy(&ptr, (char *)p + i * sizeof(void *), sizeof(ptr));
		if (pointer_referenced(memtable, ptr))
			scan_for_pointers(memtable, ptr, tal_bytelen(ptr));
	}
}

void memleak_scan_region(struct htable *memtable,
			 const void *ptr, size_t bytelen)
{
	pointer_referenced(memtable, ptr);
	scan_for_pointers(memtable, ptr, bytelen);
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
	/* Now delete the ones which are referenced. */
	memleak_scan_region(memtable, root, tal_bytelen(root));

	/* Remove memtable itself */
	pointer_referenced(memtable, memtable);
}

/* memleak can't see inside hash tables, so do them manually */
void memleak_remove_htable(struct htable *memtable, const struct htable *ht)
{
	struct htable_iter i;
	const void *p;

	for (p = htable_first(ht, &i); p; p = htable_next(ht, &i))
		memleak_scan_region(memtable, p, tal_bytelen(p));
}

/* FIXME: If uintmap used tal, this wouldn't be necessary! */
void memleak_remove_intmap_(struct htable *memtable, const struct intmap *m)
{
	void *p;
	intmap_index_t i;

	for (p = intmap_first_(m, &i); p; p = intmap_after_(m, &i))
		memleak_scan_region(memtable, p, tal_bytelen(p));
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

static void add_backtrace_notifiers(const tal_t *root)
{
	tal_add_notifier(root, TAL_NOTIFY_ADD_CHILD, add_backtrace);

	for (tal_t *i = tal_first(root); i; i = tal_next(i))
		add_backtrace_notifiers(i);
}

void memleak_add_helper_(const tal_t *p,
			 void (*cb)(struct htable *memtable, const tal_t *))
{
	struct memleak_helper *mh = tal(p, struct memleak_helper);
	mh->cb = cb;
}


/* Handle allocations marked with helpers or notleak() */
static void call_memleak_helpers(struct htable *memtable, const tal_t *p)
{
	const tal_t *i;

	for (i = tal_first(p); i; i = tal_next(i)) {
		const char *name = tal_name(i);

		if (name && strends(name, "struct memleak_helper")) {
			const struct memleak_helper *mh = i;
			mh->cb(memtable, p);
		} else if (name && strends(name, "struct memleak_notleak")) {
			const struct memleak_notleak *notleak = i;
			if (notleak->plus_children)
				remove_with_children(memtable, p);
			else
				pointer_referenced(memtable, p);
			memleak_scan_region(memtable, p, tal_bytelen(p));
		} else if (name && strends(name, "_notleak")) {
			pointer_referenced(memtable, i);
			call_memleak_helpers(memtable, i);
		} else {
			call_memleak_helpers(memtable, i);
		}
	}
}

struct htable *memleak_enter_allocations(const tal_t *ctx,
					 const void *exclude1,
					 const void *exclude2)
{
	struct htable *memtable = tal(ctx, struct htable);
	htable_init(memtable, hash_ptr, NULL);

	if (memleak_track) {
		/* First, add all pointers off NULL to table. */
		children_into_htable(exclude1, exclude2, memtable, NULL);

		/* Iterate and call helpers to eliminate hard-to-get references. */
		call_memleak_helpers(memtable, NULL);
	}

	tal_add_destructor(memtable, htable_clear);
	return memtable;
}

void memleak_init(void)
{
	memleak_track = true;
	if (backtrace_state)
		add_backtrace_notifiers(NULL);
}
#else /* !DEVELOPER */
void *notleak_(const void *ptr, bool plus_children UNNEEDED)
{
	return cast_const(void *, ptr);
}
#endif /* !DEVELOPER */
