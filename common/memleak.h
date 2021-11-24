#ifndef LIGHTNING_COMMON_MEMLEAK_H
#define LIGHTNING_COMMON_MEMLEAK_H
#include "config.h"
#include <ccan/strmap/strmap.h>
#include <ccan/tal/tal.h>
#include <inttypes.h>

struct htable;

/**
 * memleak_init: Initialize memleak detection; you call this at the start!
 *
 * notleak() won't have an effect if called before this (but naming
 * tal objects with suffix _notleak works).
 */
void memleak_init(void);

/**
 * notleak: remove a false-positive tal object.
 * @p: the tal allocation.
 *
 * This marks a tal pointer (and anything it refers to) as not being
 * leaked.  Think hard before using this!
 */
#define notleak(p) ((memleak_typeof(p))notleak_((p), false))

/* Mark a pointer and all its tal children as not being leaked.
 * You don't want this; it's for simplifying handling of the incoming
 * command which asks lightningd to do the dev check. */
#define notleak_with_children(p) ((memleak_typeof(p))notleak_((p), true))

#if HAVE_TYPEOF
#define memleak_typeof(var) typeof(var)
#else
#define memleak_typeof(var) void *
#endif /* !HAVE_TYPEOF */

void *notleak_(void *ptr, bool plus_children);

#if DEVELOPER
/**
 * memleak_add_helper: help memleak look inside this tal object
 * @p: the tal object
 * @cb: the callback.
 *
 * memleak looks for tal pointers inside a tal object memory, but some
 * structures which use bit-stealing on pointers or use non-tal allocations
 * will need this.
 *
 * The callback usually calls memleak_remove_*.
 */
#define memleak_add_helper(p, cb)					\
	memleak_add_helper_((p),					\
			    typesafe_cb_preargs(void, const tal_t *,	\
						(cb), (p),		\
						struct htable *))
#else
/* Don't refer to cb at all if !DEVELOPER */
#define memleak_add_helper(p, cb)
#endif

/* For update-mock: memleak_add_helper_ mock empty */
void memleak_add_helper_(const tal_t *p, void (*cb)(struct htable *memtable,
						    const tal_t *));

/**
 * memleak_find_allocations:  allocate a htable with all tal objects;
 * @ctx: the context to allocate the htable from
 * @exclude1: one tal pointer to exclude from adding (if non-NULL)
 * @exclude2: second tal pointer to exclude from adding (if non-NULL)
 *
 * Note that exclude1 and exclude2's tal children are also not added.
 */
struct htable *memleak_find_allocations(const tal_t *ctx,
					const void *exclude1,
					const void *exclude2);

/**
 * memleak_remove_region - remove this region and anything it references
 * @memtable: the memtable create by memleak_find_allocations.
 * @p: the pointer to remove.
 * @bytelen: the bytes within it to scan for more pointers.
 *
 * This removes @p from the memtable, then looks for any tal pointers
 * inside between @p and @p + @bytelen and calls
 * memleak_remove_region() on those if not already removed.
 */
void memleak_remove_region(struct htable *memtable,
			   const void *p, size_t bytelen);

/**
 * memleak_remove_pointer - remove this pointer
 * @memtable: the memtable create by memleak_find_allocations.
 * @p: the pointer to remove.
 *
 * This removes @p from the memtable.
 */
#define memleak_remove_pointer(memtable, p) \
	memleak_remove_region((memtable), (p), 0)

/* Helper to remove objects inside this htable (which is opaque to memleak). */
void memleak_remove_htable(struct htable *memtable, const struct htable *ht);

/* Helper to remove objects inside this uintmap (which is opaque to memleak). */
#define memleak_remove_uintmap(memtable, umap)		\
	memleak_remove_intmap_(memtable, uintmap_unwrap_(umap))

struct intmap;
void memleak_remove_intmap_(struct htable *memtable, const struct intmap *m);

/* Remove any pointers inside this strmap (which is opaque to memleak). */
#define memleak_remove_strmap(memtable, strmap) \
	memleak_remove_strmap_((memtable), tcon_unwrap(strmap))
void memleak_remove_strmap_(struct htable *memtable, const struct strmap *m);

/**
 * memleak_get: get (and remove) a leak from memtable, or NULL
 * @memtable: the memtable after all known allocations removed.
 * @backtrace: the backtrace to set if there is one.
 *
 * If this returns NULL, it means the @memtable was empty.  Otherwise
 * it return a pointer to a leak (and removes it from @memtable)
 */
const void *memleak_get(struct htable *memtable, const uintptr_t **backtrace);

extern struct backtrace_state *backtrace_state;

#if DEVELOPER
/* Only defined if DEVELOPER */
bool dump_memleak(struct htable *memtable,
		  void PRINTF_FMT(1,2) (*print)(const char *fmt, ...));
#endif

#endif /* LIGHTNING_COMMON_MEMLEAK_H */
