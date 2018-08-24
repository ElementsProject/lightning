#ifndef LIGHTNING_COMMON_MEMLEAK_H
#define LIGHTNING_COMMON_MEMLEAK_H
#include "config.h"
#include <ccan/cast/cast.h>
#include <ccan/tal/tal.h>
#include <inttypes.h>

#if HAVE_TYPEOF
#define memleak_typeof(var) typeof(var)
#else
#define memleak_typeof(var) void *
#endif /* !HAVE_TYPEOF */

/* Mark a pointer as not being leaked. */
#define notleak(p) ((memleak_typeof(p))notleak_((p), false))

/* Mark a pointer and all its tal children as not being leaked. */
#define notleak_with_children(p) ((memleak_typeof(p))notleak_((p), true))

#if DEVELOPER
void *notleak_(const void *ptr, bool plus_children);

struct htable;

/* Initialize memleak detection */
void memleak_init(void);

/* Free memleak detection. */
void memleak_cleanup(void);

/* Allocate a htable with all the memory we've allocated. */
struct htable *memleak_enter_allocations(const tal_t *ctx,
					 const void *exclude1,
					 const void *exclude2);

/* Remove any pointers to memory under root */
void memleak_remove_referenced(struct htable *memtable, const void *root);

/* Remove any pointers inside this htable (which is opaque to memleak). */
void memleak_remove_htable(struct htable *memtable, const struct htable *ht);

/* Remove any pointers inside this uintmap (which is opaque to memleak). */
#define memleak_remove_uintmap(memtable, umap)		\
	memleak_remove_intmap_(memtable, uintmap_unwrap_(umap))

struct intmap;
void memleak_remove_intmap_(struct htable *memtable, const struct intmap *m);

/* Mark this pointer as being referenced, and search within for more. */
void memleak_scan_region(struct htable *memtable,
			 const void *p, size_t bytelen);

/* Get (and remove) a leak from memtable, or NULL */
const void *memleak_get(struct htable *memtable, const uintptr_t **backtrace);

#else /* ... !DEVELOPER */
static inline void *notleak_(const void *ptr, bool plus_children UNNEEDED)
{
	return cast_const(void *, ptr);
}
#endif /* !DEVELOPER */

#endif /* LIGHTNING_COMMON_MEMLEAK_H */
