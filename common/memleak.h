#ifndef LIGHTNING_COMMON_MEMLEAK_H
#define LIGHTNING_COMMON_MEMLEAK_H
#include "config.h"
#include <ccan/tal/tal.h>

#if HAVE_TYPEOF
#define memleak_typeof(var) typeof(var)
#else
#define memleak_typeof(var) void *
#endif /* !HAVE_TYPEOF */

/* Mark a pointer as not being leaked. */
#define notleak(p) ((memleak_typeof(p))notleak_(p))

#if DEVELOPER
void *notleak_(const void *ptr);

struct htable;

/* Initialize memleak detection, with this as the root */
void memleak_init(const tal_t *root);

/* Free memleak detection. */
void memleak_cleanup(void);

/* Allocate a htable with all the memory we've allocated. */
struct htable *memleak_enter_allocations(const tal_t *ctx, const void *exclude);

/* Remove any pointers to memory under root */
void memleak_remove_referenced(struct htable *memtable, const void *root);

/* Mark this pointer as being referenced, and search within for more. */
void memleak_scan_region(struct htable *memtable, const void *p);

/* Get (and remove) a leak from memtable, or NULL */
const void *memleak_get(struct htable *memtable);

#else /* ... !DEVELOPER */
static inline void *notleak_(const void *ptr)
{
	return ptr;
}
#endif /* !DEVELOPER */

#endif /* LIGHTNING_COMMON_MEMLEAK_H */
