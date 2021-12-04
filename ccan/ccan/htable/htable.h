/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef CCAN_HTABLE_H
#define CCAN_HTABLE_H
#include "config.h"
#include <ccan/str/str.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/* Define CCAN_HTABLE_DEBUG for expensive debugging checks on each call. */
#define HTABLE_LOC __FILE__ ":" stringify(__LINE__)
#ifdef CCAN_HTABLE_DEBUG
#define htable_debug(h, loc) htable_check((h), loc)
#else
#define htable_debug(h, loc) ((void)loc, h)
#endif

/**
 * struct htable - private definition of a htable.
 *
 * It's exposed here so you can put it in your structures and so we can
 * supply inline functions.
 */
struct htable {
	size_t (*rehash)(const void *elem, void *priv);
	void *priv;
	unsigned int bits, perfect_bitnum;
	size_t elems, deleted;
	/* These are the bits which are the same in all pointers. */
	uintptr_t common_mask, common_bits;
	uintptr_t *table;
};

/**
 * HTABLE_INITIALIZER - static initialization for a hash table.
 * @name: name of this htable.
 * @rehash: hash function to use for rehashing.
 * @priv: private argument to @rehash function.
 *
 * This is useful for setting up static and global hash tables.
 *
 * Example:
 *	// For simplicity's sake, say hash value is contents of elem.
 *	static size_t rehash(const void *elem, void *unused)
 *	{
 *		(void)unused;
 *		return *(size_t *)elem;
 *	}
 *	static struct htable ht = HTABLE_INITIALIZER(ht, rehash, NULL);
 */
#define HTABLE_INITIALIZER(name, rehash, priv)				\
	{ rehash, priv, 0, 0, 0, 0, -1, 0, &name.common_bits }

/**
 * htable_init - initialize an empty hash table.
 * @ht: the hash table to initialize
 * @rehash: hash function to use for rehashing.
 * @priv: private argument to @rehash function.
 */
void htable_init(struct htable *ht,
		 size_t (*rehash)(const void *elem, void *priv), void *priv);

/**
 * htable_init_sized - initialize an empty hash table of given size.
 * @ht: the hash table to initialize
 * @rehash: hash function to use for rehashing.
 * @priv: private argument to @rehash function.
 * @size: the number of element.
 *
 * If this returns false, @ht is still usable, but may need to do reallocation
 * upon an add.  If this returns true, it will not need to reallocate within
 * @size htable_adds.
 */
bool htable_init_sized(struct htable *ht,
		       size_t (*rehash)(const void *elem, void *priv),
		       void *priv, size_t size);

/**
 * htable_count - count number of entries in a hash table.
 * @ht: the hash table
 */
static inline size_t htable_count(const struct htable *ht)
{
	return ht->elems;
}

/**
 * htable_clear - empty a hash table.
 * @ht: the hash table to clear
 *
 * This doesn't do anything to any pointers left in it.
 */
void htable_clear(struct htable *ht);


/**
 * htable_check - check hash table for consistency
 * @ht: the htable
 * @abortstr: the location to print on aborting, or NULL.
 *
 * Because hash tables have redundant information, consistency checking that
 * each element is in the correct location can be done.  This is useful as a
 * debugging check.  If @abortstr is non-NULL, that will be printed in a
 * diagnostic if the htable is inconsistent, and the function will abort.
 *
 * Returns the htable if it is consistent, NULL if not (it can never return
 * NULL if @abortstr is set).
 */
struct htable *htable_check(const struct htable *ht, const char *abortstr);

/**
 * htable_copy - duplicate a hash table.
 * @dst: the hash table to overwrite
 * @src: the hash table to copy
 *
 * Only fails on out-of-memory.
 *
 * Equivalent to (but faster than):
 *    if (!htable_init_sized(dst, src->rehash, src->priv, 1U << src->bits))
 *	   return false;
 *    v = htable_first(src, &i);
 *    while (v) {
 *		htable_add(dst, v);
 *		v = htable_next(src, i);
 *    }
 *    return true;
 */
#define htable_copy(dst, src) htable_copy_(dst, htable_debug(src, HTABLE_LOC))
bool htable_copy_(struct htable *dst, const struct htable *src);

/**
 * htable_add - add a pointer into a hash table.
 * @ht: the htable
 * @hash: the hash value of the object
 * @p: the non-NULL pointer
 *
 * Also note that this can only fail due to allocation failure.  Otherwise, it
 * returns true.
 */
#define htable_add(ht, hash, p) \
	htable_add_(htable_debug(ht, HTABLE_LOC), hash, p)
bool htable_add_(struct htable *ht, size_t hash, const void *p);

/**
 * htable_del - remove a pointer from a hash table
 * @ht: the htable
 * @hash: the hash value of the object
 * @p: the pointer
 *
 * Returns true if the pointer was found (and deleted).
 */
#define htable_del(ht, hash, p) \
	htable_del_(htable_debug(ht, HTABLE_LOC), hash, p)
bool htable_del_(struct htable *ht, size_t hash, const void *p);

/**
 * struct htable_iter - iterator or htable_first or htable_firstval etc.
 *
 * This refers to a location inside the hashtable.
 */
struct htable_iter {
	size_t off;
};

/**
 * htable_firstval - find a candidate for a given hash value
 * @htable: the hashtable
 * @i: the struct htable_iter to initialize
 * @hash: the hash value
 *
 * You'll need to check the value is what you want; returns NULL if none.
 * See Also:
 *	htable_delval()
 */
#define htable_firstval(htable, i, hash) \
	htable_firstval_(htable_debug(htable, HTABLE_LOC), i, hash)

void *htable_firstval_(const struct htable *htable,
		       struct htable_iter *i, size_t hash);

/**
 * htable_nextval - find another candidate for a given hash value
 * @htable: the hashtable
 * @i: the struct htable_iter to initialize
 * @hash: the hash value
 *
 * You'll need to check the value is what you want; returns NULL if no more.
 */
#define htable_nextval(htable, i, hash) \
	htable_nextval_(htable_debug(htable, HTABLE_LOC), i, hash)
void *htable_nextval_(const struct htable *htable,
		      struct htable_iter *i, size_t hash);

/**
 * htable_get - find an entry in the hash table
 * @ht: the hashtable
 * @h: the hash value of the entry
 * @cmp: the comparison function
 * @ptr: the pointer to hand to the comparison function.
 *
 * Convenient inline wrapper for htable_firstval/htable_nextval loop.
 */
static inline void *htable_get(const struct htable *ht,
			       size_t h,
			       bool (*cmp)(const void *candidate, void *ptr),
			       const void *ptr)
{
	struct htable_iter i;
	void *c;

	for (c = htable_firstval(ht,&i,h); c; c = htable_nextval(ht,&i,h)) {
		if (cmp(c, (void *)ptr))
			return c;
	}
	return NULL;
}

/**
 * htable_first - find an entry in the hash table
 * @ht: the hashtable
 * @i: the struct htable_iter to initialize
 *
 * Get an entry in the hashtable; NULL if empty.
 */
#define htable_first(htable, i) \
	htable_first_(htable_debug(htable, HTABLE_LOC), i)
void *htable_first_(const struct htable *htable, struct htable_iter *i);

/**
 * htable_next - find another entry in the hash table
 * @ht: the hashtable
 * @i: the struct htable_iter to use
 *
 * Get another entry in the hashtable; NULL if all done.
 * This is usually used after htable_first or prior non-NULL htable_next.
 */
#define htable_next(htable, i) \
	htable_next_(htable_debug(htable, HTABLE_LOC), i)
void *htable_next_(const struct htable *htable, struct htable_iter *i);

/**
 * htable_prev - find the previous entry in the hash table
 * @ht: the hashtable
 * @i: the struct htable_iter to use
 *
 * Get previous entry in the hashtable; NULL if all done.
 *
 * "previous" here only means the item that would have been returned by
 * htable_next() before the item it returned most recently.
 *
 * This is usually used in the middle of (or after) a htable_next iteration and
 * to "unwind" actions taken.
 */
#define htable_prev(htable, i) \
	htable_prev_(htable_debug(htable, HTABLE_LOC), i)
void *htable_prev_(const struct htable *htable, struct htable_iter *i);

/**
 * htable_delval - remove an iterated pointer from a hash table
 * @ht: the htable
 * @i: the htable_iter
 *
 * Usually used to delete a hash entry after it has been found with
 * htable_firstval etc.
 */
#define htable_delval(htable, i) \
	htable_delval_(htable_debug(htable, HTABLE_LOC), i)
void htable_delval_(struct htable *ht, struct htable_iter *i);

/**
 * htable_pick - set iterator to a random valid entry.
 * @ht: the htable
 * @seed: a random number to use.
 * @i: the htable_iter which is output (or NULL).
 *
 * Usually used with htable_delval to delete a random entry.  Returns
 * NULL iff the table is empty, otherwise a random entry.
 */
#define htable_pick(htable, seed, i)					\
	htable_pick_(htable_debug(htable, HTABLE_LOC), seed, i)
void *htable_pick_(const struct htable *ht, size_t seed, struct htable_iter *i);

/**
 * htable_set_allocator - set calloc/free functions.
 * @alloc: allocator to use, must zero memory!
 * @free: unallocator to use (@p is NULL or a return from @alloc)
 */
void htable_set_allocator(void *(*alloc)(struct htable *, size_t len),
			  void (*free)(struct htable *, void *p));
#endif /* CCAN_HTABLE_H */
