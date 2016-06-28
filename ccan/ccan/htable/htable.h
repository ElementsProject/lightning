/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef CCAN_HTABLE_H
#define CCAN_HTABLE_H
#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>

/**
 * struct htable - private definition of a htable.
 *
 * It's exposed here so you can put it in your structures and so we can
 * supply inline functions.
 */
struct htable {
	size_t (*rehash)(const void *elem, void *priv);
	void *priv;
	unsigned int bits;
	size_t elems, deleted, max, max_with_deleted;
	/* These are the bits which are the same in all pointers. */
	uintptr_t common_mask, common_bits;
	uintptr_t perfect_bit;
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
 *		return *(size_t *)elem;
 *	}
 *	static struct htable ht = HTABLE_INITIALIZER(ht, rehash, NULL);
 */
#define HTABLE_INITIALIZER(name, rehash, priv)				\
	{ rehash, priv, 0, 0, 0, 0, 0, -1, 0, 0, &name.perfect_bit }

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
 * htable_clear - empty a hash table.
 * @ht: the hash table to clear
 *
 * This doesn't do anything to any pointers left in it.
 */
void htable_clear(struct htable *ht);

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
bool htable_copy(struct htable *dst, const struct htable *src);

/**
 * htable_rehash - use a hashtree's rehash function
 * @elem: the argument to rehash()
 *
 */
size_t htable_rehash(const void *elem);

/**
 * htable_add - add a pointer into a hash table.
 * @ht: the htable
 * @hash: the hash value of the object
 * @p: the non-NULL pointer
 *
 * Also note that this can only fail due to allocation failure.  Otherwise, it
 * returns true.
 */
bool htable_add(struct htable *ht, size_t hash, const void *p);

/**
 * htable_del - remove a pointer from a hash table
 * @ht: the htable
 * @hash: the hash value of the object
 * @p: the pointer
 *
 * Returns true if the pointer was found (and deleted).
 */
bool htable_del(struct htable *ht, size_t hash, const void *p);

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
void *htable_firstval(const struct htable *htable,
		      struct htable_iter *i, size_t hash);

/**
 * htable_nextval - find another candidate for a given hash value
 * @htable: the hashtable
 * @i: the struct htable_iter to initialize
 * @hash: the hash value
 *
 * You'll need to check the value is what you want; returns NULL if no more.
 */
void *htable_nextval(const struct htable *htable,
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
void *htable_first(const struct htable *htable, struct htable_iter *i);

/**
 * htable_next - find another entry in the hash table
 * @ht: the hashtable
 * @i: the struct htable_iter to use
 *
 * Get another entry in the hashtable; NULL if all done.
 * This is usually used after htable_first or prior non-NULL htable_next.
 */
void *htable_next(const struct htable *htable, struct htable_iter *i);

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
void *htable_prev(const struct htable *htable, struct htable_iter *i);

/**
 * htable_delval - remove an iterated pointer from a hash table
 * @ht: the htable
 * @i: the htable_iter
 *
 * Usually used to delete a hash entry after it has been found with
 * htable_firstval etc.
 */
void htable_delval(struct htable *ht, struct htable_iter *i);

#endif /* CCAN_HTABLE_H */
