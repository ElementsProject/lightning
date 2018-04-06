/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_INTMAP_H
#define CCAN_INTMAP_H
#include "config.h"
#include <ccan/tcon/tcon.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>

/* Must be an unsigned type. */
#ifndef intmap_index_t
#define intmap_index_t uint64_t
#define sintmap_index_t int64_t
#endif

/**
 * struct intmap - representation of an integer map
 *
 * It's exposed here to allow you to embed it and so we can inline the
 * trivial functions.
 */
struct intmap {
	union {
		struct node *n;
		intmap_index_t i;
	} u;
	void *v;
};

/**
 * UINTMAP - declare a type-specific intmap (for unsigned integers)
 * @membertype: type for this map's values, or void * for any pointer.
 *
 * You use this to create your own typed intmap for a particular
 * (non-NULL) pointer type.
 *
 * Example:
 *	UINTMAP(int *) uint_intmap;
 *	uintmap_init(&uint_intmap);
 */
#define UINTMAP(membertype)					\
	TCON_WRAP(struct intmap, membertype uintmap_canary)

/**
 * SINTMAP - declare a type-specific intmap (for signed integers)
 * @membertype: type for this map's values, or void * for any pointer.
 *
 * You use this to create your own typed intmap for a particular type.
 * You can use an integer type as membertype, *but* remember you can't
 * use "0" as a value!
 *
 * This is different from UINTMAP because we want it to sort into
 * least (most negative) to largest order.
 *
 * Example:
 *	SINTMAP(int *) sint_intmap;
 *	sintmap_init(&sint_intmap);
 */
#define SINTMAP(membertype)					\
	TCON_WRAP(struct intmap, membertype sintmap_canary)

/**
 * uintmap_init - initialize an unsigned integer map (empty)
 * @umap: the typed intmap to initialize.
 *
 * For completeness; if you've arranged for it to be NULL already you don't
 * need this.
 *
 * Example:
 *	UINTMAP(int *) uint_intmap;
 *
 *	uintmap_init(&uint_intmap);
 */
#define uintmap_init(umap) intmap_init_(uintmap_unwrap_(umap))

/**
 * sintmap_init - initialize a signed integer map (empty)
 * @smap: the typed intmap to initialize.
 *
 * For completeness; if you've arranged for it to be NULL already you don't
 * need this.
 *
 * Example:
 *	SINTMAP(int *) sint_intmap;
 *
 *	sintmap_init(&sint_intmap);
 */
#define sintmap_init(smap) intmap_init_(sintmap_unwrap_(smap))

static inline void intmap_init_(struct intmap *map)
{
	map->u.n = NULL;
	map->v = NULL;
}

/**
 * uintmap_empty - is this unsigned integer map empty?
 * @umap: the typed intmap to check.
 *
 * Example:
 *	if (!uintmap_empty(&uint_intmap))
 *		abort();
 */
#define uintmap_empty(umap) intmap_empty_(uintmap_unwrap_(umap))

/**
 * sintmap_empty - is this signed integer map empty?
 * @smap: the typed intmap to check.
 *
 * Example:
 *	if (!sintmap_empty(&sint_intmap))
 *		abort();
 */
#define sintmap_empty(smap) intmap_empty_(sintmap_unwrap_(smap))

static inline bool intmap_empty_(const struct intmap *map)
{
	return map->v == NULL && map->u.n == NULL;
}

/**
 * uintmap_get - get a value from an unsigned integer map
 * @umap: the typed intmap to search.
 * @index: the unsigned index to search for.
 *
 * Returns the value, or NULL if it isn't in the map (and sets errno = ENOENT).
 *
 * Example:
 *	int *val = uintmap_get(&uint_intmap, 100);
 *	if (val)
 *		printf("100 => %i\n", *val);
 */
#define uintmap_get(umap, index)					\
	tcon_cast((umap), uintmap_canary,				\
		      intmap_get_(uintmap_unwrap_(umap), (index)))

/**
 * sintmap_get - get a value from a signed integer map
 * @smap: the typed intmap to search.
 * @index: the signed index to search for.
 *
 * Returns the value, or NULL if it isn't in the map (and sets errno = ENOENT).
 *
 * Example:
 *	int *val2 = sintmap_get(&sint_intmap, -100);
 *	if (val2)
 *		printf("-100 => %i\n", *val2);
 */
#define sintmap_get(smap, index)					\
	tcon_cast((smap), sintmap_canary,				\
		  intmap_get_(sintmap_unwrap_(smap), SINTMAP_OFF(index)))

void *intmap_get_(const struct intmap *map, intmap_index_t index);

/**
 * uintmap_add - place a member in an unsigned integer map.
 * @umap: the typed intmap to add to.
 * @index: the unsigned index to place in the map.
 * @value: the (non-NULL) value.
 *
 * This returns false if we run out of memory (errno = ENOMEM), or
 * (more normally) if that index already appears in the map (EEXIST).
 *
 * Note that the value is not copied, just the pointer.
 *
 * Example:
 *	val = malloc(sizeof *val);
 *	*val = 17;
 *	if (!uintmap_add(&uint_intmap, 100, val))
 *		printf("100 was already in the map\n");
 */
#define uintmap_add(umap, index, value)					\
	intmap_add_(uintmap_unwrap_(tcon_check((umap), uintmap_canary,	\
					       (value))),		\
		    (index), (void *)(value))

/**
 * sintmap_add - place a member in a signed integer map.
 * @smap: the typed intmap to add to.
 * @index: the signed index to place in the map.
 * @value: the (non-NULL) value.
 *
 * This returns false if we run out of memory (errno = ENOMEM), or
 * (more normally) if that index already appears in the map (EEXIST).
 *
 * Note that the value is not copied, just the pointer.
 *
 * Example:
 *	val = malloc(sizeof *val);
 *	*val = 17;
 *	if (!sintmap_add(&sint_intmap, -100, val))
 *		printf("-100 was already in the map\n");
 */
#define sintmap_add(smap, index, value)					\
	intmap_add_(sintmap_unwrap_(tcon_check((smap), sintmap_canary,	\
					       (value))),		\
		    SINTMAP_OFF(index), (void *)(value))

bool intmap_add_(struct intmap *map, intmap_index_t member, const void *value);

/**
 * uintmap_del - remove a member from an unsigned integer map.
 * @umap: the typed intmap to delete from.
 * @index: the unsigned index to remove from the map.
 *
 * This returns the value, or NULL if there was no value at that
 * index.
 *
 * Example:
 *	if (uintmap_del(&uint_intmap, 100) == NULL)
 *		printf("100 was not in the map?\n");
 */
#define uintmap_del(umap, index)					\
	tcon_cast((umap), uintmap_canary,				\
		  intmap_del_(uintmap_unwrap_(umap), (index)))

/**
 * sintmap_del - remove a member from a signed integer map.
 * @smap: the typed intmap to delete from.
 * @index: the signed index to remove from the map.
 *
 * This returns the value, or NULL if there was no value at that
 * index.
 *
 * Example:
 *	if (sintmap_del(&sint_intmap, -100) == NULL)
 *		printf("-100 was not in the map?\n");
 */
#define sintmap_del(smap, index)					\
	tcon_cast((smap), sintmap_canary,				\
		  intmap_del_(sintmap_unwrap_(smap), SINTMAP_OFF(index)))

void *intmap_del_(struct intmap *map, intmap_index_t index);

/**
 * uintmap_clear - remove every member from an unsigned integer map.
 * @umap: the typed intmap to clear.
 *
 * The map will be empty after this.
 *
 * Example:
 *	uintmap_clear(&uint_intmap);
 */
#define uintmap_clear(umap) intmap_clear_(uintmap_unwrap_(umap))

/**
 * sintmap_clear - remove every member from a signed integer map.
 * @smap: the typed intmap to clear.
 *
 * The map will be empty after this.
 *
 * Example:
 *	sintmap_clear(&sint_intmap);
 */
#define sintmap_clear(smap) intmap_clear_(sintmap_unwrap_(smap))

void intmap_clear_(struct intmap *map);

/**
 * uintmap_first - get first value in an unsigned intmap
 * @umap: the typed intmap to iterate through.
 * @indexp: a pointer to store the index.
 *
 * Returns NULL if the map is empty, otherwise populates *@indexp and
 * returns the lowest entry.
 */
#define uintmap_first(umap, indexp)					\
	tcon_cast((umap), uintmap_canary,				\
		  intmap_first_(uintmap_unwrap_(umap), (indexp)))

void *intmap_first_(const struct intmap *map, intmap_index_t *indexp);

/**
 * sintmap_first - get first value in a signed intmap
 * @smap: the typed intmap to iterate through.
 * @indexp: a pointer to store the index.
 *
 * Returns NULL if the map is empty, otherwise populates *@indexp and
 * returns the lowest entry.
 */
#define sintmap_first(smap, indexp)					\
	tcon_cast((smap), sintmap_canary,				\
		  sintmap_first_(sintmap_unwrap_(smap), (indexp)))

/**
 * uintmap_after - get the closest following index in an unsigned intmap
 * @umap: the typed intmap to iterate through.
 * @indexp: the preceeding index (may not exist)
 *
 * Returns NULL if the there is no entry > @indexp, otherwise
 * populates *@indexp and returns the lowest entry > @indexp.
 */
#define uintmap_after(umap, indexp)					\
	tcon_cast((umap), uintmap_canary,				\
		  intmap_after_(uintmap_unwrap_(umap), (indexp)))

void *intmap_after_(const struct intmap *map, intmap_index_t *indexp);

/**
 * sintmap_after - get the closest following index in a signed intmap
 * @smap: the typed intmap to iterate through.
 * @indexp: the preceeding index (may not exist)
 *
 * Returns NULL if the there is no entry > @indexp, otherwise
 * populates *@indexp and returns the lowest entry > @indexp.
 */
#define sintmap_after(smap, indexp)					\
	tcon_cast((smap), sintmap_canary,				\
		  sintmap_after_(sintmap_unwrap_(smap), (indexp)))

/**
 * uintmap_last - get last value in an unsigned intmap
 * @umap: the typed intmap to iterate through.
 * @indexp: a pointer to store the index.
 *
 * Returns NULL if the map is empty, otherwise populates *@indexp and
 * returns the highest entry.
 */
#define uintmap_last(umap, indexp)					\
	tcon_cast((umap), uintmap_canary,				\
		  intmap_last_(uintmap_unwrap_(umap), (indexp)))

void *intmap_last_(const struct intmap *map, intmap_index_t *indexp);

/**
 * sintmap_last - get last value in a signed intmap
 * @smap: the typed intmap to iterate through.
 * @indexp: a pointer to store the index.
 *
 * Returns NULL if the map is empty, otherwise populates *@indexp and
 * returns the highest entry.
 */
#define sintmap_last(smap, indexp)					\
	tcon_cast((smap), sintmap_canary,				\
		  sintmap_last_(sintmap_unwrap_(smap), (indexp)))

/**
 * uintmap_iterate - ordered iteration over an unsigned intmap
 * @umap: the typed intmap to iterate through.
 * @handle: the function to call.
 * @arg: the argument for the function (types should match).
 *
 * @handle's prototype should be:
 *	bool @handle(intmap_index_t index, type value, typeof(arg) arg)
 *
 * If @handle returns false, the iteration will stop and uintmap_iterate will
 * return false, otherwise uintmap_iterate will return true.
 * You should not alter the map within the @handle function!
 *
 * Example:
 *	typedef UINTMAP(int *) umap_intp;
 *	static bool dump_some(intmap_index_t index, int *value, int *num)
 *	{
 *		// Only dump out num nodes.
 *		if (*(num--) == 0)
 *			return false;
 *		printf("%lu=>%i\n", (unsigned long)index, *value);
 *		return true;
 *	}
 *
 *	static void dump_map(const umap_intp *map)
 *	{
 *		int max = 100;
 *		uintmap_iterate(map, dump_some, &max);
 *		if (max < 0)
 *			printf("... (truncated to 100 entries)\n");
 *	}
 */
#define uintmap_iterate(map, handle, arg)				\
	intmap_iterate_(tcon_unwrap(map),				\
			typesafe_cb_cast(bool (*)(intmap_index_t,	\
						  void *, void *),	\
					 bool (*)(intmap_index_t,	\
						  tcon_type((map),	\
							    uintmap_canary), \
						  __typeof__(arg)), (handle)), \
			(arg), 0)

/**
 * sintmap_iterate - ordered iteration over a signed intmap
 * @smap: the typed intmap to iterate through.
 * @handle: the function to call.
 * @arg: the argument for the function (types should match).
 *
 * @handle's prototype should be:
 *	bool @handle(sintmap_index_t index, type value, typeof(arg) arg)
 *
 * If @handle returns false, the iteration will stop and sintmap_iterate will
 * return false, otherwise sintmap_iterate will return true.
 * You should not alter the map within the @handle function!
 *
 * Example:
 *	typedef SINTMAP(int *) smap_intp;
 *	static bool dump_some(sintmap_index_t index, int *value, int *num)
 *	{
 *		// Only dump out num nodes.
 *		if (*(num--) == 0)
 *			return false;
 *		printf("%li=>%i\n", (long)index, *value);
 *		return true;
 *	}
 *
 *	static void dump_map(const smap_intp *map)
 *	{
 *		int max = 100;
 *		sintmap_iterate(map, dump_some, &max);
 *		if (max < 0)
 *			printf("... (truncated to 100 entries)\n");
 *	}
 */
#define sintmap_iterate(map, handle, arg)				\
	intmap_iterate_(tcon_unwrap(map),				\
			typesafe_cb_cast(bool (*)(intmap_index_t,	\
						  void *, void *),	\
					 bool (*)(sintmap_index_t,	\
						  tcon_type((map),	\
							    sintmap_canary), \
						  __typeof__(arg)), (handle)), \
			(arg), SINTMAP_OFFSET)

bool intmap_iterate_(const struct intmap *map,
		     bool (*handle)(intmap_index_t, void *, void *),
		     void *data,
		     intmap_index_t offset);

/* TODO: We could implement intmap_prefix. */

/* These make sure it really is a uintmap/sintmap */
#define uintmap_unwrap_(u) (tcon_unwrap(u) + 0*tcon_sizeof((u), uintmap_canary))
#define sintmap_unwrap_(s) (tcon_unwrap(s) + 0*tcon_sizeof((s), sintmap_canary))

/* We have to offset indices if they're signed, so ordering works. */
#define SINTMAP_OFFSET		((intmap_index_t)1 << (sizeof(intmap_index_t)*8-1))
#define SINTMAP_OFF(index)	((intmap_index_t)(index) + SINTMAP_OFFSET)
#define SINTMAP_UNOFF(index)	((intmap_index_t)(index) - SINTMAP_OFFSET)

/* Due to multi-evaluation, these can't be macros */
static inline void *sintmap_first_(const struct intmap *map,
				   sintmap_index_t *indexp)
{
	intmap_index_t i;
	void *ret = intmap_first_(map, &i);
	*indexp = SINTMAP_UNOFF(i);
	return ret;

}

static inline void *sintmap_after_(const struct intmap *map,
				   sintmap_index_t *indexp)
{
	intmap_index_t i = SINTMAP_OFF(*indexp);
	void *ret = intmap_after_(map, &i);
	*indexp = SINTMAP_UNOFF(i);
	return ret;
}

static inline void *sintmap_last_(const struct intmap *map,
				  sintmap_index_t *indexp)
{
	intmap_index_t i;
	void *ret = intmap_last_(map, &i);
	*indexp = SINTMAP_UNOFF(i);
	return ret;

}
#endif /* CCAN_INTMAP_H */
