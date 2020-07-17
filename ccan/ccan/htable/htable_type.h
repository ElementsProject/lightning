/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef CCAN_HTABLE_TYPE_H
#define CCAN_HTABLE_TYPE_H
#include <ccan/htable/htable.h>
#include <ccan/compiler/compiler.h>
#include "config.h"

/**
 * HTABLE_DEFINE_TYPE - create a set of htable ops for a type
 * @type: a type whose pointers will be values in the hash.
 * @keyof: a function/macro to extract a key: <keytype> @keyof(const type *elem)
 * @hashfn: a hash function for a @key: size_t @hashfn(const <keytype> *)
 * @eqfn: an equality function keys: bool @eqfn(const type *, const <keytype> *)
 * @prefix: a prefix for all the functions to define (of form <name>_*)
 *
 * NULL values may not be placed into the hash table.
 *
 * This defines the type hashtable type and an iterator type:
 *	struct <name>;
 *	struct <name>_iter;
 *
 * It also defines initialization and freeing functions:
 *	void <name>_init(struct <name> *);
 *	bool <name>_init_sized(struct <name> *, size_t);
 *	void <name>_clear(struct <name> *);
 *	bool <name>_copy(struct <name> *dst, const struct <name> *src);
 *
 * Count entries:
 *	size_t <name>_count(const struct <name> *ht);
 *
 * Add function only fails if we run out of memory:
 *	bool <name>_add(struct <name> *ht, const <type> *e);
 *
 * Delete and delete-by key return true if it was in the set:
 *	bool <name>_del(struct <name> *ht, const <type> *e);
 *	bool <name>_delkey(struct <name> *ht, const <keytype> *k);
 *
 * Delete by iterator:
 *	bool <name>_delval(struct <name> *ht, struct <name>_iter *i);
 *
 * Find and return the (first) matching element, or NULL:
 *	type *<name>_get(const struct @name *ht, const <keytype> *k);
 *
 * Find and return all matching elements, or NULL:
 *	type *<name>_getfirst(const struct @name *ht, const <keytype> *k,
 *			      struct <name>_iter *i);
 *	type *<name>_getnext(const struct @name *ht, const <keytype> *k,
 *			     struct <name>_iter *i);
 *
 * Iteration over hashtable is also supported:
 *	type *<name>_first(const struct <name> *ht, struct <name>_iter *i);
 *	type *<name>_next(const struct <name> *ht, struct <name>_iter *i);
 *	type *<name>_prev(const struct <name> *ht, struct <name>_iter *i);
 *      type *<name>_pick(const struct <name> *ht, size_t seed,
 *                        struct <name>_iter *i);
 * It's currently safe to iterate over a changing hashtable, but you might
 * miss an element.  Iteration isn't very efficient, either.
 *
 * You can use HTABLE_INITIALIZER like so:
 *	struct <name> ht = { HTABLE_INITIALIZER(ht.raw, <name>_hash, NULL) };
 */
#define HTABLE_DEFINE_TYPE(type, keyof, hashfn, eqfn, name)		\
	struct name { struct htable raw; };				\
	struct name##_iter { struct htable_iter i; };			\
	static inline size_t name##_hash(const void *elem, void *priv)	\
	{								\
		(void)priv;						\
		return hashfn(keyof((const type *)elem));		\
	}								\
	static inline UNNEEDED void name##_init(struct name *ht)	\
	{								\
		htable_init(&ht->raw, name##_hash, NULL);		\
	}								\
	static inline UNNEEDED bool name##_init_sized(struct name *ht,	\
						      size_t s)		\
	{								\
		return htable_init_sized(&ht->raw, name##_hash, NULL, s); \
	}								\
	static inline UNNEEDED size_t name##_count(const struct name *ht) \
	{								\
		return htable_count(&ht->raw);				\
	}								\
	static inline UNNEEDED void name##_clear(struct name *ht)	\
	{								\
		htable_clear(&ht->raw);					\
	}								\
	static inline UNNEEDED bool name##_copy(struct name *dst,	\
						const struct name *src)	\
	{								\
		return htable_copy(&dst->raw, &src->raw);		\
	}								\
	static inline bool name##_add(struct name *ht, const type *elem) \
	{								\
		return htable_add(&ht->raw, hashfn(keyof(elem)), elem);	\
	}								\
	static inline UNNEEDED bool name##_del(struct name *ht,		\
					       const type *elem)	\
	{								\
		return htable_del(&ht->raw, hashfn(keyof(elem)), elem);	\
	}								\
	static inline UNNEEDED type *name##_get(const struct name *ht,	\
				       const HTABLE_KTYPE(keyof, type) k) \
	{								\
		struct htable_iter i;					\
		size_t h = hashfn(k);					\
		void *c;						\
									\
		for (c = htable_firstval(&ht->raw,&i,h);		\
		     c;							\
		     c = htable_nextval(&ht->raw,&i,h)) {		\
			if (eqfn(c, k))					\
				return c;				\
		}							\
		return NULL;						\
	}								\
	static inline UNNEEDED type *name##_getmatch_(const struct name *ht, \
				         const HTABLE_KTYPE(keyof, type) k, \
				         size_t h,			\
				         type *v,			\
					 struct name##_iter *iter)	\
	{								\
		while (v) {						\
			if (eqfn(v, k))					\
				break;					\
			v = htable_nextval(&ht->raw, &iter->i, h);	\
		}							\
		return v;						\
	}								\
	static inline UNNEEDED type *name##_getfirst(const struct name *ht, \
				         const HTABLE_KTYPE(keyof, type) k, \
					 struct name##_iter *iter)	\
	{								\
		size_t h = hashfn(k);					\
		type *v = htable_firstval(&ht->raw, &iter->i, h);	\
		return name##_getmatch_(ht, k, h, v, iter);			\
	}								\
	static inline UNNEEDED type *name##_getnext(const struct name *ht, \
				         const HTABLE_KTYPE(keyof, type) k, \
					 struct name##_iter *iter)	\
	{								\
		size_t h = hashfn(k);					\
		type *v = htable_nextval(&ht->raw, &iter->i, h);	\
		return name##_getmatch_(ht, k, h, v, iter);		\
	}								\
	static inline UNNEEDED bool name##_delkey(struct name *ht,	\
					 const HTABLE_KTYPE(keyof, type) k) \
	{								\
		type *elem = name##_get(ht, k);				\
		if (elem)						\
			return name##_del(ht, elem);			\
		return false;						\
	}								\
	static inline UNNEEDED void name##_delval(struct name *ht,	\
						  struct name##_iter *iter) \
	{								\
		htable_delval(&ht->raw, &iter->i);			\
	}								\
	static inline UNNEEDED type *name##_pick(const struct name *ht,	\
						size_t seed,		\
						struct name##_iter *iter) \
	{								\
		/* Note &iter->i == NULL iff iter is NULL */		\
		return htable_pick(&ht->raw, seed, &iter->i);			\
	}								\
	static inline UNNEEDED type *name##_first(const struct name *ht, \
					 struct name##_iter *iter)	\
	{								\
		return htable_first(&ht->raw, &iter->i);		\
	}								\
	static inline UNNEEDED type *name##_next(const struct name *ht,	\
					struct name##_iter *iter)	\
	{								\
		return htable_next(&ht->raw, &iter->i);			\
	}								\
	static inline UNNEEDED type *name##_prev(const struct name *ht,	\
					struct name##_iter *iter)	\
	{								\
		return htable_prev(&ht->raw, &iter->i);			\
	}

#if HAVE_TYPEOF
#define HTABLE_KTYPE(keyof, type) typeof(keyof((const type *)NULL))
#else
/* Assumes keys are a pointer: if not, override. */
#ifndef HTABLE_KTYPE
#define HTABLE_KTYPE(keyof, type) void *
#endif
#endif
#endif /* CCAN_HTABLE_TYPE_H */
