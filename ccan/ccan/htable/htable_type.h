/* Licensed under LGPLv2+ - see LICENSE file for details */
#ifndef CCAN_HTABLE_TYPE_H
#define CCAN_HTABLE_TYPE_H
#include <ccan/htable/htable.h>
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
 *	void <name>_init_sized(struct <name> *, size_t);
 *	void <name>_clear(struct <name> *);
 *
 * Add function only fails if we run out of memory:
 *	bool <name>_add(struct <name> *ht, const <type> *e);
 *
 * Delete and delete-by key return true if it was in the set:
 *	bool <name>_del(struct <name> *ht, const <type> *e);
 *	bool <name>_delkey(struct <name> *ht, const <keytype> *k);
 *
 * Find function return the matching element, or NULL:
 *	type *<name>_get(const struct @name *ht, const <keytype> *k);
 *
 * Iteration over hashtable is also supported:
 *	type *<name>_first(const struct <name> *ht, struct <name>_iter *i);
 *	type *<name>_next(const struct <name> *ht, struct <name>_iter *i);
 *
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
		return hashfn(keyof((const type *)elem));		\
	}								\
	static inline void name##_init(struct name *ht)			\
	{								\
		htable_init(&ht->raw, name##_hash, NULL);		\
	}								\
	static inline void name##_init_sized(struct name *ht, size_t s)	\
	{								\
		htable_init_sized(&ht->raw, name##_hash, NULL, s);	\
	}								\
	static inline void name##_clear(struct name *ht)		\
	{								\
		htable_clear(&ht->raw);					\
	}								\
	static inline bool name##_add(struct name *ht, const type *elem) \
	{								\
		return htable_add(&ht->raw, hashfn(keyof(elem)), elem);	\
	}								\
	static inline bool name##_del(struct name *ht, const type *elem) \
	{								\
		return htable_del(&ht->raw, hashfn(keyof(elem)), elem);	\
	}								\
	static inline type *name##_get(const struct name *ht,		\
				       const HTABLE_KTYPE(keyof) k)	\
	{								\
		/* Typecheck for eqfn */				\
		(void)sizeof(eqfn((const type *)NULL,			\
				  keyof((const type *)NULL)));		\
		return htable_get(&ht->raw,				\
				  hashfn(k),				\
				  (bool (*)(const void *, void *))(eqfn), \
				  k);					\
	}								\
	static inline bool name##_delkey(struct name *ht,		\
					 const HTABLE_KTYPE(keyof) k)	\
	{								\
		type *elem = name##_get(ht, k);				\
		if (elem)						\
			return name##_del(ht, elem);			\
		return false;						\
	}								\
	static inline type *name##_first(const struct name *ht,		\
					 struct name##_iter *iter)	\
	{								\
		return htable_first(&ht->raw, &iter->i);		\
	}								\
	static inline type *name##_next(const struct name *ht,		\
					struct name##_iter *iter)	\
	{								\
		return htable_next(&ht->raw, &iter->i);			\
	}

#if HAVE_TYPEOF
#define HTABLE_KTYPE(keyof) typeof(keyof(NULL))
#else
#define HTABLE_KTYPE(keyof) void *
#endif
#endif /* CCAN_HTABLE_TYPE_H */
