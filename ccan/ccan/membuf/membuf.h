/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_MEMBUF_H
#define CCAN_MEMBUF_H
#include "config.h"
#include <assert.h>
#include <ccan/tcon/tcon.h>

/**
 * struct membuf - representation of a memory buffer.
 *
 * It's exposed here to allow you to embed it and so we can inline the
 * trivial functions.
 */
struct membuf {
	/* These are the cursors into buf elements */
	size_t start;
	size_t end;

	/* Number of elements in buf */
	size_t max_elems;
	/* The buffer; at this low-level, untyped. */
	char *elems;

	void *(*expandfn)(struct membuf *, void *elems, size_t max_elems);
};

/**
 * MEMBUF - declare a type-specific membuf
 * @membertype: type for this buffer's values.
 *
 * You use this to create your own typed membuf.
 *
 * Example:
 *	MEMBUF(int *) intp_membuf;
 *	printf("Address of our int * membuf = %p\n", &intp_membuf);
 */
#define MEMBUF(membertype)					\
	TCON_WRAP(struct membuf, membertype canary)

/**
 * membuf_init - initialize a type-specfic membuf.
 * @mb: the MEMBUF() declared membuf.
 * @elems: the initial buffer, if any.
 * @max_elems: the initial space @elems, in number of elements.
 * @expandfn: the function to enlarge buf (eg. membuf_realloc).
 *
 * Example:
 *	membuf_init(&intp_membuf, NULL, 0, membuf_realloc);
 */
#define membuf_init(mb, elems, num, expandfn)				\
	membuf_init_(tcon_unwrap(tcon_check_ptr((mb), canary, (elems))), \
		     (elems), (num), tcon_sizeof((mb), canary), (expandfn))

void membuf_init_(struct membuf *mb,
		  void *elems, size_t max_elems, size_t elemsize,
		  void *(*expandfn)(struct membuf *, void *, size_t));

/**
 * membuf_realloc - simple membuf helper to do realloc().
 *
 * Assumes initial buffer was NULL, or malloc().
 */
void *membuf_realloc(struct membuf *mb, void *rawelems, size_t newsize);

/**
 * membuf_num_elems - number of populated elements in the membuf.
 * @mb: the MEMBUF() declared membuf.
 */
#define membuf_num_elems(mb) membuf_num_elems_(tcon_unwrap(mb))

static inline size_t membuf_num_elems_(const struct membuf *mb)
{
	return mb->end - mb->start;
}

/**
 * membuf_elems - pointer to the populated elements in the membuf.
 * @mb: the MEMBUF() declared membuf.
 */
#define membuf_elems(mb)						\
	tcon_cast_ptr(mb, canary,					\
		      membuf_elems_(tcon_unwrap(mb), tcon_sizeof((mb), canary)))

static inline void *membuf_elems_(const struct membuf *mb, size_t elemsize)
{
	return mb->elems + mb->start * elemsize;
}

/**
 * membuf_consume - we've used up this many membuf_elems.
 * @mb: the MEMBUF() declared membuf.
 * @num: the number of elems.
 *
 * Returns a pointer to the old start of membuf, so you can mark consumed
 * and actually process in a single call.
 */
#define membuf_consume(mb, num)						\
	tcon_cast_ptr(mb, canary,					\
		      membuf_consume_(tcon_unwrap(mb), (num),		\
				      tcon_sizeof((mb), canary)))

static inline void *membuf_consume_(struct membuf *mb,
				    size_t num, size_t elemsize)
{
	void *old_start = membuf_elems_(mb, elemsize);
	assert(num <= membuf_num_elems_(mb));
	mb->start += num;

	return old_start;
}

/**
 * membuf_num_space - number of unpopulated elements at end of the membuf.
 * @mb: the MEMBUF() declared membuf.
 */
#define membuf_num_space(mb) membuf_num_space_(tcon_unwrap(mb))

static inline size_t membuf_num_space_(const struct membuf *mb)
{
	return mb->max_elems - mb->end;
}

/**
 * membuf_space - pointer to the unpopulated elements at end of membuf.
 * @mb: the MEMBUF() declared membuf.
 */
#define membuf_space(mb)						\
	tcon_cast_ptr(mb, canary,					\
		      membuf_space_(tcon_unwrap(mb), tcon_sizeof((mb), canary)))

static inline void *membuf_space_(struct membuf *mb, size_t elemsize)
{
	return mb->elems + mb->end * elemsize;
}

/**
 * membuf_added - declare that we've added this many elements.
 * @mb: the MEMBUF() declared membuf.
 * @n: the number of elements we added (must be < membuf_num_space()).
 */
#define membuf_added(mb, num)						\
	membuf_added_(tcon_unwrap(mb), (num))

static inline void membuf_added_(struct membuf *mb, size_t num)
{
	assert(num <= membuf_num_space_(mb));
	mb->end += num;
}

/**
 * membuf_prepare_space - internal routine to make sure we've got space.
 * @mb: the MEMBUF() declared membuf.
 * @num_extra: the minimum number of elements of space we need
 *
 * Usually you wouldn't call this yourself; see membuf_add() below.  But
 * you might use this if you need to know about moves within mb->elements
 * so you can adjust your own pointers/offsets.
 *
 * It returns the offset *in bytes* between the old locations and the new.
 * This is because it may not be a whole number of elements, in the case
 * of realloc!
 *
 * If you want to check for expandfn failure (which sets errno to
 * ENOMEM), you can check if membuf_num_space() is < num_extra which will
 * never otherwise happen.
 */
#define membuf_prepare_space(mb, num_extra)			\
	membuf_prepare_space_(tcon_unwrap(mb),			\
			      (num_extra),			\
			      tcon_sizeof((mb), canary))

size_t membuf_prepare_space_(struct membuf *mb,
			     size_t num_extra, size_t elemsize);

/**
 * membuf_add - add to the end of the membuf.
 * @mb: the MEMBUF() declared membuf.
 * @num: the number of elements (must be that much space available!).
 *
 * Returns the pointer to the space just added, in case you want to
 * populate it afterwards.
 *
 * Note that this may invalidate existing buf pointers!  If you want to
 * avoid that, call membuf_prepare_space(mb, num) first.
 */
#define membuf_add(mb, num)						\
	tcon_cast_ptr(mb, canary,					\
		      membuf_add_(tcon_unwrap(mb), (num),		\
				  tcon_sizeof((mb), canary)))

static inline void *membuf_add_(struct membuf *mb, size_t num, size_t elemsize)
{
	void *oldend;
	membuf_prepare_space_(mb, num, elemsize);

	oldend = membuf_space_(mb, elemsize);
	/* We assume expandfn succeeded. */
	membuf_added_(mb, num);

	return oldend;
}

/**
 * membuf_unadd - remove this many added elements.
 * @mb: the MEMBUF() declared membuf.
 * @n: the number of elements we want to "unadd" (must be < membuf_num_elems()).
 */
#define membuf_unadd(mb, num)						\
	membuf_unadd_(tcon_unwrap(mb), (num))

static inline void membuf_unadd_(struct membuf *mb, size_t num)
{
	assert(num <= membuf_num_elems_(mb));
	mb->end -= num;
}

/**
 * membuf_cleanup - reset membuf, return elems array for freeing.
 * @mb: the MEMBUF() declared membuf.
 *
 * The mb will be empty after this, and crash if you try to expand it.
 * You can membuf_init() it again, however.
 *
 * Example:
 *	free(membuf_cleanup(&intp_membuf));
 */
#define membuf_cleanup(mb) membuf_cleanup_(tcon_unwrap(mb))

static inline void *membuf_cleanup_(struct membuf *mb)
{
	mb->start = mb->end = mb->max_elems = 0;
	mb->expandfn = NULL;

	return mb->elems;
}
#endif /* CCAN_MEMBUF_H */
