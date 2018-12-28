/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef TAL_LINK_H
#define TAL_LINK_H
#include "config.h"
#include <ccan/tal/tal.h>

/**
 * tal_linkable - set up a tal object to be linkable.
 * @newobj - the newly allocated object (with a NULL parent)
 *
 * The object will be freed when @newobj is freed or the last tal_link()
 * is tal_delink'ed.
 *
 * Returns @newobj or NULL (if an allocation fails).
 *
 * Example:
 *	int *shared_count;
 *
 *	shared_count = tal_linkable(talz(NULL, int));
 *	assert(shared_count);
 */
#define tal_linkable(newobj) \
	(tal_typeof(newobj) tal_linkable_((newobj)))

/**
 * tal_link - add a(nother) link to a linkable object.
 * @ctx - the context to link to (parent of the resulting link)
 * @obj - the object previously made linkable with tal_linked().
 *
 * If @ctx is non-NULL, the link will be a child of @ctx, and this freed
 * when @ctx is.
 *
 * Returns NULL on failure (out of memory).
 *
 * Example:
 *	void *my_ctx = NULL;
 *
 *	tal_link(my_ctx, shared_count);
 */
#if HAVE_STATEMENT_EXPR
/* Weird macro avoids gcc's 'warning: value computed is not used'. */
#define tal_link(ctx, obj)				\
	({ tal_typeof(obj) tal_link_((ctx), (obj)); })
#else
#define tal_link(ctx, obj)				\
	(tal_typeof(obj) tal_link_((ctx), (obj)))
#endif

/**
 * tal_delink - explicitly remove a link from a linkable object.
 * @ctx - the context to link to (parent of the resulting link)
 * @obj - the object previously made linkable with tal_linked().
 *
 * Explicitly remove a link: normally it is implied by freeing @ctx.
 * Removing the last link frees the object.  If @obj is NULL, nothing
 * is done.
 *
 * Example:
 *	tal_delink(my_ctx, shared_count);
 */
#define tal_delink(ctx, obj)				\
	tal_delink_((ctx), (obj))

/* Internal helpers. */
void *tal_linkable_(tal_t *newobj);
void *tal_link_(const tal_t *ctx, const tal_t *dest);
void tal_delink_(const tal_t *ctx, const tal_t *dest);

#endif /* TAL_LINK_H */
