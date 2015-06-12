/* Licensed under LGPL - see LICENSE file for details */
#ifndef CCAN_TAL_TALLOC_H
#define CCAN_TAL_TALLOC_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/likely/likely.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <ccan/str/str.h>
#include <talloc.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>

/**
 * tal_t - convenient alias for void to mark tal pointers.
 *
 * Since any pointer can be a tal-allocated pointer, it's often
 * useful to use this typedef to mark them explicitly.
 */
typedef TALLOC_CTX tal_t;

/**
 * tal - basic allocator function
 * @ctx: NULL, or tal allocated object to be parent.
 * @type: the type to allocate.
 *
 * Allocates a specific type, with a given parent context.  The name
 * of the object is a string of the type, but if CCAN_TAL_DEBUG is
 * defined it also contains the file and line which allocated it.
 *
 * Example:
 *	int *p = tal(NULL, int);
 *	*p = 1;
 */
#define tal(ctx, type)							\
	((type *)tal_talloc_((ctx), sizeof(type), false,		\
			     TAL_LABEL(type, "")))

/**
 * talz - zeroing allocator function
 * @ctx: NULL, or tal allocated object to be parent.
 * @type: the type to allocate.
 *
 * Equivalent to tal() followed by memset() to zero.
 *
 * Example:
 *	p = talz(NULL, int);
 *	assert(*p == 0);
 */
#define talz(ctx, type)						\
	((type *)tal_talloc_((ctx), sizeof(type), true,		\
			     TAL_LABEL(type, "")))

/**
 * tal_free - free a tal-allocated pointer.
 * @p: NULL, or tal allocated object to free.
 *
 * This calls the destructors for p (if any), then does the same for all its
 * children (recursively) before finally freeing the memory.  It returns
 * NULL, for convenience.
 *
 * Note: errno is preserved by this call.
 *
 * Example:
 *	p = tal_free(p);
 */
#define tal_free(p) tal_talloc_free_(p)

/**
 * tal_arr - allocate an array of objects.
 * @ctx: NULL, or tal allocated object to be parent.
 * @type: the type to allocate.
 * @count: the number to allocate.
 *
 * Note that an object allocated with tal_arr() has a length property;
 * see tal_count().
 *
 * Example:
 *	p = tal_arr(NULL, int, 2);
 *	p[0] = 0;
 *	p[1] = 1;
 */
#define tal_arr(ctx, type, count)					\
	((type *)tal_talloc_arr_((ctx), sizeof(type), (count), false,	\
				 TAL_LABEL(type, "[]")))

/**
 * tal_arrz - allocate an array of zeroed objects.
 * @ctx: NULL, or tal allocated object to be parent.
 * @type: the type to allocate.
 * @count: the number to allocate.
 *
 * Note that an object allocated with tal_arrz() has a length property;
 * see tal_count().
 *
 * Example:
 *	p = tal_arrz(NULL, int, 2);
 *	assert(p[0] == 0 && p[1] == 0);
 */
#define tal_arrz(ctx, type, count) \
	((type *)tal_talloc_arr_((ctx), sizeof(type), (count), true,	\
				 TAL_LABEL(type, "[]")))

/**
 * tal_resize - enlarge or reduce a tal_arr[z].
 * @p: A pointer to the tal allocated array to resize.
 * @count: the number to allocate.
 *
 * This returns true on success (and may move *@p), or false on failure.
 * If @p has a length property, it is updated on success.
 *
 * Example:
 *	tal_resize(&p, 100);
 */
#define tal_resize(p, count) \
	tal_talloc_resize_((void **)(p), sizeof**(p), (count))

/**
 * tal_steal - change the parent of a tal-allocated pointer.
 * @ctx: The new parent.
 * @ptr: The tal allocated object to move.
 *
 * This may need to perform an allocation, in which case it may fail; thus
 * it can return NULL, otherwise returns @ptr.
 */
#define tal_steal(ctx, ptr) talloc_steal((ctx), (ptr))

/**
 * tal_add_destructor - add a callback function when this context is destroyed.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 *
 * This is a more convenient form of tal_add_notifier(@ptr,
 * TAL_NOTIFY_FREE, ...), in that the function prototype takes only @ptr.
 */
#define tal_add_destructor(ptr, function)				\
	tal_talloc_add_destructor_((ptr), typesafe_cb(void, void *,	\
						      (function), (ptr)))

/**
 * tal_del_destructor - remove a destructor callback function.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 *
 * If @function has not been successfully added as a destructor, this returns
 * false.
 *
 * Note: you can't add more than one destructor with the talloc backend!
 */
#define tal_del_destructor(ptr, function)				      \
	tal_talloc_del_destructor_((ptr), typesafe_cb(void, void *,	\
						      (function), (ptr)))

/**
 * tal_set_name - attach a name to a tal pointer.
 * @ptr: The tal allocated object.
 * @name: The name to use.
 *
 * The name is copied, unless we're certain it's a string literal.
 */
#define tal_set_name(ptr, name)				      \
	tal_talloc_set_name_((ptr), (name), TAL_TALLOC_IS_LITERAL(name))

/**
 * tal_name - get the name for a tal pointer.
 * @ptr: The tal allocated object.
 *
 * Returns NULL if no name has been set.
 */
#define tal_name(ptr) \
	tal_talloc_name_(ptr)

/**
 * tal_count - get the count of objects in a tal_arr.
 * @ptr: The tal allocated object array.
 */
#define tal_count(ptr) talloc_array_length(ptr)

/**
 * tal_parent - get the parent of a tal object.
 * @ctx: The tal allocated object.
 *
 * Returns the parent, which may be NULL.  Returns NULL if @ctx is NULL.
 */
#define tal_parent(ctx) talloc_parent(ctx)

/**
 * tal_dup - duplicate an object.
 * @ctx: The tal allocated object to be parent of the result (may be NULL).
 * @type: the type (should match type of @p!)
 * @p: the object to copy (or reparented if take())
 */
#define tal_dup(ctx, type, p)						\
	((type *)tal_talloc_dup_((ctx), tal_talloc_typechk_(p, type *),	\
				 sizeof(type), 1, 0,			\
				 TAL_LABEL(type, "")))

/**
 * tal_dup_arr - duplicate an array.
 * @ctx: The tal allocated object to be parent of the result (may be NULL).
 * @type: the type (should match type of @p!)
 * @p: the array to copy (or resized & reparented if take())
 * @n: the number of sizeof(type) entries to copy.
 * @extra: the number of extra sizeof(type) entries to allocate.
 */
#define tal_dup_arr(ctx, type, p, n, extra)					\
	((type *)tal_talloc_dup_((ctx), tal_talloc_typechk_(p, type *),	\
				 sizeof(type), (n), (extra),		\
				 TAL_LABEL(type, "[]")))


/**
 * tal_set_backend - set the allocation or error functions to use
 * @alloc_fn: NULL
 * @resize_fn: NULL
 * @free_fn: NULL
 * @error_fn: called on errors or NULL (default is abort)
 *
 * The defaults are set up so tal functions never return NULL, but you
 * can override error_fn to change that.  error_fn can return, and is
 * called if malloc or realloc fail.
 */
#define tal_set_backend(alloc_fn, resize_fn, free_fn, error_fn) \
	tal_talloc_set_backend_((alloc_fn), (resize_fn), (free_fn), (error_fn))

/**
 * tal_expand - expand a tal array with contents.
 * @a1p: a pointer to the tal array to expand.
 * @a2: the second array (can be take()).
 * @num2: the number of elements in the second array.
 *
 * Note that *@a1 and @a2 should be the same type.  tal_count(@a1) will
 * be increased by @num2.
 *
 * Example:
 *	int *arr1 = tal_arrz(NULL, int, 2);
 *	int arr2[2] = { 1, 3 };
 *
 *	tal_expand(&arr1, arr2, 2);
 *	assert(tal_count(arr1) == 4);
 *	assert(arr1[2] == 1);
 *	assert(arr1[3] == 3);
 */
#define tal_expand(a1p, a2, num2)				\
	tal_talloc_expand_((void **)(a1p), (a2), sizeof**(a1p),	\
			   (num2) + 0*sizeof(*(a1p) == (a2)))


/**
 * tal_check - set the allocation or error functions to use
 * @ctx: a tal context, or NULL.
 * @errorstr: a string to prepend calls to error_fn, or NULL.
 *
 * This sanity-checks a tal tree (unless NDEBUG is defined, in which case
 * it simply returns true).  If errorstr is not null, error_fn is called
 * when a problem is found, otherwise it is not.
 */
#define tal_check(ctx, errorstr) \
	tal_talloc_check_((ctx), (errorstr))


/* Internal support functions */
#ifndef TAL_TALLOC_LABEL
#ifdef CCAN_TAL_NO_LABELS
#define TAL_LABEL(type, arr) NULL
#else
#ifdef CCAN_TAL_DEBUG
#define TAL_LABEL(type, arr) \
	__FILE__ ":" stringify(__LINE__) ":" stringify(type) arr
#else
#define TAL_LABEL(type, arr) stringify(type) arr
#endif /* CCAN_TAL_DEBUG */
#endif
#endif

#if HAVE_BUILTIN_CONSTANT_P
#define TAL_TALLOC_IS_LITERAL(str) __builtin_constant_p(str)
#else
#define TAL_TALLOC_IS_LITERAL(str) false
#endif

#if HAVE_TYPEOF && HAVE_STATEMENT_EXPR
/* Careful: ptr can be const foo *, ptype is foo *.  Also, ptr could
 * be an array, eg "hello". */
#define tal_talloc_typechk_(ptr, ptype) ({ __typeof__((ptr)+0) _p = (ptype)(ptr); _p; })
#else
#define tal_talloc_typechk_(ptr, ptype) (ptr)
#endif

void *tal_talloc_(const tal_t *ctx, size_t bytes, bool clear,
		  const char *label);
void *tal_talloc_arr_(const tal_t *ctx, size_t bytes, size_t count, bool clear,
		      const char *label);
void *tal_talloc_free_(const tal_t *ctx);
const char *tal_talloc_name_(const tal_t *ctx);
bool tal_talloc_set_name_(tal_t *ctx, const char *name, bool literal);

bool tal_talloc_add_destructor_(const tal_t *ctx, void (*destroy)(void *me));
bool tal_talloc_del_destructor_(const tal_t *ctx, void (*destroy)(void *me));

/* ccan/tal/str uses this, so define it. */
#define tal_dup_(ctx, p, size, n, extra, add_count, label) \
	tal_talloc_dup_((ctx), (p), (size), (n), (extra), (label))
void *tal_talloc_dup_(const tal_t *ctx, const void *p, size_t size,
		      size_t n, size_t extra, const char *label);

bool tal_talloc_resize_(tal_t **ctxp, size_t size, size_t count);
bool tal_talloc_expand_(tal_t **ctxp, const void *src, size_t size, size_t count);
bool tal_talloc_check_(const tal_t *ctx, const char *errorstr);

void tal_talloc_set_backend_(void *(*alloc_fn)(size_t size),
			     void *(*resize_fn)(void *, size_t size),
			     void (*free_fn)(void *),
			     void (*error_fn)(const char *msg));

#endif /* CCAN_TAL_TALLOC_H */
