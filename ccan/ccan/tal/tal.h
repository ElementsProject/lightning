/* Licensed under BSD-MIT - see LICENSE file for details */
#ifndef CCAN_TAL_H
#define CCAN_TAL_H
#include "config.h"
#include <ccan/compiler/compiler.h>
#include <ccan/likely/likely.h>
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <ccan/str/str.h>
#include <ccan/take/take.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>

/**
 * tal_t - convenient alias for void to mark tal pointers.
 *
 * Since any pointer can be a tal-allocated pointer, it's often
 * useful to use this typedef to mark them explicitly.
 */
typedef void tal_t;

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
	((type *)tal_alloc_((ctx), sizeof(type), false, false, TAL_LABEL(type, "")))

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
#define talz(ctx, type)							\
	((type *)tal_alloc_((ctx), sizeof(type), true, false, TAL_LABEL(type, "")))

/**
 * tal_free - free a tal-allocated pointer.
 * @p: NULL, or tal allocated object to free.
 *
 * This calls the destructors for p (if any), then does the same for all its
 * children (recursively) before finally freeing the memory.  It returns
 * NULL, for convenience.
 *
 * Note: errno is preserved by this call, and also saved and restored
 * for any destructors or notifiers.
 *
 * Example:
 *	p = tal_free(p);
 */
void *tal_free(const tal_t *p);

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
	((type *)tal_alloc_arr_((ctx), sizeof(type), (count), false,	\
				true, TAL_LABEL(type, "[]")))

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
	((type *)tal_alloc_arr_((ctx), sizeof(type), (count), true,	\
				true, TAL_LABEL(type, "[]")))

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
	tal_resize_((void **)(p), sizeof**(p), (count), false)

/**
 * tal_resizez - enlarge or reduce a tal_arr[z]; zero out extra.
 * @p: A pointer to the tal allocated array to resize.
 * @count: the number to allocate.
 *
 * This returns true on success (and may move *@p), or false on failure.
 * If @p has a length property, it is updated on success.
 * On expand, new elements are memset to 0 bytes.
 *
 * Example:
 *	tal_resizez(&p, 200);
 */
#define tal_resizez(p, count) \
	tal_resize_((void **)(p), sizeof**(p), (count), true)

/**
 * tal_steal - change the parent of a tal-allocated pointer.
 * @ctx: The new parent.
 * @ptr: The tal allocated object to move.
 *
 * This may need to perform an allocation, in which case it may fail; thus
 * it can return NULL, otherwise returns @ptr.
 */
#if HAVE_STATEMENT_EXPR
/* Weird macro avoids gcc's 'warning: value computed is not used'. */
#define tal_steal(ctx, ptr) \
	({ (tal_typeof(ptr) tal_steal_((ctx),(ptr))); })
#else
#define tal_steal(ctx, ptr) \
	(tal_typeof(ptr) tal_steal_((ctx),(ptr)))
#endif

/**
 * tal_add_destructor - add a callback function when this context is destroyed.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 *
 * This is a more convenient form of tal_add_notifier(@ptr,
 * TAL_NOTIFY_FREE, ...), in that the function prototype takes only @ptr.
 *
 * Note that this can only fail if your allocfn fails and your errorfn returns.
 */
#define tal_add_destructor(ptr, function)				      \
	tal_add_destructor_((ptr), typesafe_cb(void, void *, (function), (ptr)))

/**
 * tal_del_destructor - remove a destructor callback function.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 *
 * If @function has not been successfully added as a destructor, this returns
 * false.
 */
#define tal_del_destructor(ptr, function)				      \
	tal_del_destructor_((ptr), typesafe_cb(void, void *, (function), (ptr)))

/**
 * tal_add_destructor2 - add a 2-arg callback function when context is destroyed.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 * @arg: the extra argument to the function.
 *
 * Sometimes an extra argument is required for a destructor; this
 * saves the extra argument internally to avoid the caller having to
 * do an extra allocation.
 *
 * Note that this can only fail if your allocfn fails and your errorfn returns.
 */
#define tal_add_destructor2(ptr, function, arg)				\
	tal_add_destructor2_((ptr),					\
			     typesafe_cb_cast(void (*)(tal_t *, void *), \
					      void (*)(__typeof__(ptr), \
						       __typeof__(arg)), \
					      (function)),		\
			     (arg))

/**
 * tal_del_destructor - remove a destructor callback function.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 *
 * If @function has not been successfully added as a destructor, this returns
 * false.
 */
#define tal_del_destructor(ptr, function)				      \
	tal_del_destructor_((ptr), typesafe_cb(void, void *, (function), (ptr)))

/**
 * tal_del_destructor2 - remove 2-arg callback function.
 * @ptr: The tal allocated object.
 * @function: the function to call before it's freed.
 * @arg: the extra argument to the function.
 *
 * If @function has not been successfully added as a destructor with
 * @arg, this returns false.
 */
#define tal_del_destructor2(ptr, function, arg)				\
	tal_del_destructor2_((ptr),					\
			     typesafe_cb_cast(void (*)(tal_t *, void *), \
					      void (*)(__typeof__(ptr), \
						       __typeof__(arg)), \
					      (function)),		\
			     (arg))
enum tal_notify_type {
	TAL_NOTIFY_FREE = 1,
	TAL_NOTIFY_STEAL = 2,
	TAL_NOTIFY_MOVE = 4,
	TAL_NOTIFY_RESIZE = 8,
	TAL_NOTIFY_RENAME = 16,
	TAL_NOTIFY_ADD_CHILD = 32,
	TAL_NOTIFY_DEL_CHILD = 64,
	TAL_NOTIFY_ADD_NOTIFIER = 128,
	TAL_NOTIFY_DEL_NOTIFIER = 256
};

/**
 * tal_add_notifier - add a callback function when this context changes.
 * @ptr: The tal allocated object.
 * @types: Bitwise OR of the types the callback is interested in.
 * @callback: the function to call.
 *
 * Note that this can only fail if your allocfn fails and your errorfn
 * returns.  Also note that notifiers are not reliable in the case
 * where an allocation fails, as they may be called before any
 * allocation is actually done.
 *
 * TAL_NOTIFY_FREE is called when @ptr is freed, either directly or
 * because an ancestor is freed: @info is the argument to tal_free().
 * It is exactly equivalent to a destructor, with more information.
 * errno is set to the value it was at the call of tal_free().
 *
 * TAL_NOTIFY_STEAL is called when @ptr's parent changes: @info is the
 * new parent.
 *
 * TAL_NOTIFY_MOVE is called when @ptr is realloced (via tal_resize)
 * and moved.  In this case, @ptr arg here is the new memory, and
 * @info is the old pointer.
 *
 * TAL_NOTIFY_RESIZE is called when @ptr is realloced via tal_resize:
 * @info is the new size, in bytes.  If the pointer has moved,
 * TAL_NOTIFY_MOVE callbacks are called first.
 *
 * TAL_NOTIFY_ADD_CHILD/TAL_NOTIFY_DEL_CHILD are called when @ptr is
 * the context for a tal() allocating call, or a direct child is
 * tal_free()d: @info is the child.  Note that TAL_NOTIFY_DEL_CHILD is
 * not called when this context is tal_free()d: TAL_NOTIFY_FREE is
 * considered sufficient for that case.
 *
 * TAL_NOTIFY_ADD_NOTIFIER/TAL_NOTIFIER_DEL_NOTIFIER are called when a
 * notifier is added or removed (not for this notifier): @info is the
 * callback.  This is also called for tal_add_destructor and
 * tal_del_destructor.
 */
#define tal_add_notifier(ptr, types, callback)				\
	tal_add_notifier_((ptr), (types),				\
			  typesafe_cb_postargs(void, tal_t *, (callback), \
					       (ptr),			\
					       enum tal_notify_type, void *))

/**
 * tal_del_notifier - remove a notifier callback function.
 * @ptr: The tal allocated object.
 * @callback: the function to call.
 */
#define tal_del_notifier(ptr, callback)					\
	tal_del_notifier_((ptr),					\
			  typesafe_cb_postargs(void, void *, (callback), \
					       (ptr),			\
					       enum tal_notify_type, void *), \
			  false, NULL)

/**
 * tal_set_name - attach a name to a tal pointer.
 * @ptr: The tal allocated object.
 * @name: The name to use.
 *
 * The name is copied, unless we're certain it's a string literal.
 */
#define tal_set_name(ptr, name)				      \
    tal_set_name_((ptr), (name), TAL_IS_LITERAL(name))

/**
 * tal_name - get the name for a tal pointer.
 * @ptr: The tal allocated object.
 *
 * Returns NULL if no name has been set.
 */
const char *tal_name(const tal_t *ptr);

/**
 * tal_count - get the count of objects in a tal_arr.
 * @ptr: The tal allocated object array (or NULL)
 *
 * Returns 0 if @ptr has no length property or is NULL, but be aware
 * that that is also a valid size!
 */
#define tal_count(p) (tal_len(p) / sizeof(*p))

/**
 * tal_len - get the count of bytes in a tal_arr.
 * @ptr: The tal allocated object array (or NULL)
 *
 * Returns 0 if @ptr has no length property or NULL, but be aware that that is
 * also a valid size!
 */
size_t tal_len(const tal_t *ptr);

/**
 * tal_first - get the first immediate tal object child.
 * @root: The tal allocated object to start with, or NULL.
 *
 * Returns NULL if there are no children.
 */
tal_t *tal_first(const tal_t *root);

/**
 * tal_next - get the next immediate tal object child.
 * @prev: The return value from tal_first or tal_next.
 *
 * Returns NULL if there are no more immediate children.  This should be safe to
 * call on an altering tree unless @prev is no longer valid.
 */
tal_t *tal_next(const tal_t *prev);

/**
 * tal_parent - get the parent of a tal object.
 * @ctx: The tal allocated object.
 *
 * Returns the parent, which may be NULL.  Returns NULL if @ctx is NULL.
 */
tal_t *tal_parent(const tal_t *ctx);

/**
 * tal_dup - duplicate an object.
 * @ctx: The tal allocated object to be parent of the result (may be NULL).
 * @type: the type (should match type of @p!)
 * @p: the object to copy (or reparented if take())
 */
#define tal_dup(ctx, type, p)					\
	((type *)tal_dup_((ctx), tal_typechk_(p, type *),	\
			  sizeof(type), 1, 0,			\
			  false, TAL_LABEL(type, "")))

/**
 * tal_dup_arr - duplicate an array.
 * @ctx: The tal allocated object to be parent of the result (may be NULL).
 * @type: the type (should match type of @p!)
 * @p: the array to copy (or resized & reparented if take())
 * @n: the number of sizeof(type) entries to copy.
 * @extra: the number of extra sizeof(type) entries to allocate.
 */
#define tal_dup_arr(ctx, type, p, n, extra)			\
	((type *)tal_dup_((ctx), tal_typechk_(p, type *),	\
			  sizeof(type), (n), (extra),		\
			  true, TAL_LABEL(type, "[]")))


/**
 * tal_set_backend - set the allocation or error functions to use
 * @alloc_fn: allocator or NULL (default is malloc)
 * @resize_fn: re-allocator or NULL (default is realloc)
 * @free_fn: free function or NULL (default is free)
 * @error_fn: called on errors or NULL (default is abort)
 *
 * The defaults are set up so tal functions never return NULL, but you
 * can override erorr_fn to change that.  error_fn can return, and is
 * called if alloc_fn or resize_fn fail.
 *
 * If any parameter is NULL, that function is unchanged.
 */
void tal_set_backend(void *(*alloc_fn)(size_t size),
		     void *(*resize_fn)(void *, size_t size),
		     void (*free_fn)(void *),
		     void (*error_fn)(const char *msg));

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
	tal_expand_((void **)(a1p), (a2), sizeof**(a1p),	\
		    (num2) + 0*sizeof(*(a1p) == (a2)))

/**
 * tal_cleanup - remove pointers from NULL node
 *
 * Internally, tal keeps a list of nodes allocated from @ctx NULL; this
 * prevents valgrind from noticing memory leaks.  This re-initializes
 * that list to empty.
 *
 * It also calls take_cleanup() for you.
 */
void tal_cleanup(void);


/**
 * tal_check - sanity check a tal context and its children.
 * @ctx: a tal context, or NULL.
 * @errorstr: a string to prepend calls to error_fn, or NULL.
 *
 * This sanity-checks a tal tree (unless NDEBUG is defined, in which case
 * it simply returns true).  If errorstr is not null, error_fn is called
 * when a problem is found, otherwise it is not.
 *
 * See also:
 *	tal_set_backend()
 */
bool tal_check(const tal_t *ctx, const char *errorstr);

#ifdef CCAN_TAL_DEBUG
/**
 * tal_dump - dump entire tal tree.
 *
 * This is a helper for debugging tal itself, which dumps all the tal internal
 * state.
 */
void tal_dump(void);
#endif

/* Internal support functions */
#ifndef TAL_LABEL
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
#define TAL_IS_LITERAL(str) __builtin_constant_p(str)
#else
#define TAL_IS_LITERAL(str) (sizeof(&*(str)) != sizeof(char *))
#endif

bool tal_set_name_(tal_t *ctx, const char *name, bool literal);

#if HAVE_TYPEOF
#define tal_typeof(ptr) (__typeof__(ptr))
#if HAVE_STATEMENT_EXPR
/* Careful: ptr can be const foo *, ptype is foo *.  Also, ptr could
 * be an array, eg "hello". */
#define tal_typechk_(ptr, ptype) ({ __typeof__((ptr)+0) _p = (ptype)(ptr); _p; })
#else
#define tal_typechk_(ptr, ptype) (ptr)
#endif
#else /* !HAVE_TYPEOF */
#define tal_typeof(ptr)
#define tal_typechk_(ptr, ptype) (ptr)
#endif

void *tal_alloc_(const tal_t *ctx, size_t bytes, bool clear,
		 bool add_length, const char *label);
void *tal_alloc_arr_(const tal_t *ctx, size_t bytes, size_t count, bool clear,
		     bool add_length, const char *label);

void *tal_dup_(const tal_t *ctx, const void *p TAKES, size_t size,
	       size_t n, size_t extra, bool add_length,
	       const char *label);

tal_t *tal_steal_(const tal_t *new_parent, const tal_t *t);

bool tal_resize_(tal_t **ctxp, size_t size, size_t count, bool clear);
bool tal_expand_(tal_t **ctxp, const void *src TAKES, size_t size, size_t count);

bool tal_add_destructor_(const tal_t *ctx, void (*destroy)(void *me));
bool tal_add_destructor2_(const tal_t *ctx, void (*destroy)(void *me, void *arg),
			  void *arg);
bool tal_del_destructor_(const tal_t *ctx, void (*destroy)(void *me));
bool tal_del_destructor2_(const tal_t *ctx, void (*destroy)(void *me, void *arg),
			  void *arg);

bool tal_add_notifier_(const tal_t *ctx, enum tal_notify_type types,
		       void (*notify)(tal_t *ctx, enum tal_notify_type,
				      void *info));
bool tal_del_notifier_(const tal_t *ctx,
		       void (*notify)(tal_t *ctx, enum tal_notify_type,
				      void *info),
		       bool match_extra_arg, void *arg);
#endif /* CCAN_TAL_H */
