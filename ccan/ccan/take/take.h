/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_TAKE_H
#define CCAN_TAKE_H
#include "config.h"
#include <stdbool.h>

/**
 * take - record a pointer to be consumed by the function its handed to.
 * @p: the pointer to mark, or NULL.
 *
 * This marks a pointer object to be freed by the called function,
 * which is extremely useful for chaining functions.  It works on
 * NULL, for pass-through error handling.
 */
#define take(p) (take_typeof(p) take_((p)))

/**
 * taken - check (and un-take) a pointer was passed with take()
 * @p: the pointer to check.
 *
 * A function which accepts take() arguments uses this to see if it
 * should own the pointer; it will be removed from the take list, so
 * this only returns true once.
 *
 * Example:
 *	// Silly routine to add 1
 *	static int *add_one(const int *num)
 *	{
 *		int *ret;
 *		if (taken(num))
 *			ret = (int *)num;
 *		else
 *			ret = malloc(sizeof(int));
 *		if (ret)
 *			*ret = (*num) + 1;
 *		return ret;
 *	}
 */
bool taken(const void *p);

/**
 * is_taken - check if a pointer was passed with take()
 * @p: the pointer to check.
 *
 * This is like the above, but doesn't remove it from the taken list.
 *
 * Example:
 *	// Silly routine to add 1: doesn't handle taken args!
 *	static int *add_one_notake(const int *num)
 *	{
 *		int *ret = malloc(sizeof(int));
 *		assert(!is_taken(num));
 *		if (ret)
 *			*ret = (*num) + 1;
 *		return ret;
 *	}
 */
bool is_taken(const void *p);

/**
 * taken_any - are there any taken pointers?
 *
 * Mainly useful for debugging take() leaks.
 *
 * Example:
 *	static void cleanup(void)
 *	{
 *		assert(!taken_any());
 *	}
 */
bool taken_any(void);

/**
 * take_cleanup - remove all taken pointers from list.
 *
 * This is useful in atexit() handlers for valgrind-style leak detection.
 *
 * Example:
 *	static void cleanup2(void)
 *	{
 *		take_cleanup();
 *	}
 */
void take_cleanup(void);

/**
 * take_allocfail - set function to call if we can't reallocated taken array.
 * @fn: the function.
 *
 * If this is not set, then if the array reallocation fails, the
 * pointer won't be marked taken().  If @fn returns, it is expected to
 * free the pointer; we return NULL from take() and the function handles
 * it like any allocation failure.
 *
 * Example:
 *	static void free_on_fail(const void *p)
 *	{
 *		free((void *)p);
 *	}
 *
 *	static void init(void)
 *	{
 *		take_allocfail(free_on_fail);
 *	}
 */
void take_allocfail(void (*fn)(const void *p));

/* Private functions */
#if HAVE_TYPEOF
#define take_typeof(ptr) (__typeof__(ptr))
#else
#define take_typeof(ptr)
#endif

void *take_(const void *p);
#endif /* CCAN_TAKE_H */
