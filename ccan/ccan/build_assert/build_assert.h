/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_BUILD_ASSERT_H
#define CCAN_BUILD_ASSERT_H
#include "config.h"

/**
 * BUILD_ASSERT - assert a build-time dependency.
 * @cond: the compile-time condition which must be true.
 *
 * Your compile will fail if the condition isn't true.  When the
 * compiler supports C11 _Static_assert it will also fail if the
 * condition can't be evaluated by the compiler; otherwise (older
 * compilers) a non-constant condition is silently accepted (and is
 * undefined behavior if false at runtime).
 *
 * This can only be used within a function.
 *
 * Example:
 *	#include <stddef.h>
 *	...
 *	static char *foo_to_char(struct foo *foo)
 *	{
 *		// This code needs string to be at start of foo.
 *		BUILD_ASSERT(offsetof(struct foo, string) == 0);
 *		return (char *)foo;
 *	}
 */
#if HAVE_STATIC_ASSERT
/* _Static_assert is a declaration, so do-while wrap avoids breaking if (x) BUILD_ASSERT... */
#define BUILD_ASSERT(cond) \
	do { _Static_assert(cond, "BUILD_ASSERT"); } while(0)
#else
#define BUILD_ASSERT(cond) \
	do { (void) sizeof(char [1 - 2*!(cond)]); } while(0)
#endif

/**
 * BUILD_ASSERT_OR_ZERO - assert a build-time dependency, as an expression.
 * @cond: the compile-time condition which must be true.
 *
 * Your compile will fail if the condition isn't true.  When the
 * compiler supports C11 _Static_assert it will also fail if the
 * condition can't be evaluated by the compiler; otherwise (older
 * compilers) a non-constant condition is silently accepted (and is
 * undefined behavior if false at runtime).
 *
 * This can be used in an expression: its value is "0".
 *
 * Example:
 *	#define foo_to_char(foo)					\
 *		 ((char *)(foo)						\
 *		  + BUILD_ASSERT_OR_ZERO(offsetof(struct foo, string) == 0))
 */
#if HAVE_STATIC_ASSERT
#define BUILD_ASSERT_OR_ZERO(cond) \
	(sizeof(struct { _Static_assert(cond, "BUILD_ASSERT_OR_ZERO"); char c; }) - 1)
#else
#define BUILD_ASSERT_OR_ZERO(cond) \
	(sizeof(char [1 - 2*!(cond)]) - 1)
#endif

#endif /* CCAN_BUILD_ASSERT_H */
