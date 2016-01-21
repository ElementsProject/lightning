/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_PTRINT_H
#define CCAN_PTRINT_H

#include "config.h"

#include <stddef.h>

#include <ccan/build_assert/build_assert.h>
#include <ccan/compiler/compiler.h>

/*
 * This is a deliberately incomplete type, because it should never be
 * dereferenced - instead it marks pointer values which are actually
 * encoding integers
 */
typedef struct ptrint ptrint_t;

CONST_FUNCTION static inline ptrdiff_t ptr2int(const ptrint_t *p)
{
	/*
	 * ptrdiff_t is the right size by definition, but to avoid
	 * surprises we want a warning if the user can't fit at least
	 * a regular int in there
	 */
	BUILD_ASSERT(sizeof(int) <= sizeof(ptrdiff_t));
	return (const char *)p - (const char *)NULL;
}

CONST_FUNCTION static inline ptrint_t *int2ptr(ptrdiff_t i)
{
	return (ptrint_t *)((char *)NULL + i);
}

#endif /* CCAN_PTRINT_H */
