/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_ALIGNOF_H
#define CCAN_ALIGNOF_H
#include "config.h"

/**
 * ALIGNOF - get the alignment of a type
 * @t: the type to test
 *
 * This returns a safe alignment for the given type.
 */
#if HAVE_ALIGNOF
/* A GCC extension. */
#define ALIGNOF(t) __alignof__(t)
#else
/* Alignment by measuring structure padding. */
#define ALIGNOF(t) ((char *)(&((struct { char c; t _h; } *)0)->_h) - (char *)0)
#endif

#endif /* CCAN_ALIGNOF_H */
