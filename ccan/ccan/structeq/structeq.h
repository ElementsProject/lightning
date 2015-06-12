/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_STRUCTEQ_H
#define CCAN_STRUCTEQ_H
#include <string.h>

/**
 * structeq - are two structures bitwise equal (including padding!)
 * @a: a pointer to a structure
 * @b: a pointer to a structure of the same type.
 *
 * If you *know* a structure has no padding, you can memcmp them.  At
 * least this way, the compiler will issue a warning if the structs are
 * different types!
 */
#define structeq(a, b) \
	(memcmp((a), (b), sizeof(*(a)) + 0 * sizeof((a) == (b))) == 0)
#endif /* CCAN_STRUCTEQ_H */
