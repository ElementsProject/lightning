/* CC0 license (public domain) - see LICENSE file for details */
#ifndef CCAN_CLOSEFROM_H
#define CCAN_CLOSEFROM_H
#include "config.h"
#include <stdbool.h>

#if HAVE_CLOSEFROM
/* BSD.  */
#include <unistd.h>
/* Solaris.  */
#include <stdlib.h>

static inline
bool closefrom_may_be_slow(void)
{
	return 0;
}

static inline
void closefrom_limit(unsigned int limit)
{
}

#else /* !HAVE_CLOSEFROM */

/**
 * closefrom - Close all open file descriptors, starting
 * at fromfd onwards.
 * @fromfd: the first fd to close; it and all higher file descriptors
 * will be closed.
 *
 * This is not multithread-safe: other threads in the same process
 * may or may not open new file descriptors in parallel to this call.
 * However, the expected use-case is that this will be called in a
 * child process just after fork(), meaning the child process is still
 * single-threaded.
 */
void closefrom_(int fromfd);
/* In case the standard library has it, but declared in some
 * *other* header we do not know of yet, we use closefrom_ in
 * the actual name the linker sees.
 */
#define closefrom closefrom_

/**
 * closefrom_may_be_slow - check if the closefrom() function could
 * potentially take a long time.
 *
 * The return value is true if closefrom() is emulated by
 * looping from fromfd to sysconf(_SC_OPEN_MAX), which can be
 * very large (possibly even INT_MAX on some systems).
 * If so, you might want to use setrlimit to limit _SC_OPEN_MAX.
 * If this returns false, then closefrom is efficient and you do not
 * need to limit the number of file descriptors.
 *
 * You can use closefrom_limit to perform the limiting based on
 * closefrom_may_be_slow.
 * This API is exposed in case you want to output to debug logs or
 * something similar.
 */
bool closefrom_may_be_slow(void);

/**
 * closefrom_limit - If closefrom_may_be_slow(), lower the limit on
 * the number of file descriptors we keep open, to prevent closefrom
 * from being *too* slow.
 * @limit: 0 to use a reasonable default of 4096, or non-zero for the
 * limit you prefer.
 *
 * This function does nothing if closefrom_may_be_slow() return false.
 *
 * This function only *lowers* the limit from the hard limit set by
 * root before running this program.
 * If the limit is higher than the hard limit, then the hard limit is
 * respected.
 */
void closefrom_limit(unsigned int limit);

#endif /* !HAVE_CLOSEFROM */

#endif /* CCAN_CLOSEFROM_H */
