/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_LIKELY_H
#define CCAN_LIKELY_H
#include "config.h"
#include <stdbool.h>

#ifndef CCAN_LIKELY_DEBUG
#if HAVE_BUILTIN_EXPECT
/**
 * likely - indicate that a condition is likely to be true.
 * @cond: the condition
 *
 * This uses a compiler extension where available to indicate a likely
 * code path and optimize appropriately; it's also useful for readers
 * to quickly identify exceptional paths through functions.  The
 * threshold for "likely" is usually considered to be between 90 and
 * 99%; marginal cases should not be marked either way.
 *
 * See Also:
 *	unlikely(), likely_stats()
 *
 * Example:
 *	// Returns false if we overflow.
 *	static inline bool inc_int(unsigned int *val)
 *	{
 *		(*val)++;
 *		if (likely(*val))
 *			return true;
 *		return false;
 *	}
 */
#define likely(cond) __builtin_expect(!!(cond), 1)

/**
 * unlikely - indicate that a condition is unlikely to be true.
 * @cond: the condition
 *
 * This uses a compiler extension where available to indicate an unlikely
 * code path and optimize appropriately; see likely() above.
 *
 * See Also:
 *	likely(), likely_stats(), COLD (compiler.h)
 *
 * Example:
 *	// Prints a warning if we overflow.
 *	static inline void inc_int(unsigned int *val)
 *	{
 *		(*val)++;
 *		if (unlikely(*val == 0))
 *			fprintf(stderr, "Overflow!");
 *	}
 */
#define unlikely(cond) __builtin_expect(!!(cond), 0)
#else
#define likely(cond) (!!(cond))
#define unlikely(cond) (!!(cond))
#endif
#else /* CCAN_LIKELY_DEBUG versions */
#include <ccan/str/str.h>

#define likely(cond) \
	(_likely_trace(!!(cond), 1, stringify(cond), __FILE__, __LINE__))
#define unlikely(cond) \
	(_likely_trace(!!(cond), 0, stringify(cond), __FILE__, __LINE__))

long _likely_trace(bool cond, bool expect,
		   const char *condstr,
		   const char *file, unsigned int line);
/**
 * likely_stats - return description of abused likely()/unlikely()
 * @min_hits: minimum number of hits
 * @percent: maximum percentage correct
 *
 * When CCAN_LIKELY_DEBUG is defined, likely() and unlikely() trace their
 * results: this causes a significant slowdown, but allows analysis of
 * whether the branches are labelled correctly.
 *
 * This function returns a malloc'ed description of the least-correct
 * usage of likely() or unlikely().  It ignores places which have been
 * called less than @min_hits times, and those which were predicted
 * correctly more than @percent of the time.  It returns NULL when
 * nothing meets those criteria.
 *
 * Note that this call is destructive; the returned offender is
 * removed from the trace so that the next call to likely_stats() will
 * return the next-worst likely()/unlikely() usage.
 *
 * Example:
 *	// Print every place hit more than twice which was wrong > 5%.
 *	static void report_stats(void)
 *	{
 *	#ifdef CCAN_LIKELY_DEBUG
 *		const char *bad;
 *
 *		while ((bad = likely_stats(2, 95)) != NULL) {
 *			printf("Suspicious likely: %s", bad);
 *			free(bad);
 *		}
 *	#endif
 *	}
 */
char *likely_stats(unsigned int min_hits, unsigned int percent);

/**
 * likely_stats_reset - free up memory of likely()/unlikely() branches.
 *
 * This can also plug memory leaks.
 */
void likely_stats_reset(void);
#endif /* CCAN_LIKELY_DEBUG */
#endif /* CCAN_LIKELY_H */
