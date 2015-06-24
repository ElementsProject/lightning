#ifndef LIGHTNING_VALGRIND_H
#define LIGHTNING_VALGRIND_H

#ifdef VALGRIND_HEADERS
#include <valgrind/memcheck.h>
#elif !defined(VALGRIND_CHECK_MEM_IS_DEFINED)
#define VALGRIND_CHECK_MEM_IS_DEFINED(p, len)
#define RUNNING_ON_VALGRIND 0
#endif

/* Useful for hashing: makes sure we're not hashing crap *before* we use
 * the hash value for something. */
static inline void *check_mem(const void *data, size_t len)
{
	VALGRIND_CHECK_MEM_IS_DEFINED(data, len);
	return (void *)data;
}
#endif /* LIGHTNING_VALGRIND_H */
