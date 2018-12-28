/* MIT (BSD) license - see LICENSE file for details */
#ifndef CCAN_STRUCTEQ_H
#define CCAN_STRUCTEQ_H
#include <ccan/build_assert/build_assert.h>
#include <ccan/cppmagic/cppmagic.h>
#include <string.h>
#include <stdbool.h>

/**
 * STRUCTEQ_DEF - define an ..._eq function to compare two structures.
 * @sname: name of the structure, and function (<sname>_eq) to define.
 * @padbytes: number of bytes of expected padding, or negative "max".
 * @...: name of every member of the structure.
 *
 * This generates a single memcmp() call in the common case where the
 * structure contains no padding.  Since it can't tell the difference between
 * padding and a missing member, @padbytes can be used to assert that
 * there isn't any, or how many we expect.  A negative number means
 * "up to or equal to that amount of padding", as padding can be
 * platform dependent.
 */
#define STRUCTEQ_DEF(sname, padbytes, ...)				\
static inline bool CPPMAGIC_GLUE2(sname, _eq)(const struct sname *_a, \
					      const struct sname *_b) \
{									\
	BUILD_ASSERT(((padbytes) < 0 &&					\
		      CPPMAGIC_JOIN(+, CPPMAGIC_MAP(STRUCTEQ_MEMBER_SIZE_, \
						    __VA_ARGS__))	\
		      - (padbytes) >= sizeof(*_a))			\
		     || CPPMAGIC_JOIN(+, CPPMAGIC_MAP(STRUCTEQ_MEMBER_SIZE_, \
						      __VA_ARGS__))	\
		     + (padbytes) == sizeof(*_a));			\
	if (CPPMAGIC_JOIN(+, CPPMAGIC_MAP(STRUCTEQ_MEMBER_SIZE_, __VA_ARGS__)) \
	    == sizeof(*_a))						\
		return memcmp(_a, _b, sizeof(*_a)) == 0;		\
	else								\
		return CPPMAGIC_JOIN(&&,				\
				     CPPMAGIC_MAP(STRUCTEQ_MEMBER_CMP_, \
						  __VA_ARGS__));	\
}

/* Helpers */
#define STRUCTEQ_MEMBER_SIZE_(m) sizeof((_a)->m)
#define STRUCTEQ_MEMBER_CMP_(m) memcmp(&_a->m, &_b->m, sizeof(_a->m)) == 0

#endif /* CCAN_STRUCTEQ_H */
