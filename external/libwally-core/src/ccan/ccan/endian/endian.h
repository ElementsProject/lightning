/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_ENDIAN_H
#define CCAN_ENDIAN_H
#include <stdint.h>
#include "config.h"

/**
 * BSWAP_16 - reverse bytes in a constant uint16_t value.
 * @val: constant value whose bytes to swap.
 *
 * Designed to be usable in constant-requiring initializers.
 *
 * Example:
 *	struct mystruct {
 *		char buf[BSWAP_16(0x1234)];
 *	};
 */
#define BSWAP_16(val)				\
	((((uint16_t)(val) & 0x00ff) << 8)	\
	 | (((uint16_t)(val) & 0xff00) >> 8))

/**
 * BSWAP_32 - reverse bytes in a constant uint32_t value.
 * @val: constant value whose bytes to swap.
 *
 * Designed to be usable in constant-requiring initializers.
 *
 * Example:
 *	struct mystruct {
 *		char buf[BSWAP_32(0xff000000)];
 *	};
 */
#define BSWAP_32(val)					\
	((((uint32_t)(val) & 0x000000ff) << 24)		\
	 | (((uint32_t)(val) & 0x0000ff00) << 8)		\
	 | (((uint32_t)(val) & 0x00ff0000) >> 8)		\
	 | (((uint32_t)(val) & 0xff000000) >> 24))

/**
 * BSWAP_64 - reverse bytes in a constant uint64_t value.
 * @val: constantvalue whose bytes to swap.
 *
 * Designed to be usable in constant-requiring initializers.
 *
 * Example:
 *	struct mystruct {
 *		char buf[BSWAP_64(0xff00000000000000ULL)];
 *	};
 */
#define BSWAP_64(val)						\
	((((uint64_t)(val) & 0x00000000000000ffULL) << 56)	\
	 | (((uint64_t)(val) & 0x000000000000ff00ULL) << 40)	\
	 | (((uint64_t)(val) & 0x0000000000ff0000ULL) << 24)	\
	 | (((uint64_t)(val) & 0x00000000ff000000ULL) << 8)	\
	 | (((uint64_t)(val) & 0x000000ff00000000ULL) >> 8)	\
	 | (((uint64_t)(val) & 0x0000ff0000000000ULL) >> 24)	\
	 | (((uint64_t)(val) & 0x00ff000000000000ULL) >> 40)	\
	 | (((uint64_t)(val) & 0xff00000000000000ULL) >> 56))

#if HAVE_BYTESWAP_H
#include <byteswap.h>
#else
/**
 * bswap_16 - reverse bytes in a uint16_t value.
 * @val: value whose bytes to swap.
 *
 * Example:
 *	// Output contains "1024 is 4 as two bytes reversed"
 *	printf("1024 is %u as two bytes reversed\n", bswap_16(1024));
 */
static inline uint16_t bswap_16(uint16_t val)
{
	return BSWAP_16(val);
}

/**
 * bswap_32 - reverse bytes in a uint32_t value.
 * @val: value whose bytes to swap.
 *
 * Example:
 *	// Output contains "1024 is 262144 as four bytes reversed"
 *	printf("1024 is %u as four bytes reversed\n", bswap_32(1024));
 */
static inline uint32_t bswap_32(uint32_t val)
{
	return BSWAP_32(val);
}
#endif /* !HAVE_BYTESWAP_H */

#if !HAVE_BSWAP_64
/**
 * bswap_64 - reverse bytes in a uint64_t value.
 * @val: value whose bytes to swap.
 *
 * Example:
 *	// Output contains "1024 is 1125899906842624 as eight bytes reversed"
 *	printf("1024 is %llu as eight bytes reversed\n",
 *		(unsigned long long)bswap_64(1024));
 */
static inline uint64_t bswap_64(uint64_t val)
{
	return BSWAP_64(val);
}
#endif

/* Sanity check the defines.  We don't handle weird endianness. */
#if !HAVE_LITTLE_ENDIAN && !HAVE_BIG_ENDIAN
#error "Unknown endian"
#elif HAVE_LITTLE_ENDIAN && HAVE_BIG_ENDIAN
#error "Can't compile for both big and little endian."
#endif

#ifdef __CHECKER__
/* sparse needs forcing to remove bitwise attribute from ccan/short_types */
#define ENDIAN_CAST __attribute__((force))
#define ENDIAN_TYPE __attribute__((bitwise))
#else
#define ENDIAN_CAST
#define ENDIAN_TYPE
#endif

typedef uint64_t ENDIAN_TYPE leint64_t;
typedef uint64_t ENDIAN_TYPE beint64_t;
typedef uint32_t ENDIAN_TYPE leint32_t;
typedef uint32_t ENDIAN_TYPE beint32_t;
typedef uint16_t ENDIAN_TYPE leint16_t;
typedef uint16_t ENDIAN_TYPE beint16_t;

#if HAVE_LITTLE_ENDIAN
/**
 * CPU_TO_LE64 - convert a constant uint64_t value to little-endian
 * @native: constant to convert
 */
#define CPU_TO_LE64(native) ((ENDIAN_CAST leint64_t)(native))

/**
 * CPU_TO_LE32 - convert a constant uint32_t value to little-endian
 * @native: constant to convert
 */
#define CPU_TO_LE32(native) ((ENDIAN_CAST leint32_t)(native))

/**
 * CPU_TO_LE16 - convert a constant uint16_t value to little-endian
 * @native: constant to convert
 */
#define CPU_TO_LE16(native) ((ENDIAN_CAST leint16_t)(native))

/**
 * LE64_TO_CPU - convert a little-endian uint64_t constant
 * @le_val: little-endian constant to convert
 */
#define LE64_TO_CPU(le_val) ((ENDIAN_CAST uint64_t)(le_val))

/**
 * LE32_TO_CPU - convert a little-endian uint32_t constant
 * @le_val: little-endian constant to convert
 */
#define LE32_TO_CPU(le_val) ((ENDIAN_CAST uint32_t)(le_val))

/**
 * LE16_TO_CPU - convert a little-endian uint16_t constant
 * @le_val: little-endian constant to convert
 */
#define LE16_TO_CPU(le_val) ((ENDIAN_CAST uint16_t)(le_val))

#else /* ... HAVE_BIG_ENDIAN */
#define CPU_TO_LE64(native) ((ENDIAN_CAST leint64_t)BSWAP_64(native))
#define CPU_TO_LE32(native) ((ENDIAN_CAST leint32_t)BSWAP_32(native))
#define CPU_TO_LE16(native) ((ENDIAN_CAST leint16_t)BSWAP_16(native))
#define LE64_TO_CPU(le_val) BSWAP_64((ENDIAN_CAST uint64_t)le_val)
#define LE32_TO_CPU(le_val) BSWAP_32((ENDIAN_CAST uint32_t)le_val)
#define LE16_TO_CPU(le_val) BSWAP_16((ENDIAN_CAST uint16_t)le_val)
#endif /* HAVE_BIG_ENDIAN */

#if HAVE_BIG_ENDIAN
/**
 * CPU_TO_BE64 - convert a constant uint64_t value to big-endian
 * @native: constant to convert
 */
#define CPU_TO_BE64(native) ((ENDIAN_CAST beint64_t)(native))

/**
 * CPU_TO_BE32 - convert a constant uint32_t value to big-endian
 * @native: constant to convert
 */
#define CPU_TO_BE32(native) ((ENDIAN_CAST beint32_t)(native))

/**
 * CPU_TO_BE16 - convert a constant uint16_t value to big-endian
 * @native: constant to convert
 */
#define CPU_TO_BE16(native) ((ENDIAN_CAST beint16_t)(native))

/**
 * BE64_TO_CPU - convert a big-endian uint64_t constant
 * @le_val: big-endian constant to convert
 */
#define BE64_TO_CPU(le_val) ((ENDIAN_CAST uint64_t)(le_val))

/**
 * BE32_TO_CPU - convert a big-endian uint32_t constant
 * @le_val: big-endian constant to convert
 */
#define BE32_TO_CPU(le_val) ((ENDIAN_CAST uint32_t)(le_val))

/**
 * BE16_TO_CPU - convert a big-endian uint16_t constant
 * @le_val: big-endian constant to convert
 */
#define BE16_TO_CPU(le_val) ((ENDIAN_CAST uint16_t)(le_val))

#else /* ... HAVE_LITTLE_ENDIAN */
#define CPU_TO_BE64(native) ((ENDIAN_CAST beint64_t)BSWAP_64(native))
#define CPU_TO_BE32(native) ((ENDIAN_CAST beint32_t)BSWAP_32(native))
#define CPU_TO_BE16(native) ((ENDIAN_CAST beint16_t)BSWAP_16(native))
#define BE64_TO_CPU(le_val) BSWAP_64((ENDIAN_CAST uint64_t)le_val)
#define BE32_TO_CPU(le_val) BSWAP_32((ENDIAN_CAST uint32_t)le_val)
#define BE16_TO_CPU(le_val) BSWAP_16((ENDIAN_CAST uint16_t)le_val)
#endif /* HAVE_LITTE_ENDIAN */


/**
 * cpu_to_le64 - convert a uint64_t value to little-endian
 * @native: value to convert
 */
static inline leint64_t cpu_to_le64(uint64_t native)
{
	return CPU_TO_LE64(native);
}

/**
 * cpu_to_le32 - convert a uint32_t value to little-endian
 * @native: value to convert
 */
static inline leint32_t cpu_to_le32(uint32_t native)
{
	return CPU_TO_LE32(native);
}

/**
 * cpu_to_le16 - convert a uint16_t value to little-endian
 * @native: value to convert
 */
static inline leint16_t cpu_to_le16(uint16_t native)
{
	return CPU_TO_LE16(native);
}

/**
 * le64_to_cpu - convert a little-endian uint64_t value
 * @le_val: little-endian value to convert
 */
static inline uint64_t le64_to_cpu(leint64_t le_val)
{
	return LE64_TO_CPU(le_val);
}

/**
 * le32_to_cpu - convert a little-endian uint32_t value
 * @le_val: little-endian value to convert
 */
static inline uint32_t le32_to_cpu(leint32_t le_val)
{
	return LE32_TO_CPU(le_val);
}

/**
 * le16_to_cpu - convert a little-endian uint16_t value
 * @le_val: little-endian value to convert
 */
static inline uint16_t le16_to_cpu(leint16_t le_val)
{
	return LE16_TO_CPU(le_val);
}

/**
 * cpu_to_be64 - convert a uint64_t value to big endian.
 * @native: value to convert
 */
static inline beint64_t cpu_to_be64(uint64_t native)
{
	return CPU_TO_BE64(native);
}

/**
 * cpu_to_be32 - convert a uint32_t value to big endian.
 * @native: value to convert
 */
static inline beint32_t cpu_to_be32(uint32_t native)
{
	return CPU_TO_BE32(native);
}

/**
 * cpu_to_be16 - convert a uint16_t value to big endian.
 * @native: value to convert
 */
static inline beint16_t cpu_to_be16(uint16_t native)
{
	return CPU_TO_BE16(native);
}

/**
 * be64_to_cpu - convert a big-endian uint64_t value
 * @be_val: big-endian value to convert
 */
static inline uint64_t be64_to_cpu(beint64_t be_val)
{
	return BE64_TO_CPU(be_val);
}

/**
 * be32_to_cpu - convert a big-endian uint32_t value
 * @be_val: big-endian value to convert
 */
static inline uint32_t be32_to_cpu(beint32_t be_val)
{
	return BE32_TO_CPU(be_val);
}

/**
 * be16_to_cpu - convert a big-endian uint16_t value
 * @be_val: big-endian value to convert
 */
static inline uint16_t be16_to_cpu(beint16_t be_val)
{
	return BE16_TO_CPU(be_val);
}

/* Whichever they include first, they get these definitions. */
#ifdef CCAN_SHORT_TYPES_H
/**
 * be64/be32/be16 - 64/32/16 bit big-endian representation.
 */
typedef beint64_t be64;
typedef beint32_t be32;
typedef beint16_t be16;

/**
 * le64/le32/le16 - 64/32/16 bit little-endian representation.
 */
typedef leint64_t le64;
typedef leint32_t le32;
typedef leint16_t le16;
#endif
#endif /* CCAN_ENDIAN_H */
