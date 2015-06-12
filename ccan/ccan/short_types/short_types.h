/* CC0 (Public domain) - see LICENSE file for details */
#ifndef CCAN_SHORT_TYPES_H
#define CCAN_SHORT_TYPES_H
#include <stdint.h>

/**
 * u64/s64/u32/s32/u16/s16/u8/s8 - short names for explicitly-sized types.
 */
typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef int16_t s16;
typedef uint8_t u8;
typedef int8_t s8;

/* Whichever they include first, they get these definitions. */
#ifdef CCAN_ENDIAN_H
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

#endif /* CCAN_SHORT_TYPES_H */
