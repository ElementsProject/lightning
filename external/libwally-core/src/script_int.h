#ifndef LIBWALLY_CORE_SCRIPT_INT_H
#define LIBWALLY_CORE_SCRIPT_INT_H 1

#include "ccan/ccan/endian/endian.h"

#ifdef __cplusplus
extern "C" {
#endif

/* NOTE: These internal functions do no parameter checking */
static inline size_t memcpy_len(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return len;
}

/* Read v from bytes_out in little endian */
static inline size_t uint8_from_le_bytes(const unsigned char *bytes, uint8_t *v)
{
    *v = *bytes;
    return sizeof(*v);
}

#define UINT_FROM_LE_BYTES(N) static inline size_t \
    uint ## N ## _from_le_bytes(const unsigned char *bytes, uint ## N ## _t * v) { \
        leint ## N ## _t tmp; \
        memcpy(&tmp, bytes, sizeof(tmp)); \
        *v = le ## N ## _to_cpu(tmp); \
        return sizeof(tmp); \
    }
UINT_FROM_LE_BYTES(16)
UINT_FROM_LE_BYTES(32)
UINT_FROM_LE_BYTES(64)
#undef UINT_FROM_LE_BYTES

#define UINT_FROM_BE_BYTES(N) static inline size_t \
    uint ## N ## _from_be_bytes(const unsigned char *bytes, uint ## N ## _t * v) { \
        beint ## N ## _t tmp; \
        memcpy(&tmp, bytes, sizeof(tmp)); \
        *v = be ## N ## _to_cpu(tmp); \
        return sizeof(tmp); \
    }
UINT_FROM_BE_BYTES(16)
UINT_FROM_BE_BYTES(32)
UINT_FROM_BE_BYTES(64)
#undef UINT_FROM_LE_BYTES


/* Write v to bytes_out in little endian */
static inline size_t uint8_to_le_bytes(uint8_t v, unsigned char *bytes_out)
{
    *bytes_out = v;
    return sizeof(v);
}

#define UINT_TO_LE_BYTES(N) static inline size_t \
    uint ## N ## _to_le_bytes(uint ## N ## _t v, unsigned char *bytes_out) { \
        leint ## N ## _t tmp = cpu_to_le ## N(v); \
        return memcpy_len(bytes_out, &tmp, sizeof(tmp)); \
    }
UINT_TO_LE_BYTES(16)
UINT_TO_LE_BYTES(32)
UINT_TO_LE_BYTES(64)
#undef UINT_TO_LE_BYTES

#define UINT_TO_BE_BYTES(N) static inline size_t \
    uint ## N ## _to_be_bytes(uint ## N ## _t v, unsigned char *bytes_out) { \
        beint ## N ## _t tmp = cpu_to_be ## N(v); \
        return memcpy_len(bytes_out, &tmp, sizeof(tmp)); \
    }
UINT_TO_BE_BYTES(16)
UINT_TO_BE_BYTES(32)
UINT_TO_BE_BYTES(64)
#undef UINT_TO_BE_BYTES


/* Get the number of bytes required to encode v as a varint */
size_t varint_get_length(uint64_t v);

/* Write v to bytes_out as a varint */
size_t varint_to_bytes(uint64_t v, unsigned char *bytes_out);

/* Read a variant from bytes */
size_t varint_from_bytes(const unsigned char *bytes, uint64_t *v);

size_t varint_length_from_bytes(const unsigned char *bytes);

size_t confidential_asset_length_from_bytes(const unsigned char *bytes);

size_t confidential_value_length_from_bytes(const unsigned char *bytes);

size_t confidential_nonce_length_from_bytes(const unsigned char *bytes);

size_t confidential_asset_varint_from_bytes(const unsigned char *bytes, uint64_t *v);

size_t confidential_value_varint_from_bytes(const unsigned char *bytes, uint64_t *v);

size_t confidential_nonce_varint_from_bytes(const unsigned char *bytes, uint64_t *v);

/* varbuff is a buffer of data prefixed with a varint length */

/* Get the number of bytes required to write 'n' bytes as a varbuff */
static inline size_t varbuff_get_length(size_t n)
{
    return varint_get_length(n) + n;
}

/* Write bytes to bytes_out as a varbuff */
size_t varbuff_to_bytes(const unsigned char *bytes, size_t bytes_len,
                        unsigned char *bytes_out);

/* Write confidential value to bytes_out */
size_t confidential_value_to_bytes(const unsigned char *bytes, size_t bytes_len,
                                   unsigned char *bytes_out);
#ifdef __cplusplus
}
#endif

#endif /* LIBWALLY_CORE_SCRIPT_INT_H */
