#include "internal.h"
#include "base58.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/endian/endian.h"
#include <include/wally_crypto.h>

/* Temporary stack buffer sizes */
#define BIGNUM_WORDS 128u
#define BIGNUM_BYTES (BIGNUM_WORDS * sizeof(uint32_t))
#define BASE58_ALL_DEFINED_FLAGS (BASE58_FLAG_CHECKSUM)

static const unsigned char base58_to_byte[256] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* .1234567 */
    0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 89...... */

    0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, /* .ABCDEFG */
    0x11, 0x00, 0x12, 0x13, 0x14, 0x15, 0x16, 0x00, /* H.JKLMN. */
    0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, /* PQRSTUVW */
    0x1F, 0x20, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, /* XYZ..... */

    0x00, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, /* .abcdefg */
    0x29, 0x2A, 0x2B, 0x2C, 0x00, 0x2D, 0x2E, 0x2F, /* hijk.mno */
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, /* pqrstuvx */
    0x38, 0x39, 0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, /* xyz..... */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */

    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* ........ */
};

static const char byte_to_base58[58] = {
    '1', '2', '3', '4', '5', '6', '7', '8',
    '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
    'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
    'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y','z'
};

/* Returns non-zero on error. If 0 is returned then:
 * *len <= input value - OK, bytes_out contains data.
 * *len > input value - Failed and bytes_out untouched.
 */
static int base58_decode(const char *base58, size_t base58_len,
                         unsigned char *bytes_out, size_t *len)
{
    uint32_t bn_buf[BIGNUM_WORDS];
    uint32_t *bn = bn_buf, *top_word, *bn_p;
    size_t bn_words = 0, ones, cp_len, i;
    unsigned char *cp;
    int ret = WALLY_EINVAL;

    if (!base58 || !base58_len)
        return WALLY_EINVAL; /* Empty string can't be decoded or represented */

    /* Process leading '1's */
    for (ones = 0; ones < base58_len && base58[ones] == '1'; ++ones)
        ; /* no-op*/

    if (!(base58_len -= ones)) {
        if (bytes_out && ones <= *len)
            memset(bytes_out, 0, ones);
        *len = ones;
        return WALLY_OK; /* String of all '1's */
    }
    base58 += ones; /* Skip over leading '1's */

    /* Take 6 bits to store each 58 bit number, rounded up to the next byte,
     * then round that up to a uint32_t word boundary. */
    bn_words = ((base58_len * 6 + 7) / 8 + 3) / 4;

    /* Allocate our bignum buffer if it won't fit on the stack */
    if (bn_words > BIGNUM_WORDS)
        if (!(bn = wally_malloc(bn_words * sizeof(*bn)))) {
            ret = WALLY_ENOMEM;
            goto cleanup;
        }

    /* Iterate through the characters adding them to our bignum. We keep
     * track of the current top word to avoid iterating over words that
     * we know are zero. */
    top_word = bn + bn_words - 1;
    *top_word = 0;

    for (i = 0; i < base58_len; ++i) {
        unsigned char byte = base58_to_byte[((unsigned char *)base58)[i]];
        if (!byte--)
            goto cleanup; /* Invalid char */

        for (bn_p = bn + bn_words - 1; bn_p >= top_word; --bn_p) {
            uint64_t mult = *bn_p * 58ull + byte;
            *bn_p = mult & 0xffffffff;
            byte = (mult >> 32) & 0xff;
            if (byte && bn_p == top_word) {
                *--top_word = byte; /* Increase bignum size */
                break;
            }
        }
    }

    /* We have our bignum stored from top_word to bn + bn_words - 1. Convert
     * its words to big-endian so we can simply memcpy it to bytes_out. */
    for (bn_p = top_word; bn_p < bn + bn_words; ++bn_p)
        *bn_p = cpu_to_be32(*bn_p); /* No-op on big-endian machines */

    for (cp = (unsigned char *)top_word; !*cp; ++cp)
        ; /* Skip leading zero bytes in our bignum */

    /* Copy the result if it fits, cleanup and return */
    cp_len = (unsigned char *)(bn + bn_words) - cp;

    if (bytes_out && ones + cp_len <= *len) {
        memset(bytes_out, 0, ones);
        memcpy(bytes_out + ones, cp, cp_len);
    }

    *len = ones + cp_len;
    ret = WALLY_OK;

cleanup:
    clear(bn, bn_words * sizeof(*bn));
    if (bn != bn_buf)
        wally_free(bn);
    return ret;
}

uint32_t base58_get_checksum(const unsigned char *bytes_in, size_t len_in)
{
    struct sha256 sha;
    uint32_t checksum;

    wally_sha256d(bytes_in, len_in, (unsigned char *)&sha, sizeof(sha));
    checksum = sha.u.u32[0];
    clear(&sha, sizeof(sha));
    return checksum;
}


int wally_base58_from_bytes(const unsigned char *bytes_in, size_t len_in,
                            uint32_t flags, char **output)
{
    uint32_t checksum, *cs_p = NULL;
    unsigned char bn_buf[BIGNUM_BYTES];
    unsigned char *bn = bn_buf, *top_byte, *bn_p;
    size_t bn_bytes = 0, zeros, i, orig_len = len_in;
    int ret = WALLY_EINVAL;

    if (*output)
        *output = NULL;

    if (!bytes_in || !len_in || (flags & ~BASE58_ALL_DEFINED_FLAGS) || !output)
        goto cleanup; /* Invalid argument */

    if (flags & BASE58_FLAG_CHECKSUM) {
        checksum = base58_get_checksum(bytes_in, len_in);
        cs_p = &checksum;
        len_in += 4;
    }

#define b(n) (n < orig_len ? bytes_in[n] : ((unsigned char *)cs_p)[n - orig_len])

    /* Process leading zeros */
    for (zeros = 0; zeros < len_in && !b(zeros); ++zeros)
        ; /* no-op*/

    if (zeros == len_in) {
        if (!(*output = wally_malloc(zeros + 1))) {
            ret = WALLY_ENOMEM;
            goto cleanup;
        }

        memset(*output, '1', zeros);
        (*output)[zeros] = '\0';
        return WALLY_OK; /* All 0's */
    }

    bn_bytes = (len_in - zeros) * 138 / 100 + 1; /* log(256)/log(58) rounded up */

    /* Allocate our bignum buffer if it won't fit on the stack */
    if (bn_bytes > BIGNUM_BYTES)
        if (!(bn = wally_malloc(bn_bytes))) {
            ret = WALLY_ENOMEM;
            goto cleanup;
        }

    top_byte = bn + bn_bytes - 1;
    *top_byte = 0;

    for (i = zeros; i < len_in; ++i) {
        uint32_t carry = b(i);
        for (bn_p = bn + bn_bytes - 1; bn_p >= top_byte; --bn_p) {
            carry = *bn_p * 256 + carry;
            *bn_p = carry % 58;
            carry = carry / 58;
            if (carry && bn_p == top_byte)
                *--top_byte = 0; /* Increase bignum size */
        }
    }

    while (!*top_byte && top_byte < bn + bn_bytes - 1)
        ++top_byte; /* Skip leading zero bytes in our bignum */

    /* Copy the result */
    bn_bytes = bn + bn_bytes - top_byte;

    if (!(*output = wally_malloc(zeros + bn_bytes + 1))) {
        ret = WALLY_ENOMEM;
        goto cleanup;
    }

    memset(*output, '1', zeros);
    for (i = 0; i < bn_bytes; ++i)
        (*output)[zeros + i] = byte_to_base58[top_byte[i]];
    (*output)[zeros + bn_bytes] = '\0';

    ret = WALLY_OK;

cleanup:
    clear(bn, bn_bytes);
    if (bn != bn_buf)
        wally_free(bn);
    return ret;
}


int wally_base58_get_length(const char *str_in, size_t *written)
{
    return base58_decode(str_in, strlen(str_in), NULL, written);
}

int wally_base58_to_bytes(const char *str_in, uint32_t flags,
                          unsigned char *bytes_out, size_t len,
                          size_t *written)
{
    int ret;

    if (written)
        *written = 0;

    if (!str_in || flags & ~BASE58_ALL_DEFINED_FLAGS ||
        !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (flags & BASE58_FLAG_CHECKSUM && len <= BASE58_CHECKSUM_LEN)
        return WALLY_EINVAL; /* No room for checksum */

    *written = len;
    ret = base58_decode(str_in, strlen(str_in), bytes_out, written);
    if (!ret && *written > len)
        return WALLY_OK; /* not enough space, return required amount */

    if (!ret && (flags & BASE58_FLAG_CHECKSUM)) {
        size_t offset = *written - BASE58_CHECKSUM_LEN;
        uint32_t checksum = base58_get_checksum(bytes_out, offset);

        if (memcmp(bytes_out + offset, &checksum, sizeof(checksum))) {
            clear(bytes_out, len);
            return WALLY_EINVAL; /* Checksum mismatch */
        }

        clear(bytes_out + offset, BASE58_CHECKSUM_LEN);
        *written -= BASE58_CHECKSUM_LEN;
    }
    return ret;
}
