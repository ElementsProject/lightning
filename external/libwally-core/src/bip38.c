#include "internal.h"
#include "base58.h"
#include "ccan/ccan/crypto/sha256/sha256.h"
#include "ccan/ccan/crypto/ripemd160/ripemd160.h"
#include "ccan/ccan/endian/endian.h"
#include "ccan/ccan/build_assert/build_assert.h"
#include <include/wally_bip38.h>
#include <include/wally_crypto.h>
#include <stdbool.h>

#define BIP38_FLAG_DEFAULT   (0x40 | 0x80)
#define BIP38_FLAG_COMPRESSED 0x20
#define BIP38_FLAG_RESERVED1  0x10
#define BIP38_FLAG_RESERVED2  0x08
#define BIP38_FLAG_HAVE_LOT   0x04
#define BIP38_FLAG_RESERVED3  0x02
#define BIP38_FLAG_RESERVED4  0x01
#define BIP38_FLAGS_RESERVED (BIP38_FLAG_RESERVED1 | BIP38_FLAG_RESERVED2 | \
                              BIP38_FLAG_RESERVED3 | BIP38_FLAG_RESERVED4)

#define BIP38_ALL_DEFINED_FLAGS (BIP38_KEY_MAINNET |      \
                                 BIP38_KEY_TESTNET |      \
                                 BIP38_KEY_COMPRESSED |   \
                                 BIP38_KEY_EC_MULT |      \
                                 BIP38_KEY_QUICK_CHECK |  \
                                 BIP38_KEY_RAW_MODE |     \
                                 BIP38_KEY_SWAP_ORDER |   \
                                 BIP38_FLAG_DEFAULT |     \
                                 BIP38_FLAG_COMPRESSED |  \
                                 BIP38_FLAG_HAVE_LOT)

#define BIP38_DERIVED_KEY_LEN 64u

#define BIP38_PREFIX   0x01
#define BIP38_ECMUL    0x43
#define BIP38_NO_ECMUL 0x42

struct derived_t {
    unsigned char half1_lo[BIP38_DERIVED_KEY_LEN / 4];
    unsigned char half1_hi[BIP38_DERIVED_KEY_LEN / 4];
    unsigned char half2[BIP38_DERIVED_KEY_LEN / 2];
};

struct bip38_sublayout_t {
    uint32_t hash;
    unsigned char half1[AES_BLOCK_LEN];
    unsigned char half2[AES_BLOCK_LEN];
};

struct bip38_sublayout_swapped_t {
    unsigned char half1[AES_BLOCK_LEN];
    unsigned char half2[AES_BLOCK_LEN];
    uint32_t hash;
};

struct bip38_layout_t {
    unsigned char pad1;
    unsigned char prefix;
    unsigned char ec_type;
    unsigned char flags;
    union {
        struct bip38_sublayout_t normal;
        struct bip38_sublayout_swapped_t swapped;
    } u;
    unsigned char decode_hash[BASE58_CHECKSUM_LEN];
};

/* LCOV_EXCL_START */
/* Check assumptions we expect to hold true */
static void assert_bip38_assumptions(void)
{
    /* derived_t/bip38_layout_t must be contiguous */
    BUILD_ASSERT(sizeof(struct derived_t) == BIP38_DERIVED_KEY_LEN);
    /* swapped and normal sublayouts must be the same size */
    BUILD_ASSERT(sizeof(struct bip38_sublayout_t) == sizeof(struct bip38_sublayout_swapped_t));
    /* 44 -> pad1 + 39 + BASE58_CHECKSUM_LEN */
    BUILD_ASSERT(sizeof(struct bip38_layout_t) == 44u);
    BUILD_ASSERT((sizeof(struct bip38_layout_t) - BASE58_CHECKSUM_LEN - 1) ==
                 BIP38_SERIALIZED_LEN);
}
/* LCOV_EXCL_STOP */

/* FIXME: Export this with other address functions */
static int address_from_private_key(const unsigned char *bytes,
                                    size_t bytes_len,
                                    unsigned char network,
                                    bool compressed,
                                    char **output)
{
    struct sha256 sha;
    unsigned char pub_key_short[EC_PUBLIC_KEY_LEN];
    unsigned char pub_key_long[EC_PUBLIC_KEY_UNCOMPRESSED_LEN];
    unsigned char *pub_key = pub_key_short;
    size_t pub_key_len = compressed ? EC_PUBLIC_KEY_LEN : EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
    struct {
        union {
            uint32_t network;
            unsigned char bytes[4];
        } network_bytes; /* Used for alignment */
        struct ripemd160 hash160;
    } buf;
    int ret;

    /* Network and hash160 must be contiguous */
    BUILD_ASSERT(sizeof(buf) == sizeof(struct ripemd160) + sizeof(uint32_t));

    ret = wally_ec_public_key_from_private_key(bytes, bytes_len,
                                               pub_key_short, sizeof(pub_key_short));
    if (ret == WALLY_OK && !compressed) {
        ret = wally_ec_public_key_decompress(pub_key_short, sizeof(pub_key_short),
                                             pub_key_long, sizeof(pub_key_long));
        pub_key = pub_key_long;
    }
    if (ret == WALLY_OK) {
        sha256(&sha, pub_key, pub_key_len);
        ripemd160(&buf.hash160, &sha, sizeof(sha));
        buf.network_bytes.bytes[3] = network;
        ret = wally_base58_from_bytes(&buf.network_bytes.bytes[3],
                                      sizeof(unsigned char) + sizeof(buf.hash160),
                                      BASE58_FLAG_CHECKSUM, output);
    }
    wally_clear_4(&sha, sizeof(sha), pub_key_short, sizeof(pub_key_short),
                  pub_key_long, sizeof(pub_key_long), &buf, sizeof(buf));
    return ret;
}

static void aes_enc_impl(const unsigned char *src, const unsigned char *xor,
                         const unsigned char *key, unsigned char *bytes_out)
{
    unsigned char plaintext[AES_BLOCK_LEN];
    size_t i;

    for (i = 0; i < sizeof(plaintext); ++i)
        plaintext[i] = src[i] ^ xor[i];

    wally_aes(key, AES_KEY_LEN_256, plaintext, AES_BLOCK_LEN,
              AES_FLAG_ENCRYPT, bytes_out, AES_BLOCK_LEN);

    wally_clear(plaintext, sizeof(plaintext));
}

int bip38_raw_from_private_key(const unsigned char *bytes, size_t bytes_len,
                               const unsigned char *pass, size_t pass_len,
                               uint32_t flags,
                               unsigned char *bytes_out, size_t len)
{
    const bool compressed = flags & BIP38_KEY_COMPRESSED;
    struct derived_t derived;
    struct bip38_layout_t buf;
    int ret = WALLY_EINVAL;

    if (!bytes || bytes_len != EC_PRIVATE_KEY_LEN ||
        !bytes_out || len != BIP38_SERIALIZED_LEN ||
        flags & ~BIP38_ALL_DEFINED_FLAGS)
        goto finish;

    if (flags & BIP38_KEY_RAW_MODE)
        buf.u.normal.hash = base58_get_checksum(bytes, bytes_len);
    else {
        const unsigned char network = flags & 0xff;
        char *addr58 = NULL;
        if ((ret = address_from_private_key(bytes, bytes_len,
                                            network, compressed, &addr58)))
            goto finish;

        buf.u.normal.hash = base58_get_checksum((unsigned char *)addr58, strlen(addr58));
        wally_free_string(addr58);
    }

    ret = wally_scrypt(pass, pass_len,
                       (unsigned char *)&buf.u.normal.hash, sizeof(buf.u.normal.hash),
                       16384, 8, 8,
                       (unsigned char *)&derived, sizeof(derived));
    if (ret)
        goto finish;

    buf.prefix = BIP38_PREFIX;
    buf.ec_type = BIP38_NO_ECMUL; /* FIXME: EC-Multiply support */
    buf.flags = BIP38_FLAG_DEFAULT | (compressed ? BIP38_FLAG_COMPRESSED : 0);
    aes_enc_impl(bytes + 0, derived.half1_lo, derived.half2, buf.u.normal.half1);
    aes_enc_impl(bytes + 16, derived.half1_hi, derived.half2, buf.u.normal.half2);

    if (flags & BIP38_KEY_SWAP_ORDER) {
        /* Shuffle hash from the beginning to the end (normal->swapped) */
        struct bip38_sublayout_swapped_t swapped;
        swapped.hash = buf.u.normal.hash;
        memcpy(swapped.half1, buf.u.normal.half1, sizeof(buf.u.normal.half1));
        memcpy(swapped.half2, buf.u.normal.half2, sizeof(buf.u.normal.half2));
        memcpy(&buf.u.swapped, &swapped, sizeof(swapped));
        wally_clear(&swapped, sizeof(swapped));
    }

    memcpy(bytes_out, &buf.prefix, BIP38_SERIALIZED_LEN);

finish:
    wally_clear_2(&derived, sizeof(derived), &buf, sizeof(buf));
    return ret;
}

int bip38_from_private_key(const unsigned char *bytes, size_t bytes_len,
                           const unsigned char *pass, size_t pass_len,
                           uint32_t flags, char **output)
{
    struct bip38_layout_t buf;
    int ret;

    if (!output)
        return WALLY_EINVAL;

    *output = NULL;

    ret = bip38_raw_from_private_key(bytes, bytes_len, pass, pass_len,
                                     flags, &buf.prefix, BIP38_SERIALIZED_LEN);
    if (!ret)
        ret = wally_base58_from_bytes(&buf.prefix, BIP38_SERIALIZED_LEN,
                                      BASE58_FLAG_CHECKSUM, output);

    wally_clear(&buf, sizeof(buf));
    return ret;
}


static void aes_dec_impl(const unsigned char *cyphertext, const unsigned char *xor,
                         const unsigned char *key, unsigned char *bytes_out)
{
    size_t i;

    wally_aes(key, AES_KEY_LEN_256,
              (unsigned char *)cyphertext, AES_BLOCK_LEN,
              AES_FLAG_DECRYPT,
              bytes_out, AES_BLOCK_LEN);

    for (i = 0; i < AES_BLOCK_LEN; ++i)
        bytes_out[i] ^= xor[i];
}

static int to_private_key(const char *bip38,
                          const unsigned char *bytes, size_t bytes_len,
                          const unsigned char *pass, size_t pass_len,
                          uint32_t flags,
                          unsigned char *bytes_out, size_t len)
{
    struct derived_t derived;
    struct bip38_layout_t buf;
    int ret = WALLY_EINVAL;

    if (flags & ~BIP38_ALL_DEFINED_FLAGS)
        goto finish;

    if (!(flags & BIP38_KEY_QUICK_CHECK) &&
        (!bytes_out || len != EC_PRIVATE_KEY_LEN))
        goto finish;

    if (bytes) {
        if (bytes_len != BIP38_SERIALIZED_LEN)
            goto finish;
        memcpy(&buf.prefix, bytes, BIP38_SERIALIZED_LEN);
    } else {
        size_t written;
        if ((ret = wally_base58_to_bytes(bip38, BASE58_FLAG_CHECKSUM, &buf.prefix,
                                         BIP38_SERIALIZED_LEN + BASE58_CHECKSUM_LEN,
                                         &written)))
            goto finish;

        if (written != BIP38_SERIALIZED_LEN) {
            ret = WALLY_EINVAL;
            goto finish;
        }
    }

    if (flags & BIP38_KEY_SWAP_ORDER) {
        /* Shuffle hash from the end to the beginning (swapped->normal) */
        struct bip38_sublayout_t normal;
        normal.hash = buf.u.swapped.hash;
        memcpy(normal.half1, buf.u.swapped.half1, sizeof(buf.u.swapped.half1));
        memcpy(normal.half2, buf.u.swapped.half2, sizeof(buf.u.swapped.half2));
        memcpy(&buf.u.normal, &normal, sizeof(normal));
        wally_clear(&normal, sizeof(normal));
    }

    if (buf.prefix != BIP38_PREFIX ||
        buf.flags & BIP38_FLAGS_RESERVED ||
        (buf.flags & BIP38_FLAG_DEFAULT) != BIP38_FLAG_DEFAULT ||
        buf.ec_type != BIP38_NO_ECMUL /* FIXME: EC Mul support */ ||
        buf.flags & BIP38_FLAG_HAVE_LOT) {
        ret = WALLY_EINVAL;
        goto finish;
    }

    if (flags & BIP38_KEY_QUICK_CHECK) {
        ret = WALLY_OK;
        goto finish;
    }

    if((ret = wally_scrypt(pass, pass_len,
                           (unsigned char *)&buf.u.normal.hash, sizeof(buf.u.normal.hash), 16384, 8, 8,
                           (unsigned char *)&derived, sizeof(derived))))
        goto finish;

    aes_dec_impl(buf.u.normal.half1, derived.half1_lo, derived.half2, bytes_out + 0);
    aes_dec_impl(buf.u.normal.half2, derived.half1_hi, derived.half2, bytes_out + 16);

    if (flags & BIP38_KEY_RAW_MODE) {
        if (buf.u.normal.hash != base58_get_checksum(bytes_out, len))
            ret = WALLY_EINVAL;
    } else {
        const unsigned char network = flags & 0xff;
        char *addr58 = NULL;
        ret = address_from_private_key(bytes_out, len, network,
                                       buf.flags & BIP38_FLAG_COMPRESSED, &addr58);
        if (!ret &&
            buf.u.normal.hash != base58_get_checksum((unsigned char *)addr58, strlen(addr58)))
            ret = WALLY_EINVAL;
        wally_free_string(addr58);
    }

finish:
    wally_clear_2(&derived, sizeof(derived), &buf, sizeof(buf));
    return ret;
}

int bip38_raw_to_private_key(const unsigned char *bytes, size_t bytes_len,
                             const unsigned char *pass, size_t pass_len,
                             uint32_t flags,
                             unsigned char *bytes_out, size_t len)
{
    return to_private_key(NULL, bytes, bytes_len, pass, pass_len,
                          flags, bytes_out, len);
}

int bip38_to_private_key(const char *bip38,
                         const unsigned char *pass, size_t pass_len,
                         uint32_t flags,
                         unsigned char *bytes_out, size_t len)
{
    return to_private_key(bip38, NULL, 0, pass, pass_len, flags,
                          bytes_out, len);
}

static int get_flags(const char *bip38,
                     const unsigned char *bytes, size_t bytes_len,
                     size_t *written)
{
    struct bip38_layout_t buf;

    if (!written)
        return WALLY_EINVAL;

    *written = 0;

    if (bytes) {
        if (bytes_len != BIP38_SERIALIZED_LEN)
            return WALLY_EINVAL;
        memcpy(&buf.prefix, bytes, BIP38_SERIALIZED_LEN);
    } else {
        size_t serialized_len;
        int ret;
        if ((ret = wally_base58_to_bytes(bip38, BASE58_FLAG_CHECKSUM, &buf.prefix,
                                         BIP38_SERIALIZED_LEN + BASE58_CHECKSUM_LEN,
                                         &serialized_len)))
            return ret;

        if (serialized_len != BIP38_SERIALIZED_LEN)
            return WALLY_EINVAL;
    }

    *written = buf.ec_type != BIP38_NO_ECMUL ? BIP38_KEY_EC_MULT : 0;
    *written |= buf.flags & BIP38_FLAG_COMPRESSED ? BIP38_KEY_COMPRESSED : 0;

    wally_clear(&buf, sizeof(buf));

    return WALLY_OK;
}

int bip38_raw_get_flags(const unsigned char *bytes, size_t bytes_len,
                        size_t *written)
{
    return get_flags(NULL, bytes, bytes_len, written);
}

int bip38_get_flags(const char *bip38,
                    size_t *written)
{
    return get_flags(bip38, NULL, 0, written);
}
