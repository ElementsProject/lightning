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

#define BIP38_DERVIED_KEY_LEN 64u

#define BIP38_PREFIX   0x01
#define BIP38_ECMUL    0x43
#define BIP38_NO_ECMUL 0x42

struct derived_t {
    unsigned char half1_lo[BIP38_DERVIED_KEY_LEN / 4];
    unsigned char half1_hi[BIP38_DERVIED_KEY_LEN / 4];
    unsigned char half2[BIP38_DERVIED_KEY_LEN / 2];
};

struct bip38_layout_t {
    unsigned char pad1;
    unsigned char prefix;
    unsigned char ec_type;
    unsigned char flags;
    uint32_t hash;
    unsigned char half1[AES_BLOCK_LEN];
    unsigned char half2[AES_BLOCK_LEN];
    unsigned char decode_hash[BASE58_CHECKSUM_LEN];
};

/* LCOV_EXCL_START */
/* Check assumptions we expect to hold true */
static void assert_assumptions(void)
{
    /* derived_t/bip38_layout_t must be contiguous */
    BUILD_ASSERT(sizeof(struct derived_t) == BIP38_DERVIED_KEY_LEN);
    /* 44 -> pad1 + 39 + BASE58_CHECKSUM_LEN */
    BUILD_ASSERT(sizeof(struct bip38_layout_t) == 44u);
    BUILD_ASSERT((sizeof(struct bip38_layout_t) - BASE58_CHECKSUM_LEN - 1) ==
                 BIP38_SERIALIZED_LEN);
}
/* LCOV_EXCL_STOP */

/* FIXME: Export this with other address functions */
static int address_from_private_key(const unsigned char *bytes_in,
                                    size_t len_in,
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

    ret = wally_ec_public_key_from_private_key(bytes_in, len_in,
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
    clear_n(4, &sha, sizeof(sha), pub_key_short, sizeof(pub_key_short),
            pub_key_long, sizeof(pub_key_long), &buf, sizeof(buf));
    return ret;
}

static void aes_enc(const unsigned char *src, const unsigned char *xor,
                    const unsigned char *key, unsigned char *bytes_out)
{
    unsigned char plaintext[AES_BLOCK_LEN];
    size_t i;

    for (i = 0; i < sizeof(plaintext); ++i)
        plaintext[i] = src[i] ^ xor[i];

    wally_aes(key, AES_KEY_LEN_256, plaintext, AES_BLOCK_LEN,
              AES_FLAG_ENCRYPT, bytes_out, AES_BLOCK_LEN);

    clear(plaintext, sizeof(plaintext));
}

int bip38_raw_from_private_key(const unsigned char *bytes_in, size_t len_in,
                               const unsigned char *pass, size_t pass_len,
                               uint32_t flags,
                               unsigned char *bytes_out, size_t len)
{
    const bool compressed = flags & BIP38_KEY_COMPRESSED;
    struct derived_t derived;
    struct bip38_layout_t buf;
    int ret = WALLY_EINVAL;

    if (!bytes_in || len_in != EC_PRIVATE_KEY_LEN ||
        !bytes_out || len != BIP38_SERIALIZED_LEN ||
        flags & ~BIP38_ALL_DEFINED_FLAGS)
        goto finish;

    if (flags & BIP38_KEY_RAW_MODE)
        buf.hash = base58_get_checksum(bytes_in, len_in);
    else {
        const unsigned char network = flags & 0xff;
        char *addr58 = NULL;
        if ((ret = address_from_private_key(bytes_in, len_in,
                                            network, compressed, &addr58)))
            goto finish;

        buf.hash = base58_get_checksum((unsigned char *)addr58, strlen(addr58));
        wally_free_string(addr58);
    }

    ret = wally_scrypt(pass, pass_len,
                       (unsigned char *)&buf.hash, sizeof(buf.hash), 16384, 8, 8,
                       (unsigned char *)&derived, sizeof(derived));
    if (ret)
        goto finish;

    buf.prefix = BIP38_PREFIX;
    buf.ec_type = BIP38_NO_ECMUL; /* FIXME: EC-Multiply support */
    buf.flags = BIP38_FLAG_DEFAULT | (compressed ? BIP38_FLAG_COMPRESSED : 0);
    aes_enc(bytes_in + 0, derived.half1_lo, derived.half2, buf.half1);
    aes_enc(bytes_in + 16, derived.half1_hi, derived.half2, buf.half2);

    if (flags & BIP38_KEY_SWAP_ORDER) {
        /* Shuffle hash from the beginning to the end */
        uint32_t tmp = buf.hash;
        memmove(&buf.hash, buf.half1, AES_BLOCK_LEN * 2);
        memcpy(buf.decode_hash - sizeof(uint32_t), &tmp, sizeof(uint32_t));
    }

    memcpy(bytes_out, &buf.prefix, BIP38_SERIALIZED_LEN);

finish:
    clear_n(2, &derived, sizeof(derived), &buf, sizeof(buf));
    return ret;
}

int bip38_from_private_key(const unsigned char *bytes_in, size_t len_in,
                           const unsigned char *pass, size_t pass_len,
                           uint32_t flags, char **output)
{
    struct bip38_layout_t buf;
    int ret;

    if (!output)
        return WALLY_EINVAL;

    *output = NULL;

    ret = bip38_raw_from_private_key(bytes_in, len_in, pass, pass_len,
                                     flags, &buf.prefix, BIP38_SERIALIZED_LEN);
    if (!ret)
        ret = wally_base58_from_bytes(&buf.prefix, BIP38_SERIALIZED_LEN,
                                      BASE58_FLAG_CHECKSUM, output);

    clear(&buf, sizeof(buf));
    return ret;
}


static void aes_dec(const unsigned char *cyphertext, const unsigned char *xor,
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
                          const unsigned char *bytes_in, size_t len_in,
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

    if (bytes_in) {
        if (len_in != BIP38_SERIALIZED_LEN)
            goto finish;
        memcpy(&buf.prefix, bytes_in, BIP38_SERIALIZED_LEN);
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
        /* Shuffle hash from the end to the beginning */
        uint32_t tmp;
        memcpy(&tmp, buf.decode_hash - sizeof(uint32_t), sizeof(uint32_t));
        memmove(buf.half1, &buf.hash, AES_BLOCK_LEN * 2);
        buf.hash = tmp;
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
                           (unsigned char *)&buf.hash, sizeof(buf.hash), 16384, 8, 8,
                           (unsigned char *)&derived, sizeof(derived))))
        goto finish;

    aes_dec(buf.half1, derived.half1_lo, derived.half2, bytes_out + 0);
    aes_dec(buf.half2, derived.half1_hi, derived.half2, bytes_out + 16);

    if (flags & BIP38_KEY_RAW_MODE) {
        if (buf.hash != base58_get_checksum(bytes_out, len))
            ret = WALLY_EINVAL;
    } else {
        const unsigned char network = flags & 0xff;
        char *addr58 = NULL;
        ret = address_from_private_key(bytes_out, len, network,
                                       buf.flags & BIP38_FLAG_COMPRESSED, &addr58);
        if (!ret &&
            buf.hash != base58_get_checksum((unsigned char *)addr58, strlen(addr58)))
            ret = WALLY_EINVAL;
        wally_free_string(addr58);
    }

finish:
    clear_n(2, &derived, sizeof(derived), &buf, sizeof(buf));
    return ret;
}

int bip38_raw_to_private_key(const unsigned char *bytes_in, size_t len_in,
                             const unsigned char *pass, size_t pass_len,
                             uint32_t flags,
                             unsigned char *bytes_out, size_t len)
{
    return to_private_key(NULL, bytes_in, len_in, pass, pass_len,
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
