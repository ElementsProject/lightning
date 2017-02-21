#include "internal.h"
#include <include/wally_crypto.h>
#include <stdbool.h>

#include "ctaes/ctaes.h"
#include "ctaes/ctaes.c"

#define ALL_OPS (AES_FLAG_ENCRYPT | AES_FLAG_DECRYPT)

static bool is_valid_key_len(size_t key_len)
{
    return key_len == AES_KEY_LEN_128 || key_len == AES_KEY_LEN_192 ||
           key_len == AES_KEY_LEN_256;
}

static bool are_valid_args(const unsigned char *key, size_t key_len,
                           const unsigned char *bytes_in, uint32_t flags)
{
    return key && is_valid_key_len(key_len) && bytes_in &&
           (flags & ALL_OPS) != ALL_OPS;
}

static void aes_enc(AES256_ctx *ctx,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *bytes_in, size_t len_in,
                    unsigned char *bytes_out)
{
    len_in /= AES_BLOCK_LEN;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init((AES128_ctx *)ctx, key);
        AES128_encrypt((AES128_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_192:
        AES192_init((AES192_ctx *)ctx, key);
        AES192_encrypt((AES192_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_256:
        AES256_init(ctx, key);
        AES256_encrypt(ctx, len_in, bytes_out, bytes_in);
        break;
    }
}

static void aes_dec(AES256_ctx *ctx,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *bytes_in, size_t len_in,
                    unsigned char *bytes_out)
{
    len_in /= AES_BLOCK_LEN;

    switch (key_len) {
    case AES_KEY_LEN_128:
        AES128_init((AES128_ctx *)ctx, key);
        AES128_decrypt((AES128_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_192:
        AES192_init((AES192_ctx *)ctx, key);
        AES192_decrypt((AES192_ctx *)ctx, len_in, bytes_out, bytes_in);
        break;

    case AES_KEY_LEN_256:
        AES256_init(ctx, key);
        AES256_decrypt(ctx, len_in, bytes_out, bytes_in);
        break;
    }
}

int wally_aes(const unsigned char *key, size_t key_len,
              const unsigned char *bytes_in, size_t len_in,
              uint32_t flags,
              unsigned char *bytes_out, size_t len)
{
    AES256_ctx ctx;

    if (!are_valid_args(key, key_len, bytes_in, flags) ||
        len % AES_BLOCK_LEN || !len_in || len_in % AES_BLOCK_LEN ||
        flags & ~ALL_OPS || !bytes_out || !len)
        return WALLY_EINVAL;

    if (flags & AES_FLAG_ENCRYPT)
        aes_enc(&ctx, key, key_len, bytes_in, len_in, bytes_out);
    else
        aes_dec(&ctx, key, key_len, bytes_in, len_in, bytes_out);

    clear(&ctx, sizeof(ctx));
    return WALLY_OK;
}

int wally_aes_cbc(const unsigned char *key, size_t key_len,
                  const unsigned char *iv, size_t iv_len,
                  const unsigned char *bytes_in, size_t len_in,
                  uint32_t flags,
                  unsigned char *bytes_out, size_t len,
                  size_t *written)
{
    unsigned char buf[AES_BLOCK_LEN];
    AES256_ctx ctx;
    size_t i, n, blocks;
    unsigned char remainder;

    if (written)
        *written = 0;

    if (!are_valid_args(key, key_len, bytes_in, flags) ||
        ((flags & AES_FLAG_ENCRYPT) && (len % AES_BLOCK_LEN)) ||
        ((flags & AES_FLAG_DECRYPT) && (len_in % AES_BLOCK_LEN)) ||
        !iv || iv_len != AES_BLOCK_LEN || flags & ~ALL_OPS || !written)
        return WALLY_EINVAL;

    blocks = len_in / AES_BLOCK_LEN;

    if (flags & AES_FLAG_ENCRYPT) {
        /* Determine output length from input length */
        remainder = len_in % AES_BLOCK_LEN;
        *written = (blocks + 1) * AES_BLOCK_LEN;
    } else {
        /* Determine output length from decrypted final block */
        const unsigned char *last = bytes_in + len_in - AES_BLOCK_LEN;
        const unsigned char *prev = last - AES_BLOCK_LEN;

        if (!--blocks)
            prev = iv;
        aes_dec(&ctx, key, key_len, last, AES_BLOCK_LEN, buf);
        for (n = 0; n < AES_BLOCK_LEN; ++n)
            buf[n] = prev[n] ^ buf[n];

        /* Modulo the resulting padding amount to the block size - we do
         * not attempt to verify the decryption by checking the padding in
         * the decrypted block. */
        remainder = AES_BLOCK_LEN - (buf[AES_BLOCK_LEN - 1] % AES_BLOCK_LEN);
        if (remainder == AES_BLOCK_LEN)
            remainder = 0;
        *written = blocks * AES_BLOCK_LEN + remainder;
    }
    if (len < *written || !*written)
        goto finish; /* Inform caller how much space is needed */

    if (!bytes_out) {
        clear_n(2, buf, sizeof(buf), &ctx, sizeof(ctx));
        return WALLY_EINVAL;
    }

    if (flags & AES_FLAG_DECRYPT)
        memcpy(bytes_out + blocks * AES_BLOCK_LEN, buf, remainder);

    for (i = 0; i < blocks; ++i) {
        if (flags & AES_FLAG_ENCRYPT) {
            for (n = 0; n < AES_BLOCK_LEN; ++n)
                buf[n] = bytes_in[n] ^ iv[n];
            aes_enc(&ctx, key, key_len, buf, AES_BLOCK_LEN, bytes_out);
            iv = bytes_out;
        } else {
            aes_dec(&ctx, key, key_len, bytes_in, AES_BLOCK_LEN, bytes_out);
            for (n = 0; n < AES_BLOCK_LEN; ++n)
                bytes_out[n] = bytes_out[n] ^ iv[n];
            iv = bytes_in;
        }
        bytes_in += AES_BLOCK_LEN;
        bytes_out += AES_BLOCK_LEN;
    }

    if (flags & AES_FLAG_ENCRYPT) {
        for (n = 0; n < remainder; ++n)
            buf[n] = bytes_in[n] ^ iv[n];
        remainder = 16 - remainder;
        for (; n < AES_BLOCK_LEN; ++n)
            buf[n] = remainder ^ iv[n];
        aes_enc(&ctx, key, key_len, buf, AES_BLOCK_LEN, bytes_out);
    }

finish:
    clear_n(2, buf, sizeof(buf), &ctx, sizeof(ctx));
    return WALLY_OK;
}
