/* MIT (BSD) license - see LICENSE file for details */
/* HMAC code adapted from the Bitcoin project's C++:
 *
 * src/crypto/hmac_sha512.cpp f914f1a746d7f91951c1da262a4a749dd3ebfa71
 * Copyright (c) 2014 The Bitcoin Core developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
 */
static void SHA_PRE(_mix)(struct SHA_T *sha, const unsigned char *pad,
                          const unsigned char *data, size_t data_len)
{
    struct SHA_PRE(_ctx) ctx;
    SHA_PRE(_init)(&ctx);
    SHA_PRE(_update)(&ctx, pad, sizeof(ctx.buf));
    SHA_PRE(_update)(&ctx, data, data_len);
    SHA_PRE(_done)(&ctx, sha);
    clear(&ctx, sizeof(ctx));
}

void HMAC_FUNCTION(struct SHA_T *sha,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *msg, size_t msg_len)
{
    struct SHA_PRE(_ctx) ctx;
    unsigned char ipad[sizeof(ctx.buf)];
    unsigned char opad[sizeof(ctx.buf)];
    size_t i;

    clear(ctx.buf.u8, sizeof(ctx.buf));

    if (key_len <= sizeof(ctx.buf))
        memcpy(ctx.buf.u8, key, key_len);
    else
        SHA_T((struct SHA_T *)ctx.buf.SHA_CTX_MEMBER, key, key_len);

    for (i = 0; i < sizeof(ctx.buf); ++i) {
        opad[i] = ctx.buf.u8[i] ^ 0x5c;
        ipad[i] = ctx.buf.u8[i] ^ 0x36;
    }

    SHA_PRE(_mix)((struct SHA_T *)ctx.buf.SHA_CTX_MEMBER, ipad, msg, msg_len);
    SHA_PRE(_mix)(sha, opad, ctx.buf.u8, sizeof(*sha));
    clear_n(3, &ctx, sizeof(ctx), ipad, sizeof(ipad), opad, sizeof(opad));
}

int WALLY_HMAC_FUNCTION(const unsigned char *key, size_t key_len,
                        const unsigned char *bytes_in, size_t len_in,
                        unsigned char *bytes_out, size_t len)
{
    struct SHA_T sha;
    bool aligned = alignment_ok(bytes_out, sizeof(sha.u.SHA_CTX_MEMBER));
    struct SHA_T *sha_p = aligned ? (struct SHA_T *)bytes_out : &sha;

    if (!key || !key_len || !bytes_in || !len_in ||
        !bytes_out || len != sizeof(struct SHA_T))
        return WALLY_EINVAL;

    HMAC_FUNCTION(sha_p, key, key_len, bytes_in, len_in);
    if (!aligned) {
        memcpy(bytes_out, sha_p, sizeof(*sha_p));
        clear(sha_p, sizeof(*sha_p));
    }
    return WALLY_OK;
}
