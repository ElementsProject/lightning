#include "internal.h"
#include <include/wally_crypto.h>
#include "secp256k1/include/secp256k1_schnorr.h"
#include "ccan/ccan/build_assert/build_assert.h"
#include <stdbool.h>

#define EC_FLAGS_TYPES (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)
#define EC_FLAGS_ALL (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)

#define MSG_ALL_FLAGS (BITCOIN_MESSAGE_FLAG_HASH)

static const char MSG_PREFIX[] = "\x18" "Bitcoin Signed Message:\n";

/* LCOV_EXCL_START */
/* Check assumptions we expect to hold true */
static void assert_assumptions(void)
{
    BUILD_ASSERT(sizeof(secp256k1_ecdsa_signature) == EC_SIGNATURE_LEN);
}
/* LCOV_EXCL_STOP */

static bool is_valid_ec_type(uint32_t flags)
{
    return ((flags & EC_FLAGS_TYPES) == EC_FLAG_ECDSA) ||
           ((flags & EC_FLAGS_TYPES) == EC_FLAG_SCHNORR);
}


int wally_ec_private_key_verify(const unsigned char *priv_key, size_t priv_key_len)
{
    const secp256k1_context *ctx = secp_ctx();

    if (!ctx)
        return WALLY_ENOMEM;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN)
        return WALLY_EINVAL;

    return secp256k1_ec_seckey_verify(ctx, priv_key) ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_from_private_key(const unsigned char *priv_key, size_t priv_key_len,
                                         unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_LEN;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = priv_key && priv_key_len == EC_PRIVATE_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_LEN &&
         pubkey_create(ctx, &pub, priv_key) &&
         pubkey_serialize(ctx, bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_LEN;

    if (!ok && bytes_out)
        clear(bytes_out, len);
    clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_decompress(const unsigned char *pub_key, size_t pub_key_len,
                                   unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = pub_key && pub_key_len == EC_PUBLIC_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN &&
         pubkey_parse(ctx, &pub, pub_key, pub_key_len) &&
         pubkey_serialize(ctx, bytes_out, &len_in_out, &pub, PUBKEY_UNCOMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_UNCOMPRESSED_LEN;

    if (!ok && bytes_out)
        clear(bytes_out, len);
    clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_normalize(const unsigned char *sig_in, size_t sig_in_len,
                           unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig, sig_low;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = sig_in && sig_in_len == EC_SIGNATURE_LEN &&
         bytes_out && len == EC_SIGNATURE_LEN &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_in);

    if (ok) {
        /* Note no error is returned, just whether the sig was changed */
        secp256k1_ecdsa_signature_normalize(ctx, &sig_low, &sig);

        ok = secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out,
                                                         &sig_low);
    }

    if (!ok && bytes_out)
        clear(bytes_out, len);
    clear_n(2, &sig, sizeof(sig), &sig_low, sizeof(sig_low));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_to_der(const unsigned char *sig_in, size_t sig_in_len,
                        unsigned char *bytes_out, size_t len, size_t *written)
{
    secp256k1_ecdsa_signature sig;
    size_t len_in_out = len;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = sig_in && sig_in_len == EC_SIGNATURE_LEN &&
         bytes_out && len == EC_SIGNATURE_DER_MAX_LEN && written &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_in) &&
         secp256k1_ecdsa_signature_serialize_der(ctx, bytes_out,
                                                 &len_in_out, &sig);

    if (!ok && bytes_out)
        clear(bytes_out, len);
    if (ok)
        *written = len_in_out;
    clear(&sig, sizeof(sig));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_der(const unsigned char *bytes_in, size_t len_in,
                          unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = bytes_in && len_in && bytes_out && len == EC_SIGNATURE_LEN &&
         secp256k1_ecdsa_signature_parse_der(ctx, &sig, bytes_in, len_in) &&
         secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig);

    if (!ok && bytes_out)
        clear(bytes_out, len);
    clear(&sig, sizeof(sig));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_bytes(const unsigned char *priv_key, size_t priv_key_len,
                            const unsigned char *bytes_in, size_t len_in,
                            uint32_t flags,
                            unsigned char *bytes_out, size_t len)
{
    wally_ec_nonce_t nonce_fn = wally_ops()->ec_nonce_fn;
    const secp256k1_context *ctx = secp_ctx();

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes_in || len_in != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_ALL ||
        !bytes_out || len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (flags & EC_FLAG_SCHNORR) {
        if (!secp256k1_schnorr_sign(ctx, bytes_out, bytes_in,
                                    priv_key, nonce_fn, NULL))
            return WALLY_EINVAL; /* Failed to sign */
        return WALLY_OK;
    } else {
        secp256k1_ecdsa_signature sig;

        if (!secp256k1_ecdsa_sign(ctx, &sig, bytes_in, priv_key, nonce_fn, NULL)) {
            clear(&sig, sizeof(sig));
            if (secp256k1_ec_seckey_verify(ctx, priv_key))
                return WALLY_ERROR; /* Nonce function failed */
            return WALLY_EINVAL; /* invalid priv_key */
        }

        /* Note this function is documented as never failing */
        secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig);
        clear(&sig, sizeof(sig));
    }
    return WALLY_OK;
}

int wally_ec_sig_verify(const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *bytes_in, size_t len_in,
                        uint32_t flags,
                        const unsigned char *sig_in, size_t sig_in_len)
{
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature sig;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !bytes_in || len_in != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_ALL ||
        !sig_in || sig_in_len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = pubkey_parse(ctx, &pub, pub_key, pub_key_len);

    if (flags & EC_FLAG_SCHNORR)
        ok = ok && secp256k1_schnorr_verify(ctx, sig_in, bytes_in, &pub);
    else
        ok = ok && secp256k1_ecdsa_signature_parse_compact(ctx, &sig, sig_in) &&
             secp256k1_ecdsa_verify(ctx, &sig, bytes_in, &pub);

    clear_n(2, &pub, sizeof(pub), &sig, sizeof(sig));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

static inline size_t varint_len(size_t len_in) {
    return len_in < 0xfd ? 1u : 3u;
}

int wally_format_bitcoin_message(const unsigned char *bytes_in, size_t len_in,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char buf[256], *msg_buf = bytes_out, *out;
    const bool do_hash = (flags & BITCOIN_MESSAGE_FLAG_HASH);
    size_t msg_len;

    if (written)
        *written = 0;

    if (!bytes_in || !len_in || len_in > BITCOIN_MESSAGE_MAX_LEN ||
        (flags & ~MSG_ALL_FLAGS) || !bytes_out || !written)
        return WALLY_EINVAL;

    msg_len = sizeof(MSG_PREFIX) - 1 + varint_len(len_in) + len_in;
    *written = do_hash ? SHA256_LEN : msg_len;

    if (len < *written)
        return WALLY_OK; /* Not enough output space, return required size */

    if (do_hash) {
        /* Ensure we have a suitable temporary buffer to serialise into */
        msg_buf = buf;
        if (msg_len > sizeof(buf)) {
            msg_buf = wally_malloc(msg_len);
            if (!msg_buf) {
                *written = 0;
                return WALLY_ENOMEM;
            }
        }
    }

    /* Serialise the message */
    out = msg_buf;
    memcpy(out, MSG_PREFIX, sizeof(MSG_PREFIX) - 1);
    out += sizeof(MSG_PREFIX) - 1;
    if (len_in < 0xfd)
        *out++ = len_in;
    else {
        *out++ = 0xfd;
        *out++ = len_in & 0xff;
        *out++ = len_in >> 8;
    }
    memcpy(out, bytes_in, len_in);

    if (do_hash) {
        wally_sha256d(msg_buf, msg_len, bytes_out, SHA256_LEN);
        clear(msg_buf, msg_len);
        if (msg_buf != buf)
            wally_free(msg_buf);
    }
    return WALLY_OK;
}
