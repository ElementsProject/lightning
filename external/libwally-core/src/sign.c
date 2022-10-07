#include "internal.h"
#include <include/wally_crypto.h>
#include "script_int.h"
#if 0
#include "secp256k1/include/secp256k1_schnorr.h"
#endif
#include "ccan/ccan/build_assert/build_assert.h"
#include <stdbool.h>

#define EC_FLAGS_TYPES (EC_FLAG_ECDSA | EC_FLAG_SCHNORR)

#define MSG_ALL_FLAGS (BITCOIN_MESSAGE_FLAG_HASH)

static const char MSG_PREFIX[] = "\x18" "Bitcoin Signed Message:\n";

/* LCOV_EXCL_START */
/* Check assumptions we expect to hold true */
static void assert_sign_assumptions(void)
{
    BUILD_ASSERT(sizeof(secp256k1_ecdsa_signature) == EC_SIGNATURE_LEN);
}
/* LCOV_EXCL_STOP */

static bool is_valid_ec_type(uint32_t flags)
{
    return ((flags & EC_FLAGS_TYPES) == EC_FLAG_ECDSA) ||
           ((flags & EC_FLAGS_TYPES) == EC_FLAG_SCHNORR);
}

static size_t get_expected_sig_len(uint32_t flags)
{
    return flags & EC_FLAG_RECOVERABLE ? EC_SIGNATURE_RECOVERABLE_LEN : EC_SIGNATURE_LEN;
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

int wally_ec_public_key_verify(const unsigned char *pub_key, size_t pub_key_len)
{
    secp256k1_pubkey pub;

    if (!pub_key ||
        !(pub_key_len == EC_PUBLIC_KEY_LEN || pub_key_len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN) ||
        !pubkey_parse(&pub, pub_key, pub_key_len))
        return WALLY_EINVAL;

    wally_clear(&pub, sizeof(pub));
    return WALLY_OK;
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
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_LEN;

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_decompress(const unsigned char *pub_key, size_t pub_key_len,
                                   unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_UNCOMPRESSED_LEN;
    bool ok;

    ok = pub_key && pub_key_len == EC_PUBLIC_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_UNCOMPRESSED_LEN &&
         pubkey_parse(&pub, pub_key, pub_key_len) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_UNCOMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_UNCOMPRESSED_LEN;

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_public_key_negate(const unsigned char *pub_key, size_t pub_key_len,
                               unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    size_t len_in_out = EC_PUBLIC_KEY_LEN;
    bool ok;

    ok = pub_key && pub_key_len == EC_PUBLIC_KEY_LEN &&
         bytes_out && len == EC_PUBLIC_KEY_LEN &&
         pubkey_parse(&pub, pub_key, pub_key_len) &&
         pubkey_negate(&pub) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED) &&
         len_in_out == EC_PUBLIC_KEY_LEN;

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&pub, sizeof(pub));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_normalize(const unsigned char *sig, size_t sig_len,
                           unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig_secp, sig_low;
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    bool ok;

    ok = sig && sig_len == EC_SIGNATURE_LEN &&
         bytes_out && len == EC_SIGNATURE_LEN &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig);

    if (ok) {
        /* Note no error is returned, just whether the sig was changed */
        secp256k1_ecdsa_signature_normalize(ctx, &sig_low, &sig_secp);

        ok = secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out,
                                                         &sig_low);
    }

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear_2(&sig_secp, sizeof(sig_secp), &sig_low, sizeof(sig_low));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_to_der(const unsigned char *sig, size_t sig_len,
                        unsigned char *bytes_out, size_t len, size_t *written)
{
    secp256k1_ecdsa_signature sig_secp;
    size_t len_in_out = len;
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    bool ok;

    if (written)
        *written = 0;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = sig && sig_len == EC_SIGNATURE_LEN &&
         bytes_out && len >= EC_SIGNATURE_DER_MAX_LEN && written &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
         secp256k1_ecdsa_signature_serialize_der(ctx, bytes_out,
                                                 &len_in_out, &sig_secp);

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    if (ok)
        *written = len_in_out;
    wally_clear(&sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_der(const unsigned char *bytes, size_t bytes_len,
                          unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig_secp;
    const secp256k1_context *ctx = secp256k1_context_no_precomp;
    bool ok;

    ok = bytes && bytes_len && bytes_out && len == EC_SIGNATURE_LEN &&
         secp256k1_ecdsa_signature_parse_der(ctx, &sig_secp, bytes, bytes_len) &&
         secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig_secp);

    if (!ok && bytes_out)
        wally_clear(bytes_out, len);
    wally_clear(&sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_from_bytes(const unsigned char *priv_key, size_t priv_key_len,
                            const unsigned char *bytes, size_t bytes_len,
                            uint32_t flags,
                            unsigned char *bytes_out, size_t len)
{
    wally_ec_nonce_t nonce_fn = wally_ops()->ec_nonce_fn;
    const secp256k1_context *ctx = secp_ctx();

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_ALL ||
        !bytes_out || len != get_expected_sig_len(flags))
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (flags & EC_FLAG_SCHNORR) {
        if (flags & EC_FLAG_RECOVERABLE)
            return WALLY_EINVAL; /* Only ECDSA is supported for recoverable sigs */

#if 0 /*FIXME: Schnorr is unavailable in secp for now*/
        if (!secp256k1_schnorr_sign(ctx, bytes_out, bytes,
                                    priv_key, nonce_fn, NULL))
            return WALLY_EINVAL; /* Failed to sign */
        return WALLY_OK;
#endif
        return WALLY_EINVAL;
    } else {
        unsigned char extra_entropy[32] = {0}, *entropy_p = NULL;
        unsigned char *bytes_out_p = flags & EC_FLAG_RECOVERABLE ? bytes_out + 1 : bytes_out;
        uint32_t counter = 0;
        secp256k1_ecdsa_recoverable_signature sig_secp;
        int recid;

        while (true) {
            if (!secp256k1_ecdsa_sign_recoverable(ctx, &sig_secp, bytes, priv_key, nonce_fn, entropy_p)) {
                wally_clear(&sig_secp, sizeof(sig_secp));
                if (!secp256k1_ec_seckey_verify(ctx, priv_key))
                    return WALLY_EINVAL; /* invalid priv_key */
                return WALLY_ERROR;     /* Nonce function failed */
            }

            /* Note this function is documented as never failing */
            secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, bytes_out_p, &recid, &sig_secp);

            if (!(flags & EC_FLAG_GRIND_R) || *bytes_out_p < 0x80) {
                wally_clear(&sig_secp, sizeof(sig_secp));
                /* Note the following assumes the key is compressed */
                if (flags & EC_FLAG_RECOVERABLE)
                    bytes_out[0] = 27 + recid + 4;

                return WALLY_OK;
            }
            /* Incremement nonce to grind for low-R */
            entropy_p = extra_entropy;
            ++counter;
            uint32_to_le_bytes(counter, entropy_p);
        }
    }
}

int wally_ec_sig_verify(const unsigned char *pub_key, size_t pub_key_len,
                        const unsigned char *bytes, size_t bytes_len,
                        uint32_t flags,
                        const unsigned char *sig, size_t sig_len)
{
    secp256k1_pubkey pub;
    secp256k1_ecdsa_signature sig_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !is_valid_ec_type(flags) || flags & ~EC_FLAGS_TYPES ||
        !sig || sig_len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = pubkey_parse(&pub, pub_key, pub_key_len);

    if (flags & EC_FLAG_SCHNORR)
#if 0 /*FIXME: Schnorr is unavailable in secp for now*/
        ok = ok && secp256k1_schnorr_verify(ctx, sig, bytes, &pub);
#else
        ok = false;
#endif
    else
        ok = ok && secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
             secp256k1_ecdsa_verify(ctx, &sig_secp, bytes, &pub);

    wally_clear_2(&pub, sizeof(pub), &sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_ec_sig_to_public_key(const unsigned char *bytes, size_t bytes_len,
                               const unsigned char *sig, size_t sig_len,
                               unsigned char *bytes_out, size_t len)
{
    secp256k1_pubkey pub;
    secp256k1_ecdsa_recoverable_signature sig_secp;
    const secp256k1_context *ctx = secp_ctx();
    size_t len_in_out = EC_PUBLIC_KEY_LEN;
    int recid;
    bool ok;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !sig || sig_len != EC_SIGNATURE_RECOVERABLE_LEN ||
        !bytes_out || len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;

    recid = (sig[0] - 27) & 3;
    ok = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig_secp, &sig[1], recid) &&
         secp256k1_ecdsa_recover(ctx, &pub, &sig_secp, bytes) &&
         pubkey_serialize(bytes_out, &len_in_out, &pub, PUBKEY_COMPRESSED);

    wally_clear_2(&pub, sizeof(pub), &sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

static inline size_t varint_len(size_t bytes_len) {
    return bytes_len < 0xfd ? 1u : 3u;
}

int wally_format_bitcoin_message(const unsigned char *bytes, size_t bytes_len,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char buf[256], *msg_buf = bytes_out, *out;
    const bool do_hash = (flags & BITCOIN_MESSAGE_FLAG_HASH);
    size_t msg_len;

    if (written)
        *written = 0;

    if (!bytes || !bytes_len || bytes_len > BITCOIN_MESSAGE_MAX_LEN ||
        (flags & ~MSG_ALL_FLAGS) || !bytes_out || !written)
        return WALLY_EINVAL;

    msg_len = sizeof(MSG_PREFIX) - 1 + varint_len(bytes_len) + bytes_len;
    *written = do_hash ? SHA256_LEN : msg_len;

    if (len < *written)
        return WALLY_OK; /* Not enough output space, return required size */

    if (do_hash) {
        /* Ensure we have a suitable temporary buffer to serialize into */
        msg_buf = buf;
        if (msg_len > sizeof(buf)) {
            msg_buf = wally_malloc(msg_len);
            if (!msg_buf) {
                *written = 0;
                return WALLY_ENOMEM;
            }
        }
    }

    /* Serialize the message */
    out = msg_buf;
    memcpy(out, MSG_PREFIX, sizeof(MSG_PREFIX) - 1);
    out += sizeof(MSG_PREFIX) - 1;
    if (bytes_len < 0xfd)
        *out++ = bytes_len;
    else {
        *out++ = 0xfd;
        *out++ = bytes_len & 0xff;
        *out++ = bytes_len >> 8;
    }
    memcpy(out, bytes, bytes_len);

    if (do_hash) {
        wally_sha256d(msg_buf, msg_len, bytes_out, SHA256_LEN);
        wally_clear(msg_buf, msg_len);
        if (msg_buf != buf)
            wally_free(msg_buf);
    }
    return WALLY_OK;
}

#ifndef BUILD_STANDARD_SECP
int wally_s2c_sig_from_bytes(const unsigned char *priv_key, size_t priv_key_len,
                             const unsigned char *bytes, size_t bytes_len,
                             const unsigned char *s2c_data, size_t s2c_data_len,
                             uint32_t flags,
                             unsigned char *s2c_opening_out, size_t s2c_opening_out_len,
                             unsigned char *bytes_out, size_t len)
{
    secp256k1_ecdsa_signature sig_secp;
    secp256k1_ecdsa_s2c_opening opening_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !s2c_data || s2c_data_len != WALLY_S2C_DATA_LEN ||
        flags != EC_FLAG_ECDSA ||
        !bytes_out || len != EC_SIGNATURE_LEN ||
        !s2c_opening_out || s2c_opening_out_len != WALLY_S2C_OPENING_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_ecdsa_s2c_sign(ctx, &sig_secp, &opening_secp, bytes, priv_key, s2c_data)) {
        wally_clear_2(&sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
        if (!secp256k1_ec_seckey_verify(ctx, priv_key))
            return WALLY_EINVAL; /* invalid priv_key */
        return WALLY_ERROR;     /* Nonce function failed */
    }

    ok = secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig_secp) &&
         secp256k1_ecdsa_s2c_opening_serialize(ctx, s2c_opening_out, &opening_secp);

    wally_clear_2(&sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

int wally_s2c_commitment_verify(const unsigned char *sig, size_t sig_len,
                                const unsigned char *s2c_data, size_t s2c_data_len,
                                const unsigned char *s2c_opening, size_t s2c_opening_len,
                                uint32_t flags)
{
    secp256k1_ecdsa_signature sig_secp;
    secp256k1_ecdsa_s2c_opening opening_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!sig || sig_len != EC_SIGNATURE_LEN ||
        !s2c_data || s2c_data_len != WALLY_S2C_DATA_LEN ||
        !s2c_opening || s2c_opening_len != WALLY_S2C_OPENING_LEN ||
        flags != EC_FLAG_ECDSA)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
         secp256k1_ecdsa_s2c_opening_parse(ctx, &opening_secp, s2c_opening) &&
         secp256k1_ecdsa_s2c_verify_commit(ctx, &sig_secp, s2c_data, &opening_secp);

    wally_clear_2(&sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}
#endif /* ndef BUILD_STANDARD_SECP */
