#include "internal.h"
#include <include/wally_crypto.h>
#include <include/wally_anti_exfil.h>
#include <stdbool.h>

#ifndef BUILD_STANDARD_SECP

WALLY_CORE_API int wally_ae_host_commit_from_bytes(
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len)
{
    const secp256k1_context *ctx = secp_ctx();

    if (!entropy || entropy_len != WALLY_S2C_DATA_LEN ||
        flags != EC_FLAG_ECDSA ||
        !bytes_out || len != WALLY_HOST_COMMITMENT_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!secp256k1_ecdsa_anti_exfil_host_commit(ctx, bytes_out, entropy))
        return WALLY_ERROR; /* Should not happen! */
    return WALLY_OK;
}

WALLY_CORE_API int wally_ae_signer_commit_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *commitment,
    size_t commitment_len,
    uint32_t flags,
    unsigned char *s2c_opening_out,
    size_t s2c_opening_out_len)
{
    secp256k1_ecdsa_s2c_opening opening_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !commitment || commitment_len != WALLY_HOST_COMMITMENT_LEN ||
        flags != EC_FLAG_ECDSA ||
        !s2c_opening_out || s2c_opening_out_len != WALLY_S2C_OPENING_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = secp256k1_ecdsa_anti_exfil_signer_commit(ctx, &opening_secp, bytes, priv_key, commitment) &&
         secp256k1_ecdsa_s2c_opening_serialize(ctx, s2c_opening_out, &opening_secp);

    wally_clear(&opening_secp, sizeof(opening_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

WALLY_CORE_API int wally_ae_sig_from_bytes(
    const unsigned char *priv_key,
    size_t priv_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *entropy,
    size_t entropy_len,
    uint32_t flags,
    unsigned char *bytes_out,
    size_t len)
{
    secp256k1_ecdsa_signature sig_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !entropy || entropy_len != WALLY_S2C_DATA_LEN ||
        flags != EC_FLAG_ECDSA ||
        !bytes_out || len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = secp256k1_anti_exfil_sign(ctx, &sig_secp, bytes, priv_key, entropy) &&
         secp256k1_ecdsa_signature_serialize_compact(ctx, bytes_out, &sig_secp);

    wally_clear(&sig_secp, sizeof(sig_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

WALLY_CORE_API int wally_ae_verify(
    const unsigned char *pub_key,
    size_t pub_key_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *entropy,
    size_t entropy_len,
    const unsigned char *s2c_opening,
    size_t s2c_opening_len,
    uint32_t flags,
    const unsigned char *sig,
    size_t sig_len)
{
    secp256k1_pubkey pub_secp;
    secp256k1_ecdsa_signature sig_secp;
    secp256k1_ecdsa_s2c_opening opening_secp;
    const secp256k1_context *ctx = secp_ctx();
    bool ok;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !bytes || bytes_len != EC_MESSAGE_HASH_LEN ||
        !entropy || entropy_len != WALLY_S2C_DATA_LEN ||
        !s2c_opening || s2c_opening_len != WALLY_S2C_OPENING_LEN ||
        flags != EC_FLAG_ECDSA ||
        !sig || sig_len != EC_SIGNATURE_LEN)
        return WALLY_EINVAL;

    if (!ctx)
        return WALLY_ENOMEM;

    ok = pubkey_parse(&pub_secp, pub_key, pub_key_len) &&
         secp256k1_ecdsa_signature_parse_compact(ctx, &sig_secp, sig) &&
         secp256k1_ecdsa_s2c_opening_parse(ctx, &opening_secp, s2c_opening) &&
         secp256k1_anti_exfil_host_verify(ctx, &sig_secp, bytes, &pub_secp, entropy, &opening_secp);

    wally_clear_3(&pub_secp, sizeof(pub_secp), &sig_secp, sizeof(sig_secp), &opening_secp, sizeof(opening_secp));
    return ok ? WALLY_OK : WALLY_EINVAL;
}

#endif /* ndef BUILD_STANDARD_SECP */
