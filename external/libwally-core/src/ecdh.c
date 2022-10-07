#include "internal.h"
#include <include/wally_crypto.h>
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_ecdh.h"

int wally_ecdh(const unsigned char *pub_key, size_t pub_key_len,
               const unsigned char *priv_key, size_t priv_key_len,
               unsigned char *bytes_out, size_t len)
{
    const secp256k1_context *ctx = secp_ctx();
    secp256k1_pubkey pub;
    int ret = WALLY_OK;

    if (!ctx)
        return WALLY_ENOMEM;

    if (!pub_key || pub_key_len != EC_PUBLIC_KEY_LEN ||
        !priv_key || priv_key_len != EC_PRIVATE_KEY_LEN ||
        !bytes_out || len != SHA256_LEN)
        return WALLY_EINVAL;

    if (!pubkey_parse(&pub, pub_key, pub_key_len) ||
        !seckey_verify(priv_key)) {
        ret = WALLY_EINVAL;
    } else if (!secp256k1_ecdh(ctx, bytes_out, &pub, priv_key, NULL, NULL)) {
        wally_clear(bytes_out, len);
        ret = WALLY_ERROR;
    }

    wally_clear(&pub, sizeof(pub));
    return ret;
}
