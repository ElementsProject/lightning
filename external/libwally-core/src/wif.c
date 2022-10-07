#include "internal.h"
#include "base58.h"
#include <include/wally_address.h>
#include <include/wally_crypto.h>

#define WIF_ALL_DEFINED_FLAGS (WALLY_WIF_FLAG_COMPRESSED | WALLY_WIF_FLAG_UNCOMPRESSED)

int wally_wif_from_bytes(const unsigned char *priv_key,
                         size_t priv_key_len,
                         uint32_t prefix,
                         uint32_t flags,
                         char **output)
{
    int ret;
    unsigned char buf[2 + EC_PRIVATE_KEY_LEN];
    size_t buf_len = sizeof(buf);

    if (output)
        *output = NULL;

    if(!priv_key || priv_key_len != EC_PRIVATE_KEY_LEN || (prefix & ~0xff) ||
       (flags & ~WIF_ALL_DEFINED_FLAGS) || !output)
        return WALLY_EINVAL;

    buf[0] = (unsigned char) prefix & 0xff;
    memcpy(&buf[1], priv_key, EC_PRIVATE_KEY_LEN);

    if (flags & WALLY_WIF_FLAG_UNCOMPRESSED)
        buf_len--;
    else
        buf[buf_len - 1] = 0x01;

    ret = wally_base58_from_bytes(buf, buf_len, BASE58_FLAG_CHECKSUM, output);

    wally_clear(buf, sizeof(buf));
    return ret;
}

static int is_uncompressed(const char *base58, unsigned char *bytes, size_t len, size_t *uncompressed)
{
    int ret;
    size_t written;

    if ((ret = wally_base58_to_bytes(base58, BASE58_FLAG_CHECKSUM, bytes, len, &written)))
        return ret;

    if (written > len)
        return WALLY_EINVAL; /** Not enough space for decoded WIF string */

    if (written == EC_PRIVATE_KEY_LEN + 1) {
        *uncompressed = 1;
        return WALLY_OK;
    } else if ((written == EC_PRIVATE_KEY_LEN + 2) && bytes[EC_PRIVATE_KEY_LEN + 1] == 0x01) {
        *uncompressed = 0;
        return WALLY_OK;
    }

    return WALLY_EINVAL;
}

int wally_wif_to_bytes(const char *wif,
                       uint32_t prefix,
                       uint32_t flags,
                       unsigned char *bytes_out,
                       size_t len)
{
    int ret;
    unsigned char buf[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];
    size_t uncompressed;

    if (!wif || (flags & ~WIF_ALL_DEFINED_FLAGS) || (prefix & ~0xff) ||
        !bytes_out || len != EC_PRIVATE_KEY_LEN)
        return WALLY_EINVAL;

    ret = is_uncompressed(wif, buf, sizeof(buf), &uncompressed);

    if (ret != WALLY_OK ||
        (buf[0] != prefix) ||
        (uncompressed && flags != WALLY_WIF_FLAG_UNCOMPRESSED) ||
        (!uncompressed && flags != WALLY_WIF_FLAG_COMPRESSED)) {
        wally_clear(buf, sizeof(buf));
        return WALLY_EINVAL; /** Incorrect format, prefix does not match or inconsistent flag */
    }

    memcpy(bytes_out, &buf[1], EC_PRIVATE_KEY_LEN);

    wally_clear(buf, sizeof(buf));
    return WALLY_OK;
}

int wally_wif_is_uncompressed(const char *wif,
                              size_t *written)
{
    int ret;
    unsigned char buf[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN];

    if (!wif || !written)
        return WALLY_EINVAL;

    ret = is_uncompressed(wif, buf, sizeof(buf), written);

    wally_clear(buf, sizeof(buf));
    return ret;
}

int wally_wif_to_public_key(const char *wif,
                            uint32_t prefix,
                            unsigned char *bytes_out,
                            size_t len,
                            size_t *written)
{
    int ret;
    size_t uncompressed;
    unsigned char buf[2 + EC_PRIVATE_KEY_LEN + BASE58_CHECKSUM_LEN], pub_key[EC_PUBLIC_KEY_LEN];

    if (written)
        *written = 0;

    if (!wif || (prefix & ~0xff) || !bytes_out)
        return WALLY_EINVAL;

    ret = is_uncompressed(wif, buf, sizeof(buf), &uncompressed);

    if (buf[0] != prefix || ret) {
        wally_clear(buf, sizeof(buf));
        return WALLY_EINVAL; /** Prefix does not match or invalid format*/
    }

    *written = uncompressed ? EC_PUBLIC_KEY_UNCOMPRESSED_LEN : EC_PUBLIC_KEY_LEN;

    if (len < *written) {
        wally_clear(buf, sizeof(buf));
        return WALLY_OK; /* Not enough output space, return required size */
    }

    if (uncompressed) {
        if (!(ret = wally_ec_public_key_from_private_key(&buf[1], EC_PRIVATE_KEY_LEN, pub_key, EC_PUBLIC_KEY_LEN)))
            ret = wally_ec_public_key_decompress(pub_key, EC_PUBLIC_KEY_LEN, bytes_out, EC_PUBLIC_KEY_UNCOMPRESSED_LEN);
    } else
        ret = wally_ec_public_key_from_private_key(&buf[1], EC_PRIVATE_KEY_LEN, bytes_out, EC_PUBLIC_KEY_LEN);

    if (ret != WALLY_OK)
        *written = 0;

    wally_clear_2(buf, sizeof(buf), pub_key, sizeof(pub_key));
    return ret;
}

int wally_wif_to_address(const char *wif,
                         uint32_t prefix,
                         uint32_t version,
                         char **output)
{
    int ret;
    unsigned char pubkey[EC_PUBLIC_KEY_UNCOMPRESSED_LEN], address[HASH160_LEN + 1];
    size_t written;

    if (output)
        *output = NULL;

    if (!wif || (prefix & ~0xff) || (version & ~0xff) || !output)
        return WALLY_EINVAL;

    if ((ret = wally_wif_to_public_key(wif, prefix, pubkey, sizeof(pubkey), &written)))
        return ret;

    address[0] = (unsigned char) version & 0xff;

    if ((ret = wally_hash160(pubkey, written, &address[1], HASH160_LEN)))
        return ret;

    ret = wally_base58_from_bytes(address, sizeof(address), BASE58_FLAG_CHECKSUM, output);

    wally_clear_2(pubkey, sizeof(pubkey), address, sizeof(address));
    return ret;
}
