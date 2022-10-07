#include "internal.h"
#include "ccan/ccan/str/hex/hex.h"

int wally_hex_n_verify(const char *hex, size_t hex_len)
{
    if (!hex || !hex_len || hex_len & 0x1)
        return WALLY_EINVAL;

    while (hex_len--) {
        char c = *hex++;
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return WALLY_EINVAL;
    }
    return WALLY_OK;
}

int wally_hex_verify(const char *hex)
{
    return wally_hex_n_verify(hex, hex ? strlen(hex) : 0);
}

int wally_hex_from_bytes(const unsigned char *bytes, size_t bytes_len,
                         char **output)
{
    if (output)
        *output = NULL;

    if (!bytes || !output)
        return WALLY_EINVAL;

    *output = wally_malloc(hex_str_size(bytes_len));
    if (!*output)
        return WALLY_ENOMEM;

    /* Note we ignore the return value as this call cannot fail */
    hex_encode(bytes, bytes_len, *output, hex_str_size(bytes_len));
    return WALLY_OK;
}

int wally_hex_n_to_bytes(const char *hex, size_t hex_len,
                         unsigned char *bytes_out, size_t len, size_t *written)
{
    if (written)
        *written = 0;

    if (!hex || !bytes_out || !len || hex_len & 0x1)
        return WALLY_EINVAL;

    if (len < hex_len / 2) {
        if (written)
            *written = hex_len / 2;
        return WALLY_OK; /* Not enough room in bytes_out, or empty string */
    }

    len = hex_len / 2; /* hex_decode expects exact length */
    if (!hex_decode(hex, hex_len, bytes_out, len))
        return WALLY_EINVAL;

    if (written)
        *written = len;

    return WALLY_OK;
}

int wally_hex_to_bytes(const char *hex,
                       unsigned char *bytes_out, size_t len, size_t *written)
{
    return wally_hex_n_to_bytes(hex, hex ? strlen(hex) : 0, bytes_out, len, written);
}
