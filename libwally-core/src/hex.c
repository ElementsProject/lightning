#include "internal.h"
#include "ccan/ccan/str/hex/hex.h"

int wally_hex_from_bytes(const unsigned char *bytes_in, size_t len_in,
                         char **output)
{
    if (output)
        *output = NULL;

    if (!bytes_in || !output)
        return WALLY_EINVAL;

    *output = wally_malloc(hex_str_size(len_in));
    if (!*output)
        return WALLY_ENOMEM;

    /* Note we ignore the return value as this call cannot fail */
    hex_encode(bytes_in, len_in, *output, hex_str_size(len_in));
    return WALLY_OK;
}

int wally_hex_to_bytes(const char *hex,
                       unsigned char *bytes_out, size_t len, size_t *written)
{
    size_t len_in = hex ? strlen(hex) : 0;

    if (written)
        *written = 0;

    if (!hex || !bytes_out || !len || len_in & 0x1)
        return WALLY_EINVAL;

    if (len < len_in / 2) {
        *written = len_in / 2;
        return WALLY_OK; /* Not enough room in bytes_out, or empty string */
    }

    len = len_in / 2; /* hex_decode expects exact length */
    if (!hex_decode(hex, len_in, bytes_out, len))
        return WALLY_EINVAL;

    if (written)
        *written = len;

    return WALLY_OK;
}
