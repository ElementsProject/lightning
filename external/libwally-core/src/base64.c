#include "internal.h"
#include "ccan/ccan/base64/base64.h"

int wally_base64_from_bytes(const unsigned char *bytes, size_t bytes_len,
                            uint32_t flags, char **output)
{
    char *encoded;
    size_t encoded_len;

    if (output)
        *output = NULL;

    if (!bytes || !bytes_len || flags || !output)
        return WALLY_EINVAL;

    encoded_len = base64_encoded_length(bytes_len) + 1; /* +1 for NUL */
    if ((encoded = wally_malloc(encoded_len)) == NULL)
        return WALLY_ENOMEM;

    if (base64_encode(encoded, encoded_len, (const char *)bytes, bytes_len) < 0) {
        clear_and_free(encoded, encoded_len);
        return WALLY_EINVAL;
    }
    *output = encoded;
    return WALLY_OK;
}

int wally_base64_get_maximum_length(const char *str_in, uint32_t flags, size_t *written)
{
    if (written)
        *written = 0;

    if (!str_in || !*str_in || flags || !written)
        return WALLY_EINVAL;

    *written = base64_decoded_length(strlen(str_in));
    return WALLY_OK;
}

int wally_base64_to_bytes(const char *str_in, uint32_t flags,
                          unsigned char *bytes_out, size_t len,
                          size_t *written)
{
    size_t decode_len, str_in_len;
    ssize_t actual_len;

    if (written)
        *written = 0;

    if (!str_in || flags || !bytes_out || !len || !written)
        return WALLY_EINVAL;

    str_in_len = strlen(str_in);
    decode_len = base64_decoded_length(str_in_len);
    if (len < decode_len) {
        /* Not enough space; return the amount required */
        *written = decode_len;
        return WALLY_OK;
    }

    actual_len = base64_decode((char *)bytes_out, decode_len, str_in, str_in_len);
    if (actual_len < 0)
        return WALLY_EINVAL; /* Invalid base64 data */
    *written = actual_len;
    return WALLY_OK;
}
