#include "internal.h"
#include <include/wally_bip32.h>
#include <include/wally_crypto.h>
#include <include/wally_symmetric.h>
#include <stdbool.h>

#define LABEL_SIZE 64

static const unsigned char DOMAIN_STR[] = {
    'S', 'y', 'm', 'm', 'e', 't', 'r', 'i', 'c', ' ', 'k', 'e', 'y', ' ', 's', 'e', 'e', 'd'
};

/* TODO: move to a common header */
static bool is_valid_seed_length(size_t len) {
    return len == BIP32_ENTROPY_LEN_512 || len == BIP32_ENTROPY_LEN_256 ||
           len == BIP32_ENTROPY_LEN_128;
}

int wally_symmetric_key_from_seed(
    const unsigned char *bytes,
    size_t bytes_len,
    unsigned char *bytes_out,
    size_t len)
{
    if (!bytes || !is_valid_seed_length(bytes_len) || !bytes_out || len != HMAC_SHA512_LEN)
        return WALLY_EINVAL;

    return wally_hmac_sha512(DOMAIN_STR, sizeof(DOMAIN_STR), bytes, bytes_len, bytes_out, len);
}

int wally_symmetric_key_from_parent(
    const unsigned char *bytes,
    size_t bytes_len,
    uint32_t version,
    const unsigned char *label,
    size_t label_len,
    unsigned char *bytes_out,
    size_t len)
{
    unsigned char buff[LABEL_SIZE], *buff_p = buff;
    int ret = WALLY_OK;
    size_t buff_len;

    if (!bytes || bytes_len != HMAC_SHA512_LEN || version != 0 || !label ||
        !label_len || !bytes_out || len != HMAC_SHA512_LEN)
        return WALLY_EINVAL;

    buff_len = label_len + 1;
    if (buff_len > LABEL_SIZE) {
        buff_p = wally_malloc(buff_len);
        if (buff_p == NULL)
            return WALLY_ENOMEM;
    }

    *buff_p = version;
    memcpy(buff_p + 1, label, label_len);

    ret = wally_hmac_sha512(bytes, HMAC_SHA512_LEN / 2, buff_p, buff_len, bytes_out, len);

    wally_clear(buff_p, buff_len);
    if (buff_p != buff)
        wally_free(buff_p);

    return ret;
}

