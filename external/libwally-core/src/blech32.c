/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "internal.h"
#include <stdlib.h>
#include <stdint.h>
#include <include/wally_address.h>
#include <include/wally_script.h>
#include <include/wally_crypto.h>
#include "script.h"

#ifdef BUILD_ELEMENTS

#define CHECKSUM_BLECH32 0x1
#define CHECKSUM_BLECH32M 0x455972a3350f7a1ull

static uint64_t blech32_polymod_step(uint64_t pre) {
    uint8_t b = pre >> 55;
    return ((pre & 0x7fffffffffffffULL) << 5) ^
           (-((b >> 0) & 1) & 0x7d52fba40bd886ULL) ^
           (-((b >> 1) & 1) & 0x5e8dbf1a03950cULL) ^
           (-((b >> 2) & 1) & 0x1c3a3c74072a18ULL) ^
           (-((b >> 3) & 1) & 0x385d72fa0e5139ULL) ^
           (-((b >> 4) & 1) & 0x7093e5a608865bULL);
}

static const char *blech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t blech32_charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
    1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
    1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

#define WALLY_BLECH32_MAXLEN ((size_t) 1000)

static int blech32_encode(char *output, const char *hrp, const uint8_t *data, size_t data_len, size_t max_input_len, bool is_blech32m) {
    uint64_t chk = 1;
    size_t i = 0;
    while (hrp[i] != 0) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = blech32_polymod_step(chk) ^ (ch >> 5);
        ++i;
    }
    if (i + 13 + data_len > max_input_len) return 0;
    chk = blech32_polymod_step(chk);
    while (*hrp != 0) {
        chk = blech32_polymod_step(chk) ^ (*hrp & 0x1f);
        *(output++) = *(hrp++);
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return 0;
        chk = blech32_polymod_step(chk) ^ (*data);
        *(output++) = blech32_charset[*(data++)];
    }
    for (i = 0; i < 12; ++i) {
        chk = blech32_polymod_step(chk);
    }
    chk ^= is_blech32m ? CHECKSUM_BLECH32M : CHECKSUM_BLECH32;
    for (i = 0; i < 12; ++i) {
        *(output++) = blech32_charset[(chk >> ((11 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return 1;
}

static int blech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input, size_t max_input_len, bool *is_blech32m) {
    uint64_t chk = 1;
    size_t i;
    size_t input_len = strlen(input);
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    if (input_len < 8 || input_len > max_input_len) {
        return 0;
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    if (1 + *data_len >= input_len || *data_len < 12) {
        return 0;
    }
    hrp_len = input_len - (1 + *data_len);
    *(data_len) -= 12;
    for (i = 0; i < hrp_len; ++i) {
        int ch = input[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }
        if (ch >= 'a' && ch <= 'z') {
            have_lower = 1;
        } else if (ch >= 'A' && ch <= 'Z') {
            have_upper = 1;
            ch = (ch - 'A') + 'a';
        }
        hrp[i] = ch;
        chk = blech32_polymod_step(chk) ^ (ch >> 5);
    }
    hrp[i] = 0;
    chk = blech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = blech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : blech32_charset_rev[(int)input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            return 0;
        }
        chk = blech32_polymod_step(chk) ^ v;
        if (i + 12 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return 0;
    }
    *is_blech32m = chk == CHECKSUM_BLECH32M;
    return chk == CHECKSUM_BLECH32 || chk == CHECKSUM_BLECH32M;
}

static int blech32_convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    while (inlen--) {
        val = (val << inbits) | *(in++);
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[(*outlen)++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[(*outlen)++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    return 1;
}

static int blech32_addr_encode(char *output, const char *hrp, uint8_t witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[WALLY_BLECH32_MAXLEN];
    size_t datalen = 0;
    if (witver > 16) goto fail;
    if (witver == 0 && witprog_len != 53 && witprog_len != 65) goto fail;
    if (witprog_len < 2 || witprog_len > 65) goto fail;
    data[0] = witver;
    blech32_convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
    ++datalen;
    return blech32_encode(output, hrp, data, datalen, WALLY_BLECH32_MAXLEN, witver != 0);
fail:
    wally_clear_2(data, sizeof(data), (void *)witprog, witprog_len);
    return 0;
}

static int blech32_addr_decode(uint8_t *witver, uint8_t *witdata, size_t *witdata_len, const char *hrp, const char *addr) {
    uint8_t data[WALLY_BLECH32_MAXLEN];
    char hrp_actual[WALLY_BLECH32_MAXLEN];
    size_t data_len;
    bool is_blech32m = false;
    if (!blech32_decode(hrp_actual, data, &data_len, addr, WALLY_BLECH32_MAXLEN, &is_blech32m)) goto fail;
    if (data_len == 0 || data_len > (WALLY_BLECH32_MAXLEN - 4)) goto fail;
    if (strncmp(hrp, hrp_actual, WALLY_BLECH32_MAXLEN - 5) != 0) goto fail;
    if (data[0] == 0 && is_blech32m) goto fail;
    if (data[0] != 0 && !is_blech32m) goto fail;
    if (data[0] > 16) goto fail;
    *witdata_len = 0;
    if (!blech32_convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0)) goto fail;
    if (*witdata_len < 2 || *witdata_len > 65) goto fail;
    if (data[0] == 0 && *witdata_len != 53 && *witdata_len != 65) goto fail;
    *witver = data[0];
    return 1;
fail:
    wally_clear_2(data, sizeof(data), hrp_actual, sizeof(hrp_actual));
    return 0;
}

int wally_confidential_addr_to_addr_segwit(
    const char *address,
    const char *confidential_addr_family,
    const char *addr_family,
    char **output)
{
    unsigned char buf[WALLY_BLECH32_MAXLEN];
    unsigned char *hash_bytes_p = &buf[EC_PUBLIC_KEY_LEN - 2];
    size_t written = 0;
    int ret;
    uint8_t witver;

    if (output)
        *output = NULL;

    if (!address || !output)
        return WALLY_EINVAL;

    if (!blech32_addr_decode(&witver, buf, &written, confidential_addr_family, address))
        ret = WALLY_EINVAL;
    else if (written != 53 && written != 65)
        ret = WALLY_EINVAL;
    else {
        written = written - EC_PUBLIC_KEY_LEN + 2;
        hash_bytes_p[0] = value_to_op_n(witver);
        hash_bytes_p[1] = (unsigned char) (written - 2);
        ret = wally_addr_segwit_from_bytes(hash_bytes_p, written,
                                           addr_family, 0, output);
    }

    wally_clear(buf, sizeof(buf));
    return ret;
}

int wally_confidential_addr_segwit_to_ec_public_key(
    const char *address,
    const char *confidential_addr_family,
    unsigned char *bytes_out,
    size_t len)
{
    unsigned char buf[WALLY_BLECH32_MAXLEN];
    size_t written = 0;
    int ret = WALLY_OK;
    uint8_t witver;

    if (!address || !bytes_out || !confidential_addr_family || len != EC_PUBLIC_KEY_LEN)
        return WALLY_EINVAL;

    if (!blech32_addr_decode(&witver, buf, &written, confidential_addr_family, address))
        ret = WALLY_EINVAL;
    else if (written != 53 && written != 65)
        ret = WALLY_EINVAL;
    else
        memcpy(bytes_out, buf, EC_PUBLIC_KEY_LEN);

    wally_clear(buf, sizeof(buf));
    return ret;
}

int wally_confidential_addr_from_addr_segwit(
    const char *address,
    const char *addr_family,
    const char *confidential_addr_family,
    const unsigned char *pub_key,
    size_t pub_key_len,
    char **output)
{
    char result[WALLY_BLECH32_MAXLEN + 1];
    unsigned char buf[EC_PUBLIC_KEY_LEN + SHA256_LEN];
    unsigned char *hash_bytes_p = &buf[EC_PUBLIC_KEY_LEN - 2];
    size_t written = SHA256_LEN + 2;
    int ret;
    size_t witver;

    if (output)
        *output = NULL;

    if (!address || !addr_family || !confidential_addr_family || !pub_key ||
        pub_key_len != EC_PUBLIC_KEY_LEN || !output ||
        strlen(confidential_addr_family) >= WALLY_BLECH32_MAXLEN)
        return WALLY_EINVAL;

    /* get witness program's script */
    ret = wally_addr_segwit_to_bytes(address, addr_family, 0,
                                     hash_bytes_p, written, &written);
    if (ret == WALLY_OK) {
        if ((written != (HASH160_LEN + 2)) && (written != (SHA256_LEN + 2))) {
            ret = WALLY_EINVAL;
            goto done;
        }

        if (!script_is_op_n(hash_bytes_p[0], true, &witver)) {
            ret = WALLY_EINVAL;
            goto done;
        }

        /* Copy the confidentialKey / witness program */
        memcpy(buf, pub_key, pub_key_len);
        written -= 2;   /* ignore witnessVersion & hashSize */
        written += EC_PUBLIC_KEY_LEN;
        if (!blech32_addr_encode(result, confidential_addr_family, witver & 0xff, buf, written))
            return WALLY_ERROR;

        *output = wally_strdup(result);
        ret = (*output) ? WALLY_OK : WALLY_ENOMEM;
    }

done:
    wally_clear(buf, sizeof(buf));
    wally_clear(result, sizeof(result));
    return ret;
}

#endif /* BUILD_ELEMENTS */
