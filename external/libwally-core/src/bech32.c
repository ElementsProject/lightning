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

#define CHECKSUM_BECH32 0x1
#define CHECKSUM_BECH32M 0x2bc830a3

static uint32_t bech32_polymod_step(uint32_t pre) {
    uint8_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
           (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
           (-((b >> 1) & 1) & 0x26508e6dUL) ^
           (-((b >> 2) & 1) & 0x1ea119faUL) ^
           (-((b >> 3) & 1) & 0x3d4233ddUL) ^
           (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t charset_rev[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
    1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
    1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static int bech32_encode(char *output, const char *hrp, size_t hrp_len, const uint8_t *data, size_t data_len, size_t max_input_len, bool is_bech32m) {
    uint32_t chk = 1;
    size_t i;
    for (i = 0; i < hrp_len; ++i) {
        int ch = hrp[i];
        if (ch < 33 || ch > 126) {
            return 0;
        }

        if (ch >= 'A' && ch <= 'Z') return 0;
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
    }
    if (i + 7 + data_len > max_input_len) return 0;
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (hrp[i] & 0x1f);
        *(output++) = hrp[i];
    }
    *(output++) = '1';
    for (i = 0; i < data_len; ++i) {
        if (*data >> 5) return 0;
        chk = bech32_polymod_step(chk) ^ (*data);
        *(output++) = charset[*(data++)];
    }
    for (i = 0; i < 6; ++i) {
        chk = bech32_polymod_step(chk);
    }
    chk ^= is_bech32m ? CHECKSUM_BECH32M : CHECKSUM_BECH32;
    for (i = 0; i < 6; ++i) {
        *(output++) = charset[(chk >> ((5 - i) * 5)) & 0x1f];
    }
    *output = 0;
    return 1;
}

static int bech32_decode(char *hrp, uint8_t *data, size_t *data_len, const char *input, size_t input_len, size_t max_input_len, bool *is_bech32m) {
    uint32_t chk = 1;
    size_t i;
    size_t hrp_len;
    int have_lower = 0, have_upper = 0;
    if (input_len < 8 || input_len > max_input_len) {
        return 0;
    }
    *data_len = 0;
    while (*data_len < input_len && input[(input_len - 1) - *data_len] != '1') {
        ++(*data_len);
    }
    if (1 + *data_len >= input_len || *data_len < 6) {
        return 0;
    }
    hrp_len = input_len - (1 + *data_len);
    *(data_len) -= 6;
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
        chk = bech32_polymod_step(chk) ^ (ch >> 5);
    }
    hrp[i] = 0;
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) {
        chk = bech32_polymod_step(chk) ^ (input[i] & 0x1f);
    }
    ++i;
    while (i < input_len) {
        int v = (input[i] & 0x80) ? -1 : charset_rev[(int)input[i]];
        if (input[i] >= 'a' && input[i] <= 'z') have_lower = 1;
        if (input[i] >= 'A' && input[i] <= 'Z') have_upper = 1;
        if (v == -1) {
            return 0;
        }
        chk = bech32_polymod_step(chk) ^ v;
        if (i + 6 < input_len) {
            data[i - (1 + hrp_len)] = v;
        }
        ++i;
    }
    if (have_lower && have_upper) {
        return 0;
    }
    *is_bech32m = chk == CHECKSUM_BECH32M;
    return chk == CHECKSUM_BECH32 || chk == CHECKSUM_BECH32M;
}

static int convert_bits(uint8_t *out, size_t *outlen, int outbits, const uint8_t *in, size_t inlen, int inbits, int pad) {
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

static int segwit_addr_encode(char *output, const char *hrp, size_t hrp_len, uint8_t witver, const uint8_t *witprog, size_t witprog_len) {
    uint8_t data[65];
    size_t datalen = 0;
    if (witver > 16) goto fail;
    if (witver == 0 && witprog_len != 20 && witprog_len != 32) goto fail;
    if (witprog_len < 2 || witprog_len > 40) goto fail;
    data[0] = witver;
    convert_bits(data + 1, &datalen, 5, witprog, witprog_len, 8, 1);
    ++datalen;
    return bech32_encode(output, hrp, hrp_len, data, datalen, 90, witver != 0);
fail:
    wally_clear_2(data, sizeof(data), (void *)witprog, witprog_len);
    return 0;
}

static int segwit_addr_decode(uint8_t *witver, uint8_t *witdata, size_t *witdata_len, const char *hrp, size_t hrp_len, const char *addr, size_t addr_len) {
    uint8_t data[84];
    char hrp_actual[84];
    size_t data_len, hrp_actual_len;
    bool is_bech32m = false;
    if (!bech32_decode(hrp_actual, data, &data_len, addr, addr_len, 90, &is_bech32m)) goto fail;
    if (data_len == 0 || data_len > 65) goto fail;
    hrp_actual_len = strlen(hrp_actual);
    if (hrp_actual_len != hrp_len || memcmp(hrp_actual, hrp, hrp_len) != 0) goto fail;
    if (data[0] == 0 && is_bech32m) goto fail;
    if (data[0] != 0 && !is_bech32m) goto fail;
    if (data[0] > 16) goto fail;
    *witdata_len = 0;
    if (!convert_bits(witdata, witdata_len, 8, data + 1, data_len - 1, 5, 0)) goto fail;
    if (*witdata_len < 2 || *witdata_len > 40) goto fail;
    if (data[0] == 0 && *witdata_len != 20 && *witdata_len != 32) goto fail;
    *witver = data[0];
    return 1;
fail:
    wally_clear_2(data, sizeof(data), hrp_actual, sizeof(hrp_actual));
    return 0;
}

int wally_addr_segwit_from_bytes(const unsigned char *bytes, size_t bytes_len,
                                 const char *addr_family, uint32_t flags,
                                 char **output)
{
    char result[90];
    size_t push_size;
    int ret;
    size_t witver;
    size_t addr_family_len = addr_family ? strlen(addr_family) : 0;

    if (output)
        *output = 0;

    if (!addr_family || flags || !bytes || !bytes_len || !output)
        return WALLY_EINVAL;

    if (!script_is_op_n(bytes[0], true, &witver))
        return WALLY_EINVAL;

    ret = script_get_push_size_from_bytes(bytes + 1, bytes_len - 1, &push_size);
    if (ret != WALLY_OK)
        return WALLY_EINVAL;
    else if (witver == 0 && push_size != HASH160_LEN && push_size != SHA256_LEN)
        return WALLY_EINVAL;

    result[0] = '\0';
    if (!segwit_addr_encode(result, addr_family, addr_family_len, witver & 0xff, bytes + 2, bytes_len - 2))
        return WALLY_ERROR;

    *output = wally_strdup(result);
    wally_clear(result, sizeof(result));
    return *output ? WALLY_OK : WALLY_ENOMEM;
}


int wally_addr_segwit_n_to_bytes(const char *addr, size_t addr_len,
                                 const char *addr_family, size_t addr_family_len,
                                 uint32_t flags,
                                 unsigned char *bytes_out, size_t len,
                                 size_t *written)
{
    unsigned char decoded[40];
    int ret;
    uint8_t witver;

    if (written)
        *written = 0;

    if (flags || !addr_family || !addr_family_len || !addr || addr_len < 8 || !bytes_out || !len || !written)
        return WALLY_EINVAL;

    if (!segwit_addr_decode(&witver, decoded, written, addr_family, addr_family_len, addr, addr_len)) {
        *written = 0;
        ret = WALLY_EINVAL;
    } else {
        ret = wally_witness_program_from_bytes_and_version(
            decoded, *written, witver, flags, bytes_out, len, written);
    }

    wally_clear(decoded, sizeof(decoded));
    return ret;
}

int wally_addr_segwit_to_bytes(const char *addr, const char *addr_family,
                               uint32_t flags,
                               unsigned char *bytes_out, size_t len,
                               size_t *written)
{
    return wally_addr_segwit_n_to_bytes(addr, addr ? strlen(addr) : 0,
                                        addr_family, addr_family ? strlen(addr_family) : 0,
                                        flags, bytes_out, len, written);
}

int wally_addr_segwit_n_get_version(const char *addr, size_t addr_len,
                                    const char *addr_family, size_t addr_family_len,
                                    uint32_t flags, size_t *written)
{
    unsigned char witness_program[WALLY_WITNESSSCRIPT_MAX_LEN];
    int ret = wally_addr_segwit_n_to_bytes(addr, addr_len, addr_family, addr_family_len,
                                           flags, witness_program, sizeof(witness_program),
                                           written);
    if (ret == WALLY_OK && !script_is_op_n(witness_program[0], true, written)) {
        *written = 0;
        ret = WALLY_EINVAL;
    }
    return ret;
}

int wally_addr_segwit_get_version(const char *addr, const char *addr_family,
                                  uint32_t flags, size_t *written)
{
    return wally_addr_segwit_n_get_version(addr, addr ? strlen(addr) : 0,
                                           addr_family, addr_family ? strlen(addr_family) : 0,
                                           flags, written);
}
