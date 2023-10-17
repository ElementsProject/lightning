/* Stolen from https://github.com/sipa/bech32/blob/master/ref/c/segwit_addr.h,
 * with only the two ' > 90' checks hoisted */

/* Copyright (c) 2017, 2021 Pieter Wuille
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

#ifndef LIGHTNING_COMMON_BECH32_H
#define LIGHTNING_COMMON_BECH32_H
#include "config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/** Encode a SegWit address
 *
 *  Out: output:   Pointer to a buffer of size 73 + strlen(hrp) that will be
 *                 updated to contain the null-terminated address.
 *  In:  hrp:      Pointer to the null-terminated human readable part to use
 *                 (chain/network specific).
 *       ver:      Version of the witness program (between 0 and 16 inclusive).
 *       prog:     Data bytes for the witness program (between 2 and 40 bytes).
 *       prog_len: Number of data bytes in prog.
 *  Returns 1 if successful.
 */
int segwit_addr_encode(
    char *output,
    const char *hrp,
    int ver,
    const uint8_t *prog,
    size_t prog_len
);

/** Decode a SegWit address
 *
 *  Out: ver:      Pointer to an int that will be updated to contain the witness
 *                 program version (between 0 and 16 inclusive).
 *       prog:     Pointer to a buffer of size 40 that will be updated to
 *                 contain the witness program bytes.
 *       prog_len: Pointer to a size_t that will be updated to contain the length
 *                 of bytes in prog.
 *       hrp:      Pointer to the null-terminated human readable part that is
 *                 expected (chain/network specific).
 *       addr:     Pointer to the null-terminated address.
 *  Returns 1 if successful.
 */
int segwit_addr_decode(
    int* ver,
    uint8_t* prog,
    size_t* prog_len,
    const char* hrp,
    const char* addr
);

/** Supported encodings. */
typedef enum {
    BECH32_ENCODING_NONE,
    BECH32_ENCODING_BECH32,
    BECH32_ENCODING_BECH32M
} bech32_encoding;

/** Encode a Bech32 or Bech32m string
 *
 *  Out: output:  Pointer to a buffer of size strlen(hrp) + data_len + 8 that
 *                will be updated to contain the null-terminated Bech32 string.
 *  In: hrp :     Pointer to the null-terminated human readable part.
 *      data :    Pointer to an array of 5-bit values.
 *      data_len: Length of the data array.
 *      max_output_len: Maximum valid length of output (90 for segwit usage).
 *      enc:      Which encoding to use (BECH32_ENCODING_BECH32{,M}).
 *  Returns 1 if successful.
 */
int bech32_encode(
    char *output,
    const char *hrp,
    const uint8_t *data,
    size_t data_len,
    size_t max_output_len,
    bech32_encoding enc
);

/** Decode a Bech32 or Bech32m string
 *
 *  Out: hrp:      Pointer to a buffer of size strlen(input) - 6. Will be
 *                 updated to contain the null-terminated human readable part.
 *       data:     Pointer to a buffer of size strlen(input) - 8 that will
 *                 hold the encoded 5-bit data values.
 *       data_len: Pointer to a size_t that will be updated to be the number
 *                 of entries in data.
 *  In: input:     Pointer to a null-terminated Bech32 string.
 *      max_input_len: Maximum valid length of input (90 for segwit usage).
 *  Returns BECH32_ENCODING_BECH32{,M} to indicate decoding was successful
 *  with the specified encoding standard. BECH32_ENCODING_NONE is returned if
 *  decoding failed.
 */
bech32_encoding bech32_decode(
    char *hrp,
    uint8_t *data,
    size_t *data_len,
    const char *input,
    size_t max_input_len
);

/* Helper from bech32: translates inbits-bit bytes to outbits-bit bytes.
 * @outlen is incremented as bytes are added.
 * @pad is true if we're to pad, otherwise truncate last byte if necessary
 */
int bech32_convert_bits(uint8_t* out, size_t* outlen, int outbits,
			const uint8_t* in, size_t inlen, int inbits,
			int pad);

/* The charset, and reverse mapping */
extern const char bech32_charset[32];
extern const int8_t bech32_charset_rev[128];

/* Global to weaken csum checks for fuzzing. */
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
extern bool dev_bech32_nocsum;
#endif

#endif /* LIGHTNING_COMMON_BECH32_H */

