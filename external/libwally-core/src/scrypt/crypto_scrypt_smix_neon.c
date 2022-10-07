/*-
 * Copyright 2009 Colin Percival
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#if 0
#include "scrypt_platform.h"
#include <arm_neon.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifdef USE_OPENSSL_PBKDF2
#include <openssl/evp.h>
#else
#include "sha256.h"
#endif
#include "sysendian.h"
#include "crypto_scrypt.h"
#include "crypto_scrypt-neon-salsa208.h"
static void blkcpy(void *, void *, size_t);
static void blkxor(void *, void *, size_t);
void crypto_core_salsa208_armneon2(void *);
static void blockmix_salsa8(uint8x16_t *, uint8x16_t *, uint8x16_t *, size_t);
static uint64_t integerify(void *, size_t);
static void smix(uint8_t *, size_t, uint64_t, void *, void *);
#endif

static void
neon_blkcpy(void * dest, void * src, size_t len)
{
    uint8x16_t * D = dest;
    uint8x16_t * S = src;
    size_t L = len / 16;
    size_t i;
    for (i = 0; i < L; i++)
        D[i] = S[i];
}
static void
neon_blkxor(void * dest, void * src, size_t len)
{
    uint8x16_t * D = dest;
    uint8x16_t * S = src;
    size_t L = len / 16;
    size_t i;
    for (i = 0; i < L; i++)
        D[i] = veorq_u8(D[i], S[i]);
}

/*
 * version 20110505
 * D. J. Bernstein
 * Public domain.
 *
 * Based on crypto_core/salsa208/armneon/core.c from SUPERCOP 20130419
 */
#define ROUNDS 8
static void
neon_salsa20_8_intrinsic(void * input)
{
    int i;
    const uint32x4_t abab = {-1,0,-1,0};
    /*
     * This is modified since we only have one argument. Usually you'd rearrange
     * the constant, key, and input bytes, but we just have one linear array to
     * rearrange which is a bit easier.
     */
    /*
     * Change the input to be diagonals as if it's a 4x4 matrix of 32-bit values.
     */
    uint32x4_t x0x5x10x15;
    uint32x4_t x12x1x6x11;
    uint32x4_t x8x13x2x7;
    uint32x4_t x4x9x14x3;
    uint32x4_t x0x1x10x11;
    uint32x4_t x12x13x6x7;
    uint32x4_t x8x9x2x3;
    uint32x4_t x4x5x14x15;
    uint32x4_t x0x1x2x3;
    uint32x4_t x4x5x6x7;
    uint32x4_t x8x9x10x11;
    uint32x4_t x12x13x14x15;
    x0x1x2x3 = vld1q_u8((uint8_t *) input);
    x4x5x6x7 = vld1q_u8(16 + (uint8_t *) input);
    x8x9x10x11 = vld1q_u8(32 + (uint8_t *) input);
    x12x13x14x15 = vld1q_u8(48 + (uint8_t *) input);
    x0x1x10x11 = vcombine_u32(vget_low_u32(x0x1x2x3), vget_high_u32(x8x9x10x11));
    x4x5x14x15 = vcombine_u32(vget_low_u32(x4x5x6x7), vget_high_u32(x12x13x14x15));
    x8x9x2x3 = vcombine_u32(vget_low_u32(x8x9x10x11), vget_high_u32(x0x1x2x3));
    x12x13x6x7 = vcombine_u32(vget_low_u32(x12x13x14x15), vget_high_u32(x4x5x6x7));
    x0x5x10x15 = vbslq_u32(abab,x0x1x10x11,x4x5x14x15);
    x8x13x2x7 = vbslq_u32(abab,x8x9x2x3,x12x13x6x7);
    x4x9x14x3 = vbslq_u32(abab,x4x5x14x15,x8x9x2x3);
    x12x1x6x11 = vbslq_u32(abab,x12x13x6x7,x0x1x10x11);
    {
    uint32x4_t start0 = x0x5x10x15;
    uint32x4_t start1 = x12x1x6x11;
    uint32x4_t start3 = x4x9x14x3;
    uint32x4_t start2 = x8x13x2x7;
    /* From here on this should be the same as the SUPERCOP version. */
    uint32x4_t diag0 = start0;
    uint32x4_t diag1 = start1;
    uint32x4_t diag2 = start2;
    uint32x4_t diag3 = start3;
    uint32x4_t a0;
    uint32x4_t a1;
    uint32x4_t a2;
    uint32x4_t a3;
    for (i = ROUNDS;i > 0;i -= 2) {
        a0 = diag1 + diag0;
        diag3 ^= vsriq_n_u32(vshlq_n_u32(a0,7),a0,25);
        a1 = diag0 + diag3;
        diag2 ^= vsriq_n_u32(vshlq_n_u32(a1,9),a1,23);
        a2 = diag3 + diag2;
        diag1 ^= vsriq_n_u32(vshlq_n_u32(a2,13),a2,19);
        a3 = diag2 + diag1;
        diag0 ^= vsriq_n_u32(vshlq_n_u32(a3,18),a3,14);
        diag3 = vextq_u32(diag3,diag3,3);
        diag2 = vextq_u32(diag2,diag2,2);
        diag1 = vextq_u32(diag1,diag1,1);
        a0 = diag3 + diag0;
        diag1 ^= vsriq_n_u32(vshlq_n_u32(a0,7),a0,25);
        a1 = diag0 + diag1;
        diag2 ^= vsriq_n_u32(vshlq_n_u32(a1,9),a1,23);
        a2 = diag1 + diag2;
        diag3 ^= vsriq_n_u32(vshlq_n_u32(a2,13),a2,19);
        a3 = diag2 + diag3;
        diag0 ^= vsriq_n_u32(vshlq_n_u32(a3,18),a3,14);
        diag1 = vextq_u32(diag1,diag1,3);
        diag2 = vextq_u32(diag2,diag2,2);
        diag3 = vextq_u32(diag3,diag3,1);
    }
    x0x5x10x15 = diag0 + start0;
    x12x1x6x11 = diag1 + start1;
    x8x13x2x7 = diag2 + start2;
    x4x9x14x3 = diag3 + start3;
    x0x1x10x11 = vbslq_u32(abab,x0x5x10x15,x12x1x6x11);
    x12x13x6x7 = vbslq_u32(abab,x12x1x6x11,x8x13x2x7);
    x8x9x2x3 = vbslq_u32(abab,x8x13x2x7,x4x9x14x3);
    x4x5x14x15 = vbslq_u32(abab,x4x9x14x3,x0x5x10x15);
    x0x1x2x3 = vcombine_u32(vget_low_u32(x0x1x10x11),vget_high_u32(x8x9x2x3));
    x4x5x6x7 = vcombine_u32(vget_low_u32(x4x5x14x15),vget_high_u32(x12x13x6x7));
    x8x9x10x11 = vcombine_u32(vget_low_u32(x8x9x2x3),vget_high_u32(x0x1x10x11));
    x12x13x14x15 = vcombine_u32(vget_low_u32(x12x13x6x7),vget_high_u32(x4x5x14x15));
    vst1q_u8((uint8_t *) input,(uint8x16_t) x0x1x2x3);
    vst1q_u8(16 + (uint8_t *) input,(uint8x16_t) x4x5x6x7);
    vst1q_u8(32 + (uint8_t *) input,(uint8x16_t) x8x9x10x11);
    vst1q_u8(48 + (uint8_t *) input,(uint8x16_t) x12x13x14x15);
    }
}

/**
 * blockmix_salsa8(B, Y, r):
 * Compute B = BlockMix_{salsa20/8, r}(B).  The input B must be 128r bytes in
 * length; the temporary space Y must also be the same size.
 */
static void
neon_blockmix_salsa8(uint8x16_t * Bin, uint8x16_t * Bout, uint8x16_t * X, size_t r)
{
    size_t i;
    /* 1: X <-- B_{2r - 1} */
    neon_blkcpy(X, &Bin[8 * r - 4], 64);
    /* 2: for i = 0 to 2r - 1 do */
    for (i = 0; i < r; i++) {
        /* 3: X <-- H(X \xor B_i) */
        neon_blkxor(X, &Bin[i * 8], 64);
        neon_salsa20_8_intrinsic((void *) X);
        /* 4: Y_i <-- X */
        /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        neon_blkcpy(&Bout[i * 4], X, 64);
        /* 3: X <-- H(X \xor B_i) */
        neon_blkxor(X, &Bin[i * 8 + 4], 64);
        neon_salsa20_8_intrinsic((void *) X);
        /* 4: Y_i <-- X */
        /* 6: B' <-- (Y_0, Y_2 ... Y_{2r-2}, Y_1, Y_3 ... Y_{2r-1}) */
        neon_blkcpy(&Bout[(r + i) * 4], X, 64);
    }
}

static inline uint64_t
neon_le64dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;

	/* Only return the lower 32 bits since N cannot be > 2^32 */
	return (uint64_t)(p[0]) + ((uint64_t)(p[1]) << 8) +
	    ((uint64_t)(p[2]) << 16) + ((uint64_t)(p[3]) << 24);
}

/**
 * integerify(B, r):
 * Return the result of parsing B_{2r-1} as a little-endian integer.
 */
static uint64_t
neon_integerify(void * B, size_t r)
{
    uint8_t * X = (void*)((uintptr_t)(B) + (2 * r - 1) * 64);
    return (neon_le64dec(X));
}
/**
 * smix(B, r, N, V, XY):
 * Compute B = SMix_r(B, N).  The input B must be 128r bytes in length; the
 * temporary storage V must be 128rN bytes in length; the temporary storage
 * XY must be 256r bytes in length.  The value N must be a power of 2.
 */
static void
crypto_scrypt_smix_neon(uint8_t * B, size_t r, uint64_t N, void * V, void * XY)
{
    uint8x16_t * X = XY;
    uint8x16_t * Y = (void *)((uintptr_t)(XY) + 128 * r);
    uint8x16_t * Z = (void *)((uintptr_t)(XY) + 256 * r);
    uint64_t i, j;

    /* 1: X <-- B */
    neon_blkcpy(X, B, 128 * r);
    /* 2: for i = 0 to N - 1 do */
    for (i = 0; i < N; i += 2) {
        /* 3: V_i <-- X */
        neon_blkcpy(((unsigned char *)V) + i * 128 * r, X, 128 * r);
        /* 4: X <-- H(X) */
        neon_blockmix_salsa8(X, Y, Z, r);
        /* 3: V_i <-- X */
        neon_blkcpy(((unsigned char *)V) + (i + 1) * 128 * r, Y, 128 * r);
        /* 4: X <-- H(X) */
        neon_blockmix_salsa8(Y, X, Z, r);
    }
    /* 6: for i = 0 to N - 1 do */
    for (i = 0; i < N; i += 2) {
        /* 7: j <-- Integerify(X) mod N */
        j = neon_integerify(X, r) & (N - 1);
        /* 8: X <-- H(X \xor V_j) */
        neon_blkxor(X, ((unsigned char *)V) + j * 128 * r, 128 * r);
        neon_blockmix_salsa8(X, Y, Z, r);
        /* 7: j <-- Integerify(X) mod N */
        j = neon_integerify(Y, r) & (N - 1);
        /* 8: X <-- H(X \xor V_j) */
        neon_blkxor(Y, ((unsigned char *)V) + j * 128 * r, 128 * r);
        neon_blockmix_salsa8(Y, X, Z, r);
    }
    /* 10: B' <-- X */
    neon_blkcpy(B, X, 128 * r);
}
