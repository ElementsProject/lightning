/***********************************************************************
 * Copyright (c) 2015 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_SCHNORR_IMPL_H_
#define _SECP256K1_SCHNORR_IMPL_H_

#include <string.h>

#include "schnorr.h"
#include "num.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"

/**
 * Custom Schnorr-based signature scheme:
 *
 * Signing:
 *   Inputs: 32-byte message m, 32-byte scalar key x (!=0), 32-byte scalar nonce k (!=0)
 *
 *   Compute point R = k * G. Reject nonce if R's y coordinate is odd (or negate nonce).
 *   Compute 32-byte r, the serialization of R's x coordinate.
 *   Compute scalar h = Hash(r || m). Reject nonce if h == 0 or h >= order.
 *   Compute scalar s = k - h * x.
 *   The signature is (r, s).
 *
 *
 * Verification:
 *   Inputs: 32-byte message m, public key point Q, signature: (32-byte r, scalar s)
 *
 *   Signature is invalid if s >= order.
 *   Signature is invalid if r >= p.
 *   Compute scalar h = Hash(r || m). Signature is invalid if h == 0 or h >= order.
 *   Option 1 (faster for single verification):
 *     Compute point R = h * Q + s * G. Signature is invalid if R is infinity or R's y coordinate is odd.
 *     Signature is valid if the serialization of R's x coordinate equals r.
 *   Option 2 (allows batch validation and pubkey recovery):
 *     Decompress x coordinate r into point R, with odd y coordinate. Fail if R is not on the curve.
 *     Signature is valid if R + h * Q + s * G == 0.
 */

static int secp256k1_schnorr_sig_sign(const secp256k1_ecmult_gen_context_t* ctx, unsigned char *sig64, const secp256k1_scalar_t *key, secp256k1_scalar_t *nonce, secp256k1_schnorr_msghash_t hash, const unsigned char *msg32) {
    secp256k1_gej_t Rj;
    secp256k1_ge_t Ra;
    unsigned char h32[32];
    secp256k1_scalar_t h, s;
    int overflow;

    if (secp256k1_scalar_is_zero(key) || secp256k1_scalar_is_zero(nonce)) {
        return 0;
    }

    secp256k1_ecmult_gen(ctx, &Rj, nonce);
    secp256k1_ge_set_gej(&Ra, &Rj);
    secp256k1_fe_normalize(&Ra.y);
    if (secp256k1_fe_is_odd(&Ra.y)) {
        secp256k1_scalar_negate(nonce, nonce);
    }
    secp256k1_fe_normalize(&Ra.x);
    secp256k1_fe_get_b32(sig64, &Ra.x);
    hash(h32, sig64, msg32);
    overflow = 0;
    secp256k1_scalar_set_b32(&h, h32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&h)) {
        return 0;
    }
    secp256k1_scalar_mul(&s, &h, key);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&s, &s, nonce);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context_t* ctx, const unsigned char *sig64, const secp256k1_ge_t *pubkey, secp256k1_schnorr_msghash_t hash, const unsigned char *msg32) {
    secp256k1_gej_t Qj, Rj;
    secp256k1_ge_t Ra;
    secp256k1_fe_t Rx;
    secp256k1_scalar_t h, s;
    unsigned char hh[32];
    int overflow;

    if (secp256k1_ge_is_infinity(pubkey)) {
        return 0;
    }
    hash(hh, sig64, msg32);
    overflow = 0;
    secp256k1_scalar_set_b32(&h, hh, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&h)) {
        return 0;
    }
    overflow = 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_fe_set_b32(&Rx, sig64)) {
        return 0;
    }
    secp256k1_gej_set_ge(&Qj, pubkey);
    secp256k1_ecmult(ctx, &Rj, &Qj, &h, &s);
    if (secp256k1_gej_is_infinity(&Rj)) {
        return 0;
    }
    secp256k1_ge_set_gej_var(&Ra, &Rj);
    secp256k1_fe_normalize_var(&Ra.y);
    if (secp256k1_fe_is_odd(&Ra.y)) {
        return 0;
    }
    return secp256k1_fe_equal_var(&Rx, &Ra.x);
}

#endif
