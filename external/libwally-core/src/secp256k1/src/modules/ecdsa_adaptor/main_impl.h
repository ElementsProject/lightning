/**********************************************************************
 * Copyright (c) 2020-2021 Jonas Nick, Jesse Posner                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "include/secp256k1_ecdsa_adaptor.h"
#include "modules/ecdsa_adaptor/dleq_impl.h"

/* (R, R', s', dleq_proof) */
static int secp256k1_ecdsa_adaptor_sig_serialize(unsigned char *adaptor_sig162, secp256k1_ge *r, secp256k1_ge *rp, const secp256k1_scalar *sp, const secp256k1_scalar *dleq_proof_e, const secp256k1_scalar *dleq_proof_s) {
    size_t size = 33;

    if (!secp256k1_eckey_pubkey_serialize(r, adaptor_sig162, &size, 1)) {
        return 0;
    }
    if (!secp256k1_eckey_pubkey_serialize(rp, &adaptor_sig162[33], &size, 1)) {
        return 0;
    }
    secp256k1_scalar_get_b32(&adaptor_sig162[66], sp);
    secp256k1_scalar_get_b32(&adaptor_sig162[98], dleq_proof_e);
    secp256k1_scalar_get_b32(&adaptor_sig162[130], dleq_proof_s);

    return 1;
}

static int secp256k1_ecdsa_adaptor_sig_deserialize(secp256k1_ge *r, secp256k1_scalar *sigr, secp256k1_ge *rp, secp256k1_scalar *sp, secp256k1_scalar *dleq_proof_e, secp256k1_scalar *dleq_proof_s, const unsigned char *adaptor_sig162) {
    /* If r is deserialized, require that a sigr is provided to receive
     * the X-coordinate */
    VERIFY_CHECK((r == NULL) || (r != NULL && sigr != NULL));
    if (r != NULL) {
        if (!secp256k1_eckey_pubkey_parse(r, &adaptor_sig162[0], 33)) {
            return 0;
        }
    }
    if (sigr != NULL) {
        secp256k1_scalar_set_b32(sigr, &adaptor_sig162[1], NULL);
        if (secp256k1_scalar_is_zero(sigr)) {
            return 0;
        }
    }
    if (rp != NULL) {
        if (!secp256k1_eckey_pubkey_parse(rp, &adaptor_sig162[33], 33)) {
            return 0;
        }
    }
    if (sp != NULL) {
        if (!secp256k1_scalar_set_b32_seckey(sp, &adaptor_sig162[66])) {
            return 0;
        }
    }
    if (dleq_proof_e != NULL) {
        secp256k1_scalar_set_b32(dleq_proof_e, &adaptor_sig162[98], NULL);
    }
    if (dleq_proof_s != NULL) {
        int overflow;
        secp256k1_scalar_set_b32(dleq_proof_s, &adaptor_sig162[130], &overflow);
        if (overflow) {
            return 0;
        }
    }
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/non")||SHA256("ECDSAadaptor/non"). */
static void secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x791dae43ul;
    sha->s[1] = 0xe52d3b44ul;
    sha->s[2] = 0x37f9edeaul;
    sha->s[3] = 0x9bfd2ab1ul;
    sha->s[4] = 0xcfb0f44dul;
    sha->s[5] = 0xccf1d880ul;
    sha->s[6] = 0xd18f2c13ul;
    sha->s[7] = 0xa37b9024ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("ECDSAadaptor/aux")||SHA256("ECDSAadaptor/aux"). */
static void secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xd14c7bd9ul;
    sha->s[1] = 0x095d35e6ul;
    sha->s[2] = 0xb8490a88ul;
    sha->s[3] = 0xfb00ef74ul;
    sha->s[4] = 0x0baa488ful;
    sha->s[5] = 0x69366693ul;
    sha->s[6] = 0x1c81c5baul;
    sha->s[7] = 0xc33b296aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_ecdsa_adaptor to derive the nonce using a tagged hash function. */
static const unsigned char ecdsa_adaptor_algo[16] = "ECDSAadaptor/non";

/* Modified BIP-340 nonce function */
static int nonce_function_ecdsa_adaptor(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *pk33, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithims. An optimized tagging implementation is used if the default
     * tag is provided. */
    if (algolen == sizeof(ecdsa_adaptor_algo)
            && secp256k1_memcmp_var(algo, ecdsa_adaptor_algo, algolen) == 0) {
        secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged(&sha);
    } else if (algolen == sizeof(dleq_algo)
            && secp256k1_memcmp_var(algo, dleq_algo, algolen) == 0) {
        secp256k1_nonce_function_dleq_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash (masked-)key||pk||msg using the tagged hash as per BIP-340 */
    if (data != NULL) {
        secp256k1_sha256_write(&sha, masked_key, 32);
    } else {
        secp256k1_sha256_write(&sha, key32, 32);
    }
    secp256k1_sha256_write(&sha, pk33, 33);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_nonce_function_hardened_ecdsa_adaptor secp256k1_nonce_function_ecdsa_adaptor = nonce_function_ecdsa_adaptor;

int secp256k1_ecdsa_adaptor_encrypt(const secp256k1_context* ctx, unsigned char *adaptor_sig162, unsigned char *seckey32, const secp256k1_pubkey *enckey, const unsigned char *msg32, secp256k1_nonce_function_hardened_ecdsa_adaptor noncefp, void *ndata) {
    secp256k1_scalar k;
    secp256k1_gej rj, rpj;
    secp256k1_ge r, rp;
    secp256k1_ge enckey_ge;
    secp256k1_scalar dleq_proof_s;
    secp256k1_scalar dleq_proof_e;
    secp256k1_scalar sk;
    secp256k1_scalar msg;
    secp256k1_scalar sp;
    secp256k1_scalar sigr;
    secp256k1_scalar n;
    unsigned char nonce32[32] = { 0 };
    unsigned char buf33[33];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(seckey32 != NULL);
    ARG_CHECK(enckey != NULL);
    ARG_CHECK(msg32 != NULL);

    secp256k1_scalar_clear(&dleq_proof_e);
    secp256k1_scalar_clear(&dleq_proof_s);

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_ecdsa_adaptor;
    }

    ret &= secp256k1_pubkey_load(ctx, &enckey_ge, enckey);
    ret &= secp256k1_eckey_pubkey_serialize(&enckey_ge, buf33, &size, 1);
    ret &= !!noncefp(nonce32, msg32, seckey32, buf33, ecdsa_adaptor_algo, sizeof(ecdsa_adaptor_algo), ndata);
    secp256k1_scalar_set_b32(&k, nonce32, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    /* R' := k*G */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rpj, &k);
    secp256k1_ge_set_gej(&rp, &rpj);
    /* R = k*Y; */
    secp256k1_ecmult_const(&rj, &enckey_ge, &k, 256);
    secp256k1_ge_set_gej(&r, &rj);
    /* We declassify the non-secret values rp and r to allow using them
     * as branch points. */
    secp256k1_declassify(ctx, &rp, sizeof(rp));
    secp256k1_declassify(ctx, &r, sizeof(r));

    /* dleq_proof = DLEQ_prove(k, (R', Y, R)) */
    ret &= secp256k1_dleq_prove(ctx, &dleq_proof_s, &dleq_proof_e, &k, &enckey_ge, &rp, &r, noncefp, ndata);

    ret &= secp256k1_scalar_set_b32_seckey(&sk, seckey32);
    secp256k1_scalar_cmov(&sk, &secp256k1_scalar_one, !ret);
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    secp256k1_fe_normalize(&r.x);
    secp256k1_fe_get_b32(buf33, &r.x);
    secp256k1_scalar_set_b32(&sigr, buf33, NULL);
    ret &= !secp256k1_scalar_is_zero(&sigr);
    /* s' = k⁻¹(m + R.x * x) */
    secp256k1_scalar_mul(&n, &sigr, &sk);
    secp256k1_scalar_add(&n, &n, &msg);
    secp256k1_scalar_inverse(&sp, &k);
    secp256k1_scalar_mul(&sp, &sp, &n);
    ret &= !secp256k1_scalar_is_zero(&sp);

    /* return (R, R', s', dleq_proof) */
    ret &= secp256k1_ecdsa_adaptor_sig_serialize(adaptor_sig162, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s);

    secp256k1_memczero(adaptor_sig162, 162, !ret);
    secp256k1_scalar_clear(&n);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);

    return ret;
}

int secp256k1_ecdsa_adaptor_verify(const secp256k1_context* ctx, const unsigned char *adaptor_sig162, const secp256k1_pubkey *pubkey, const unsigned char *msg32, const secp256k1_pubkey *enckey) {
    secp256k1_scalar dleq_proof_s, dleq_proof_e;
    secp256k1_scalar msg;
    secp256k1_ge pubkey_ge;
    secp256k1_ge r, rp;
    secp256k1_scalar sp;
    secp256k1_scalar sigr;
    secp256k1_ge enckey_ge;
    secp256k1_gej derived_rp;
    secp256k1_scalar sn, u1, u2;
    secp256k1_gej pubkeyj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(enckey != NULL);

    if (!secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig162)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &enckey_ge, enckey)) {
        return 0;
    }
    /* DLEQ_verify((R', Y, R), dleq_proof) */
    if(!secp256k1_dleq_verify(&dleq_proof_s, &dleq_proof_e, &rp, &enckey_ge, &r)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    if (!secp256k1_pubkey_load(ctx, &pubkey_ge, pubkey)) {
        return 0;
    }

    /* return R' == s'⁻¹(m * G + R.x * X) */
    secp256k1_scalar_inverse_var(&sn, &sp);
    secp256k1_scalar_mul(&u1, &sn, &msg);
    secp256k1_scalar_mul(&u2, &sn, &sigr);
    secp256k1_gej_set_ge(&pubkeyj, &pubkey_ge);
    secp256k1_ecmult(&derived_rp, &pubkeyj, &u2, &u1);
    if (secp256k1_gej_is_infinity(&derived_rp)) {
        return 0;
    }
    secp256k1_gej_neg(&derived_rp, &derived_rp);
    secp256k1_gej_add_ge_var(&derived_rp, &derived_rp, &rp, NULL);
    return secp256k1_gej_is_infinity(&derived_rp);
}

int secp256k1_ecdsa_adaptor_decrypt(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *deckey32, const unsigned char *adaptor_sig162) {
    secp256k1_scalar deckey;
    secp256k1_scalar sp;
    secp256k1_scalar s;
    secp256k1_scalar sigr;
    int overflow;
    int high;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(deckey32 != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);

    secp256k1_scalar_clear(&sp);
    secp256k1_scalar_set_b32(&deckey, deckey32, &overflow);
    ret &= !overflow;
    ret &= secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, &sp, NULL, NULL, adaptor_sig162);
    ret &= !secp256k1_scalar_is_zero(&deckey);
    secp256k1_scalar_inverse(&s, &deckey);
    /* s = s' * y⁻¹ */
    secp256k1_scalar_mul(&s, &s, &sp);
    high = secp256k1_scalar_is_high(&s);
    secp256k1_scalar_cond_negate(&s, high);
    secp256k1_ecdsa_signature_save(sig, &sigr, &s);

    secp256k1_memczero(&sig->data[0], 64, !ret);
    secp256k1_scalar_clear(&deckey);
    secp256k1_scalar_clear(&sp);
    secp256k1_scalar_clear(&s);

    return ret;
}

int secp256k1_ecdsa_adaptor_recover(const secp256k1_context* ctx, unsigned char *deckey32, const secp256k1_ecdsa_signature *sig, const unsigned char *adaptor_sig162, const secp256k1_pubkey *enckey) {
    secp256k1_scalar sp, adaptor_sigr;
    secp256k1_scalar s, r;
    secp256k1_scalar deckey;
    secp256k1_ge enckey_expected_ge;
    secp256k1_gej enckey_expected_gej;
    unsigned char enckey33[33];
    unsigned char enckey_expected33[33];
    size_t size = 33;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(deckey32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(enckey != NULL);

    if (!secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &adaptor_sigr, NULL, &sp, NULL, NULL, adaptor_sig162)) {
        return 0;
    }
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    /* Check that we're not looking at some unrelated signature */
    ret &= secp256k1_scalar_eq(&adaptor_sigr, &r);
    /* y = s⁻¹ * s' */
    ret &= !secp256k1_scalar_is_zero(&s);
    secp256k1_scalar_inverse(&deckey, &s);
    secp256k1_scalar_mul(&deckey, &deckey, &sp);

    /* Deal with ECDSA malleability */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &enckey_expected_gej, &deckey);
    secp256k1_ge_set_gej(&enckey_expected_ge, &enckey_expected_gej);
    /* We declassify non-secret enckey_expected_ge to allow using it as a
     * branch point. */
    secp256k1_declassify(ctx, &enckey_expected_ge, sizeof(enckey_expected_ge));
    if (!secp256k1_eckey_pubkey_serialize(&enckey_expected_ge, enckey_expected33, &size, SECP256K1_EC_COMPRESSED)) {
        /* Unreachable from tests (and other VERIFY builds) and therefore this
         * branch should be ignored in test coverage analysis.
         *
         * Proof:
         *     eckey_pubkey_serialize fails <=> deckey = 0
         *     deckey = 0 <=> s^-1 = 0 or sp = 0
         *     case 1: s^-1 = 0 impossible by the definition of multiplicative
         *             inverse and because the scalar_inverse implementation
         *             VERIFY_CHECKs that the inputs are valid scalars.
         *     case 2: sp = 0 impossible because ecdsa_adaptor_sig_deserialize would have already failed
         */
        return 0;
    }
    if (!secp256k1_ec_pubkey_serialize(ctx, enckey33, &size, enckey, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    if (secp256k1_memcmp_var(&enckey_expected33[1], &enckey33[1], 32) != 0) {
        return 0;
    }
    if (enckey_expected33[0] != enckey33[0]) {
        /* try Y_implied == -Y */
        secp256k1_scalar_negate(&deckey, &deckey);
    }
    secp256k1_scalar_get_b32(deckey32, &deckey);

    secp256k1_scalar_clear(&deckey);
    secp256k1_scalar_clear(&sp);
    secp256k1_scalar_clear(&s);

    return ret;
}

#endif
