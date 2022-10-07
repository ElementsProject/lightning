/***********************************************************************
 * Copyright (c) 2021 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_SESSION_IMPL_H
#define SECP256K1_MODULE_MUSIG_SESSION_IMPL_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_musig.h"

#include "keyagg.h"
#include "session.h"
#include "../../eckey.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

static const unsigned char secp256k1_musig_secnonce_magic[4] = { 0x22, 0x0e, 0xdc, 0xf1 };

static void secp256k1_musig_secnonce_save(secp256k1_musig_secnonce *secnonce, secp256k1_scalar *k) {
    memcpy(&secnonce->data[0], secp256k1_musig_secnonce_magic, 4);
    secp256k1_scalar_get_b32(&secnonce->data[4], &k[0]);
    secp256k1_scalar_get_b32(&secnonce->data[36], &k[1]);
}

static int secp256k1_musig_secnonce_load(const secp256k1_context* ctx, secp256k1_scalar *k, secp256k1_musig_secnonce *secnonce) {
    int is_zero;
    ARG_CHECK(secp256k1_memcmp_var(&secnonce->data[0], secp256k1_musig_secnonce_magic, 4) == 0);
    secp256k1_scalar_set_b32(&k[0], &secnonce->data[4], NULL);
    secp256k1_scalar_set_b32(&k[1], &secnonce->data[36], NULL);
    /* We make very sure that the nonce isn't invalidated by checking the values
     * in addition to the magic. */
    is_zero = secp256k1_scalar_is_zero(&k[0]) & secp256k1_scalar_is_zero(&k[1]);
    secp256k1_declassify(ctx, &is_zero, sizeof(is_zero));
    ARG_CHECK(!is_zero);
    return 1;
}

/* If flag is true, invalidate the secnonce; otherwise leave it. Constant-time. */
static void secp256k1_musig_secnonce_invalidate(const secp256k1_context* ctx, secp256k1_musig_secnonce *secnonce, int flag) {
    secp256k1_memczero(secnonce->data, sizeof(secnonce->data), flag);
    /* The flag argument is usually classified. So, above code makes the magic
     * classified. However, we need the magic to be declassified to be able to
     * compare it during secnonce_load. */
    secp256k1_declassify(ctx, secnonce->data, sizeof(secp256k1_musig_secnonce_magic));
}

static const unsigned char secp256k1_musig_pubnonce_magic[4] = { 0xf5, 0x7a, 0x3d, 0xa0 };

/* Requires that none of the provided group elements is infinity. Works for both
 * musig_pubnonce and musig_aggnonce. */
static void secp256k1_musig_pubnonce_save(secp256k1_musig_pubnonce* nonce, secp256k1_ge* ge) {
    int i;
    memcpy(&nonce->data[0], secp256k1_musig_pubnonce_magic, 4);
    for (i = 0; i < 2; i++) {
        secp256k1_point_save(nonce->data + 4+64*i, &ge[i]);
    }
}

/* Works for both musig_pubnonce and musig_aggnonce. Returns 1 unless the nonce
 * wasn't properly initialized */
static int secp256k1_musig_pubnonce_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_musig_pubnonce* nonce) {
    int i;

    ARG_CHECK(secp256k1_memcmp_var(&nonce->data[0], secp256k1_musig_pubnonce_magic, 4) == 0);
    for (i = 0; i < 2; i++) {
        secp256k1_point_load(&ge[i], nonce->data + 4 + 64*i);
    }
    return 1;
}

static void secp256k1_musig_aggnonce_save(secp256k1_musig_aggnonce* nonce, secp256k1_ge* ge) {
    secp256k1_musig_pubnonce_save((secp256k1_musig_pubnonce *) nonce, ge);
}

static int secp256k1_musig_aggnonce_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_musig_aggnonce* nonce) {
    return secp256k1_musig_pubnonce_load(ctx, ge, (secp256k1_musig_pubnonce *) nonce);
}

static const unsigned char secp256k1_musig_session_cache_magic[4] = { 0x9d, 0xed, 0xe9, 0x17 };

/* A session consists of
 * - 4 byte session cache magic
 * - 1 byte the parity of the final nonce
 * - 32 byte serialized x-only final nonce
 * - 32 byte nonce coefficient b
 * - 32 byte signature challenge hash e
 * - 32 byte scalar s that is added to the partial signatures of the signers
 */
static void secp256k1_musig_session_save(secp256k1_musig_session *session, const secp256k1_musig_session_internal *session_i) {
    unsigned char *ptr = session->data;

    memcpy(ptr, secp256k1_musig_session_cache_magic, 4);
    ptr += 4;
    *ptr = session_i->fin_nonce_parity;
    ptr += 1;
    memcpy(ptr, session_i->fin_nonce, 32);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->noncecoef);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->challenge);
    ptr += 32;
    secp256k1_scalar_get_b32(ptr, &session_i->s_part);
}

static int secp256k1_musig_session_load(const secp256k1_context* ctx, secp256k1_musig_session_internal *session_i, const secp256k1_musig_session *session) {
    const unsigned char *ptr = session->data;

    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_musig_session_cache_magic, 4) == 0);
    ptr += 4;
    session_i->fin_nonce_parity = *ptr;
    ptr += 1;
    memcpy(session_i->fin_nonce, ptr, 32);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->noncecoef, ptr, NULL);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->challenge, ptr, NULL);
    ptr += 32;
    secp256k1_scalar_set_b32(&session_i->s_part, ptr, NULL);
    return 1;
}

static const unsigned char secp256k1_musig_partial_sig_magic[4] = { 0xeb, 0xfb, 0x1a, 0x32 };

static void secp256k1_musig_partial_sig_save(secp256k1_musig_partial_sig* sig, secp256k1_scalar *s) {
    memcpy(&sig->data[0], secp256k1_musig_partial_sig_magic, 4);
    secp256k1_scalar_get_b32(&sig->data[4], s);
}

static int secp256k1_musig_partial_sig_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_musig_partial_sig* sig) {
    int overflow;

    ARG_CHECK(secp256k1_memcmp_var(&sig->data[0], secp256k1_musig_partial_sig_magic, 4) == 0);
    secp256k1_scalar_set_b32(s, &sig->data[4], &overflow);
    /* Parsed signatures can not overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

int secp256k1_musig_pubnonce_serialize(const secp256k1_context* ctx, unsigned char *out66, const secp256k1_musig_pubnonce* nonce) {
    secp256k1_ge ge[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out66 != NULL);
    memset(out66, 0, 66);
    ARG_CHECK(nonce != NULL);

    if (!secp256k1_musig_pubnonce_load(ctx, ge, nonce)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        int ret;
        size_t size = 33;
        ret = secp256k1_eckey_pubkey_serialize(&ge[i], &out66[33*i], &size, 1);
        /* serialize must succeed because the point was just loaded */
        VERIFY_CHECK(ret && size == 33);
    }
    return 1;
}

int secp256k1_musig_pubnonce_parse(const secp256k1_context* ctx, secp256k1_musig_pubnonce* nonce, const unsigned char *in66) {
    secp256k1_ge ge[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(in66 != NULL);

    for (i = 0; i < 2; i++) {
        if (!secp256k1_eckey_pubkey_parse(&ge[i], &in66[33*i], 33)) {
            return 0;
        }
        if (!secp256k1_ge_is_in_correct_subgroup(&ge[i])) {
            return 0;
        }
    }
    /* The group elements can not be infinity because they were just parsed */
    secp256k1_musig_pubnonce_save(nonce, ge);
    return 1;
}

int secp256k1_musig_aggnonce_serialize(const secp256k1_context* ctx, unsigned char *out66, const secp256k1_musig_aggnonce* nonce) {
    return secp256k1_musig_pubnonce_serialize(ctx, out66, (secp256k1_musig_pubnonce*) nonce);
}

int secp256k1_musig_aggnonce_parse(const secp256k1_context* ctx, secp256k1_musig_aggnonce* nonce, const unsigned char *in66) {
    return secp256k1_musig_pubnonce_parse(ctx, (secp256k1_musig_pubnonce*) nonce, in66);
}

int secp256k1_musig_partial_sig_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_musig_partial_sig* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(sig != NULL);
    memcpy(out32, &sig->data[4], 32);
    return 1;
}

int secp256k1_musig_partial_sig_parse(const secp256k1_context* ctx, secp256k1_musig_partial_sig* sig, const unsigned char *in32) {
    secp256k1_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in32 != NULL);

    secp256k1_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_musig_partial_sig_save(sig, &tmp);
    return 1;
}

/* Normalizes the x-coordinate of the given group element. */
static int secp256k1_xonly_ge_serialize(unsigned char *output32, secp256k1_ge *ge) {
    if (secp256k1_ge_is_infinity(ge)) {
        return 0;
    }
    secp256k1_fe_normalize_var(&ge->x);
    secp256k1_fe_get_b32(output32, &ge->x);
    return 1;
}

static void secp256k1_nonce_function_musig(secp256k1_scalar *k, const unsigned char *session_id, const unsigned char *msg32, const unsigned char *key32, const unsigned char *agg_pk32, const unsigned char *extra_input32) {
    secp256k1_sha256 sha;
    unsigned char seed[32];
    unsigned char i;
    enum { n_extra_in = 4 };
    const unsigned char *extra_in[n_extra_in];

    /* TODO: this doesn't have the same sidechannel resistance as the BIP340
     * nonce function because the seckey feeds directly into SHA. */

    /* Subtract one from `sizeof` to avoid hashing the implicit null byte */
    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"MuSig/nonce", sizeof("MuSig/nonce") - 1);
    secp256k1_sha256_write(&sha, session_id, 32);
    extra_in[0] = msg32;
    extra_in[1] = key32;
    extra_in[2] = agg_pk32;
    extra_in[3] = extra_input32;
    for (i = 0; i < n_extra_in; i++) {
        unsigned char len;
        if (extra_in[i] != NULL) {
            len = 32;
            secp256k1_sha256_write(&sha, &len, 1);
            secp256k1_sha256_write(&sha, extra_in[i], 32);
        } else {
            len = 0;
            secp256k1_sha256_write(&sha, &len, 1);
        }
    }
    secp256k1_sha256_finalize(&sha, seed);

    for (i = 0; i < 2; i++) {
        unsigned char buf[32];
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, seed, 32);
        secp256k1_sha256_write(&sha, &i, sizeof(i));
        secp256k1_sha256_finalize(&sha, buf);
        secp256k1_scalar_set_b32(&k[i], buf, NULL);
    }
}

int secp256k1_musig_nonce_gen(const secp256k1_context* ctx, secp256k1_musig_secnonce *secnonce, secp256k1_musig_pubnonce *pubnonce, const unsigned char *session_id32, const unsigned char *seckey, const unsigned char *msg32, const secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char *extra_input32) {
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_scalar k[2];
    secp256k1_ge nonce_pt[2];
    int i;
    unsigned char pk_ser[32];
    unsigned char *pk_ser_ptr = NULL;
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    memset(secnonce, 0, sizeof(*secnonce));
    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(session_id32 != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    if (seckey == NULL) {
        /* Check in constant time that the session_id is not 0 as a
         * defense-in-depth measure that may protect against a faulty RNG. */
        unsigned char acc = 0;
        for (i = 0; i < 32; i++) {
            acc |= session_id32[i];
        }
        ret &= !!acc;
        memset(&acc, 0, sizeof(acc));
    }

    /* Check that the seckey is valid to be able to sign for it later. */
    if (seckey != NULL) {
        secp256k1_scalar sk;
        ret &= secp256k1_scalar_set_b32_seckey(&sk, seckey);
        secp256k1_scalar_clear(&sk);
    }

    if (keyagg_cache != NULL) {
        int ret_tmp;
        if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
            return 0;
        }
        ret_tmp = secp256k1_xonly_ge_serialize(pk_ser, &cache_i.pk);
        /* Serialization can not fail because the loaded point can not be infinity. */
        VERIFY_CHECK(ret_tmp);
        pk_ser_ptr = pk_ser;
    }
    secp256k1_nonce_function_musig(k, session_id32, msg32, seckey, pk_ser_ptr, extra_input32);
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[0]));
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[1]));
    VERIFY_CHECK(!secp256k1_scalar_eq(&k[0], &k[1]));
    secp256k1_musig_secnonce_save(secnonce, k);
    secp256k1_musig_secnonce_invalidate(ctx, secnonce, !ret);

    for (i = 0; i < 2; i++) {
        secp256k1_gej nonce_ptj;
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &nonce_ptj, &k[i]);
        secp256k1_ge_set_gej(&nonce_pt[i], &nonce_ptj);
        secp256k1_declassify(ctx, &nonce_pt[i], sizeof(nonce_pt));
        secp256k1_scalar_clear(&k[i]);
    }
    /* nonce_pt won't be infinity because k != 0 with overwhelming probability */
    secp256k1_musig_pubnonce_save(pubnonce, nonce_pt);
    return ret;
}

static int secp256k1_musig_sum_nonces(const secp256k1_context* ctx, secp256k1_gej *summed_nonces, const secp256k1_musig_pubnonce * const* pubnonces, size_t n_pubnonces) {
    size_t i;
    int j;

    secp256k1_gej_set_infinity(&summed_nonces[0]);
    secp256k1_gej_set_infinity(&summed_nonces[1]);

    for (i = 0; i < n_pubnonces; i++) {
        secp256k1_ge nonce_pt[2];
        if (!secp256k1_musig_pubnonce_load(ctx, nonce_pt, pubnonces[i])) {
            return 0;
        }
        for (j = 0; j < 2; j++) {
            secp256k1_gej_add_ge_var(&summed_nonces[j], &summed_nonces[j], &nonce_pt[j], NULL);
        }
    }
    return 1;
}

int secp256k1_musig_nonce_agg(const secp256k1_context* ctx, secp256k1_musig_aggnonce  *aggnonce, const secp256k1_musig_pubnonce * const* pubnonces, size_t n_pubnonces) {
    secp256k1_gej aggnonce_ptj[2];
    secp256k1_ge aggnonce_pt[2];
    int i;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(n_pubnonces > 0);

    if (!secp256k1_musig_sum_nonces(ctx, aggnonce_ptj, pubnonces, n_pubnonces)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        if (secp256k1_gej_is_infinity(&aggnonce_ptj[i])) {
            /* Set to G according to the specification */
            aggnonce_pt[i] = secp256k1_ge_const_g;
        } else {
            secp256k1_ge_set_gej(&aggnonce_pt[i], &aggnonce_ptj[i]);
        }
    }
    secp256k1_musig_aggnonce_save(aggnonce, aggnonce_pt);
    return 1;
}

/* tagged_hash(aggnonce[0], aggnonce[1], agg_pk, msg) */
static int secp256k1_musig_compute_noncehash(unsigned char *noncehash, secp256k1_ge *aggnonce, const unsigned char *agg_pk32, const unsigned char *msg) {
    unsigned char buf[33];
    secp256k1_sha256 sha;
    int i;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char*)"MuSig/noncecoef", sizeof("MuSig/noncecoef") - 1);
    for (i = 0; i < 2; i++) {
        size_t size;
        if (!secp256k1_eckey_pubkey_serialize(&aggnonce[i], buf, &size, 1)) {
            return 0;
        }
        VERIFY_CHECK(size == sizeof(buf));
        secp256k1_sha256_write(&sha, buf, sizeof(buf));
    }
    secp256k1_sha256_write(&sha, agg_pk32, 32);
    secp256k1_sha256_write(&sha, msg, 32);
    secp256k1_sha256_finalize(&sha, noncehash);
    return 1;
}

static int secp256k1_musig_nonce_process_internal(int *fin_nonce_parity, unsigned char *fin_nonce, secp256k1_scalar *b, secp256k1_gej *aggnoncej, const unsigned char *agg_pk32, const unsigned char *msg) {
    unsigned char noncehash[32];
    secp256k1_ge fin_nonce_pt;
    secp256k1_gej fin_nonce_ptj;
    secp256k1_ge aggnonce[2];

    secp256k1_ge_set_gej(&aggnonce[0], &aggnoncej[0]);
    secp256k1_ge_set_gej(&aggnonce[1], &aggnoncej[1]);
    if (!secp256k1_musig_compute_noncehash(noncehash, aggnonce, agg_pk32, msg)) {
        return 0;
    }
    /* fin_nonce = aggnonce[0] + b*aggnonce[1] */
    secp256k1_scalar_set_b32(b, noncehash, NULL);
    secp256k1_ecmult(&fin_nonce_ptj, &aggnoncej[1], b, NULL);
    secp256k1_gej_add_ge(&fin_nonce_ptj, &fin_nonce_ptj, &aggnonce[0]);
    secp256k1_ge_set_gej(&fin_nonce_pt, &fin_nonce_ptj);
    if (!secp256k1_xonly_ge_serialize(fin_nonce, &fin_nonce_pt)) {
        /* unreachable with overwhelming probability */
        return 0;
    }
    secp256k1_fe_normalize_var(&fin_nonce_pt.y);
    *fin_nonce_parity = secp256k1_fe_is_odd(&fin_nonce_pt.y);
    return 1;
}

int secp256k1_musig_nonce_process(const secp256k1_context* ctx, secp256k1_musig_session *session, const secp256k1_musig_aggnonce  *aggnonce, const unsigned char *msg32, const secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_pubkey *adaptor) {
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_ge aggnonce_pt[2];
    secp256k1_gej aggnonce_ptj[2];
    unsigned char fin_nonce[32];
    secp256k1_musig_session_internal session_i;
    unsigned char agg_pk32[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(keyagg_cache != NULL);

    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    secp256k1_fe_get_b32(agg_pk32, &cache_i.pk.x);

    if (!secp256k1_musig_aggnonce_load(ctx, aggnonce_pt, aggnonce)) {
        return 0;
    }
    secp256k1_gej_set_ge(&aggnonce_ptj[0], &aggnonce_pt[0]);
    secp256k1_gej_set_ge(&aggnonce_ptj[1], &aggnonce_pt[1]);
    /* Add public adaptor to nonce */
    if (adaptor != NULL) {
        secp256k1_ge adaptorp;
        if (!secp256k1_pubkey_load(ctx, &adaptorp, adaptor)) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&aggnonce_ptj[0], &aggnonce_ptj[0], &adaptorp, NULL);
    }
    if (!secp256k1_musig_nonce_process_internal(&session_i.fin_nonce_parity, fin_nonce, &session_i.noncecoef, aggnonce_ptj, agg_pk32, msg32)) {
        return 0;
    }

    secp256k1_schnorrsig_challenge(&session_i.challenge, fin_nonce, msg32, 32, agg_pk32);

    /* If there is a tweak then set `challenge` times `tweak` to the `s`-part.*/
    secp256k1_scalar_set_int(&session_i.s_part, 0);
    if (!secp256k1_scalar_is_zero(&cache_i.tweak)) {
        secp256k1_scalar e_tmp;
        secp256k1_scalar_mul(&e_tmp, &session_i.challenge, &cache_i.tweak);
        if (secp256k1_fe_is_odd(&cache_i.pk.y)) {
            secp256k1_scalar_negate(&e_tmp, &e_tmp);
        }
        secp256k1_scalar_add(&session_i.s_part, &session_i.s_part, &e_tmp);
    }
    memcpy(session_i.fin_nonce, fin_nonce, sizeof(session_i.fin_nonce));
    secp256k1_musig_session_save(session, &session_i);
    return 1;
}

void secp256k1_musig_partial_sign_clear(secp256k1_scalar *sk, secp256k1_scalar *k) {
    secp256k1_scalar_clear(sk);
    secp256k1_scalar_clear(&k[0]);
    secp256k1_scalar_clear(&k[1]);
}

int secp256k1_musig_partial_sign(const secp256k1_context* ctx, secp256k1_musig_partial_sig *partial_sig, secp256k1_musig_secnonce *secnonce, const secp256k1_keypair *keypair, const secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_musig_session *session) {
    secp256k1_scalar sk;
    secp256k1_ge pk;
    secp256k1_scalar k[2];
    secp256k1_scalar mu, s;
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_musig_session_internal session_i;
    int ret;

    VERIFY_CHECK(ctx != NULL);

    ARG_CHECK(secnonce != NULL);
    /* Fails if the magic doesn't match */
    ret = secp256k1_musig_secnonce_load(ctx, k, secnonce);
    /* Set nonce to zero to avoid nonce reuse. This will cause subsequent calls
     * of this function to fail */
    memset(secnonce, 0, sizeof(*secnonce));
    if (!ret) {
        secp256k1_musig_partial_sign_clear(&sk, k);
        return 0;
    }

    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(session != NULL);

    if (!secp256k1_keypair_load(ctx, &sk, &pk, keypair)) {
        secp256k1_musig_partial_sign_clear(&sk, k);
        return 0;
    }
    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        secp256k1_musig_partial_sign_clear(&sk, k);
        return 0;
    }
    secp256k1_fe_normalize_var(&pk.y);

    /* The specification requires that the secret key is multiplied by
     * g[v]*g*gp. All factors are -1 or 1. The value g[v] is -1 iff
     * secp256k1_fe_is_odd(&cache_i.pk.y)), g is is -1 iff parity_acc is 1 and
     * gp is -1 if secp256k1_fe_is_odd(&pk.y). Therefore, multiplying by
     * g[v]*g*gp is equivalent to negating if
     *     secp256k1_fe_is_odd(&cache_i.pk.y))
     *       XOR cache_i.parity_acc
     *       XOR secp256k1_fe_is_odd(&pk.y).
     */
    if ((secp256k1_fe_is_odd(&cache_i.pk.y)
         != cache_i.parity_acc)
         != secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    /* Multiply KeyAgg coefficient */
    secp256k1_fe_normalize_var(&pk.x);
    /* TODO Cache mu */
    secp256k1_musig_keyaggcoef(&mu, &cache_i, &pk.x);
    secp256k1_scalar_mul(&sk, &sk, &mu);

    if (!secp256k1_musig_session_load(ctx, &session_i, session)) {
        secp256k1_musig_partial_sign_clear(&sk, k);
        return 0;
    }

    if (session_i.fin_nonce_parity) {
        secp256k1_scalar_negate(&k[0], &k[0]);
        secp256k1_scalar_negate(&k[1], &k[1]);
    }

    /* Sign */
    secp256k1_scalar_mul(&s, &session_i.challenge, &sk);
    secp256k1_scalar_mul(&k[1], &session_i.noncecoef, &k[1]);
    secp256k1_scalar_add(&k[0], &k[0], &k[1]);
    secp256k1_scalar_add(&s, &s, &k[0]);
    secp256k1_musig_partial_sig_save(partial_sig, &s);
    secp256k1_musig_partial_sign_clear(&sk, k);
    return 1;
}

int secp256k1_musig_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_musig_partial_sig *partial_sig, const secp256k1_musig_pubnonce *pubnonce, const secp256k1_xonly_pubkey *pubkey, const secp256k1_musig_keyagg_cache *keyagg_cache, const secp256k1_musig_session *session) {
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_musig_session_internal session_i;
    secp256k1_scalar mu, e, s;
    secp256k1_gej pkj;
    secp256k1_ge nonce_pt[2];
    secp256k1_gej rj;
    secp256k1_gej tmp;
    secp256k1_ge pkp;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubnonce != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(keyagg_cache != NULL);
    ARG_CHECK(session != NULL);

    if (!secp256k1_musig_session_load(ctx, &session_i, session)) {
        return 0;
    }

    /* Compute "effective" nonce rj = aggnonce[0] + b*aggnonce[1] */
    /* TODO: use multiexp to compute -s*G + e*mu*pubkey + aggnonce[0] + b*aggnonce[1] */
    if (!secp256k1_musig_pubnonce_load(ctx, nonce_pt, pubnonce)) {
        return 0;
    }
    secp256k1_gej_set_ge(&rj, &nonce_pt[1]);
    secp256k1_ecmult(&rj, &rj, &session_i.noncecoef, NULL);
    secp256k1_gej_add_ge_var(&rj, &rj, &nonce_pt[0], NULL);

    if (!secp256k1_xonly_pubkey_load(ctx, &pkp, pubkey)) {
        return 0;
    }
    if (!secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache)) {
        return 0;
    }
    /* Multiplying the challenge by the KeyAgg coefficient is equivalent
     * to multiplying the signer's public key by the coefficient, except
     * much easier to do. */
    secp256k1_musig_keyaggcoef(&mu, &cache_i, &pkp.x);
    secp256k1_scalar_mul(&e, &session_i.challenge, &mu);

    /* The specification requires that the public key is multiplied by g[v]*g.
     * All factors are -1 or 1. The value g[v] is -1 iff
     * secp256k1_fe_is_odd(&cache_i.pk.y)) and g is is -1 iff parity_acc is 1.
     * Therefore, multiplying by g[v]*g is equivalent to negating if
     * fe_is_odd(&cache_i.pk.y) XOR parity_acc. */
    if (secp256k1_fe_is_odd(&cache_i.pk.y)
            != cache_i.parity_acc) {
        secp256k1_scalar_negate(&e, &e);
    }

    if (!secp256k1_musig_partial_sig_load(ctx, &s, partial_sig)) {
        return 0;
    }
    /* Compute -s*G + e*pkj + rj (e already includes the keyagg coefficient mu) */
    secp256k1_scalar_negate(&s, &s);
    secp256k1_gej_set_ge(&pkj, &pkp);
    secp256k1_ecmult(&tmp, &pkj, &e, &s);
    if (session_i.fin_nonce_parity) {
        secp256k1_gej_neg(&rj, &rj);
    }
    secp256k1_gej_add_var(&tmp, &tmp, &rj, NULL);

    return secp256k1_gej_is_infinity(&tmp);
}

int secp256k1_musig_partial_sig_agg(const secp256k1_context* ctx, unsigned char *sig64, const secp256k1_musig_session *session, const secp256k1_musig_partial_sig * const* partial_sigs, size_t n_sigs) {
    size_t i;
    secp256k1_musig_session_internal session_i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(partial_sigs != NULL);
    ARG_CHECK(n_sigs > 0);

    if (!secp256k1_musig_session_load(ctx, &session_i, session)) {
        return 0;
    }
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar term;
        if (!secp256k1_musig_partial_sig_load(ctx, &term, partial_sigs[i])) {
            return 0;
        }
        secp256k1_scalar_add(&session_i.s_part, &session_i.s_part, &term);
    }
    secp256k1_scalar_get_b32(&sig64[32], &session_i.s_part);
    memcpy(&sig64[0], session_i.fin_nonce, 32);
    return 1;
}

#endif
