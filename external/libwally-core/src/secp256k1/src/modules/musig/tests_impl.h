/***********************************************************************
 * Copyright (c) 2018 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_TESTS_IMPL_H
#define SECP256K1_MODULE_MUSIG_TESTS_IMPL_H

#include <stdlib.h>
#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_musig.h"

#include "session.h"
#include "keyagg.h"
#include "../../scalar.h"
#include "../../scratch.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static int create_keypair_and_pk(secp256k1_keypair *keypair, secp256k1_xonly_pubkey *pk, const unsigned char *sk) {
    int ret;
    secp256k1_keypair keypair_tmp;
    ret = secp256k1_keypair_create(ctx, &keypair_tmp, sk);
    ret &= secp256k1_keypair_xonly_pub(ctx, pk, NULL, &keypair_tmp);
    if (keypair != NULL) {
        *keypair = keypair_tmp;
    }
    return ret;
}

/* Just a simple (non-adaptor, non-tweaked) 2-of-2 MuSig aggregate, sign, verify
 * test. */
void musig_simple_test(secp256k1_scratch_space *scratch) {
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    secp256k1_musig_pubnonce pubnonce[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr[2];
    secp256k1_musig_aggnonce aggnonce;
    unsigned char msg[32];
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_musig_keyagg_cache keyagg_cache;
    unsigned char session_id[2][32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    secp256k1_musig_partial_sig partial_sig[2];
    const secp256k1_musig_partial_sig *partial_sig_ptr[2];
    unsigned char final_sig[64];
    secp256k1_musig_session session;
    int i;

    secp256k1_testrand256(msg);
    for (i = 0; i < 2; i++) {
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
        CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce[i], &pubnonce[i], session_id[i], sk[i], NULL, NULL, NULL) == 1);
    }

    CHECK(secp256k1_musig_pubkey_agg(ctx, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg, &keyagg_cache, NULL) == 1);

    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[i], &secnonce[i], &keypair[i], &keyagg_cache, &session) == 1);
        CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[i], &pubnonce[i], &pk[i], &keyagg_cache, &session) == 1);
    }

    CHECK(secp256k1_musig_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), &agg_pk) == 1);
}

void pubnonce_summing_to_inf(secp256k1_musig_pubnonce *pubnonce) {
    secp256k1_ge ge[2];
    int i;
    secp256k1_gej summed_nonces[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr[2];

    ge[0] = secp256k1_ge_const_g;
    ge[1] = secp256k1_ge_const_g;

    for (i = 0; i < 2; i++) {
        secp256k1_musig_pubnonce_save(&pubnonce[i], ge);
        pubnonce_ptr[i] = &pubnonce[i];
        secp256k1_ge_neg(&ge[0], &ge[0]);
        secp256k1_ge_neg(&ge[1], &ge[1]);
    }

    secp256k1_musig_sum_nonces(ctx, summed_nonces, pubnonce_ptr, 2);
    CHECK(secp256k1_gej_is_infinity(&summed_nonces[0]));
    CHECK(secp256k1_gej_is_infinity(&summed_nonces[1]));
}

int memcmp_and_randomize(unsigned char *value, const unsigned char *expected, size_t len) {
    int ret;
    size_t i;
    ret = secp256k1_memcmp_var(value, expected, len);
    for (i = 0; i < len; i++) {
        value[i] = secp256k1_testrand_bits(8);
    }
    return ret;
}

void musig_api_tests(secp256k1_scratch_space *scratch) {
    secp256k1_scratch_space *scratch_small;
    secp256k1_musig_partial_sig partial_sig[2];
    const secp256k1_musig_partial_sig *partial_sig_ptr[2];
    secp256k1_musig_partial_sig invalid_partial_sig;
    const secp256k1_musig_partial_sig *invalid_partial_sig_ptr[2];
    unsigned char final_sig[64];
    unsigned char pre_sig[64];
    unsigned char buf[32];
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    secp256k1_keypair invalid_keypair;
    unsigned char max64[64];
    unsigned char zeros68[68] = { 0 };
    unsigned char session_id[2][32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_musig_secnonce secnonce_tmp;
    secp256k1_musig_secnonce invalid_secnonce;
    secp256k1_musig_pubnonce pubnonce[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr[2];
    unsigned char pubnonce_ser[66];
    secp256k1_musig_pubnonce inf_pubnonce[2];
    const secp256k1_musig_pubnonce *inf_pubnonce_ptr[2];
    secp256k1_musig_pubnonce invalid_pubnonce;
    const secp256k1_musig_pubnonce *invalid_pubnonce_ptr[1];
    secp256k1_musig_aggnonce aggnonce;
    unsigned char aggnonce_ser[66];
    unsigned char msg[32];
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_pubkey full_agg_pk;
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_keyagg_cache invalid_keyagg_cache;
    secp256k1_musig_session session;
    secp256k1_musig_session invalid_session;
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    secp256k1_xonly_pubkey invalid_pk;
    const secp256k1_xonly_pubkey *invalid_pk_ptr2[2];
    const secp256k1_xonly_pubkey *invalid_pk_ptr3[3];
    unsigned char tweak[32];
    int nonce_parity;
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor1[32];
    secp256k1_pubkey adaptor;
    int i;

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sttc, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);

    memset(max64, 0xff, sizeof(max64));
    memset(&invalid_keypair, 0, sizeof(invalid_keypair));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_secnonce, 0, sizeof(invalid_secnonce));
    memset(&invalid_partial_sig, 0, sizeof(invalid_partial_sig));
    pubnonce_summing_to_inf(inf_pubnonce);
    /* Simulate structs being uninitialized by setting it to 0s. We don't want
     * to produce undefined behavior by actually providing uninitialized
     * structs. */
    memset(&invalid_keyagg_cache, 0, sizeof(invalid_keyagg_cache));
    memset(&invalid_pk, 0, sizeof(invalid_pk));
    memset(&invalid_pubnonce, 0, sizeof(invalid_pubnonce));
    memset(&invalid_session, 0, sizeof(invalid_session));

    secp256k1_testrand256(sec_adaptor);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(tweak);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor) == 1);
    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        invalid_pk_ptr2[i] = &invalid_pk;
        invalid_pk_ptr3[i] = &pk[i];
        pubnonce_ptr[i] = &pubnonce[i];
        inf_pubnonce_ptr[i] = &inf_pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        invalid_partial_sig_ptr[i] = &partial_sig[i];
        secp256k1_testrand256(session_id[i]);
        secp256k1_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(&keypair[i], &pk[i], sk[i]));
    }
    invalid_pubnonce_ptr[0] = &invalid_pubnonce;
    invalid_partial_sig_ptr[0] = &invalid_partial_sig;
    /* invalid_pk_ptr3 has two valid, one invalid pk, which is important to test
     * musig_pubkey_agg */
    invalid_pk_ptr3[2] = &invalid_pk;

    /** main test body **/

    /** Key aggregation **/
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_agg(none, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(sign, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    /* pubkey_agg does not require a scratch space */
    CHECK(secp256k1_musig_pubkey_agg(vrfy, NULL, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    /* A small scratch space works too, but will result in using an ineffecient algorithm */
    scratch_small = secp256k1_scratch_space_create(ctx, 1);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch_small, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    secp256k1_scratch_space_destroy(ctx, scratch_small);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, NULL, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, NULL, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, NULL, 2) == 0);
    CHECK(ecount == 1);
    CHECK(memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, invalid_pk_ptr2, 2) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, invalid_pk_ptr3, 3) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 0) == 0);
    CHECK(ecount == 4);
    CHECK(memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, NULL, 0) == 0);
    CHECK(ecount == 5);
    CHECK(memcmp_and_randomize(agg_pk.data, zeros68, sizeof(agg_pk.data)) == 0);

    CHECK(secp256k1_musig_pubkey_agg(none, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(sign, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(vrfy, scratch, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);

    /* pubkey_get */
    ecount = 0;
    CHECK(secp256k1_musig_pubkey_get(none, &full_agg_pk, &keyagg_cache) == 1);
    CHECK(secp256k1_musig_pubkey_get(none, NULL, &keyagg_cache) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubkey_get(none, &full_agg_pk, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_memcmp_var(&full_agg_pk, zeros68, sizeof(full_agg_pk)) == 0);

    /** Tweaking **/
    {
        int (*tweak_func[2]) (const secp256k1_context* ctx, secp256k1_pubkey *output_pubkey, secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char *tweak32);
        tweak_func[0] = secp256k1_musig_pubkey_ec_tweak_add;
        tweak_func[1] = secp256k1_musig_pubkey_xonly_tweak_add;
        for (i = 0; i < 2; i++) {
            secp256k1_pubkey tmp_output_pk;
            secp256k1_musig_keyagg_cache tmp_keyagg_cache = keyagg_cache;
            ecount = 0;
            CHECK((*tweak_func[i])(ctx, &tmp_output_pk, &tmp_keyagg_cache, tweak) == 1);
            /* Reset keyagg_cache */
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(none, &tmp_output_pk, &tmp_keyagg_cache, tweak) == 1);
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(sign, &tmp_output_pk, &tmp_keyagg_cache, tweak) == 1);
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_keyagg_cache, tweak) == 1);
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(vrfy, NULL, &tmp_keyagg_cache, tweak) == 1);
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, NULL, tweak) == 0);
            CHECK(ecount == 1);
            CHECK(memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_keyagg_cache, NULL) == 0);
            CHECK(ecount == 2);
            CHECK(memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_keyagg_cache = keyagg_cache;
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &tmp_keyagg_cache, max64) == 0);
            CHECK(ecount == 2);
            CHECK(memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
            tmp_keyagg_cache = keyagg_cache;
            /* Uninitialized keyagg_cache */
            CHECK((*tweak_func[i])(vrfy, &tmp_output_pk, &invalid_keyagg_cache, tweak) == 0);
            CHECK(ecount == 3);
            CHECK(memcmp_and_randomize(tmp_output_pk.data, zeros68, sizeof(tmp_output_pk.data)) == 0);
        }
    }

    /** Session creation **/
    ecount = 0;
    CHECK(secp256k1_musig_nonce_gen(none, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 1);
    CHECK(secp256k1_musig_nonce_gen(vrfy, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 1);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_musig_nonce_gen(sttc, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_nonce_gen(sign, NULL, &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], NULL, session_id[0], sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], NULL, sk[0], msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 4);
    CHECK(memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* no seckey and session_id is 0 */
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], zeros68, NULL, msg, &keyagg_cache, max64) == 0);
    CHECK(ecount == 4);
    CHECK(memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    /* session_id 0 is fine when a seckey is provided */
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], zeros68, sk[0], msg, &keyagg_cache, max64) == 1);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, msg, &keyagg_cache, max64) == 1);
    CHECK(ecount == 4);
    /* invalid seckey */
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], max64, msg, &keyagg_cache, max64) == 0);
    CHECK(memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], NULL, &keyagg_cache, max64) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, NULL, max64) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &invalid_keyagg_cache, max64) == 0);
    CHECK(ecount == 5);
    CHECK(memcmp_and_randomize(secnonce[0].data, zeros68, sizeof(secnonce[0].data)) == 0);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], sk[0], msg, &keyagg_cache, NULL) == 1);
    CHECK(ecount == 5);

    /* Every in-argument except session_id can be NULL */
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[0], &pubnonce[0], session_id[0], NULL, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(sign, &secnonce[1], &pubnonce[1], session_id[1], sk[1], NULL, NULL, NULL) == 1);

    /** Serialize and parse public nonces **/
    ecount = 0;
    CHECK(secp256k1_musig_pubnonce_serialize(none, NULL, &pubnonce[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubnonce_serialize(none, pubnonce_ser, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK(secp256k1_musig_pubnonce_serialize(none, pubnonce_ser, &invalid_pubnonce) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp_and_randomize(pubnonce_ser, zeros68, sizeof(pubnonce_ser)) == 0);
    CHECK(secp256k1_musig_pubnonce_serialize(none, pubnonce_ser, &pubnonce[0]) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_pubnonce_parse(none, &pubnonce[0], pubnonce_ser) == 1);
    CHECK(secp256k1_musig_pubnonce_parse(none, NULL, pubnonce_ser) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_pubnonce_parse(none, &pubnonce[0], NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubnonce_parse(none, &pubnonce[0], zeros68) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_pubnonce_parse(none, &pubnonce[0], pubnonce_ser) == 1);

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_musig_pubnonce tmp;
        CHECK(secp256k1_musig_pubnonce_serialize(none, pubnonce_ser, &pubnonce[0]) == 1);
        CHECK(secp256k1_musig_pubnonce_parse(none, &tmp, pubnonce_ser) == 1);
        CHECK(memcmp(&tmp, &pubnonce[0], sizeof(tmp)) == 0);
    }

    /** Receive nonces and aggregate **/
    ecount = 0;
    CHECK(secp256k1_musig_nonce_agg(none, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_musig_nonce_agg(none, NULL, pubnonce_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_nonce_agg(none, &aggnonce, NULL, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_nonce_agg(none, &aggnonce, pubnonce_ptr, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_nonce_agg(none, &aggnonce, invalid_pubnonce_ptr, 1) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_nonce_agg(none, &aggnonce, inf_pubnonce_ptr, 2) == 1);
    {
        /* Check that the aggnonce is set to G */
        secp256k1_ge aggnonce_pt[2];
        secp256k1_musig_pubnonce_load(ctx, aggnonce_pt, (secp256k1_musig_pubnonce*)&aggnonce);
        for (i = 0; i < 2; i++) {
            ge_equals_ge(&aggnonce_pt[i], &secp256k1_ge_const_g);
        }
    }
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_nonce_agg(none, &aggnonce, pubnonce_ptr, 2) == 1);

    /** Serialize and parse aggregate nonces **/
    ecount = 0;
    CHECK(secp256k1_musig_aggnonce_serialize(none, aggnonce_ser, &aggnonce) == 1);
    CHECK(secp256k1_musig_aggnonce_serialize(none, NULL, &aggnonce) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_aggnonce_serialize(none, aggnonce_ser, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(memcmp_and_randomize(aggnonce_ser, zeros68, sizeof(aggnonce_ser)) == 0);
    CHECK(secp256k1_musig_aggnonce_serialize(none, aggnonce_ser, (secp256k1_musig_aggnonce*) &invalid_pubnonce) == 0);
    CHECK(ecount == 3);
    CHECK(memcmp_and_randomize(aggnonce_ser, zeros68, sizeof(aggnonce_ser)) == 0);
    CHECK(secp256k1_musig_aggnonce_serialize(none, aggnonce_ser, &aggnonce) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_aggnonce_parse(none, &aggnonce, aggnonce_ser) == 1);
    CHECK(secp256k1_musig_aggnonce_parse(none, NULL, aggnonce_ser) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_aggnonce_parse(none, &aggnonce, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_aggnonce_parse(none, &aggnonce, zeros68) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_aggnonce_parse(none, &aggnonce, aggnonce_ser) == 1);

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_musig_aggnonce tmp;
        CHECK(secp256k1_musig_aggnonce_serialize(none, aggnonce_ser, &aggnonce) == 1);
        CHECK(secp256k1_musig_aggnonce_parse(none, &tmp, aggnonce_ser) == 1);
        CHECK(memcmp(&tmp, &aggnonce, sizeof(tmp)) == 0);
    }

    /** Process nonces **/
    ecount = 0;
    CHECK(secp256k1_musig_nonce_process(none, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 1);
    CHECK(secp256k1_musig_nonce_process(sign, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 1);
    CHECK(secp256k1_musig_nonce_process(vrfy, NULL, &aggnonce, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, NULL, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, (secp256k1_musig_aggnonce*) &invalid_pubnonce, msg, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, &aggnonce, NULL, &keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, &aggnonce, msg, NULL, &adaptor) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, &aggnonce, msg, &invalid_keyagg_cache, &adaptor) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, &aggnonce, msg, &keyagg_cache, NULL) == 1);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_nonce_process(vrfy, &session, &aggnonce, msg, &keyagg_cache, (secp256k1_pubkey *)&invalid_pk) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_musig_nonce_process(vrfy, &session, &aggnonce, msg, &keyagg_cache, &adaptor) == 1);

    ecount = 0;
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, &session) == 1);
    /* The secnonce is set to 0 and subsequent signing attempts fail */
    CHECK(memcmp(&secnonce_tmp, zeros68, sizeof(secnonce_tmp)) == 0);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 1);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, NULL, &secnonce_tmp, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 2);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], NULL, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &invalid_secnonce, &keypair[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, NULL, &keyagg_cache, &session) == 0);
    CHECK(ecount == 5);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &invalid_keypair, &keyagg_cache, &session) == 0);
    CHECK(ecount == 6);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], NULL, &session) == 0);
    CHECK(ecount == 7);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &invalid_keyagg_cache, &session) == 0);
    CHECK(ecount == 8);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, NULL) == 0);
    CHECK(ecount == 9);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce_tmp, &keypair[0], &keyagg_cache, &invalid_session) == 0);
    CHECK(ecount == 10);
    memcpy(&secnonce_tmp, &secnonce[0], sizeof(secnonce_tmp));

    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[0], &secnonce[0], &keypair[0], &keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sign(none, &partial_sig[1], &secnonce[1], &keypair[1], &keyagg_cache, &session) == 1);

    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_serialize(none, buf, &partial_sig[0]) == 1);
    CHECK(secp256k1_musig_partial_sig_serialize(none, NULL, &partial_sig[0]) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_serialize(none, buf, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_parse(none, &partial_sig[0], buf) == 1);
    CHECK(secp256k1_musig_partial_sig_parse(none, NULL, buf) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_parse(none, &partial_sig[0], max64) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_parse(none, &partial_sig[0], NULL) == 0);
    CHECK(ecount == 4);

    {
        /* Check that serialize and parse results in the same value */
        secp256k1_musig_partial_sig tmp;
        CHECK(secp256k1_musig_partial_sig_serialize(none, buf, &partial_sig[0]) == 1);
        CHECK(secp256k1_musig_partial_sig_parse(none, &tmp, buf) == 1);
        CHECK(memcmp(&tmp, &partial_sig[0], sizeof(tmp)) == 0);
    }

    /** Partial signature verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_verify(none, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(sign, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, NULL, &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &invalid_partial_sig, &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], NULL, &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &invalid_pubnonce, &pk[0], &keyagg_cache, &session) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], NULL, &keyagg_cache, &session) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &invalid_pk, &keyagg_cache, &session) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], NULL, &session) == 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &invalid_keyagg_cache, &session) == 0);
    CHECK(ecount == 8);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, NULL) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &invalid_session) == 0);
    CHECK(ecount == 10);

    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[0], &pubnonce[0], &pk[0], &keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(vrfy, &partial_sig[1], &pubnonce[1], &pk[1], &keyagg_cache, &session) == 1);

    /** Signature aggregation and verification */
    ecount = 0;
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_musig_partial_sig_agg(none, NULL, &session, partial_sig_ptr, 2) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, NULL, partial_sig_ptr, 2) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &invalid_session, partial_sig_ptr, 2) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &session, NULL, 2) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &session, invalid_partial_sig_ptr, 2) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 0) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 1) == 1);
    CHECK(secp256k1_musig_partial_sig_agg(none, pre_sig, &session, partial_sig_ptr, 2) == 1);

    /** Adaptor signature verification */
    ecount = 0;
    CHECK(secp256k1_musig_nonce_parity(none, &nonce_parity, &session) == 1);
    CHECK(secp256k1_musig_nonce_parity(none, NULL, &session) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_nonce_parity(none, &nonce_parity, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_nonce_parity(none, &nonce_parity, &invalid_session) == 0);
    CHECK(ecount == 3);

    ecount = 0;
    CHECK(secp256k1_musig_adapt(none, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_musig_adapt(none, NULL, pre_sig, sec_adaptor, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_adapt(none, final_sig, NULL, sec_adaptor, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_adapt(none, final_sig, max64, sec_adaptor, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_adapt(none, final_sig, pre_sig, NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_adapt(none, final_sig, pre_sig, max64, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_adapt(none, final_sig, pre_sig, sec_adaptor, 2) == 0);
    CHECK(ecount == 4);
    /* sig and pre_sig argument point to the same location */
    memcpy(final_sig, pre_sig, sizeof(final_sig));
    CHECK(secp256k1_musig_adapt(none, final_sig, final_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    CHECK(secp256k1_musig_adapt(none, final_sig, pre_sig, sec_adaptor, nonce_parity) == 1);
    CHECK(secp256k1_schnorrsig_verify(vrfy, final_sig, msg, sizeof(msg), &agg_pk) == 1);

    /** Secret adaptor can be extracted from signature */
    ecount = 0;
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, nonce_parity) == 1);
    CHECK(memcmp(sec_adaptor, sec_adaptor1, 32) == 0);
    /* wrong nonce parity */
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, !nonce_parity) == 1);
    CHECK(memcmp(sec_adaptor, sec_adaptor1, 32) != 0);
    CHECK(secp256k1_musig_extract_adaptor(none, NULL, final_sig, pre_sig, 0) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, NULL, pre_sig, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, max64, pre_sig, 0) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, final_sig, NULL, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, final_sig, max64, 0) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_musig_extract_adaptor(none, sec_adaptor1, final_sig, pre_sig, 2) == 0);
    CHECK(ecount == 4);

    /** cleanup **/
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(sttc);
}

void musig_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    secp256k1_scalar k1[2], k2[2];

    secp256k1_nonce_function_musig(k1, args[0], args[1], args[2], args[3], args[4]);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    secp256k1_nonce_function_musig(k2, args[0], args[1], args[2], args[3], args[4]);
    CHECK(secp256k1_scalar_eq(&k1[0], &k2[0]) == 0);
    CHECK(secp256k1_scalar_eq(&k1[1], &k2[1]) == 0);
}

void musig_nonce_test(void) {
    unsigned char *args[5];
    unsigned char session_id[32];
    unsigned char sk[32];
    unsigned char msg[32];
    unsigned char agg_pk[32];
    unsigned char extra_input[32];
    int i, j;
    secp256k1_scalar k[5][2];

    secp256k1_testrand_bytes_test(session_id, sizeof(session_id));
    secp256k1_testrand_bytes_test(sk, sizeof(sk));
    secp256k1_testrand_bytes_test(msg, sizeof(msg));
    secp256k1_testrand_bytes_test(agg_pk, sizeof(agg_pk));
    secp256k1_testrand_bytes_test(extra_input, sizeof(extra_input));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = session_id;
    args[1] = msg;
    args[2] = sk;
    args[3] = agg_pk;
    args[4] = extra_input;
    for (i = 0; i < count; i++) {
        musig_nonce_bitflip(args, 0, sizeof(session_id));
        musig_nonce_bitflip(args, 1, sizeof(msg));
        musig_nonce_bitflip(args, 2, sizeof(sk));
        musig_nonce_bitflip(args, 3, sizeof(agg_pk));
        musig_nonce_bitflip(args, 4, sizeof(extra_input));
    }
    /* Check that if any argument is NULL, a different nonce is produced than if
     * any other argument is NULL. */
    memcpy(msg, session_id, sizeof(msg));
    memcpy(sk, session_id, sizeof(sk));
    memcpy(agg_pk, session_id, sizeof(agg_pk));
    memcpy(extra_input, session_id, sizeof(extra_input));
    secp256k1_nonce_function_musig(k[0], args[0], args[1], args[2], args[3], args[4]);
    secp256k1_nonce_function_musig(k[1], args[0], NULL, args[2], args[3], args[4]);
    secp256k1_nonce_function_musig(k[2], args[0], args[1], NULL, args[3], args[4]);
    secp256k1_nonce_function_musig(k[3], args[0], args[1], args[2], NULL, args[4]);
    secp256k1_nonce_function_musig(k[4], args[0], args[1], args[2], args[3], NULL);
    for (i = 0; i < 4; i++) {
        for (j = i+1; j < 5; j++) {
            CHECK(secp256k1_scalar_eq(&k[i][0], &k[j][0]) == 0);
            CHECK(secp256k1_scalar_eq(&k[i][1], &k[j][1]) == 0);
        }
    }
}

void scriptless_atomic_swap(secp256k1_scratch_space *scratch) {
    /* Throughout this test "a" and "b" refer to two hypothetical blockchains,
     * while the indices 0 and 1 refer to the two signers. Here signer 0 is
     * sending a-coins to signer 1, while signer 1 is sending b-coins to signer
     * 0. Signer 0 produces the adaptor signatures. */
    unsigned char pre_sig_a[64];
    unsigned char final_sig_a[64];
    unsigned char pre_sig_b[64];
    unsigned char final_sig_b[64];
    secp256k1_musig_partial_sig partial_sig_a[2];
    const secp256k1_musig_partial_sig *partial_sig_a_ptr[2];
    secp256k1_musig_partial_sig partial_sig_b[2];
    const secp256k1_musig_partial_sig *partial_sig_b_ptr[2];
    unsigned char sec_adaptor[32];
    unsigned char sec_adaptor_extracted[32];
    secp256k1_pubkey pub_adaptor;
    unsigned char sk_a[2][32];
    unsigned char sk_b[2][32];
    secp256k1_keypair keypair_a[2];
    secp256k1_keypair keypair_b[2];
    secp256k1_xonly_pubkey pk_a[2];
    const secp256k1_xonly_pubkey *pk_a_ptr[2];
    secp256k1_xonly_pubkey pk_b[2];
    const secp256k1_xonly_pubkey *pk_b_ptr[2];
    secp256k1_musig_keyagg_cache keyagg_cache_a;
    secp256k1_musig_keyagg_cache keyagg_cache_b;
    secp256k1_xonly_pubkey agg_pk_a;
    secp256k1_xonly_pubkey agg_pk_b;
    secp256k1_musig_secnonce secnonce_a[2];
    secp256k1_musig_secnonce secnonce_b[2];
    secp256k1_musig_pubnonce pubnonce_a[2];
    secp256k1_musig_pubnonce pubnonce_b[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr_a[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr_b[2];
    secp256k1_musig_aggnonce aggnonce_a;
    secp256k1_musig_aggnonce aggnonce_b;
    secp256k1_musig_session session_a, session_b;
    int nonce_parity_a;
    int nonce_parity_b;
    unsigned char seed_a[2][32] = { "a0", "a1" };
    unsigned char seed_b[2][32] = { "b0", "b1" };
    const unsigned char msg32_a[32] = "this is the message blockchain a";
    const unsigned char msg32_b[32] = "this is the message blockchain b";
    int i;

    /* Step 1: key setup */
    for (i = 0; i < 2; i++) {
        pk_a_ptr[i] = &pk_a[i];
        pk_b_ptr[i] = &pk_b[i];
        pubnonce_ptr_a[i] = &pubnonce_a[i];
        pubnonce_ptr_b[i] = &pubnonce_b[i];
        partial_sig_a_ptr[i] = &partial_sig_a[i];
        partial_sig_b_ptr[i] = &partial_sig_b[i];

        secp256k1_testrand256(sk_a[i]);
        secp256k1_testrand256(sk_b[i]);
        CHECK(create_keypair_and_pk(&keypair_a[i], &pk_a[i], sk_a[i]) == 1);
        CHECK(create_keypair_and_pk(&keypair_b[i], &pk_b[i], sk_b[i]) == 1);
    }
    secp256k1_testrand256(sec_adaptor);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pub_adaptor, sec_adaptor) == 1);

    CHECK(secp256k1_musig_pubkey_agg(ctx, scratch, &agg_pk_a, &keyagg_cache_a, pk_a_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(ctx, scratch, &agg_pk_b, &keyagg_cache_b, pk_b_ptr, 2) == 1);

    CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce_a[0], &pubnonce_a[0], seed_a[0], sk_a[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce_a[1], &pubnonce_a[1], seed_a[1], sk_a[1], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce_b[0], &pubnonce_b[0], seed_b[0], sk_b[0], NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce_b[1], &pubnonce_b[1], seed_b[1], sk_b[1], NULL, NULL, NULL) == 1);

    /* Step 2: Exchange nonces */
    CHECK(secp256k1_musig_nonce_agg(ctx, &aggnonce_a, pubnonce_ptr_a, 2) == 1);
    CHECK(secp256k1_musig_nonce_process(ctx, &session_a, &aggnonce_a, msg32_a, &keyagg_cache_a, &pub_adaptor) == 1);
    CHECK(secp256k1_musig_nonce_parity(ctx, &nonce_parity_a, &session_a) == 1);
    CHECK(secp256k1_musig_nonce_agg(ctx, &aggnonce_b, pubnonce_ptr_b, 2) == 1);
    CHECK(secp256k1_musig_nonce_process(ctx, &session_b, &aggnonce_b, msg32_b, &keyagg_cache_b, &pub_adaptor) == 1);
    CHECK(secp256k1_musig_nonce_parity(ctx, &nonce_parity_b, &session_b) == 1);

    /* Step 3: Signer 0 produces partial signatures for both chains. */
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_a[0], &secnonce_a[0], &keypair_a[0], &keyagg_cache_a, &session_a) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_b[0], &secnonce_b[0], &keypair_b[0], &keyagg_cache_b, &session_b) == 1);

    /* Step 4: Signer 1 receives partial signatures, verifies them and creates a
     * partial signature to send B-coins to signer 0. */
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig_a[0], &pubnonce_a[0], &pk_a[0], &keyagg_cache_a, &session_a) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig_b[0], &pubnonce_b[0], &pk_b[0], &keyagg_cache_b, &session_b) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_b[1], &secnonce_b[1], &keypair_b[1], &keyagg_cache_b, &session_b) == 1);

    /* Step 5: Signer 0 aggregates its own partial signature with the partial
     * signature from signer 1 and adapts it. This results in a complete
     * signature which is broadcasted by signer 0 to take B-coins. */
    CHECK(secp256k1_musig_partial_sig_agg(ctx, pre_sig_b, &session_b, partial_sig_b_ptr, 2) == 1);
    CHECK(secp256k1_musig_adapt(ctx, final_sig_b, pre_sig_b, sec_adaptor, nonce_parity_b) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig_b, msg32_b, sizeof(msg32_b), &agg_pk_b) == 1);

    /* Step 6: Signer 1 signs, extracts adaptor from the published signature,
     * and adapts the signature to take A-coins. */
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig_a[1], &secnonce_a[1], &keypair_a[1], &keyagg_cache_a, &session_a) == 1);
    CHECK(secp256k1_musig_partial_sig_agg(ctx, pre_sig_a, &session_a, partial_sig_a_ptr, 2) == 1);
    CHECK(secp256k1_musig_extract_adaptor(ctx, sec_adaptor_extracted, final_sig_b, pre_sig_b, nonce_parity_b) == 1);
    CHECK(memcmp(sec_adaptor_extracted, sec_adaptor, sizeof(sec_adaptor)) == 0); /* in real life we couldn't check this, of course */
    CHECK(secp256k1_musig_adapt(ctx, final_sig_a, pre_sig_a, sec_adaptor_extracted, nonce_parity_a) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig_a, msg32_a, sizeof(msg32_a), &agg_pk_a) == 1);
}

void sha256_tag_test_internal(secp256k1_sha256 *sha_tagged, unsigned char *tag, size_t taglen) {
    secp256k1_sha256 sha;
    unsigned char buf[32];
    unsigned char buf2[32];
    size_t i;

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, tag, taglen);
    secp256k1_sha256_finalize(&sha, buf);
    /* buf = SHA256(tag) */

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(&sha, buf, 32);
    /* Is buffer fully consumed? */
    CHECK((sha.bytes & 0x3F) == 0);

    /* Compare with tagged SHA */
    for (i = 0; i < 8; i++) {
        CHECK(sha_tagged->s[i] == sha.s[i]);
    }
    secp256k1_sha256_write(&sha, buf, 32);
    secp256k1_sha256_write(sha_tagged, buf, 32);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_sha256_finalize(sha_tagged, buf2);
    CHECK(memcmp(buf, buf2, 32) == 0);
}

/* Checks that the initialized tagged hashes initialized have the expected
 * state. */
void sha256_tag_test(void) {
    secp256k1_sha256 sha_tagged;
    {
        char tag[11] = "KeyAgg list";
        secp256k1_musig_keyagglist_sha256(&sha_tagged);
        sha256_tag_test_internal(&sha_tagged, (unsigned char*)tag, sizeof(tag));
    }
    {
        char tag[18] = "KeyAgg coefficient";
        secp256k1_musig_keyaggcoef_sha256(&sha_tagged);
        sha256_tag_test_internal(&sha_tagged, (unsigned char*)tag, sizeof(tag));
    }
}

/* Attempts to create a signature for the aggregate public key using given secret
 * keys and keyagg_cache. */
void musig_tweak_test_helper(const secp256k1_xonly_pubkey* agg_pk, const unsigned char *sk0, const unsigned char *sk1, secp256k1_musig_keyagg_cache *keyagg_cache) {
    secp256k1_xonly_pubkey pk[2];
    unsigned char session_id[2][32];
    unsigned char msg[32];
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_musig_pubnonce pubnonce[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr[2];
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_keypair keypair[2];
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig partial_sig[2];
    const secp256k1_musig_partial_sig *partial_sig_ptr[2];
    unsigned char final_sig[64];
    int i;

    for (i = 0; i < 2; i++) {
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        secp256k1_testrand256(session_id[i]);
    }
    CHECK(create_keypair_and_pk(&keypair[0], &pk[0], sk0) == 1);
    CHECK(create_keypair_and_pk(&keypair[1], &pk[1], sk1) == 1);
    secp256k1_testrand256(msg);

    CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce[0], &pubnonce[0], session_id[0], sk0, NULL, NULL, NULL) == 1);
    CHECK(secp256k1_musig_nonce_gen(ctx, &secnonce[1], &pubnonce[1], session_id[1], sk1, NULL, NULL, NULL) == 1);

    CHECK(secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg, keyagg_cache, NULL) == 1);

    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[0], &secnonce[0], &keypair[0], keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig[1], &secnonce[1], &keypair[1], keyagg_cache, &session) == 1);

    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[0], &pubnonce[0], &pk[0], keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sig[1], &pubnonce[1], &pk[1], keyagg_cache, &session) == 1);

    CHECK(secp256k1_musig_partial_sig_agg(ctx, final_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(ctx, final_sig, msg, sizeof(msg), agg_pk) == 1);
}

/* Create aggregate public key P[0], tweak multiple times (using xonly and
 * ordinary tweaking) and test signing. */
void musig_tweak_test(secp256k1_scratch_space *scratch) {
    unsigned char sk[2][32];
    secp256k1_xonly_pubkey pk[2];
    const secp256k1_xonly_pubkey *pk_ptr[2];
    secp256k1_musig_keyagg_cache keyagg_cache;
    enum { N_TWEAKS = 8 };
    secp256k1_pubkey P[N_TWEAKS + 1];
    secp256k1_xonly_pubkey P_xonly[N_TWEAKS + 1];
    int i;

    /* Key Setup */
    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        secp256k1_testrand256(sk[i]);
        CHECK(create_keypair_and_pk(NULL, &pk[i], sk[i]) == 1);
    }
    /* Compute P0 = keyagg(pk0, pk1) and test signing for it */
    CHECK(secp256k1_musig_pubkey_agg(ctx, scratch, &P_xonly[0], &keyagg_cache, pk_ptr, 2) == 1);
    musig_tweak_test_helper(&P_xonly[0], sk[0], sk[1], &keyagg_cache);
    CHECK(secp256k1_musig_pubkey_get(ctx, &P[0], &keyagg_cache));

    /* Compute Pi = f(Pj) + tweaki*G where where j = i-1 and try signing for
     * that key. If xonly is set to true, the function f is normalizes the input
     * point to have an even X-coordinate ("xonly-tweaking").
     * Otherwise, the function f is the identity function. */
    for (i = 1; i <= N_TWEAKS; i++) {
        unsigned char tweak[32];
        int P_parity;
        int xonly = secp256k1_testrand_bits(1);

        secp256k1_testrand256(tweak);
        if (xonly) {
            CHECK(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &P[i], &keyagg_cache, tweak) == 1);
        } else {
            CHECK(secp256k1_musig_pubkey_ec_tweak_add(ctx, &P[i], &keyagg_cache, tweak) == 1);
        }
        CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &P_xonly[i], &P_parity, &P[i]));
        /* Check that musig_pubkey_tweak_add produces same result as
         * xonly_pubkey_tweak_add or ec_pubkey_tweak_add. */
        if (xonly) {
            unsigned char P_serialized[32];
            CHECK(secp256k1_xonly_pubkey_serialize(ctx, P_serialized, &P_xonly[i]));
            CHECK(secp256k1_xonly_pubkey_tweak_add_check(ctx, P_serialized, P_parity, &P_xonly[i-1], tweak) == 1);
        } else {
            secp256k1_pubkey tmp_key = P[i-1];
            CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &tmp_key, tweak));
            CHECK(memcmp(&tmp_key, &P[i], sizeof(tmp_key)) == 0);
        }
        /* Test signing for P[i] */
        musig_tweak_test_helper(&P_xonly[i], sk[0], sk[1], &keyagg_cache);
    }
}

void musig_test_vectors_keyagg_helper(const unsigned char **pk_ser, int n_pks, const unsigned char *agg_pk_expected, int has_second_pk, int second_pk_idx) {
    secp256k1_xonly_pubkey *pk = malloc(n_pks * sizeof(*pk));
    const secp256k1_xonly_pubkey **pk_ptr = malloc(n_pks * sizeof(*pk_ptr));
    secp256k1_keyagg_cache_internal cache_i;
    secp256k1_xonly_pubkey agg_pk;
    unsigned char agg_pk_ser[32];
    secp256k1_musig_keyagg_cache keyagg_cache;
    int i;

    for (i = 0; i < n_pks; i++) {
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &pk[i], pk_ser[i]) == 1);
        pk_ptr[i] = &pk[i];
    }

    CHECK(secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, &keyagg_cache, pk_ptr, n_pks) == 1);
    CHECK(secp256k1_keyagg_cache_load(ctx, &cache_i, &keyagg_cache) == 1);
    CHECK(secp256k1_fe_is_zero(&cache_i.second_pk_x) == !has_second_pk);
    if (!secp256k1_fe_is_zero(&cache_i.second_pk_x)) {
        secp256k1_ge pk_pt;
        CHECK(secp256k1_xonly_pubkey_load(ctx, &pk_pt, &pk[second_pk_idx]) == 1);
        CHECK(secp256k1_fe_equal_var(&pk_pt.x, &cache_i.second_pk_x) == 1);
    }
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, agg_pk_ser, &agg_pk) == 1);
    /* TODO: remove when test vectors are not expected to change anymore */
    /* int k, l; */
    /* printf("const unsigned char agg_pk_expected[32] = {\n"); */
    /* for (k = 0; k < 4; k++) { */
    /*     printf("    "); */
    /*     for (l = 0; l < 8; l++) { */
    /*         printf("0x%02X, ", agg_pk_ser[k*8+l]); */
    /*     } */
    /*     printf("\n"); */
    /* } */
    /* printf("};\n"); */
    CHECK(secp256k1_memcmp_var(agg_pk_ser, agg_pk_expected, sizeof(agg_pk_ser)) == 0);
    free(pk);
    free(pk_ptr);
}

/* Test vector public keys */
const unsigned char vec_pk[3][32] = {
    /* X1 */
    {
        0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
        0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
        0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
        0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9
    },
    /* X2 */
    {
        0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F,
        0x36, 0x18, 0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE,
        0x58, 0xFE, 0xAE, 0x1D, 0xA2, 0xDE, 0xCE, 0xD8,
        0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59
    },
    /* X3 */
    {
        0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18,
        0x15, 0xC2, 0xF2, 0x4B, 0x4D, 0x80, 0xA8, 0xE3,
        0x14, 0x93, 0x16, 0xC3, 0x51, 0x8C, 0xE7, 0xB7,
        0xAD, 0x33, 0x83, 0x68, 0xD0, 0x38, 0xCA, 0x66
    }
};

void musig_test_vectors_keyagg(void) {
    size_t i;
    const unsigned char *pk[4];
    const unsigned char agg_pk_expected[4][32] = {
        { /* 0 */
            0xE5, 0x83, 0x01, 0x40, 0x51, 0x21, 0x95, 0xD7,
            0x4C, 0x83, 0x07, 0xE3, 0x96, 0x37, 0xCB, 0xE5,
            0xFB, 0x73, 0x0E, 0xBE, 0xAB, 0x80, 0xEC, 0x51,
            0x4C, 0xF8, 0x8A, 0x87, 0x7C, 0xEE, 0xEE, 0x0B,
        },
        { /* 1 */
            0xD7, 0x0C, 0xD6, 0x9A, 0x26, 0x47, 0xF7, 0x39,
            0x09, 0x73, 0xDF, 0x48, 0xCB, 0xFA, 0x2C, 0xCC,
            0x40, 0x7B, 0x8B, 0x2D, 0x60, 0xB0, 0x8C, 0x5F,
            0x16, 0x41, 0x18, 0x5C, 0x79, 0x98, 0xA2, 0x90,
        },
        { /* 2 */
            0x81, 0xA8, 0xB0, 0x93, 0x91, 0x2C, 0x9E, 0x48,
            0x14, 0x08, 0xD0, 0x97, 0x76, 0xCE, 0xFB, 0x48,
            0xAE, 0xB8, 0xB6, 0x54, 0x81, 0xB6, 0xBA, 0xAF,
            0xB3, 0xC5, 0x81, 0x01, 0x06, 0x71, 0x7B, 0xEB,
        },
        { /* 3 */
            0x2E, 0xB1, 0x88, 0x51, 0x88, 0x7E, 0x7B, 0xDC,
            0x5E, 0x83, 0x0E, 0x89, 0xB1, 0x9D, 0xDB, 0xC2,
            0x80, 0x78, 0xF1, 0xFA, 0x88, 0xAA, 0xD0, 0xAD,
            0x01, 0xCA, 0x06, 0xFE, 0x4F, 0x80, 0x21, 0x0B,
        },
    };

    for (i = 0; i < sizeof(agg_pk_expected)/sizeof(agg_pk_expected[0]); i++) {
        size_t n_pks;
        int has_second_pk;
        int second_pk_idx;
        switch (i) {
            case 0:
                /* [X1, X2, X3] */
                n_pks = 3;
                pk[0] = vec_pk[0];
                pk[1] = vec_pk[1];
                pk[2] = vec_pk[2];
                has_second_pk = 1;
                second_pk_idx = 1;
                break;
            case 1:
                /* [X3, X2, X1] */
                n_pks = 3;
                pk[2] = vec_pk[0];
                pk[1] = vec_pk[1];
                pk[0] = vec_pk[2];
                has_second_pk = 1;
                second_pk_idx = 1;
                break;
            case 2:
                /* [X1, X1, X1] */
                n_pks = 3;
                pk[0] = vec_pk[0];
                pk[1] = vec_pk[0];
                pk[2] = vec_pk[0];
                has_second_pk = 0;
                second_pk_idx = 0; /* unchecked */
                break;
            case 3:
                /* [X1, X1, X2, X2] */
                n_pks = 4;
                pk[0] = vec_pk[0];
                pk[1] = vec_pk[0];
                pk[2] = vec_pk[1];
                pk[3] = vec_pk[1];
                has_second_pk = 1;
                second_pk_idx = 2; /* second_pk_idx = 3 is equally valid */
                break;
            default:
                CHECK(0);
        }
        musig_test_vectors_keyagg_helper(pk, n_pks, agg_pk_expected[i], has_second_pk, second_pk_idx);
    }
}

void musig_test_vectors_noncegen(void) {
    enum { N = 3 };
    secp256k1_scalar k[N][2];
    const unsigned char k32_expected[N][2][32] = {
        {
            {
                0x8D, 0xD0, 0x99, 0x51, 0x79, 0x50, 0x5E, 0xB1,
                0x27, 0x3A, 0x07, 0x11, 0x58, 0x23, 0xC8, 0x6E,
                0xF7, 0x14, 0x39, 0x0F, 0xDE, 0x2D, 0xEE, 0xB6,
                0xF9, 0x31, 0x6A, 0xEE, 0xBE, 0x5C, 0x71, 0xFC,
            },
            {
                0x73, 0x29, 0x2E, 0x47, 0x11, 0x34, 0x7D, 0xD3,
                0x9E, 0x36, 0x05, 0xEE, 0xD6, 0x45, 0x65, 0x49,
                0xB3, 0x0F, 0x3B, 0xC7, 0x16, 0x22, 0x5A, 0x18,
                0x65, 0xBA, 0xE1, 0xD9, 0x84, 0xEF, 0xF8, 0x9D,
            },
        },
        /* msg32 is NULL */
        {
            {
                0x67, 0x02, 0x5A, 0xF2, 0xA3, 0x56, 0x0B, 0xFC,
                0x1D, 0x95, 0xBD, 0xA6, 0xB2, 0x0B, 0x21, 0x50,
                0x97, 0x63, 0xDB, 0x17, 0x3B, 0xD9, 0x37, 0x30,
                0x17, 0x24, 0x66, 0xEC, 0xAF, 0xA2, 0x60, 0x3B,
            },
            {
                0x0B, 0x1D, 0x9E, 0x8F, 0x43, 0xBD, 0xAE, 0x69,
                0x99, 0x6E, 0x0E, 0x3A, 0xBC, 0x30, 0x06, 0x4C,
                0x52, 0x37, 0x3E, 0x05, 0x3E, 0x70, 0xC6, 0xD6,
                0x18, 0x4B, 0xFA, 0xDA, 0xE0, 0xF0, 0xE2, 0xD9,
            },
        },
        /* All fields except session_id are NULL */
        {
            {
                0xA6, 0xC3, 0x24, 0xC7, 0xE8, 0xD1, 0x8A, 0xAA,
                0x59, 0xD7, 0xB4, 0x74, 0xDD, 0x73, 0x82, 0x6D,
                0x7E, 0x74, 0x91, 0x3F, 0x9B, 0x36, 0x12, 0xE4,
                0x4F, 0x28, 0x6E, 0x07, 0x54, 0x14, 0x58, 0x21,
            },
            {
                0x4E, 0x75, 0xD3, 0x81, 0xCD, 0xB7, 0x3C, 0x68,
                0xA0, 0x7E, 0x64, 0x15, 0xE0, 0x0E, 0x89, 0x32,
                0x44, 0x21, 0x87, 0x4F, 0x4E, 0x03, 0xE8, 0x67,
                0x73, 0x4E, 0x33, 0x20, 0xCE, 0x24, 0xBA, 0x8E,
            },
        },
    };
    unsigned char args[5][32];
    int i, j;

    for (i = 0; i < 5; i++) {
        memset(args[i], i, sizeof(args[i]));
    }

    secp256k1_nonce_function_musig(k[0], args[0], args[1], args[2], args[3], args[4]);
    secp256k1_nonce_function_musig(k[1], args[0], NULL, args[2], args[3], args[4]);
    secp256k1_nonce_function_musig(k[2], args[0], NULL, NULL, NULL, NULL);
    /* TODO: remove when test vectors are not expected to change anymore */
    /* int t, u; */
    /* printf("const unsigned char k32_expected[N][2][32] = {\n"); */
    /* for (i = 0; i < N; i++) { */
    /*     printf("    {\n"); */
    /*     for (j = 0; j < 2; j++) { */
    /*         unsigned char k32[32]; */
    /*         secp256k1_scalar_get_b32(k32, &k[i][j]); */
    /*         printf("        {\n"); */
    /*         for (t = 0; t < 4; t++) { */
    /*             printf("            "); */
    /*             for (u = 0; u < 8; u++) { */
    /*                 printf("0x%02X, ", k32[t*8+u]); */
    /*             } */
    /*             printf("\n"); */
    /*         } */
    /*         printf("        },\n"); */
    /*     } */
    /*     printf("    },\n"); */
    /* } */
    /* printf("};\n"); */
    for (i = 0; i < N; i++) {
        for (j = 0; j < 2; j++) {
            unsigned char k32[32];
            secp256k1_scalar_get_b32(k32, &k[i][j]);
            CHECK(memcmp(k32, k32_expected[i][j], 32) == 0);
        }
    }
}

void musig_test_vectors_sign_helper(secp256k1_musig_keyagg_cache *keyagg_cache, int *fin_nonce_parity, unsigned char *sig, const unsigned char *secnonce_bytes, const unsigned char *agg_pubnonce_ser, const unsigned char *sk, const unsigned char *msg, const unsigned char tweak[][32], const int *is_xonly_t, int n_tweaks, const secp256k1_pubkey *adaptor, const unsigned char **pk_ser, int signer_pos) {
    secp256k1_keypair signer_keypair;
    secp256k1_musig_secnonce secnonce;
    secp256k1_xonly_pubkey pk[3];
    const secp256k1_xonly_pubkey *pk_ptr[3];
    secp256k1_xonly_pubkey agg_pk;
    secp256k1_musig_session session;
    secp256k1_musig_aggnonce agg_pubnonce;
    secp256k1_musig_partial_sig partial_sig;
    int i;

    CHECK(create_keypair_and_pk(&signer_keypair, &pk[signer_pos], sk) == 1);
    for (i = 0; i < 3; i++) {
        if (i != signer_pos) {
            int offset = i < signer_pos ? 0 : -1;
            CHECK(secp256k1_xonly_pubkey_parse(ctx, &pk[i], pk_ser[i + offset]) == 1);
        }
        pk_ptr[i] = &pk[i];
    }
    CHECK(secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, keyagg_cache, pk_ptr, 3) == 1);
    for (i = 0; i < n_tweaks; i++) {
        if (is_xonly_t[i]) {
            CHECK(secp256k1_musig_pubkey_xonly_tweak_add(ctx, NULL, keyagg_cache, tweak[i]) == 1);
        } else {
            CHECK(secp256k1_musig_pubkey_ec_tweak_add(ctx, NULL, keyagg_cache, tweak[i]) == 1);
        }
    }
    memcpy(&secnonce.data[0], secp256k1_musig_secnonce_magic, 4);
    memcpy(&secnonce.data[4], secnonce_bytes, sizeof(secnonce.data) - 4);
    CHECK(secp256k1_musig_aggnonce_parse(ctx, &agg_pubnonce, agg_pubnonce_ser) == 1);
    CHECK(secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, msg, keyagg_cache, adaptor) == 1);
    CHECK(secp256k1_musig_partial_sign(ctx, &partial_sig, &secnonce, &signer_keypair, keyagg_cache, &session) == 1);
    CHECK(secp256k1_musig_nonce_parity(ctx, fin_nonce_parity, &session) == 1);
    memcpy(sig, &partial_sig.data[4], 32);
}

int musig_test_pk_parity(const secp256k1_musig_keyagg_cache *keyagg_cache) {
    secp256k1_keyagg_cache_internal cache_i;
    CHECK(secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache) == 1);
    return secp256k1_fe_is_odd(&cache_i.pk.y);
}

int musig_test_is_second_pk(const secp256k1_musig_keyagg_cache *keyagg_cache, const unsigned char *sk) {
    secp256k1_ge pkp;
    secp256k1_xonly_pubkey pk;
    secp256k1_keyagg_cache_internal cache_i;
    CHECK(create_keypair_and_pk(NULL, &pk, sk));
    CHECK(secp256k1_xonly_pubkey_load(ctx, &pkp, &pk));
    CHECK(secp256k1_keyagg_cache_load(ctx, &cache_i, keyagg_cache));
    return secp256k1_fe_equal_var(&cache_i.second_pk_x, &pkp.x);
}

/* TODO: Add test vectors for failed signing */
void musig_test_vectors_sign(void) {
    unsigned char sig[32];
    secp256k1_musig_keyagg_cache keyagg_cache;
    int fin_nonce_parity;
    const unsigned char secnonce[64] = {
        0x50, 0x8B, 0x81, 0xA6, 0x11, 0xF1, 0x00, 0xA6,
        0xB2, 0xB6, 0xB2, 0x96, 0x56, 0x59, 0x08, 0x98,
        0xAF, 0x48, 0x8B, 0xCF, 0x2E, 0x1F, 0x55, 0xCF,
        0x22, 0xE5, 0xCF, 0xB8, 0x44, 0x21, 0xFE, 0x61,
        0xFA, 0x27, 0xFD, 0x49, 0xB1, 0xD5, 0x00, 0x85,
        0xB4, 0x81, 0x28, 0x5E, 0x1C, 0xA2, 0x05, 0xD5,
        0x5C, 0x82, 0xCC, 0x1B, 0x31, 0xFF, 0x5C, 0xD5,
        0x4A, 0x48, 0x98, 0x29, 0x35, 0x59, 0x01, 0xF7,
    };
    /* The nonces are already aggregated */
    const unsigned char agg_pubnonce[66] = {
        0x02,
        0x84, 0x65, 0xFC, 0xF0, 0xBB, 0xDB, 0xCF, 0x44,
        0x3A, 0xAB, 0xCC, 0xE5, 0x33, 0xD4, 0x2B, 0x4B,
        0x5A, 0x10, 0x96, 0x6A, 0xC0, 0x9A, 0x49, 0x65,
        0x5E, 0x8C, 0x42, 0xDA, 0xAB, 0x8F, 0xCD, 0x61,
        0x03,
        0x74, 0x96, 0xA3, 0xCC, 0x86, 0x92, 0x6D, 0x45,
        0x2C, 0xAF, 0xCF, 0xD5, 0x5D, 0x25, 0x97, 0x2C,
        0xA1, 0x67, 0x5D, 0x54, 0x93, 0x10, 0xDE, 0x29,
        0x6B, 0xFF, 0x42, 0xF7, 0x2E, 0xEE, 0xA8, 0xC9,
    };
    const unsigned char sk[32] = {
        0x7F, 0xB9, 0xE0, 0xE6, 0x87, 0xAD, 0xA1, 0xEE,
        0xBF, 0x7E, 0xCF, 0xE2, 0xF2, 0x1E, 0x73, 0xEB,
        0xDB, 0x51, 0xA7, 0xD4, 0x50, 0x94, 0x8D, 0xFE,
        0x8D, 0x76, 0xD7, 0xF2, 0xD1, 0x00, 0x76, 0x71,
    };
    const unsigned char msg[32] = {
        0xF9, 0x54, 0x66, 0xD0, 0x86, 0x77, 0x0E, 0x68,
        0x99, 0x64, 0x66, 0x42, 0x19, 0x26, 0x6F, 0xE5,
        0xED, 0x21, 0x5C, 0x92, 0xAE, 0x20, 0xBA, 0xB5,
        0xC9, 0xD7, 0x9A, 0xDD, 0xDD, 0xF3, 0xC0, 0xCF,
    };
    const unsigned char *pk[2] = { vec_pk[0], vec_pk[1] };

    {
        /* This is a test where the combined public key point has an _odd_ y
         * coordinate, the signer _is not_ the second pubkey in the list and the
         * nonce parity is 1. */
        const unsigned char sig_expected[32] = {
            0x68, 0x53, 0x7C, 0xC5, 0x23, 0x4E, 0x50, 0x5B,
            0xD1, 0x40, 0x61, 0xF8, 0xDA, 0x9E, 0x90, 0xC2,
            0x20, 0xA1, 0x81, 0x85, 0x5F, 0xD8, 0xBD, 0xB7,
            0xF1, 0x27, 0xBB, 0x12, 0x40, 0x3B, 0x4D, 0x3B,
        };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, NULL, NULL, 0, NULL, pk, 0);
        /* TODO: remove when test vectors are not expected to change anymore */
        /* int k, l; */
        /* printf("const unsigned char sig_expected[32] = {\n"); */
        /* for (k = 0; k < 4; k++) { */
        /*     printf("    "); */
        /*     for (l = 0; l < 8; l++) { */
        /*         printf("0x%02X, ", sig[k*8+l]); */
        /*     } */
        /*     printf("\n"); */
        /* } */
        /* printf("};\n"); */

        /* Check that the description of the test vector is correct */
        CHECK(musig_test_pk_parity(&keyagg_cache) == 1);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 1);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test where the aggregate public key point has an _even_ y
        * coordinate, the signer _is_ the second pubkey in the list and the
        * nonce parity is 0. */
        const unsigned char sig_expected[32] = {
            0x2D, 0xF6, 0x7B, 0xFF, 0xF1, 0x8E, 0x3D, 0xE7,
            0x97, 0xE1, 0x3C, 0x64, 0x75, 0xC9, 0x63, 0x04,
            0x81, 0x38, 0xDA, 0xEC, 0x5C, 0xB2, 0x0A, 0x35,
            0x7C, 0xEC, 0xA7, 0xC8, 0x42, 0x42, 0x95, 0xEA,
        };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, NULL, NULL, 0, NULL, pk, 1);
        /* Check that the description of the test vector is correct */
        CHECK(musig_test_pk_parity(&keyagg_cache) == 0);
        CHECK(musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 0);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test where the parity of aggregate public key point (1) is unequal to the
        * nonce parity (0). */
        const unsigned char sig_expected[32] = {
            0x0D, 0x5B, 0x65, 0x1E, 0x6D, 0xE3, 0x4A, 0x29,
            0xA1, 0x2D, 0xE7, 0xA8, 0xB4, 0x18, 0x3B, 0x4A,
            0xE6, 0xA7, 0xF7, 0xFB, 0xE1, 0x5C, 0xDC, 0xAF,
            0xA4, 0xA3, 0xD1, 0xBC, 0xAA, 0xBC, 0x75, 0x17,
        };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, NULL, NULL, 0, NULL, pk, 2);
        /* Check that the description of the test vector is correct */
        CHECK(musig_test_pk_parity(&keyagg_cache) == 1);
        CHECK(fin_nonce_parity == 0);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test that includes an xonly public key tweak. */
        const unsigned char sig_expected[32] = {
            0x5E, 0x24, 0xC7, 0x49, 0x6B, 0x56, 0x5D, 0xEB,
            0xC3, 0xB9, 0x63, 0x9E, 0x6F, 0x13, 0x04, 0xA2,
            0x15, 0x97, 0xF9, 0x60, 0x3D, 0x3A, 0xB0, 0x5B,
            0x49, 0x13, 0x64, 0x17, 0x75, 0xE1, 0x37, 0x5B,
        };
        const unsigned char tweak[1][32] = {{
            0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
            0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
            0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
            0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
        }};
        int is_xonly_t[1] = { 1 };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, tweak, is_xonly_t, 1, NULL, pk, 2);

        CHECK(musig_test_pk_parity(&keyagg_cache) == 1);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 1);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test that includes an ordinary public key tweak. */
        const unsigned char sig_expected[32] = {
            0x78, 0x40, 0x8D, 0xDC, 0xAB, 0x48, 0x13, 0xD1,
            0x39, 0x4C, 0x97, 0xD4, 0x93, 0xEF, 0x10, 0x84,
            0x19, 0x5C, 0x1D, 0x4B, 0x52, 0xE6, 0x3E, 0xCD,
            0x7B, 0xC5, 0x99, 0x16, 0x44, 0xE4, 0x4D, 0xDD,
        };
        const unsigned char tweak[1][32] = {{
            0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
            0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
            0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
            0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
        }};
        int is_xonly_t[1] = { 0 };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, tweak, is_xonly_t, 1, NULL, pk, 2);

        CHECK(musig_test_pk_parity(&keyagg_cache) == 1);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 0);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test that includes an ordinary and an x-only public key tweak. */
        const unsigned char sig_expected[32] = {
            0xC3, 0xA8, 0x29, 0xA8, 0x14, 0x80, 0xE3, 0x6E,
            0xC3, 0xAB, 0x05, 0x29, 0x64, 0x50, 0x9A, 0x94,
            0xEB, 0xF3, 0x42, 0x10, 0x40, 0x3D, 0x16, 0xB2,
            0x26, 0xA6, 0xF1, 0x6E, 0xC8, 0x5B, 0x73, 0x57,
        };

        const unsigned char tweak[2][32] = {
            {
                0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
                0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
                0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
                0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
            },
            {
                0xAE, 0x2E, 0xA7, 0x97, 0xCC, 0x0F, 0xE7, 0x2A,
                0xC5, 0xB9, 0x7B, 0x97, 0xF3, 0xC6, 0x95, 0x7D,
                0x7E, 0x41, 0x99, 0xA1, 0x67, 0xA5, 0x8E, 0xB0,
                0x8B, 0xCA, 0xFF, 0xDA, 0x70, 0xAC, 0x04, 0x55,
            },
        };
        int is_xonly_t[2] = { 0, 1 };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, tweak, is_xonly_t, 2, NULL, pk, 2);
        CHECK(musig_test_pk_parity(&keyagg_cache) == 0);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 0);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test with four tweaks: x-only, ordinary, x-only, ordinary. */
        const unsigned char sig_expected[32] = {
            0x8C, 0x44, 0x73, 0xC6, 0xA3, 0x82, 0xBD, 0x3C,
            0x4A, 0xD7, 0xBE, 0x59, 0x81, 0x8D, 0xA5, 0xED,
            0x7C, 0xF8, 0xCE, 0xC4, 0xBC, 0x21, 0x99, 0x6C,
            0xFD, 0xA0, 0x8B, 0xB4, 0x31, 0x6B, 0x8B, 0xC7,
        };
        const unsigned char tweak[4][32] = {
            {
                0xE8, 0xF7, 0x91, 0xFF, 0x92, 0x25, 0xA2, 0xAF,
                0x01, 0x02, 0xAF, 0xFF, 0x4A, 0x9A, 0x72, 0x3D,
                0x96, 0x12, 0xA6, 0x82, 0xA2, 0x5E, 0xBE, 0x79,
                0x80, 0x2B, 0x26, 0x3C, 0xDF, 0xCD, 0x83, 0xBB,
            },
            {
                0xAE, 0x2E, 0xA7, 0x97, 0xCC, 0x0F, 0xE7, 0x2A,
                0xC5, 0xB9, 0x7B, 0x97, 0xF3, 0xC6, 0x95, 0x7D,
                0x7E, 0x41, 0x99, 0xA1, 0x67, 0xA5, 0x8E, 0xB0,
                0x8B, 0xCA, 0xFF, 0xDA, 0x70, 0xAC, 0x04, 0x55,
            },
            {
                0xF5, 0x2E, 0xCB, 0xC5, 0x65, 0xB3, 0xD8, 0xBE,
                0xA2, 0xDF, 0xD5, 0xB7, 0x5A, 0x4F, 0x45, 0x7E,
                0x54, 0x36, 0x98, 0x09, 0x32, 0x2E, 0x41, 0x20,
                0x83, 0x16, 0x26, 0xF2, 0x90, 0xFA, 0x87, 0xE0,
            },
            {
                0x19, 0x69, 0xAD, 0x73, 0xCC, 0x17, 0x7F, 0xA0,
                0xB4, 0xFC, 0xED, 0x6D, 0xF1, 0xF7, 0xBF, 0x99,
                0x07, 0xE6, 0x65, 0xFD, 0xE9, 0xBA, 0x19, 0x6A,
                0x74, 0xFE, 0xD0, 0xA3, 0xCF, 0x5A, 0xEF, 0x9D,
            },
        };
        int is_xonly_t[4] = { 1, 0, 1, 0 };
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, tweak, is_xonly_t, 4, NULL, pk, 2);
        CHECK(musig_test_pk_parity(&keyagg_cache) == 0);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 1);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
    {
       /* This is a test that includes an adaptor. */
        const unsigned char sig_expected[32] = {
            0xD7, 0x67, 0xD0, 0x7D, 0x9A, 0xB8, 0x19, 0x8C,
            0x9F, 0x64, 0xE3, 0xFD, 0x9F, 0x7B, 0x8B, 0xAA,
            0xC6, 0x05, 0xF1, 0x8D, 0xFF, 0x18, 0x95, 0x24,
            0x2D, 0x93, 0x95, 0xD9, 0xC8, 0xE6, 0xDD, 0x7C,
        };
        const unsigned char sec_adaptor[32] = {
            0xD5, 0x6A, 0xD1, 0x85, 0x00, 0xF2, 0xD7, 0x8A,
            0xB9, 0x54, 0x80, 0x53, 0x76, 0xF3, 0x9D, 0x1B,
            0x6D, 0x62, 0x04, 0x95, 0x12, 0x39, 0x04, 0x6D,
            0x99, 0x3A, 0x9C, 0x31, 0xE0, 0xF4, 0x78, 0x71,
        };
        secp256k1_pubkey pub_adaptor;
        CHECK(secp256k1_ec_pubkey_create(ctx, &pub_adaptor, sec_adaptor) == 1);
        musig_test_vectors_sign_helper(&keyagg_cache, &fin_nonce_parity, sig, secnonce, agg_pubnonce, sk, msg, NULL, NULL, 0, &pub_adaptor, pk, 2);

        CHECK(musig_test_pk_parity(&keyagg_cache) == 1);
        CHECK(!musig_test_is_second_pk(&keyagg_cache, sk));
        CHECK(fin_nonce_parity == 1);
        CHECK(memcmp(sig, sig_expected, 32) == 0);
    }
}

void run_musig_tests(void) {
    int i;
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);

    for (i = 0; i < count; i++) {
        musig_simple_test(scratch);
    }
    musig_api_tests(scratch);
    musig_nonce_test();
    for (i = 0; i < count; i++) {
        /* Run multiple times to ensure that pk and nonce have different y
         * parities */
        scriptless_atomic_swap(scratch);
        musig_tweak_test(scratch);
    }
    sha256_tag_test();
    musig_test_vectors_keyagg();
    musig_test_vectors_noncegen();
    musig_test_vectors_sign();

    secp256k1_scratch_space_destroy(ctx, scratch);
}

#endif
