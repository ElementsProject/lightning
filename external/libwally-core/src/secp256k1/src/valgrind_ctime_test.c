/***********************************************************************
 * Copyright (c) 2020 Gregory Maxwell                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <valgrind/memcheck.h>
#include <stdio.h>
#include <string.h>

#include "../include/secp256k1.h"
#include "assumptions.h"
#include "util.h"

#ifdef ENABLE_MODULE_ECDH
# include "../include/secp256k1_ecdh.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "../include/secp256k1_recovery.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "../include/secp256k1_extrakeys.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
#include "../include/secp256k1_schnorrsig.h"
#endif

#ifdef ENABLE_MODULE_ECDSA_S2C
#include "include/secp256k1_ecdsa_s2c.h"
#endif

#ifdef ENABLE_MODULE_ECDSA_ADAPTOR
#include "include/secp256k1_ecdsa_adaptor.h"
#endif

#ifdef ENABLE_MODULE_MUSIG
#include "include/secp256k1_musig.h"
#endif

void run_tests(secp256k1_context *ctx, unsigned char *key);

int main(void) {
    secp256k1_context* ctx;
    unsigned char key[32];
    int ret, i;

    if (!RUNNING_ON_VALGRIND) {
        fprintf(stderr, "This test can only usefully be run inside valgrind.\n");
        fprintf(stderr, "Usage: libtool --mode=execute valgrind ./valgrind_ctime_test\n");
        return 1;
    }
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                   | SECP256K1_CONTEXT_VERIFY
                                   | SECP256K1_CONTEXT_DECLASSIFY);
    /** In theory, testing with a single secret input should be sufficient:
     *  If control flow depended on secrets the tool would generate an error.
     */
    for (i = 0; i < 32; i++) {
        key[i] = i + 65;
    }

    run_tests(ctx, key);

    /* Test context randomisation. Do this last because it leaves the context
     * tainted. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_context_randomize(ctx, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);

    secp256k1_context_destroy(ctx);
    return 0;
}

void run_tests(secp256k1_context *ctx, unsigned char *key) {
    secp256k1_ecdsa_signature signature;
    secp256k1_pubkey pubkey;
    size_t siglen = 74;
    size_t outputlen = 33;
    int i;
    int ret;
    unsigned char msg[32];
    unsigned char sig[74];
    unsigned char spubkey[33];
#ifdef ENABLE_MODULE_RECOVERY
    secp256k1_ecdsa_recoverable_signature recoverable_signature;
    int recid;
#endif
#ifdef ENABLE_MODULE_EXTRAKEYS
    secp256k1_keypair keypair;
#endif

    for (i = 0; i < 32; i++) {
        msg[i] = i + 1;
    }

    /* Test keygen. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_ec_pubkey_create(ctx, &pubkey, key);
    VALGRIND_MAKE_MEM_DEFINED(&pubkey, sizeof(secp256k1_pubkey));
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);
    CHECK(secp256k1_ec_pubkey_serialize(ctx, spubkey, &outputlen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    /* Test signing. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_ecdsa_sign(ctx, &signature, msg, key, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&signature, sizeof(secp256k1_ecdsa_signature));
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature));

#ifdef ENABLE_MODULE_ECDH
    /* Test ECDH. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_ecdh(ctx, msg, &pubkey, key, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
#endif

#ifdef ENABLE_MODULE_RECOVERY
    /* Test signing a recoverable signature. */
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_signature, msg, key, NULL, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&recoverable_signature, sizeof(recoverable_signature));
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret);
    CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig, &recid, &recoverable_signature));
    CHECK(recid >= 0 && recid <= 3);
#endif

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_ec_seckey_verify(ctx, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_ec_seckey_negate(ctx, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(msg, 32);
    ret = secp256k1_ec_seckey_tweak_add(ctx, key, msg);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(msg, 32);
    ret = secp256k1_ec_seckey_tweak_mul(ctx, key, msg);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    /* Test keypair_create and keypair_xonly_tweak_add. */
#ifdef ENABLE_MODULE_EXTRAKEYS
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_keypair_create(ctx, &keypair, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    /* The tweak is not treated as a secret in keypair_tweak_add */
    VALGRIND_MAKE_MEM_DEFINED(msg, 32);
    ret = secp256k1_keypair_xonly_tweak_add(ctx, &keypair, msg);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);

    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    VALGRIND_MAKE_MEM_UNDEFINED(&keypair, sizeof(keypair));
    ret = secp256k1_keypair_sec(ctx, key, &keypair);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
    VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
    ret = secp256k1_keypair_create(ctx, &keypair, key);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
    ret = secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
    CHECK(ret == 1);
#endif

#ifdef ENABLE_MODULE_ECDSA_S2C
    {
        unsigned char s2c_data[32] = {0};
        unsigned char s2c_data_comm[32] = {0};
        secp256k1_ecdsa_s2c_opening s2c_opening;

        VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
        VALGRIND_MAKE_MEM_UNDEFINED(s2c_data, 32);
        ret = secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, msg, key, s2c_data);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_UNDEFINED(s2c_data, 32);
        ret = secp256k1_ecdsa_anti_exfil_host_commit(ctx, s2c_data_comm, s2c_data);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
        VALGRIND_MAKE_MEM_UNDEFINED(s2c_data, 32);
        ret = secp256k1_ecdsa_anti_exfil_signer_commit(ctx, &s2c_opening, msg, key, s2c_data);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);
    }
#endif

#ifdef ENABLE_MODULE_ECDSA_ADAPTOR
    {
        unsigned char adaptor_sig[162];
        unsigned char deckey[32];
        unsigned char expected_deckey[32];
        secp256k1_pubkey enckey;

        for (i = 0; i < 32; i++) {
            deckey[i] = i + 2;
        }

        ret = secp256k1_ec_pubkey_create(ctx, &enckey, deckey);
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
        ret = secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, key, &enckey, msg, NULL, NULL);
        VALGRIND_MAKE_MEM_DEFINED(adaptor_sig, sizeof(adaptor_sig));
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_UNDEFINED(deckey, 32);
        ret = secp256k1_ecdsa_adaptor_decrypt(ctx, &signature, deckey, adaptor_sig);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_UNDEFINED(&signature, 32);
        ret = secp256k1_ecdsa_adaptor_recover(ctx, expected_deckey, &signature, adaptor_sig, &enckey);
        VALGRIND_MAKE_MEM_DEFINED(expected_deckey, sizeof(expected_deckey));
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_DEFINED(deckey, sizeof(deckey));
        ret = secp256k1_memcmp_var(deckey, expected_deckey, sizeof(expected_deckey));
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 0);
    }
#endif

#ifdef ENABLE_MODULE_MUSIG
    {
        secp256k1_xonly_pubkey pk;
        const secp256k1_xonly_pubkey *pk_ptr[1];
        secp256k1_xonly_pubkey agg_pk;
        unsigned char session_id[32];
        secp256k1_musig_secnonce secnonce;
        secp256k1_musig_pubnonce pubnonce;
        const secp256k1_musig_pubnonce *pubnonce_ptr[1];
        secp256k1_musig_aggnonce aggnonce;
        secp256k1_musig_keyagg_cache cache;
        secp256k1_musig_session session;
        secp256k1_musig_partial_sig partial_sig;
        const secp256k1_musig_partial_sig *partial_sig_ptr[1];
        unsigned char extra_input[32];
        unsigned char sec_adaptor[32];
        secp256k1_pubkey adaptor;
        unsigned char pre_sig[64];
        int nonce_parity;

        pk_ptr[0] = &pk;
        pubnonce_ptr[0] = &pubnonce;
        VALGRIND_MAKE_MEM_DEFINED(key, 32);
        memcpy(session_id, key, sizeof(session_id));
        session_id[0] = session_id[0] + 1;
        memcpy(extra_input, key, sizeof(extra_input));
        extra_input[0] = extra_input[0] + 2;
        memcpy(sec_adaptor, key, sizeof(sec_adaptor));
        sec_adaptor[0] = extra_input[0] + 3;
        partial_sig_ptr[0] = &partial_sig;

        CHECK(secp256k1_keypair_create(ctx, &keypair, key));
        CHECK(secp256k1_keypair_xonly_pub(ctx, &pk, NULL, &keypair));
        CHECK(secp256k1_musig_pubkey_agg(ctx, NULL, &agg_pk, &cache, pk_ptr, 1));
        CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, sec_adaptor));
        VALGRIND_MAKE_MEM_UNDEFINED(key, 32);
        VALGRIND_MAKE_MEM_UNDEFINED(session_id, sizeof(session_id));
        VALGRIND_MAKE_MEM_UNDEFINED(extra_input, sizeof(extra_input));
        VALGRIND_MAKE_MEM_UNDEFINED(sec_adaptor, sizeof(sec_adaptor));
        ret = secp256k1_musig_nonce_gen(ctx, &secnonce, &pubnonce, session_id, key, msg, &cache, extra_input);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);
        CHECK(secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptr, 1));
        CHECK(secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg, &cache, &adaptor) == 1);

        ret = secp256k1_keypair_create(ctx, &keypair, key);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);
        ret = secp256k1_musig_partial_sign(ctx, &partial_sig, &secnonce, &keypair, &cache, &session);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);

        VALGRIND_MAKE_MEM_DEFINED(&partial_sig, sizeof(partial_sig));
        CHECK(secp256k1_musig_partial_sig_agg(ctx, pre_sig, &session, partial_sig_ptr, 1));
        VALGRIND_MAKE_MEM_DEFINED(pre_sig, sizeof(pre_sig));

        CHECK(secp256k1_musig_nonce_parity(ctx, &nonce_parity, &session));
        ret = secp256k1_musig_adapt(ctx, sig, pre_sig, sec_adaptor, nonce_parity);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);
        ret = secp256k1_musig_extract_adaptor(ctx, sec_adaptor, sig, pre_sig, nonce_parity);
        VALGRIND_MAKE_MEM_DEFINED(&ret, sizeof(ret));
        CHECK(ret == 1);
    }
#endif
}
