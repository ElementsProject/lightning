/**********************************************************************
 * Copyright (c) 2019-2020 Marko Bencun, Jonas Nick                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_S2C_TESTS_H
#define SECP256K1_MODULE_ECDSA_S2C_TESTS_H

#include "include/secp256k1_ecdsa_s2c.h"

static void test_ecdsa_s2c_tagged_hash(void) {
    unsigned char tag_data[14] = "s2c/ecdsa/data";
    unsigned char tag_point[15] = "s2c/ecdsa/point";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;
    unsigned char output[32];
    unsigned char output_optimized[32];

    secp256k1_sha256_initialize_tagged(&sha, tag_data, sizeof(tag_data));
    secp256k1_s2c_ecdsa_data_sha256_tagged(&sha_optimized);
    secp256k1_sha256_finalize(&sha, output);
    secp256k1_sha256_finalize(&sha_optimized, output_optimized);
    CHECK(secp256k1_memcmp_var(output, output_optimized, 32) == 0);

    secp256k1_sha256_initialize_tagged(&sha, tag_point, sizeof(tag_point));
    secp256k1_s2c_ecdsa_point_sha256_tagged(&sha_optimized);
    secp256k1_sha256_finalize(&sha, output);
    secp256k1_sha256_finalize(&sha_optimized, output_optimized);
    CHECK(secp256k1_memcmp_var(output, output_optimized, 32) == 0);
}

void run_s2c_opening_test(void) {
    int i = 0;
    unsigned char output[33];
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    unsigned char input[33] = {
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02
    };
    secp256k1_ecdsa_s2c_opening opening;
    int32_t ecount = 0;

    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);

    /* First parsing, then serializing works */
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1);
    CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, output, &opening) == 1);
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1);
    CHECK(ecount == 0);

    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, NULL, input) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1);

    CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, NULL, &opening) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, output, NULL) == 0);

    CHECK(ecount == 4);
    /* Invalid pubkey makes parsing fail */
    input[0] = 0;  /* bad oddness bit */
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 0);
    input[0] = 2;
    input[31] = 1; /* point not on the curve */
    CHECK(secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 0);
    CHECK(ecount == 4); /* neither of the above are API errors */

    /* Try parsing and serializing a bunch of openings */
    for (i = 0; i < count; i++) {
        /* This is expected to fail in about 50% of iterations because the
         * points' x-coordinates are uniformly random */
        if (secp256k1_ecdsa_s2c_opening_parse(none, &opening, input) == 1) {
            CHECK(secp256k1_ecdsa_s2c_opening_serialize(none, output, &opening) == 1);
            CHECK(memcmp(output, input, sizeof(output)) == 0);
        }
        secp256k1_testrand256(&input[1]);
        /* Set pubkey oddness tag to first bit of input[1] */
        input[0] = (input[1] & 1) + 2;
    }

    secp256k1_context_destroy(none);
}

static void test_ecdsa_s2c_api(void) {
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);

    secp256k1_ecdsa_s2c_opening s2c_opening;
    secp256k1_ecdsa_signature sig;
    const unsigned char msg[32] = "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
    const unsigned char sec[32] = "ssssssssssssssssssssssssssssssss";
    const unsigned char s2c_data[32] = "dddddddddddddddddddddddddddddddd";
    const unsigned char hostrand[32] = "hrhrhrhrhrhrhrhrhrhrhrhrhrhrhrhr";
    unsigned char hostrand_commitment[32];
    secp256k1_pubkey pk;

    int32_t ecount;
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, sec));

    ecount = 0;
    CHECK(secp256k1_ecdsa_s2c_sign(both, NULL, &s2c_opening, msg, sec, s2c_data) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_s2c_sign(both, &sig, NULL, msg, sec, s2c_data) == 1);
    CHECK(ecount == 1); /* NULL opening is not an API error */
    CHECK(secp256k1_ecdsa_s2c_sign(both, &sig, &s2c_opening, NULL, sec, s2c_data) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_s2c_sign(both, &sig, &s2c_opening, msg, NULL, s2c_data) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_s2c_sign(both, &sig, &s2c_opening, msg, sec, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_s2c_sign(none, &sig, &s2c_opening, msg, sec, s2c_data) == 1);
    CHECK(secp256k1_ecdsa_s2c_sign(vrfy, &sig, &s2c_opening, msg, sec, s2c_data) == 1);
    CHECK(secp256k1_ecdsa_s2c_sign(sign, &sig, &s2c_opening, msg, sec, s2c_data) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_s2c_sign(sttc, &sig, &s2c_opening, msg, sec, s2c_data) == 0);
    CHECK(ecount == 5);

    CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, &pk) == 1);

    ecount = 0;
    CHECK(secp256k1_ecdsa_s2c_verify_commit(both, NULL, s2c_data, &s2c_opening) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(both, &sig, NULL, &s2c_opening) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(both, &sig, s2c_data, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(none, &sig, s2c_data, &s2c_opening) == 1);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(sign, &sig, s2c_data, &s2c_opening) == 1);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &sig, s2c_data, &s2c_opening) == 1);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &sig, sec, &s2c_opening) == 0);
    CHECK(ecount == 3); /* wrong data is not an API error */

    /* Signing with NULL s2c_opening gives the same result */
    CHECK(secp256k1_ecdsa_s2c_sign(sign, &sig, NULL, msg, sec, s2c_data) == 1);
    CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &sig, s2c_data, &s2c_opening) == 1);

    /* anti-exfil */
    ecount = 0;
    CHECK(secp256k1_ecdsa_anti_exfil_host_commit(none, NULL, hostrand) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_anti_exfil_host_commit(none, hostrand_commitment, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_anti_exfil_host_commit(none, hostrand_commitment, hostrand) == 1);
    CHECK(ecount == 2);

    ecount = 0;
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(both, NULL, msg, sec, hostrand_commitment) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(both, &s2c_opening, NULL, sec, hostrand_commitment) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(both, &s2c_opening, msg, NULL, hostrand_commitment) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(both, &s2c_opening, msg, sec, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(none, &s2c_opening, msg, sec, hostrand_commitment) == 1);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(vrfy, &s2c_opening, msg, sec, hostrand_commitment) == 1);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(sign, &s2c_opening, msg, sec, hostrand_commitment) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(sttc, &s2c_opening, msg, sec, hostrand_commitment) == 0);
    CHECK(ecount == 5);

    ecount = 0;
    CHECK(secp256k1_anti_exfil_sign(both, NULL, msg, sec, hostrand) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_anti_exfil_sign(both, &sig, NULL, sec, hostrand) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_anti_exfil_sign(both, &sig, msg, NULL, hostrand) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_anti_exfil_sign(both, &sig, msg, sec, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_anti_exfil_sign(none, &sig, msg, sec, hostrand) == 1);
    CHECK(secp256k1_anti_exfil_sign(vrfy, &sig, msg, sec, hostrand) == 1);
    CHECK(secp256k1_anti_exfil_sign(both, &sig, msg, sec, hostrand) == 1);
    CHECK(ecount == 4);
    CHECK(secp256k1_anti_exfil_sign(sttc, &sig, msg, sec, hostrand) == 0);
    CHECK(ecount == 5);

    ecount = 0;
    CHECK(secp256k1_anti_exfil_host_verify(both, NULL, msg, &pk, hostrand, &s2c_opening) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_anti_exfil_host_verify(both, &sig, NULL, &pk, hostrand, &s2c_opening) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_anti_exfil_host_verify(both, &sig, msg, NULL, hostrand, &s2c_opening) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_anti_exfil_host_verify(both, &sig, msg, &pk, NULL, &s2c_opening) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_anti_exfil_host_verify(both, &sig, msg, &pk, hostrand, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_anti_exfil_host_verify(none, &sig, msg, &pk, hostrand, &s2c_opening) == 1);
    CHECK(secp256k1_anti_exfil_host_verify(sign, &sig, msg, &pk, hostrand, &s2c_opening) == 1);
    CHECK(secp256k1_anti_exfil_host_verify(vrfy, &sig, msg, &pk, hostrand, &s2c_opening) == 1);
    CHECK(ecount == 5);

    secp256k1_context_destroy(both);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sttc);
}

/* When using sign-to-contract commitments, the nonce function is fixed, so we can use fixtures to test. */
typedef struct {
    /* Data to commit to */
    unsigned char s2c_data[32];
    /* Original nonce */
    unsigned char expected_s2c_opening[33];
    /* Original nonce (anti-exfil protocol, which mixes in host randomness) */
    unsigned char expected_s2c_exfil_opening[33];
} ecdsa_s2c_test;

static ecdsa_s2c_test ecdsa_s2c_tests[] = {
    {
        "\x1b\xf6\xfb\x42\xf4\x1e\xb8\x76\xc4\xd7\xaa\x0d\x67\x24\x2b\x00\xba\xab\x99\xdc\x20\x84\x49\x3e\x4e\x63\x27\x7f\xa1\xf7\x7f\x22",
        "\x03\xf0\x30\xde\xf3\x18\x8c\x0f\x56\xfc\xea\x87\x43\x5b\x30\x76\x43\xf4\x5d\xaf\xe2\x2c\xbc\x82\xfd\x56\x03\x4f\xae\x97\x41\x7d\x3a",
        "\x02\xdf\x63\x75\x5d\x1f\x32\x92\xbf\xfe\xd8\x29\x86\xb1\x06\x49\x7c\x93\xb1\xf8\xbd\xc0\x45\x4b\x6b\x0b\x0a\x47\x79\xc0\xef\x71\x88",
    },
    {
        "\x35\x19\x9a\x8f\xbf\x84\xad\x6e\xf6\x9a\x18\x4c\x1b\x19\x28\x5b\xef\xbe\x06\xe6\x0b\x62\x64\xe6\xd3\x73\x89\x3f\x68\x55\xe2\x4a",
        "\x03\x90\x17\x17\xce\x7c\x74\x84\xa2\xce\x1b\x7d\xc7\x40\x3b\x14\xe0\x35\x49\x71\x39\x3e\xc0\x92\xa7\xf3\xe0\xc8\xe4\xe2\xd2\x63\x9d",
        "\x02\xc0\x4a\xc7\xf7\x71\xe8\xeb\xdb\xf3\x15\xff\x5e\x58\xb7\xfe\x95\x16\x10\x21\x03\x50\x00\x66\x17\x2c\x4f\xac\x5b\x20\xf9\xe0\xea",
    },
};

static void test_ecdsa_s2c_fixed_vectors(void) {
    const unsigned char privkey[32] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    };
    const unsigned char message[32] = {
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    };
    size_t i;

    for (i = 0; i < sizeof(ecdsa_s2c_tests) / sizeof(ecdsa_s2c_tests[0]); i++) {
        secp256k1_ecdsa_s2c_opening s2c_opening;
        unsigned char opening_ser[33];
        const ecdsa_s2c_test *test = &ecdsa_s2c_tests[i];
        secp256k1_ecdsa_signature signature;
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, message, privkey, test->s2c_data) == 1);
        CHECK(secp256k1_ecdsa_s2c_opening_serialize(ctx, opening_ser, &s2c_opening) == 1);
        CHECK(memcmp(test->expected_s2c_opening, opening_ser, sizeof(opening_ser)) == 0);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, test->s2c_data, &s2c_opening) == 1);
    }
}

static void test_ecdsa_s2c_sign_verify(void) {
    unsigned char privkey[32];
    secp256k1_pubkey pubkey;
    unsigned char message[32];
    unsigned char noncedata[32];
    unsigned char s2c_data[32];
    unsigned char s2c_data2[32];
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_s2c_opening s2c_opening;

    /* Generate a random key, message, noncedata and s2c_data. */
    {
        secp256k1_scalar key;
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

        secp256k1_testrand256_test(message);
        secp256k1_testrand256_test(noncedata);
        secp256k1_testrand256_test(s2c_data);
        secp256k1_testrand256_test(s2c_data2);
    }

    { /* invalid privkeys */
        unsigned char zero_privkey[32] = {0};
        unsigned char overflow_privkey[32] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, NULL, message, zero_privkey, s2c_data) == 0);
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, NULL, message, overflow_privkey, s2c_data) == 0);
    }
    /* Check that the sign-to-contract signature is valid, with s2c_data. Also check the commitment. */
    {
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, s2c_data, &s2c_opening) == 1);
    }
    /* Check that an invalid commitment does not verify */
    {
        unsigned char sigbytes[64];
        size_t i;
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);

        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, sigbytes, &signature) == 1);
        for(i = 0; i < 32; i++) {
            /* change one byte */
            sigbytes[i] = (((int)sigbytes[i]) + 1) % 256;
            CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sigbytes) == 1);
            CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, s2c_data, &s2c_opening) == 0);
            /* revert */
            sigbytes[i] = (((int)sigbytes[i]) + 255) % 256;
        }
    }
}

static void test_ecdsa_anti_exfil_signer_commit(void) {
    size_t i;
    unsigned char privkey[32] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    };
    unsigned char message[32] = {
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    };
    /* Check that original pubnonce is derived from s2c_data */
    for (i = 0; i < sizeof(ecdsa_s2c_tests) / sizeof(ecdsa_s2c_tests[0]); i++) {
        secp256k1_ecdsa_s2c_opening s2c_opening;
        unsigned char buf[33];
        const ecdsa_s2c_test *test = &ecdsa_s2c_tests[i];
        CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(ctx, &s2c_opening, message, privkey, test->s2c_data) == 1);
        CHECK(secp256k1_ecdsa_s2c_opening_serialize(ctx, buf, &s2c_opening) == 1);
        CHECK(memcmp(test->expected_s2c_exfil_opening, buf, sizeof(buf)) == 0);
    }
}

/* This tests the full ECDSA Anti-Exfil Protocol */
static void test_ecdsa_anti_exfil(void) {
    unsigned char signer_privkey[32];
    unsigned char host_msg[32];
    unsigned char host_commitment[32];
    unsigned char host_nonce_contribution[32];
    secp256k1_pubkey signer_pubkey;
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_s2c_opening s2c_opening;

    /* Generate a random key, message. */
    {
        secp256k1_scalar key;
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(signer_privkey, &key);
        CHECK(secp256k1_ec_pubkey_create(ctx, &signer_pubkey, signer_privkey) == 1);
        secp256k1_testrand256_test(host_msg);
        secp256k1_testrand256_test(host_nonce_contribution);
    }

    /* Protocol step 1. */
    CHECK(secp256k1_ecdsa_anti_exfil_host_commit(ctx, host_commitment, host_nonce_contribution) == 1);
    /* Protocol step 2. */
    CHECK(secp256k1_ecdsa_anti_exfil_signer_commit(ctx, &s2c_opening, host_msg, signer_privkey, host_commitment) == 1);
    /* Protocol step 3: host_nonce_contribution send to signer to be used in step 4. */
    /* Protocol step 4. */
    CHECK(secp256k1_anti_exfil_sign(ctx, &signature, host_msg, signer_privkey, host_nonce_contribution) == 1);
    /* Protocol step 5. */
    CHECK(secp256k1_anti_exfil_host_verify(ctx, &signature, host_msg, &signer_pubkey, host_nonce_contribution, &s2c_opening) == 1);
    /* Protocol step 5 (explicitly) */
    CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, host_nonce_contribution, &s2c_opening) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature, host_msg, &signer_pubkey) == 1);

    { /* host_verify: commitment does not match */
        unsigned char sigbytes[64];
        size_t i;
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, sigbytes, &signature) == 1);
        for(i = 0; i < 32; i++) {
            /* change one byte */
            sigbytes[i] += 1;
            CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sigbytes) == 1);
            CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, host_nonce_contribution, &s2c_opening) == 0);
            CHECK(secp256k1_anti_exfil_host_verify(ctx, &signature, host_msg, &signer_pubkey, host_nonce_contribution, &s2c_opening) == 0);
            /* revert */
            sigbytes[i] -= 1;
        }
        CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sigbytes) == 1);
    }
    { /* host_verify: message does not match */
        unsigned char bad_msg[32];
        secp256k1_testrand256_test(bad_msg);
        CHECK(secp256k1_anti_exfil_host_verify(ctx, &signature, host_msg, &signer_pubkey, host_nonce_contribution, &s2c_opening) == 1);
        CHECK(secp256k1_anti_exfil_host_verify(ctx, &signature, bad_msg, &signer_pubkey, host_nonce_contribution, &s2c_opening) == 0);
    }
    { /* s2c_sign: host provided data that didn't match commitment */
        secp256k1_ecdsa_s2c_opening orig_opening = s2c_opening;
        unsigned char bad_nonce_contribution[32] = { 1, 2, 3, 4 };
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, host_msg, signer_privkey, bad_nonce_contribution) == 1);
        /* good signature but the opening (original public nonce does not match the original */
        CHECK(secp256k1_ecdsa_verify(ctx, &signature, host_msg, &signer_pubkey) == 1);
        CHECK(secp256k1_anti_exfil_host_verify(ctx, &signature, host_msg, &signer_pubkey, host_nonce_contribution, &s2c_opening) == 0);
        CHECK(secp256k1_anti_exfil_host_verify(ctx, &signature, host_msg, &signer_pubkey, bad_nonce_contribution, &s2c_opening) == 1);
        CHECK(memcmp(&s2c_opening, &orig_opening, sizeof(s2c_opening)) != 0);
    }
}

static void run_ecdsa_s2c_tests(void) {
    run_s2c_opening_test();
    test_ecdsa_s2c_tagged_hash();
    test_ecdsa_s2c_api();
    test_ecdsa_s2c_fixed_vectors();
    test_ecdsa_s2c_sign_verify();

    test_ecdsa_anti_exfil_signer_commit();
    test_ecdsa_anti_exfil();
}

#endif /* SECP256K1_MODULE_ECDSA_S2C_TESTS_H */
