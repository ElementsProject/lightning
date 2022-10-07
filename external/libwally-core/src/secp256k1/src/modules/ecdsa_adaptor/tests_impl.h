#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H

#include "include/secp256k1_ecdsa_adaptor.h"

void rand_scalar(secp256k1_scalar *scalar) {
    unsigned char buf32[32];
    secp256k1_testrand256(buf32);
    secp256k1_scalar_set_b32(scalar, buf32, NULL);
}

void rand_point(secp256k1_ge *point) {
    secp256k1_scalar x;
    secp256k1_gej pointj;
    rand_scalar(&x);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pointj, &x);
    secp256k1_ge_set_gej(point, &pointj);
}

void dleq_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    secp256k1_scalar k1, k2;

    CHECK(secp256k1_dleq_nonce(&k1, args[0], args[1], args[2], args[3], NULL, args[4]) == 1);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    CHECK(secp256k1_dleq_nonce(&k2, args[0], args[1], args[2], args[3], NULL, args[4]) == 1);
    CHECK(secp256k1_scalar_eq(&k1, &k2) == 0);
}

void dleq_tests(void) {
    secp256k1_scalar s, e, sk, k;
    secp256k1_ge gen2, p1, p2;
    unsigned char *args[5];
    unsigned char sk32[32];
    unsigned char gen2_33[33];
    unsigned char p1_33[33];
    unsigned char p2_33[33];
    unsigned char aux_rand[32];
    int i;
    size_t pubkey_size = 33;

    rand_point(&gen2);
    rand_scalar(&sk);
    secp256k1_dleq_pair(&ctx->ecmult_gen_ctx, &p1, &p2, &sk, &gen2);
    CHECK(secp256k1_dleq_prove(ctx, &s, &e, &sk, &gen2, &p1, &p2, NULL, NULL) == 1);
    CHECK(secp256k1_dleq_verify(&s, &e, &p1, &gen2, &p2) == 1);

    {
        secp256k1_scalar tmp;
        secp256k1_scalar_set_int(&tmp, 1);
        CHECK(secp256k1_dleq_verify(&tmp, &e, &p1, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&s, &tmp, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_ge p_tmp;
        rand_point(&p_tmp);
        CHECK(secp256k1_dleq_verify(&s, &e, &p_tmp, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&s, &e, &p1, &p_tmp, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&s, &e, &p1, &gen2, &p_tmp) == 0);
    }
    {
        secp256k1_ge p_inf;
        secp256k1_ge_set_infinity(&p_inf);
        CHECK(secp256k1_dleq_prove(ctx, &s, &e, &sk, &p_inf, &p1, &p2, NULL, NULL) == 0);
        CHECK(secp256k1_dleq_prove(ctx, &s, &e, &sk, &gen2, &p_inf, &p2, NULL, NULL) == 0);
        CHECK(secp256k1_dleq_prove(ctx, &s, &e, &sk, &gen2, &p1, &p_inf, NULL, NULL) == 0);
    }

    /* Nonce tests */
    secp256k1_scalar_get_b32(sk32, &sk);
    CHECK(secp256k1_eckey_pubkey_serialize(&gen2, gen2_33, &pubkey_size, 1));
    CHECK(secp256k1_eckey_pubkey_serialize(&p1, p1_33, &pubkey_size, 1));
    CHECK(secp256k1_eckey_pubkey_serialize(&p2, p2_33, &pubkey_size, 1));
    CHECK(secp256k1_dleq_nonce(&k, sk32, gen2_33, p1_33, p2_33, NULL, NULL) == 1);

    secp256k1_testrand_bytes_test(sk32, sizeof(sk32));
    secp256k1_testrand_bytes_test(gen2_33, sizeof(gen2_33));
    secp256k1_testrand_bytes_test(p1_33, sizeof(p1_33));
    secp256k1_testrand_bytes_test(p2_33, sizeof(p2_33));
    secp256k1_testrand_bytes_test(aux_rand, sizeof(aux_rand));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = sk32;
    args[1] = gen2_33;
    args[2] = p1_33;
    args[3] = p2_33;
    args[4] = aux_rand;
    for (i = 0; i < count; i++) {
        dleq_nonce_bitflip(args, 0, sizeof(sk32));
        dleq_nonce_bitflip(args, 1, sizeof(gen2_33));
        dleq_nonce_bitflip(args, 2, sizeof(p1_33));
        /* Flip p2 */
        dleq_nonce_bitflip(args, 3, sizeof(p2_33));
        /* Flip p2 again */
        dleq_nonce_bitflip(args, 3, sizeof(p2_33));
        dleq_nonce_bitflip(args, 4, sizeof(aux_rand));
    }

    /* NULL aux_rand argument is allowed. */
    CHECK(secp256k1_dleq_nonce(&k, sk32, gen2_33, p1_33, p2_33, NULL, NULL) == 1);
}

void rand_flip_bit(unsigned char *array, size_t n) {
    array[secp256k1_testrand_int(n)] ^= 1 << secp256k1_testrand_int(8);
}

/* Helper function for test_ecdsa_adaptor_spec_vectors
 * Checks that the adaptor signature is valid for the public and encryption keys. */
void test_ecdsa_adaptor_spec_vectors_check_verify(const unsigned char *adaptor_sig162, const unsigned char *msg32, const unsigned char *pubkey33, const unsigned char *encryption_key33, int expected) {
    secp256k1_pubkey pubkey;
    secp256k1_ge pubkey_ge;
    secp256k1_pubkey encryption_key;
    secp256k1_ge encryption_key_ge;

    CHECK(secp256k1_eckey_pubkey_parse(&encryption_key_ge, encryption_key33, 33) == 1);
    secp256k1_pubkey_save(&encryption_key, &encryption_key_ge);
    CHECK(secp256k1_eckey_pubkey_parse(&pubkey_ge, pubkey33, 33) == 1);
    secp256k1_pubkey_save(&pubkey, &pubkey_ge);

    CHECK(expected == secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig162, &pubkey, msg32, &encryption_key));
}

/* Helper function for test_ecdsa_adaptor_spec_vectors
 * Checks that the signature can be decrypted from the adaptor signature and the decryption key. */
void test_ecdsa_adaptor_spec_vectors_check_decrypt(const unsigned char *adaptor_sig162, const unsigned char *decryption_key32, const unsigned char *signature64, int expected) {
    unsigned char signature[64];
    secp256k1_ecdsa_signature s;

    CHECK(secp256k1_ecdsa_adaptor_decrypt(ctx, &s, decryption_key32, adaptor_sig162) == 1);
    CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &s) == 1);

    CHECK(expected == !(secp256k1_memcmp_var(signature, signature64, 64)));
}

/* Helper function for test_ecdsa_adaptor_spec_vectors
 * Checks that the decryption key can be recovered from the adaptor signature, encryption key, and the signature. */
void test_ecdsa_adaptor_spec_vectors_check_recover(const unsigned char *adaptor_sig162, const unsigned char *encryption_key33, const unsigned char *decryption_key32, const unsigned char *signature64, int expected) {
    unsigned char deckey32[32] = { 0 };
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey encryption_key;
    secp256k1_ge encryption_key_ge;

    CHECK(secp256k1_eckey_pubkey_parse(&encryption_key_ge, encryption_key33, 33) == 1);
    secp256k1_pubkey_save(&encryption_key, &encryption_key_ge);

    CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &sig, signature64) == 1);
    CHECK(expected == secp256k1_ecdsa_adaptor_recover(ctx, deckey32, &sig, adaptor_sig162, &encryption_key));
    if (decryption_key32 != NULL) {
        CHECK(expected == !(secp256k1_memcmp_var(deckey32, decryption_key32, 32)));
    }
}

/* Helper function for test_ecdsa_adaptor_spec_vectors
 * Checks deserialization and serialization. */
void test_ecdsa_adaptor_spec_vectors_check_serialization(const unsigned char *adaptor_sig162, int expected) {
    unsigned char buf[162];
    secp256k1_scalar dleq_proof_s, dleq_proof_e;
    secp256k1_ge r, rp;
    secp256k1_scalar sp;
    secp256k1_scalar sigr;

    CHECK(expected == secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig162));
    if (expected == 1) {
        CHECK(secp256k1_ecdsa_adaptor_sig_serialize(buf, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s) == 1);
        CHECK(secp256k1_memcmp_var(buf, adaptor_sig162, 162) == 0);
    }
}

/* Test vectors according to ECDSA adaptor signature spec. See
 * https://github.com/discreetlogcontracts/dlcspecs/blob/596a177375932a47306f07e7385f398f52519a83/test/ecdsa_adaptor.json. */
void test_ecdsa_adaptor_spec_vectors(void) {
    {
        /* Test vector 0 */
        /* kind: verification test */
        /* plain valid adaptor signature  */
        const unsigned char adaptor_sig[162] = {
            0x03, 0x42, 0x4d, 0x14, 0xa5, 0x47, 0x1c, 0x04,
            0x8a, 0xb8, 0x7b, 0x3b, 0x83, 0xf6, 0x08, 0x5d,
            0x12, 0x5d, 0x58, 0x64, 0x24, 0x9a, 0xe4, 0x29,
            0x7a, 0x57, 0xc8, 0x4e, 0x74, 0x71, 0x0b, 0xb6,
            0x73, 0x02, 0x23, 0xf3, 0x25, 0x04, 0x2f, 0xce,
            0x53, 0x5d, 0x04, 0x0f, 0xee, 0x52, 0xec, 0x13,
            0x23, 0x1b, 0xf7, 0x09, 0xcc, 0xd8, 0x42, 0x33,
            0xc6, 0x94, 0x4b, 0x90, 0x31, 0x7e, 0x62, 0x52,
            0x8b, 0x25, 0x27, 0xdf, 0xf9, 0xd6, 0x59, 0xa9,
            0x6d, 0xb4, 0xc9, 0x9f, 0x97, 0x50, 0x16, 0x83,
            0x08, 0x63, 0x3c, 0x18, 0x67, 0xb7, 0x0f, 0x3a,
            0x18, 0xfb, 0x0f, 0x45, 0x39, 0xa1, 0xae, 0xce,
            0xdc, 0xd1, 0xfc, 0x01, 0x48, 0xfc, 0x22, 0xf3,
            0x6b, 0x63, 0x03, 0x08, 0x3e, 0xce, 0x3f, 0x87,
            0x2b, 0x18, 0xe3, 0x5d, 0x36, 0x8b, 0x39, 0x58,
            0xef, 0xe5, 0xfb, 0x08, 0x1f, 0x77, 0x16, 0x73,
            0x6c, 0xcb, 0x59, 0x8d, 0x26, 0x9a, 0xa3, 0x08,
            0x4d, 0x57, 0xe1, 0x85, 0x5e, 0x1e, 0xa9, 0xa4,
            0x5e, 0xfc, 0x10, 0x46, 0x3b, 0xbf, 0x32, 0xae,
            0x37, 0x80, 0x29, 0xf5, 0x76, 0x3c, 0xeb, 0x40,
            0x17, 0x3f
        };
        const unsigned char message_hash[32] = {
            0x81, 0x31, 0xe6, 0xf4, 0xb4, 0x57, 0x54, 0xf2,
            0xc9, 0x0b, 0xd0, 0x66, 0x88, 0xce, 0xea, 0xbc,
            0x0c, 0x45, 0x05, 0x54, 0x60, 0x72, 0x99, 0x28,
            0xb4, 0xee, 0xcf, 0x11, 0x02, 0x6a, 0x9e, 0x2d
        };
        const unsigned char pubkey[33] = {
            0x03, 0x5b, 0xe5, 0xe9, 0x47, 0x82, 0x09, 0x67,
            0x4a, 0x96, 0xe6, 0x0f, 0x1f, 0x03, 0x7f, 0x61,
            0x76, 0x54, 0x0f, 0xd0, 0x01, 0xfa, 0x1d, 0x64,
            0x69, 0x47, 0x70, 0xc5, 0x6a, 0x77, 0x09, 0xc4,
            0x2c
        };
        const unsigned char encryption_key[33] = {
            0x02, 0xc2, 0x66, 0x2c, 0x97, 0x48, 0x8b, 0x07,
            0xb6, 0xe8, 0x19, 0x12, 0x4b, 0x89, 0x89, 0x84,
            0x92, 0x06, 0x33, 0x4a, 0x4c, 0x2f, 0xbd, 0xf6,
            0x91, 0xf7, 0xb3, 0x4d, 0x2b, 0x16, 0xe9, 0xc2,
            0x93
        };
        const unsigned char decryption_key[32] = {
            0x0b, 0x2a, 0xba, 0x63, 0xb8, 0x85, 0xa0, 0xf0,
            0xe9, 0x6f, 0xa0, 0xf3, 0x03, 0x92, 0x0c, 0x7f,
            0xb7, 0x43, 0x1d, 0xdf, 0xa9, 0x43, 0x76, 0xad,
            0x94, 0xd9, 0x69, 0xfb, 0xf4, 0x10, 0x9d, 0xc8
        };
        const unsigned char signature[64] = {
            0x42, 0x4d, 0x14, 0xa5, 0x47, 0x1c, 0x04, 0x8a,
            0xb8, 0x7b, 0x3b, 0x83, 0xf6, 0x08, 0x5d, 0x12,
            0x5d, 0x58, 0x64, 0x24, 0x9a, 0xe4, 0x29, 0x7a,
            0x57, 0xc8, 0x4e, 0x74, 0x71, 0x0b, 0xb6, 0x73,
            0x29, 0xe8, 0x0e, 0x0e, 0xe6, 0x0e, 0x57, 0xaf,
            0x3e, 0x62, 0x5b, 0xba, 0xe1, 0x67, 0x2b, 0x1e,
            0xca, 0xa5, 0x8e, 0xff, 0xe6, 0x13, 0x42, 0x6b,
            0x02, 0x4f, 0xa1, 0x62, 0x1d, 0x90, 0x33, 0x94
        };
        test_ecdsa_adaptor_spec_vectors_check_verify(adaptor_sig, message_hash, pubkey, encryption_key, 1);
        test_ecdsa_adaptor_spec_vectors_check_decrypt(adaptor_sig, decryption_key, signature, 1);
        test_ecdsa_adaptor_spec_vectors_check_recover(adaptor_sig, encryption_key, decryption_key, signature, 1);
    }
    {
        /* Test vector 1 */
        /* verification test */
        /* the decrypted signature is high so it must be negated first
         * AND the extracted decryption key must be negated */
        const unsigned char adaptor_sig[162] = {
            0x03, 0x60, 0x35, 0xc8, 0x98, 0x60, 0xec, 0x62,
            0xad, 0x15, 0x3f, 0x69, 0xb5, 0xb3, 0x07, 0x7b,
            0xcd, 0x08, 0xfb, 0xb0, 0xd2, 0x8d, 0xc7, 0xf7,
            0xf6, 0xdf, 0x4a, 0x05, 0xcc, 0xa3, 0x54, 0x55,
            0xbe, 0x03, 0x70, 0x43, 0xb6, 0x3c, 0x56, 0xf6,
            0x31, 0x7d, 0x99, 0x28, 0xe8, 0xf9, 0x10, 0x07,
            0x33, 0x57, 0x48, 0xc4, 0x98, 0x24, 0x22, 0x0d,
            0xb1, 0x4a, 0xd1, 0x0d, 0x80, 0xa5, 0xd0, 0x0a,
            0x96, 0x54, 0xaf, 0x09, 0x96, 0xc1, 0x82, 0x4c,
            0x64, 0xc9, 0x0b, 0x95, 0x1b, 0xb2, 0x73, 0x4a,
            0xae, 0xcf, 0x78, 0xd4, 0xb3, 0x61, 0x31, 0xa4,
            0x72, 0x38, 0xc3, 0xfa, 0x2b, 0xa2, 0x5e, 0x2c,
            0xed, 0x54, 0x25, 0x5b, 0x06, 0xdf, 0x69, 0x6d,
            0xe1, 0x48, 0x3c, 0x37, 0x67, 0x24, 0x2a, 0x37,
            0x28, 0x82, 0x6e, 0x05, 0xf7, 0x9e, 0x39, 0x81,
            0xe1, 0x25, 0x53, 0x35, 0x5b, 0xba, 0x8a, 0x01,
            0x31, 0xcd, 0x37, 0x0e, 0x63, 0xe3, 0xda, 0x73,
            0x10, 0x6f, 0x63, 0x85, 0x76, 0xa5, 0xaa, 0xb0,
            0xea, 0x6d, 0x45, 0xc0, 0x42, 0x57, 0x4c, 0x0c,
            0x8d, 0x0b, 0x14, 0xb8, 0xc7, 0xc0, 0x1c, 0xfe,
            0x90, 0x72
        };
        const unsigned char message_hash[32] = {
            0x81, 0x31, 0xe6, 0xf4, 0xb4, 0x57, 0x54, 0xf2,
            0xc9, 0x0b, 0xd0, 0x66, 0x88, 0xce, 0xea, 0xbc,
            0x0c, 0x45, 0x05, 0x54, 0x60, 0x72, 0x99, 0x28,
            0xb4, 0xee, 0xcf, 0x11, 0x02, 0x6a, 0x9e, 0x2d
        };
        const unsigned char pubkey[33] = {
            0x03, 0x5b, 0xe5, 0xe9, 0x47, 0x82, 0x09, 0x67,
            0x4a, 0x96, 0xe6, 0x0f, 0x1f, 0x03, 0x7f, 0x61,
            0x76, 0x54, 0x0f, 0xd0, 0x01, 0xfa, 0x1d, 0x64,
            0x69, 0x47, 0x70, 0xc5, 0x6a, 0x77, 0x09, 0xc4,
            0x2c
        };
        const unsigned char encryption_key[33] = {
            0x02, 0x4e, 0xee, 0x18, 0xbe, 0x9a, 0x5a, 0x52,
            0x24, 0x00, 0x0f, 0x91, 0x6c, 0x80, 0xb3, 0x93,
            0x44, 0x79, 0x89, 0xe7, 0x19, 0x4b, 0xc0, 0xb0,
            0xf1, 0xad, 0x7a, 0x03, 0x36, 0x97, 0x02, 0xbb,
            0x51
        };
        const unsigned char decryption_key[32] = {
            0xdb, 0x2d, 0xeb, 0xdd, 0xb0, 0x02, 0x47, 0x3a,
            0x00, 0x1d, 0xd7, 0x0b, 0x06, 0xf6, 0xc9, 0x7b,
            0xdc, 0xd1, 0xc4, 0x6b, 0xa1, 0x00, 0x12, 0x37,
            0xfe, 0x0e, 0xe1, 0xae, 0xff, 0xb2, 0xb6, 0xc4
        };
        const unsigned char signature[64] = {
            0x60, 0x35, 0xc8, 0x98, 0x60, 0xec, 0x62, 0xad,
            0x15, 0x3f, 0x69, 0xb5, 0xb3, 0x07, 0x7b, 0xcd,
            0x08, 0xfb, 0xb0, 0xd2, 0x8d, 0xc7, 0xf7, 0xf6,
            0xdf, 0x4a, 0x05, 0xcc, 0xa3, 0x54, 0x55, 0xbe,
            0x4c, 0xea, 0xcf, 0x92, 0x15, 0x46, 0xc0, 0x3d,
            0xd1, 0xbe, 0x59, 0x67, 0x23, 0xad, 0x1e, 0x76,
            0x91, 0xbd, 0xac, 0x73, 0xd8, 0x8c, 0xc3, 0x6c,
            0x42, 0x1c, 0x5e, 0x7f, 0x08, 0x38, 0x43, 0x05
        };
        test_ecdsa_adaptor_spec_vectors_check_verify(adaptor_sig, message_hash, pubkey, encryption_key, 1);
        test_ecdsa_adaptor_spec_vectors_check_decrypt(adaptor_sig, decryption_key, signature, 1);
        test_ecdsa_adaptor_spec_vectors_check_recover(adaptor_sig, encryption_key, decryption_key, signature, 1);
    }
    {
        /* Test vector 2 */
        /* verification test */
        /* proof is wrong */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xf9, 0x4d, 0xca, 0x20, 0x6d, 0x75, 0x82,
            0xc0, 0x15, 0xfb, 0x9b, 0xff, 0xe4, 0xe4, 0x3b,
            0x14, 0x59, 0x1b, 0x30, 0xef, 0x7d, 0x2b, 0x46,
            0x4d, 0x10, 0x3e, 0xc5, 0xe1, 0x16, 0x59, 0x5d,
            0xba, 0x03, 0x12, 0x7f, 0x8a, 0xc3, 0x53, 0x3d,
            0x24, 0x92, 0x80, 0x33, 0x24, 0x74, 0x33, 0x90,
            0x00, 0x92, 0x2e, 0xb6, 0xa5, 0x8e, 0x3b, 0x9b,
            0xf4, 0xfc, 0x7e, 0x01, 0xe4, 0xb4, 0xdf, 0x2b,
            0x7a, 0x41, 0x00, 0xa1, 0xe0, 0x89, 0xf1, 0x6e,
            0x5d, 0x70, 0xbb, 0x89, 0xf9, 0x61, 0x51, 0x6f,
            0x1d, 0xe0, 0x68, 0x4c, 0xc7, 0x9d, 0xb9, 0x78,
            0x49, 0x5d, 0xf2, 0xf3, 0x99, 0xb0, 0xd0, 0x1e,
            0xd7, 0x24, 0x0f, 0xa6, 0xe3, 0x25, 0x2a, 0xed,
            0xb5, 0x8b, 0xdc, 0x6b, 0x58, 0x77, 0xb0, 0xc6,
            0x02, 0x62, 0x8a, 0x23, 0x5d, 0xd1, 0xcc, 0xae,
            0xbd, 0xdd, 0xcb, 0xe9, 0x61, 0x98, 0xc0, 0xc2,
            0x1b, 0xea, 0xd7, 0xb0, 0x5f, 0x42, 0x3b, 0x67,
            0x3d, 0x14, 0xd2, 0x06, 0xfa, 0x15, 0x07, 0xb2,
            0xdb, 0xe2, 0x72, 0x2a, 0xf7, 0x92, 0xb8, 0xc2,
            0x66, 0xfc, 0x25, 0xa2, 0xd9, 0x01, 0xd7, 0xe2,
            0xc3, 0x35
        };
        const unsigned char message_hash[32] = {
            0x81, 0x31, 0xe6, 0xf4, 0xb4, 0x57, 0x54, 0xf2,
            0xc9, 0x0b, 0xd0, 0x66, 0x88, 0xce, 0xea, 0xbc,
            0x0c, 0x45, 0x05, 0x54, 0x60, 0x72, 0x99, 0x28,
            0xb4, 0xee, 0xcf, 0x11, 0x02, 0x6a, 0x9e, 0x2d
        };
        const unsigned char pubkey[33] = {
            0x03, 0x5b, 0xe5, 0xe9, 0x47, 0x82, 0x09, 0x67,
            0x4a, 0x96, 0xe6, 0x0f, 0x1f, 0x03, 0x7f, 0x61,
            0x76, 0x54, 0x0f, 0xd0, 0x01, 0xfa, 0x1d, 0x64,
            0x69, 0x47, 0x70, 0xc5, 0x6a, 0x77, 0x09, 0xc4,
            0x2c
        };
        const unsigned char encryption_key[33] = {
            0x02, 0x14, 0xcc, 0xb7, 0x56, 0x24, 0x9a, 0xd6,
            0xe7, 0x33, 0xc8, 0x02, 0x85, 0xea, 0x7a, 0xc2,
            0xee, 0x12, 0xff, 0xeb, 0xbc, 0xee, 0x4e, 0x55,
            0x6e, 0x68, 0x10, 0x79, 0x3a, 0x60, 0xc4, 0x5a,
            0xd4
        };
        const unsigned char decryption_key[32] = {
            0x1d, 0xfc, 0xfc, 0x08, 0x80, 0xe7, 0x25, 0x09,
            0x76, 0x8a, 0xb4, 0x6f, 0x25, 0x45, 0xb3, 0x31,
            0x68, 0xb8, 0xb8, 0xdf, 0x8e, 0x4f, 0x5f, 0xeb,
            0x50, 0x59, 0xaa, 0x37, 0x50, 0xee, 0x59, 0xd0
        };
        const unsigned char signature[64] = {
            0x42, 0x4d, 0x14, 0xa5, 0x47, 0x1c, 0x04, 0x8a,
            0xb8, 0x7b, 0x3b, 0x83, 0xf6, 0x08, 0x5d, 0x12,
            0x5d, 0x58, 0x64, 0x24, 0x9a, 0xe4, 0x29, 0x7a,
            0x57, 0xc8, 0x4e, 0x74, 0x71, 0x0b, 0xb6, 0x73,
            0x29, 0xe8, 0x0e, 0x0e, 0xe6, 0x0e, 0x57, 0xaf,
            0x3e, 0x62, 0x5b, 0xba, 0xe1, 0x67, 0x2b, 0x1e,
            0xca, 0xa5, 0x8e, 0xff, 0xe6, 0x13, 0x42, 0x6b,
            0x02, 0x4f, 0xa1, 0x62, 0x1d, 0x90, 0x33, 0x94
        };
        test_ecdsa_adaptor_spec_vectors_check_verify(adaptor_sig, message_hash, pubkey, encryption_key, 0);
        test_ecdsa_adaptor_spec_vectors_check_decrypt(adaptor_sig, decryption_key, signature, 0);
        test_ecdsa_adaptor_spec_vectors_check_recover(adaptor_sig, encryption_key, decryption_key, signature, 0);
    }
    {
        /* Test vector 3 */
        /* recovery test */
        /* plain recovery */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xf2, 0xdb, 0x6e, 0x9e, 0xd3, 0x30, 0x92,
            0xcc, 0x0b, 0x89, 0x8f, 0xd6, 0xb2, 0x82, 0xe9,
            0x9b, 0xda, 0xec, 0xcb, 0x3d, 0xe8, 0x5c, 0x2d,
            0x25, 0x12, 0xd8, 0xd5, 0x07, 0xf9, 0xab, 0xab,
            0x29, 0x02, 0x10, 0xc0, 0x1b, 0x5b, 0xed, 0x70,
            0x94, 0xa1, 0x26, 0x64, 0xae, 0xaa, 0xb3, 0x40,
            0x2d, 0x87, 0x09, 0xa8, 0xf3, 0x62, 0xb1, 0x40,
            0x32, 0x8d, 0x1b, 0x36, 0xdd, 0x7c, 0xb4, 0x20,
            0xd0, 0x2f, 0xb6, 0x6b, 0x12, 0x30, 0xd6, 0x1c,
            0x16, 0xd0, 0xcd, 0x0a, 0x2a, 0x02, 0x24, 0x6d,
            0x5a, 0xc7, 0x84, 0x8d, 0xcd, 0x6f, 0x04, 0xfe,
            0x62, 0x70, 0x53, 0xcd, 0x3c, 0x70, 0x15, 0xa7,
            0xd4, 0xaa, 0x6a, 0xc2, 0xb0, 0x43, 0x47, 0x34,
            0x8b, 0xd6, 0x7d, 0xa4, 0x3b, 0xe8, 0x72, 0x25,
            0x15, 0xd9, 0x9a, 0x79, 0x85, 0xfb, 0xfa, 0x66,
            0xf0, 0x36, 0x5c, 0x70, 0x1d, 0xe7, 0x6f, 0xf0,
            0x40, 0x0d, 0xff, 0xdc, 0x9f, 0xa8, 0x4d, 0xdd,
            0xf4, 0x13, 0xa7, 0x29, 0x82, 0x3b, 0x16, 0xaf,
            0x60, 0xaa, 0x63, 0x61, 0xbc, 0x32, 0xe7, 0xcf,
            0xd6, 0x70, 0x1e, 0x32, 0x95, 0x7c, 0x72, 0xac,
            0xe6, 0x7b
        };
        const unsigned char encryption_key[33] = {
            0x02, 0x7e, 0xe4, 0xf8, 0x99, 0xbc, 0x9c, 0x5f,
            0x2b, 0x62, 0x6f, 0xa1, 0xa9, 0xb3, 0x7c, 0xe2,
            0x91, 0xc0, 0x38, 0x8b, 0x52, 0x27, 0xe9, 0x0b,
            0x0f, 0xd8, 0xf4, 0xfa, 0x57, 0x61, 0x64, 0xed,
            0xe7
        };
        const unsigned char decryption_key[32] = {
            0x9c, 0xf3, 0xea, 0x9b, 0xe5, 0x94, 0x36, 0x6b,
            0x78, 0xc4, 0x57, 0x16, 0x29, 0x08, 0xaf, 0x3c,
            0x2e, 0xa1, 0x77, 0x05, 0x81, 0x77, 0xe9, 0xc6,
            0xbf, 0x99, 0x04, 0x79, 0x27, 0x77, 0x3a, 0x06
        };
        const unsigned char signature[64] = {
            0xf2, 0xdb, 0x6e, 0x9e, 0xd3, 0x30, 0x92, 0xcc,
            0x0b, 0x89, 0x8f, 0xd6, 0xb2, 0x82, 0xe9, 0x9b,
            0xda, 0xec, 0xcb, 0x3d, 0xe8, 0x5c, 0x2d, 0x25,
            0x12, 0xd8, 0xd5, 0x07, 0xf9, 0xab, 0xab, 0x29,
            0x21, 0x81, 0x1f, 0xe7, 0xb5, 0x3b, 0xec, 0xf3,
            0xb7, 0xaf, 0xfa, 0x94, 0x42, 0xab, 0xaa, 0x93,
            0xc0, 0xab, 0x8a, 0x8e, 0x45, 0xcd, 0x7e, 0xe2,
            0xea, 0x8d, 0x25, 0x8b, 0xfc, 0x25, 0xd4, 0x64
        };
        test_ecdsa_adaptor_spec_vectors_check_decrypt(adaptor_sig, decryption_key, signature, 1);
        test_ecdsa_adaptor_spec_vectors_check_recover(adaptor_sig, encryption_key, decryption_key, signature, 1);
    }
    {
        /* Test vector 4 */
        /* recovery test */
        /* the R value of the signature does not match */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xaa, 0x86, 0xd7, 0x80, 0x59, 0xa9, 0x10,
            0x59, 0xc2, 0x9e, 0xc1, 0xa7, 0x57, 0xc4, 0xdc,
            0x02, 0x9f, 0xf6, 0x36, 0xa1, 0xe6, 0xc1, 0x14,
            0x2f, 0xef, 0xe1, 0xe9, 0xd7, 0x33, 0x96, 0x17,
            0xc0, 0x03, 0xa8, 0x15, 0x3e, 0x50, 0xc0, 0xc8,
            0x57, 0x4a, 0x38, 0xd3, 0x89, 0xe6, 0x1b, 0xbb,
            0x0b, 0x58, 0x15, 0x16, 0x9e, 0x06, 0x09, 0x24,
            0xe4, 0xb5, 0xf2, 0xe7, 0x8f, 0xf1, 0x3a, 0xa7,
            0xad, 0x85, 0x8e, 0x0c, 0x27, 0xc4, 0xb9, 0xee,
            0xd9, 0xd6, 0x05, 0x21, 0xb3, 0xf5, 0x4f, 0xf8,
            0x3c, 0xa4, 0x77, 0x4b, 0xe5, 0xfb, 0x3a, 0x68,
            0x0f, 0x82, 0x0a, 0x35, 0xe8, 0x84, 0x0f, 0x4a,
            0xaf, 0x2d, 0xe8, 0x8e, 0x7c, 0x5c, 0xff, 0x38,
            0xa3, 0x7b, 0x78, 0x72, 0x59, 0x04, 0xef, 0x97,
            0xbb, 0x82, 0x34, 0x13, 0x28, 0xd5, 0x59, 0x87,
            0x01, 0x9b, 0xd3, 0x8a, 0xe1, 0x74, 0x5e, 0x3e,
            0xfe, 0x0f, 0x8e, 0xa8, 0xbd, 0xfe, 0xde, 0x0d,
            0x37, 0x8f, 0xc1, 0xf9, 0x6e, 0x94, 0x4a, 0x75,
            0x05, 0x24, 0x9f, 0x41, 0xe9, 0x37, 0x81, 0x50,
            0x9e, 0xe0, 0xba, 0xde, 0x77, 0x29, 0x0d, 0x39,
            0xcd, 0x12
        };
        const unsigned char encryption_key[33] = {
            0x03, 0x51, 0x76, 0xd2, 0x41, 0x29, 0x74, 0x1b,
            0x0f, 0xca, 0xa5, 0xfd, 0x67, 0x50, 0x72, 0x7c,
            0xe3, 0x08, 0x60, 0x44, 0x7e, 0x0a, 0x92, 0xc9,
            0xeb, 0xeb, 0xde, 0xb7, 0xc3, 0xf9, 0x39, 0x95,
            0xed
        };
        const unsigned char signature[64] = {
            0xf7, 0xf7, 0xfe, 0x6b, 0xd0, 0x56, 0xfc, 0x4a,
            0xbd, 0x70, 0xd3, 0x35, 0xf7, 0x2d, 0x0a, 0xa1,
            0xe8, 0x40, 0x6b, 0xba, 0x68, 0xf3, 0xe5, 0x79,
            0xe4, 0x78, 0x94, 0x75, 0x32, 0x35, 0x64, 0xa4,
            0x52, 0xc4, 0x61, 0x76, 0xc7, 0xfb, 0x40, 0xaa,
            0x37, 0xd5, 0x65, 0x13, 0x41, 0xf5, 0x56, 0x97,
            0xda, 0xb2, 0x7d, 0x84, 0xa2, 0x13, 0xb3, 0x0c,
            0x93, 0x01, 0x1a, 0x77, 0x90, 0xba, 0xce, 0x8c
        };
        test_ecdsa_adaptor_spec_vectors_check_recover(adaptor_sig, encryption_key, NULL, signature, 0);
    }
    {
        /* Test vector 5 */
        /* recovery test */
        /* recovery from high s signature */
        const unsigned char adaptor_sig[162] = {
            0x03, 0x2c, 0x63, 0x7c, 0xd7, 0x97, 0xdd, 0x8c,
            0x2c, 0xe2, 0x61, 0x90, 0x7e, 0xd4, 0x3e, 0x82,
            0xd6, 0xd1, 0xa4, 0x8c, 0xba, 0xbb, 0xbe, 0xce,
            0x80, 0x11, 0x33, 0xdd, 0x8d, 0x70, 0xa0, 0x1b,
            0x14, 0x03, 0xeb, 0x61, 0x5a, 0x3e, 0x59, 0xb1,
            0xcb, 0xbf, 0x4f, 0x87, 0xac, 0xaf, 0x64, 0x5b,
            0xe1, 0xed, 0xa3, 0x2a, 0x06, 0x66, 0x11, 0xf3,
            0x5d, 0xd5, 0x55, 0x78, 0x02, 0x80, 0x2b, 0x14,
            0xb1, 0x9c, 0x81, 0xc0, 0x4c, 0x3f, 0xef, 0xac,
            0x57, 0x83, 0xb2, 0x07, 0x7b, 0xd4, 0x3f, 0xa0,
            0xa3, 0x9a, 0xb8, 0xa6, 0x4d, 0x4d, 0x78, 0x33,
            0x2a, 0x5d, 0x62, 0x1e, 0xa2, 0x3e, 0xca, 0x46,
            0xbc, 0x01, 0x10, 0x11, 0xab, 0x82, 0xdd, 0xa6,
            0xde, 0xb8, 0x56, 0x99, 0xf5, 0x08, 0x74, 0x4d,
            0x70, 0xd4, 0x13, 0x4b, 0xea, 0x03, 0xf7, 0x84,
            0xd2, 0x85, 0xb5, 0xc6, 0xc1, 0x5a, 0x56, 0xe4,
            0xe1, 0xfa, 0xb4, 0xbc, 0x35, 0x6a, 0xbb, 0xde,
            0xbb, 0x3b, 0x8f, 0xe1, 0xe5, 0x5e, 0x6d, 0xd6,
            0xd2, 0xa9, 0xea, 0x45, 0x7e, 0x91, 0xb2, 0xe6,
            0x64, 0x2f, 0xae, 0x69, 0xf9, 0xdb, 0xb5, 0x25,
            0x88, 0x54
        };
        const unsigned char encryption_key[33] = {
            0x02, 0x04, 0x25, 0x37, 0xe9, 0x13, 0xad, 0x74,
            0xc4, 0xbb, 0xd8, 0xda, 0x96, 0x07, 0xad, 0x3b,
            0x9c, 0xb2, 0x97, 0xd0, 0x8e, 0x01, 0x4a, 0xfc,
            0x51, 0x13, 0x30, 0x83, 0xf1, 0xbd, 0x68, 0x7a,
            0x62
        };
        const unsigned char decryption_key[32] = {
            0x32, 0x47, 0x19, 0xb5, 0x1f, 0xf2, 0x47, 0x4c,
            0x94, 0x38, 0xeb, 0x76, 0x49, 0x4b, 0x0d, 0xc0,
            0xbc, 0xce, 0xeb, 0x52, 0x9f, 0x0a, 0x54, 0x28,
            0xfd, 0x19, 0x8a, 0xd8, 0xf8, 0x86, 0xe9, 0x9c
        };
        const unsigned char signature[64] = {
            0x2c, 0x63, 0x7c, 0xd7, 0x97, 0xdd, 0x8c, 0x2c,
            0xe2, 0x61, 0x90, 0x7e, 0xd4, 0x3e, 0x82, 0xd6,
            0xd1, 0xa4, 0x8c, 0xba, 0xbb, 0xbe, 0xce, 0x80,
            0x11, 0x33, 0xdd, 0x8d, 0x70, 0xa0, 0x1b, 0x14,
            0xb5, 0xf2, 0x43, 0x21, 0xf5, 0x50, 0xb7, 0xb9,
            0xdd, 0x06, 0xee, 0x4f, 0xcf, 0xd8, 0x2b, 0xda,
            0xd8, 0xb1, 0x42, 0xff, 0x93, 0xa7, 0x90, 0xcc,
            0x4d, 0x9f, 0x79, 0x62, 0xb3, 0x8c, 0x6a, 0x3b
        };
        test_ecdsa_adaptor_spec_vectors_check_decrypt(adaptor_sig, decryption_key, signature, 0);
        test_ecdsa_adaptor_spec_vectors_check_recover(adaptor_sig, encryption_key, decryption_key, signature, 1);
    }
    {
        /* Test vector 6 */
        /* serialization test */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xe6, 0xd5, 0x1d, 0xa7, 0xbc, 0x2b, 0xf2,
            0x4c, 0xf9, 0xdf, 0xd9, 0xac, 0xc6, 0xc4, 0xf0,
            0xa3, 0xe7, 0x4d, 0x8a, 0x62, 0x73, 0xee, 0x5a,
            0x57, 0x3e, 0xd6, 0x81, 0x8e, 0x30, 0x95, 0xb6,
            0x09, 0x03, 0xf3, 0x3b, 0xc9, 0x8f, 0x9d, 0x2e,
            0xa3, 0x51, 0x1f, 0x2e, 0x24, 0xf3, 0x35, 0x85,
            0x57, 0xc8, 0x15, 0xab, 0xd7, 0x71, 0x3c, 0x93,
            0x18, 0xaf, 0x9f, 0x4d, 0xfa, 0xb4, 0x44, 0x18,
            0x98, 0xec, 0xd6, 0x19, 0xac, 0xb1, 0xcb, 0x75,
            0xc1, 0xa5, 0x94, 0x6f, 0xba, 0xf7, 0x16, 0xd2,
            0x27, 0x19, 0x9a, 0x64, 0x79, 0xa6, 0x78, 0xd1,
            0x0a, 0x6d, 0x95, 0x51, 0x2d, 0x67, 0x4f, 0xb7,
            0x70, 0x3d, 0x85, 0xb5, 0x89, 0x80, 0xb8, 0xe6,
            0xc5, 0x4b, 0xd2, 0x06, 0x16, 0xbd, 0xb9, 0x46,
            0x1d, 0xcc, 0xd8, 0xee, 0xbb, 0x7d, 0x7e, 0x7c,
            0x83, 0xa9, 0x14, 0x52, 0xcc, 0x20, 0xed, 0xf5,
            0x3b, 0xe5, 0xb0, 0xfe, 0x0d, 0xb4, 0x4d, 0xdd,
            0xaa, 0xaf, 0xbe, 0x73, 0x76, 0x78, 0xc6, 0x84,
            0xb6, 0xe8, 0x9b, 0x9b, 0x4b, 0x67, 0x9b, 0x18,
            0x55, 0xaa, 0x6e, 0xd6, 0x44, 0x49, 0x8b, 0x89,
            0xc9, 0x18
        };
        test_ecdsa_adaptor_spec_vectors_check_serialization(adaptor_sig, 1);
    }
    {
        /* Test vector 7 */
        /* serialization test */
        /* R can be above curve order */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc,
            0x2c, 0x03, 0xf3, 0x3b, 0xc9, 0x8f, 0x9d, 0x2e,
            0xa3, 0x51, 0x1f, 0x2e, 0x24, 0xf3, 0x35, 0x85,
            0x57, 0xc8, 0x15, 0xab, 0xd7, 0x71, 0x3c, 0x93,
            0x18, 0xaf, 0x9f, 0x4d, 0xfa, 0xb4, 0x44, 0x18,
            0x98, 0xec, 0xd6, 0x19, 0xac, 0xb1, 0xcb, 0x75,
            0xc1, 0xa5, 0x94, 0x6f, 0xba, 0xf7, 0x16, 0xd2,
            0x27, 0x19, 0x9a, 0x64, 0x79, 0xa6, 0x78, 0xd1,
            0x0a, 0x6d, 0x95, 0x51, 0x2d, 0x67, 0x4f, 0xb7,
            0x70, 0x3d, 0x85, 0xb5, 0x89, 0x80, 0xb8, 0xe6,
            0xc5, 0x4b, 0xd2, 0x06, 0x16, 0xbd, 0xb9, 0x46,
            0x1d, 0xcc, 0xd8, 0xee, 0xbb, 0x7d, 0x7e, 0x7c,
            0x83, 0xa9, 0x14, 0x52, 0xcc, 0x20, 0xed, 0xf5,
            0x3b, 0xe5, 0xb0, 0xfe, 0x0d, 0xb4, 0x4d, 0xdd,
            0xaa, 0xaf, 0xbe, 0x73, 0x76, 0x78, 0xc6, 0x84,
            0xb6, 0xe8, 0x9b, 0x9b, 0x4b, 0x67, 0x9b, 0x18,
            0x55, 0xaa, 0x6e, 0xd6, 0x44, 0x49, 0x8b, 0x89,
            0xc9, 0x18
        };
        test_ecdsa_adaptor_spec_vectors_check_serialization(adaptor_sig, 1);
    }
    {
        /* Test vector 8 */
        /* serialization test */
        /* R_a can be above curve order */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xe6, 0xd5, 0x1d, 0xa7, 0xbc, 0x2b, 0xf2,
            0x4c, 0xf9, 0xdf, 0xd9, 0xac, 0xc6, 0xc4, 0xf0,
            0xa3, 0xe7, 0x4d, 0x8a, 0x62, 0x73, 0xee, 0x5a,
            0x57, 0x3e, 0xd6, 0x81, 0x8e, 0x30, 0x95, 0xb6,
            0x09, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
            0xfc, 0x2c, 0xd6, 0x19, 0xac, 0xb1, 0xcb, 0x75,
            0xc1, 0xa5, 0x94, 0x6f, 0xba, 0xf7, 0x16, 0xd2,
            0x27, 0x19, 0x9a, 0x64, 0x79, 0xa6, 0x78, 0xd1,
            0x0a, 0x6d, 0x95, 0x51, 0x2d, 0x67, 0x4f, 0xb7,
            0x70, 0x3d, 0x85, 0xb5, 0x89, 0x80, 0xb8, 0xe6,
            0xc5, 0x4b, 0xd2, 0x06, 0x16, 0xbd, 0xb9, 0x46,
            0x1d, 0xcc, 0xd8, 0xee, 0xbb, 0x7d, 0x7e, 0x7c,
            0x83, 0xa9, 0x14, 0x52, 0xcc, 0x20, 0xed, 0xf5,
            0x3b, 0xe5, 0xb0, 0xfe, 0x0d, 0xb4, 0x4d, 0xdd,
            0xaa, 0xaf, 0xbe, 0x73, 0x76, 0x78, 0xc6, 0x84,
            0xb6, 0xe8, 0x9b, 0x9b, 0x4b, 0x67, 0x9b, 0x18,
            0x55, 0xaa, 0x6e, 0xd6, 0x44, 0x49, 0x8b, 0x89,
            0xc9, 0x18
        };
        test_ecdsa_adaptor_spec_vectors_check_serialization(adaptor_sig, 1);
    }
    {
        /* Test vector 9 */
        /* serialization test */
        /* s_a cannot be zero */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xe6, 0xd5, 0x1d, 0xa7, 0xbc, 0x2b, 0xf2,
            0x4c, 0xf9, 0xdf, 0xd9, 0xac, 0xc6, 0xc4, 0xf0,
            0xa3, 0xe7, 0x4d, 0x8a, 0x62, 0x73, 0xee, 0x5a,
            0x57, 0x3e, 0xd6, 0x81, 0x8e, 0x30, 0x95, 0xb6,
            0x09, 0x03, 0xf3, 0x3b, 0xc9, 0x8f, 0x9d, 0x2e,
            0xa3, 0x51, 0x1f, 0x2e, 0x24, 0xf3, 0x35, 0x85,
            0x57, 0xc8, 0x15, 0xab, 0xd7, 0x71, 0x3c, 0x93,
            0x18, 0xaf, 0x9f, 0x4d, 0xfa, 0xb4, 0x44, 0x18,
            0x98, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x85, 0xb5, 0x89, 0x80, 0xb8, 0xe6,
            0xc5, 0x4b, 0xd2, 0x06, 0x16, 0xbd, 0xb9, 0x46,
            0x1d, 0xcc, 0xd8, 0xee, 0xbb, 0x7d, 0x7e, 0x7c,
            0x83, 0xa9, 0x14, 0x52, 0xcc, 0x20, 0xed, 0xf5,
            0x3b, 0xe5, 0xb0, 0xfe, 0x0d, 0xb4, 0x4d, 0xdd,
            0xaa, 0xaf, 0xbe, 0x73, 0x76, 0x78, 0xc6, 0x84,
            0xb6, 0xe8, 0x9b, 0x9b, 0x4b, 0x67, 0x9b, 0x18,
            0x55, 0xaa, 0x6e, 0xd6, 0x44, 0x49, 0x8b, 0x89,
            0xc9, 0x18
        };
        test_ecdsa_adaptor_spec_vectors_check_serialization(adaptor_sig, 0);
    }
    {
        /* Test vector 10 */
        /* serialization test */
        /* s_a too high */
        const unsigned char adaptor_sig[162] = {
            0x03, 0xe6, 0xd5, 0x1d, 0xa7, 0xbc, 0x2b, 0xf2,
            0x4c, 0xf9, 0xdf, 0xd9, 0xac, 0xc6, 0xc4, 0xf0,
            0xa3, 0xe7, 0x4d, 0x8a, 0x62, 0x73, 0xee, 0x5a,
            0x57, 0x3e, 0xd6, 0x81, 0x8e, 0x30, 0x95, 0xb6,
            0x09, 0x03, 0xf3, 0x3b, 0xc9, 0x8f, 0x9d, 0x2e,
            0xa3, 0x51, 0x1f, 0x2e, 0x24, 0xf3, 0x35, 0x85,
            0x57, 0xc8, 0x15, 0xab, 0xd7, 0x71, 0x3c, 0x93,
            0x18, 0xaf, 0x9f, 0x4d, 0xfa, 0xb4, 0x44, 0x18,
            0x98, 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
            0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
            0x41, 0x41, 0x85, 0xb5, 0x89, 0x80, 0xb8, 0xe6,
            0xc5, 0x4b, 0xd2, 0x06, 0x16, 0xbd, 0xb9, 0x46,
            0x1d, 0xcc, 0xd8, 0xee, 0xbb, 0x7d, 0x7e, 0x7c,
            0x83, 0xa9, 0x14, 0x52, 0xcc, 0x20, 0xed, 0xf5,
            0x3b, 0xe5, 0xb0, 0xfe, 0x0d, 0xb4, 0x4d, 0xdd,
            0xaa, 0xaf, 0xbe, 0x73, 0x76, 0x78, 0xc6, 0x84,
            0xb6, 0xe8, 0x9b, 0x9b, 0x4b, 0x67, 0x9b, 0x18,
            0x55, 0xaa, 0x6e, 0xd6, 0x44, 0x49, 0x8b, 0x89,
            0xc9, 0x18
        };
        test_ecdsa_adaptor_spec_vectors_check_serialization(adaptor_sig, 0);
    }
}

/* Nonce function that returns constant 0 */
static int ecdsa_adaptor_nonce_function_failing(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *encryption_key33, const unsigned char *algo, size_t algolen, void *data) {
    (void) msg32;
    (void) key32;
    (void) encryption_key33;
    (void) algo;
    (void) algolen;
    (void) data;
    (void) nonce32;
    return 0;
}

/* Nonce function that sets nonce to 0 */
static int ecdsa_adaptor_nonce_function_0(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *encryption_key33, const unsigned char *algo, size_t algolen, void *data) {
    (void) msg32;
    (void) key32;
    (void) encryption_key33;
    (void) algo;
    (void) algolen;
    (void) data;

    memset(nonce32, 0, 32);
    return 1;
}

/* Nonce function that sets nonce to 0xFF...0xFF */
static int ecdsa_adaptor_nonce_function_overflowing(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *encryption_key33, const unsigned char *algo, size_t algolen, void *data) {
    (void) msg32;
    (void) key32;
    (void) encryption_key33;
    (void) algo;
    (void) algolen;
    (void) data;

    memset(nonce32, 0xFF, 32);
    return 1;
}

/* Checks that a bit flip in the n_flip-th argument (that has n_bytes many
 * bytes) changes the hash function
 */
void nonce_function_ecdsa_adaptor_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes, size_t algolen) {
    unsigned char nonces[2][32];
    CHECK(nonce_function_ecdsa_adaptor(nonces[0], args[0], args[1], args[2], args[3], algolen, args[4]) == 1);
    secp256k1_testrand_flip(args[n_flip], n_bytes);
    CHECK(nonce_function_ecdsa_adaptor(nonces[1], args[0], args[1], args[2], args[3], algolen, args[4]) == 1);
    CHECK(secp256k1_memcmp_var(nonces[0], nonces[1], 32) != 0);
}

/* Tests for the equality of two sha256 structs. This function only produces a
 * correct result if an integer multiple of 64 many bytes have been written
 * into the hash functions. */
void ecdsa_adaptor_test_sha256_eq(const secp256k1_sha256 *sha1, const secp256k1_sha256 *sha2) {
    /* Is buffer fully consumed? */
    CHECK((sha1->bytes & 0x3F) == 0);

    CHECK(sha1->bytes == sha2->bytes);
    CHECK(secp256k1_memcmp_var(sha1->s, sha2->s, sizeof(sha1->s)) == 0);
}

void run_nonce_function_ecdsa_adaptor_tests(void) {
    unsigned char tag[16] = "ECDSAadaptor/non";
    unsigned char aux_tag[16] = "ECDSAadaptor/aux";
    unsigned char algo[16] = "ECDSAadaptor/non";
    size_t algolen = sizeof(algo);
    unsigned char dleq_tag[4] = "DLEQ";
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;
    unsigned char nonce[32];
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char pk[33];
    unsigned char aux_rand[32];
    unsigned char *args[5];
    int i;

    /* Check that hash initialized by
     * secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged has the expected
     * state. */
    secp256k1_sha256_initialize_tagged(&sha, tag, sizeof(tag));
    secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged(&sha_optimized);
    ecdsa_adaptor_test_sha256_eq(&sha, &sha_optimized);

   /* Check that hash initialized by
    * secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged_aux has the expected
    * state. */
    secp256k1_sha256_initialize_tagged(&sha, aux_tag, sizeof(aux_tag));
    secp256k1_nonce_function_ecdsa_adaptor_sha256_tagged_aux(&sha_optimized);
    ecdsa_adaptor_test_sha256_eq(&sha, &sha_optimized);

   /* Check that hash initialized by
    * secp256k1_nonce_function_dleq_sha256_tagged_aux has the expected
    * state. */
    secp256k1_sha256_initialize_tagged(&sha, dleq_tag, sizeof(dleq_tag));
    secp256k1_nonce_function_dleq_sha256_tagged(&sha_optimized);
    ecdsa_adaptor_test_sha256_eq(&sha, &sha_optimized);

    secp256k1_testrand_bytes_test(msg, sizeof(msg));
    secp256k1_testrand_bytes_test(key, sizeof(key));
    secp256k1_testrand_bytes_test(pk, sizeof(pk));
    secp256k1_testrand_bytes_test(aux_rand, sizeof(aux_rand));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = msg;
    args[1] = key;
    args[2] = pk;
    args[3] = algo;
    args[4] = aux_rand;
    for (i = 0; i < count; i++) {
        nonce_function_ecdsa_adaptor_bitflip(args, 0, sizeof(msg), algolen);
        nonce_function_ecdsa_adaptor_bitflip(args, 1, sizeof(key), algolen);
        nonce_function_ecdsa_adaptor_bitflip(args, 2, sizeof(pk), algolen);
        /* Flip algo special case "ECDSAadaptor/non" */
        nonce_function_ecdsa_adaptor_bitflip(args, 3, sizeof(algo), algolen);
        /* Flip algo again */
        nonce_function_ecdsa_adaptor_bitflip(args, 3, sizeof(algo), algolen);
        nonce_function_ecdsa_adaptor_bitflip(args, 4, sizeof(aux_rand), algolen);
    }

    /* NULL algo is disallowed */
    CHECK(nonce_function_ecdsa_adaptor(nonce, msg, key, pk, NULL, 0, NULL) == 0);
    /* Empty algo is fine */
    memset(algo, 0x00, algolen);
    CHECK(nonce_function_ecdsa_adaptor(nonce, msg, key, pk, algo, algolen, NULL) == 1);
    /* Other algo is fine */
    memset(algo, 0xFF, algolen);
    CHECK(nonce_function_ecdsa_adaptor(nonce, msg, key, pk, algo, algolen, NULL) == 1);
    /* dleq algo is fine */
    CHECK(nonce_function_ecdsa_adaptor(nonce, msg, key, pk, dleq_algo, sizeof(dleq_algo), NULL) == 1);

    /* Different algolen gives different nonce */
    for (i = 0; i < count; i++) {
        unsigned char nonce2[32];
        uint32_t offset = secp256k1_testrand_int(algolen - 1);
        size_t algolen_tmp = (algolen + offset) % algolen;

        CHECK(nonce_function_ecdsa_adaptor(nonce2, msg, key, pk, algo, algolen_tmp, NULL) == 1);
        CHECK(secp256k1_memcmp_var(nonce, nonce2, 32) != 0);
    }

    /* NULL aux_rand argument is allowed. */
    CHECK(nonce_function_ecdsa_adaptor(nonce, msg, key, pk, algo, algolen, NULL) == 1);
}

void test_ecdsa_adaptor_api(void) {
    secp256k1_pubkey pubkey;
    secp256k1_pubkey enckey;
    secp256k1_pubkey zero_pk;
    secp256k1_ecdsa_signature sig;
    unsigned char sk[32];
    unsigned char msg[32];
    unsigned char asig[162];
    unsigned char deckey[32];

    /** setup **/
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    int ecount;

    secp256k1_context_set_error_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_error_callback(sttc, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sttc, counting_illegal_callback_fn, &ecount);

    secp256k1_testrand256(sk);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(deckey);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, sk) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &enckey, deckey) == 1);
    memset(&zero_pk, 0, sizeof(zero_pk));

    /** main test body **/
    ecount = 0;
    CHECK(secp256k1_ecdsa_adaptor_encrypt(none, asig, sk, &enckey, msg, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(vrfy, asig, sk, &enckey, msg, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, asig, sk, &enckey, msg, NULL, NULL) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sttc, asig, sk, &enckey, msg, NULL, NULL) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, NULL, sk, &enckey, msg, NULL, NULL) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, asig, sk, &enckey, NULL, NULL, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, asig, NULL, &enckey, msg, NULL, NULL) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, asig, sk, NULL, msg, NULL, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, asig, sk, &zero_pk, msg, NULL, NULL) == 0);
    CHECK(ecount == 6);

    ecount = 0;
    CHECK(secp256k1_ecdsa_adaptor_encrypt(sign, asig, sk, &enckey, msg, NULL, NULL) == 1);
    CHECK(secp256k1_ecdsa_adaptor_verify(none, asig, &pubkey, msg, &enckey) == 1);
    CHECK(secp256k1_ecdsa_adaptor_verify(sign, asig, &pubkey, msg, &enckey) == 1);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, asig, &pubkey, msg, &enckey) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, NULL, &pubkey, msg, &enckey) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, asig, &pubkey, NULL, &enckey) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, asig, &pubkey, msg, NULL) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, asig, NULL, msg, &enckey) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, asig, &zero_pk, msg, &enckey) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_ecdsa_adaptor_verify(vrfy, asig, &pubkey, msg, &zero_pk) == 0);
    CHECK(ecount == 6);

    ecount = 0;
    CHECK(secp256k1_ecdsa_adaptor_decrypt(none, &sig, deckey, asig) == 1);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(sign, &sig, deckey, asig) == 1);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(vrfy, &sig, deckey, asig) == 1);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(both, &sig, deckey, asig) == 1);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(both, NULL, deckey, asig) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(both, &sig, NULL, asig) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(both, &sig, deckey, NULL) == 0);
    CHECK(ecount == 3);

    ecount = 0;
    CHECK(secp256k1_ecdsa_adaptor_decrypt(both, &sig, deckey, asig) == 1);
    CHECK(secp256k1_ecdsa_adaptor_recover(none, deckey, &sig, asig, &enckey) == 1);
    CHECK(secp256k1_ecdsa_adaptor_recover(vrfy, deckey, &sig, asig, &enckey) == 1);
    CHECK(secp256k1_ecdsa_adaptor_recover(sign, deckey, &sig, asig, &enckey) == 1);
    CHECK(ecount == 0);
    CHECK(secp256k1_ecdsa_adaptor_recover(sttc, deckey, &sig, asig, &enckey) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_ecdsa_adaptor_recover(sign, NULL, &sig, asig, &enckey) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_ecdsa_adaptor_recover(sign, deckey, NULL, asig, &enckey) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_ecdsa_adaptor_recover(sign, deckey, &sig, NULL, &enckey) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_ecdsa_adaptor_recover(sign, deckey, &sig, asig, NULL) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_ecdsa_adaptor_recover(sign, deckey, &sig, asig, &zero_pk) == 0);
    CHECK(ecount == 6);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
    secp256k1_context_destroy(sttc);
}

void adaptor_tests(void) {
    unsigned char seckey[32];
    secp256k1_pubkey pubkey;
    unsigned char msg[32];
    unsigned char deckey[32];
    secp256k1_pubkey enckey;
    unsigned char adaptor_sig[162];
    secp256k1_ecdsa_signature sig;
    unsigned char zeros162[162] = { 0 };
    unsigned char zeros64[64] = { 0 };
    unsigned char big[32];

    secp256k1_testrand256(seckey);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(deckey);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &enckey, deckey) == 1);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, seckey, &enckey, msg, NULL, NULL) == 1);

    {
        /* Test overflowing seckey */
        memset(big, 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, big, &enckey, msg, NULL, NULL) == 0);
        CHECK(secp256k1_memcmp_var(adaptor_sig, zeros162, sizeof(adaptor_sig)) == 0);

        /* Test different nonce functions */
        memset(adaptor_sig, 1, sizeof(adaptor_sig));
        CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, seckey, &enckey, msg, ecdsa_adaptor_nonce_function_failing, NULL) == 0);
        CHECK(secp256k1_memcmp_var(adaptor_sig, zeros162, sizeof(adaptor_sig)) == 0);
        memset(&adaptor_sig, 1, sizeof(adaptor_sig));
        CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, seckey, &enckey, msg, ecdsa_adaptor_nonce_function_0, NULL) == 0);
        CHECK(secp256k1_memcmp_var(adaptor_sig, zeros162, sizeof(adaptor_sig)) == 0);
        CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, adaptor_sig, seckey, &enckey, msg, ecdsa_adaptor_nonce_function_overflowing, NULL) == 1);
        CHECK(secp256k1_memcmp_var(adaptor_sig, zeros162, sizeof(adaptor_sig)) != 0);
    }
    {
        /* Test adaptor_sig_serialize roundtrip */
        secp256k1_ge r, rp;
        secp256k1_scalar sigr;
        secp256k1_scalar sp;
        secp256k1_scalar dleq_proof_s, dleq_proof_e;
        secp256k1_ge p_inf;
        unsigned char adaptor_sig_tmp[162];

        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig) == 1);

        CHECK(secp256k1_ecdsa_adaptor_sig_serialize(adaptor_sig_tmp, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s) == 1);
        CHECK(secp256k1_memcmp_var(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp)) == 0);

        /* Test adaptor_sig_serialize points at infinity */
        secp256k1_ge_set_infinity(&p_inf);
        CHECK(secp256k1_ecdsa_adaptor_sig_serialize(adaptor_sig_tmp, &p_inf, &rp, &sp, &dleq_proof_e, &dleq_proof_s) == 0);
        CHECK(secp256k1_ecdsa_adaptor_sig_serialize(adaptor_sig_tmp, &r, &p_inf, &sp, &dleq_proof_e, &dleq_proof_s) == 0);
    }
    {
        /* Test adaptor_sig_deserialize */
        secp256k1_ge r, rp;
        secp256k1_scalar sigr;
        secp256k1_scalar sp;
        secp256k1_scalar dleq_proof_s, dleq_proof_e;
        unsigned char adaptor_sig_tmp[162];

        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig) == 1);

        /* r */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, NULL, NULL, NULL, NULL, adaptor_sig) == 1);
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[0], 0xFF, 33);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, NULL, NULL, NULL, NULL, adaptor_sig_tmp) == 0);

        /* sigr */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, NULL, NULL, NULL, adaptor_sig) == 1);
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[1], 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, NULL, NULL, NULL, adaptor_sig_tmp) == 1);
        memset(&adaptor_sig_tmp[1], 0, 32);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, NULL, NULL, NULL, adaptor_sig_tmp) == 0);

        /* rp */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, &rp, NULL, NULL, NULL, adaptor_sig) == 1);
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[33], 0xFF, 33);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, &rp, NULL, NULL, NULL, adaptor_sig_tmp) == 0);

        /* sp */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, NULL, &sp, NULL, NULL, adaptor_sig) == 1);
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[66], 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, NULL, &sp, NULL, NULL, adaptor_sig_tmp) == 0);

        /* dleq_proof_e */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, NULL, NULL, &dleq_proof_e, NULL, adaptor_sig) == 1);
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[98], 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, NULL, NULL, &dleq_proof_e, NULL, adaptor_sig_tmp) == 1);

        /* dleq_proof_s */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, NULL, NULL, NULL, &dleq_proof_s, adaptor_sig) == 1);
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[130], 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, NULL, NULL, NULL, NULL, &dleq_proof_s, adaptor_sig_tmp) == 0);
    }

    /* Test adaptor_sig_verify */
    CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig, &pubkey, msg, &enckey) == 1);
    CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig, &enckey, msg, &enckey) == 0);
    CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig, &pubkey, msg, &pubkey) == 0);
    {
        /* Test failed adaptor sig deserialization */
        unsigned char adaptor_sig_tmp[162];
        memset(&adaptor_sig_tmp, 0xFF, 162);
        CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig_tmp, &pubkey, msg, &enckey) == 0);
    }
    {
        /* Test that any flipped bit in the adaptor signature will make
         * verification fail */
        unsigned char adaptor_sig_tmp[162];
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        rand_flip_bit(&adaptor_sig_tmp[1], sizeof(adaptor_sig_tmp) - 1);
        CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig_tmp, &pubkey, msg, &enckey) == 0);
    }
    {
        unsigned char msg_tmp[32];
        memcpy(msg_tmp, msg, sizeof(msg_tmp));
        rand_flip_bit(msg_tmp, sizeof(msg_tmp));
        CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig, &pubkey, msg_tmp, &enckey) == 0);
    }
    {
        /* Verification must check that the derived R' is not equal to the point at
         * infinity before negating it. R' is derived as follows:
         *
         * R' == s'⁻¹(m * G + R.x * X)
         *
         * When the base point, G, is multiplied by the subgroup order, q, the
         * result is the point at infinity, 0:
         *
         * q * G = 0
         *
         * Thus, if we set s' equal to R.x, m equal to (q - 1) * R.x, and X equal to
         * G, then our derived R' will be 0:
         *
         * R' = R.x⁻¹((q - 1 * R.x) * G + R.x * G) = q * G = 0 */

        /* t := q - 1 */
        const unsigned char target[32] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40
        };
        unsigned char seckey_tmp[32] = { 0 };
        unsigned char msg_tmp[32];
        unsigned char adaptor_sig_tmp[162];
        secp256k1_pubkey pubkey_tmp;
        secp256k1_scalar sigr, t, m;

        /* m := t * sigr */
        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, NULL, NULL, NULL, adaptor_sig) == 1);
        secp256k1_scalar_set_b32(&t, target, NULL);
        secp256k1_scalar_mul(&m, &t, &sigr);
        secp256k1_scalar_get_b32(msg_tmp, &m);

        /* X := G */
        seckey_tmp[31] = 1;
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_tmp, seckey_tmp) == 1);

        /* sp := sigr */
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memcpy(&adaptor_sig_tmp[66], &adaptor_sig_tmp[1], 32);

        CHECK(secp256k1_ecdsa_adaptor_verify(ctx, adaptor_sig_tmp, &pubkey_tmp, msg_tmp, &enckey) == 0);
    }

    /* Test decryption */
    CHECK(secp256k1_ecdsa_adaptor_decrypt(ctx, &sig, deckey, adaptor_sig) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, &pubkey) == 1);

    {
        /* Test overflowing decryption key */
        secp256k1_ecdsa_signature s;
        memset(big, 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_decrypt(ctx, &s, big, adaptor_sig) == 0);
        CHECK(secp256k1_memcmp_var(&s.data[0], zeros64, sizeof(&s.data[0])) == 0);
    }
    {
        /* Test key recover */
        unsigned char decryption_key_tmp[32];
        unsigned char adaptor_sig_tmp[162];

        CHECK(secp256k1_ecdsa_adaptor_recover(ctx, decryption_key_tmp, &sig, adaptor_sig, &enckey) == 1);
        CHECK(secp256k1_memcmp_var(deckey, decryption_key_tmp, sizeof(deckey)) == 0);

        /* Test failed sp deserialization */
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        memset(&adaptor_sig_tmp[66], 0xFF, 32);
        CHECK(secp256k1_ecdsa_adaptor_recover(ctx, decryption_key_tmp, &sig, adaptor_sig_tmp, &enckey) == 0);
    }
}

void multi_hop_lock_tests(void) {
    unsigned char seckey_a[32];
    unsigned char seckey_b[32];
    unsigned char pop[32];
    unsigned char tx_ab[32];
    unsigned char tx_bc[32];
    unsigned char buf[32];
    unsigned char asig_ab[162];
    unsigned char asig_bc[162];
    secp256k1_pubkey pubkey_pop;
    secp256k1_pubkey pubkey_a, pubkey_b;
    secp256k1_pubkey l, r;
    secp256k1_ge l_ge, r_ge;
    secp256k1_scalar t1, t2, tp;
    secp256k1_scalar deckey;
    secp256k1_ecdsa_signature sig_ab, sig_bc;

    secp256k1_testrand256(seckey_a);
    secp256k1_testrand256(seckey_b);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_a, seckey_a));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_b, seckey_b));

    /* Carol setup */
    /* Proof of payment */
    secp256k1_testrand256(pop);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_pop, pop));

    /* Alice setup */
    secp256k1_testrand256(tx_ab);
    rand_scalar(&t1);
    rand_scalar(&t2);
    secp256k1_scalar_add(&tp, &t1, &t2);
    /* Left lock */
    secp256k1_pubkey_load(ctx, &l_ge, &pubkey_pop);
    CHECK(secp256k1_eckey_pubkey_tweak_add(&l_ge, &t1));
    secp256k1_pubkey_save(&l, &l_ge);
    /* Right lock */
    secp256k1_pubkey_load(ctx, &r_ge, &pubkey_pop);
    CHECK(secp256k1_eckey_pubkey_tweak_add(&r_ge, &tp));
    secp256k1_pubkey_save(&r, &r_ge);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, asig_ab, seckey_a, &l, tx_ab, NULL, NULL));

    /* Bob setup */
    CHECK(secp256k1_ecdsa_adaptor_verify(ctx, asig_ab, &pubkey_a, tx_ab, &l));
    secp256k1_testrand256(tx_bc);
    CHECK(secp256k1_ecdsa_adaptor_encrypt(ctx, asig_bc, seckey_b, &r, tx_bc, NULL, NULL));

    /* Carol decrypt */
    CHECK(secp256k1_ecdsa_adaptor_verify(ctx, asig_bc, &pubkey_b, tx_bc, &r));
    secp256k1_scalar_set_b32(&deckey, pop, NULL);
    secp256k1_scalar_add(&deckey, &deckey, &tp);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(ctx, &sig_bc, buf, asig_bc));
    CHECK(secp256k1_ecdsa_verify(ctx, &sig_bc, tx_bc, &pubkey_b));

    /* Bob recover and decrypt */
    CHECK(secp256k1_ecdsa_adaptor_recover(ctx, buf, &sig_bc, asig_bc, &r));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t2, &t2);
    secp256k1_scalar_add(&deckey, &deckey, &t2);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_ecdsa_adaptor_decrypt(ctx, &sig_ab, buf, asig_ab));
    CHECK(secp256k1_ecdsa_verify(ctx, &sig_ab, tx_ab, &pubkey_a));

    /* Alice recover and derive proof of payment */
    CHECK(secp256k1_ecdsa_adaptor_recover(ctx, buf, &sig_ab, asig_ab, &l));
    secp256k1_scalar_set_b32(&deckey, buf, NULL);
    secp256k1_scalar_negate(&t1, &t1);
    secp256k1_scalar_add(&deckey, &deckey, &t1);
    secp256k1_scalar_get_b32(buf, &deckey);
    CHECK(secp256k1_memcmp_var(buf, pop, 32) == 0);
}

void run_ecdsa_adaptor_tests(void) {
    int i;
    run_nonce_function_ecdsa_adaptor_tests();

    test_ecdsa_adaptor_api();
    test_ecdsa_adaptor_spec_vectors();
    for (i = 0; i < count; i++) {
        dleq_tests();
    }
    for (i = 0; i < count; i++) {
        adaptor_tests();
    }
    for (i = 0; i < count; i++) {
        multi_hop_lock_tests();
    }
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H */
