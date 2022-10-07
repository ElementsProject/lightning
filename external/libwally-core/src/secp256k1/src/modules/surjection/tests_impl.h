/**********************************************************************
 * Copyright (c) 2016 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SURJECTIONPROOF_TESTS
#define SECP256K1_MODULE_SURJECTIONPROOF_TESTS

#include "testrand.h"
#include "group.h"
#include "include/secp256k1_generator.h"
#include "include/secp256k1_rangeproof.h"
#include "include/secp256k1_surjectionproof.h"

static void test_surjectionproof_api(void) {
    unsigned char seed[32];
    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *sttc = secp256k1_context_clone(secp256k1_context_no_precomp);
    secp256k1_fixed_asset_tag fixed_input_tags[10];
    secp256k1_fixed_asset_tag fixed_output_tag;
    secp256k1_generator ephemeral_input_tags[10];
    secp256k1_generator ephemeral_output_tag;
    unsigned char input_blinding_key[10][32];
    unsigned char output_blinding_key[32];
    unsigned char serialized_proof[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
    size_t  serialized_len;
    secp256k1_surjectionproof proof;
    secp256k1_surjectionproof* proof_on_heap;
    size_t n_inputs = sizeof(fixed_input_tags) / sizeof(fixed_input_tags[0]);
    size_t input_index;
    int32_t ecount = 0;
    size_t i;

    secp256k1_testrand256(seed);
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


    for (i = 0; i < n_inputs; i++) {
        secp256k1_testrand256(input_blinding_key[i]);
        secp256k1_testrand256(fixed_input_tags[i].data);
        CHECK(secp256k1_generator_generate_blinded(ctx, &ephemeral_input_tags[i], fixed_input_tags[i].data, input_blinding_key[i]));
    }
    secp256k1_testrand256(output_blinding_key);
    memcpy(&fixed_output_tag, &fixed_input_tags[0], sizeof(fixed_input_tags[0]));
    CHECK(secp256k1_generator_generate_blinded(ctx, &ephemeral_output_tag, fixed_output_tag.data, output_blinding_key));

    /* check allocate_initialized */
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) != 0);
    CHECK(proof_on_heap != 0);
    secp256k1_surjectionproof_destroy(proof_on_heap);
    CHECK(ecount == 0);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, NULL, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, NULL, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, NULL, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS + 1, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, n_inputs, &fixed_input_tags[0], 100, seed) != 0);
    CHECK(proof_on_heap != 0);
    secp256k1_surjectionproof_destroy(proof_on_heap);
    CHECK(ecount == 4);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, n_inputs + 1, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 3, NULL, 100, seed) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 6);
    CHECK((secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 0, seed) & 1) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_surjectionproof_allocate_initialized(none, &proof_on_heap, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, NULL) == 0);
    CHECK(proof_on_heap == 0);
    CHECK(ecount == 7);

    /* we are now going to test essentially the same functions, just without heap allocation.
     * reset ecount. */
    ecount = 0;

    /* check initialize */
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) != 0);
    CHECK(ecount == 0);
    CHECK(secp256k1_surjectionproof_initialize(none, NULL, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, NULL, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 2);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, NULL, n_inputs, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 3);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS + 1, 3, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, n_inputs, &fixed_input_tags[0], 100, seed) != 0);
    CHECK(ecount == 4);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, n_inputs + 1, &fixed_input_tags[0], 100, seed) == 0);
    CHECK(ecount == 5);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, 3, NULL, 100, seed) == 0);
    CHECK(ecount == 6);
    CHECK((secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 0, seed) & 1) == 0);
    CHECK(ecount == 6);
    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], 100, NULL) == 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_surjectionproof_initialize(none, &proof, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[0], 100, seed) != 0);
    /* check generate */
    CHECK(secp256k1_surjectionproof_generate(none, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) != 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_surjectionproof_generate(vrfy, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) != 0);
    CHECK(ecount == 7);

    CHECK(secp256k1_surjectionproof_generate(sign, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 1);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) != 0);
    CHECK(ecount == 7);
    CHECK(secp256k1_surjectionproof_generate(sttc, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 8);

    CHECK(secp256k1_surjectionproof_generate(both, NULL, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 9);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, NULL, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs + 1, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs - 1, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, 0, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 10);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, NULL, 0, input_blinding_key[0], output_blinding_key) == 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 1, input_blinding_key[0], output_blinding_key) != 0);
    CHECK(ecount == 11);  /* the above line "succeeds" but generates an invalid proof as the input_index is wrong. it is fairly expensive to detect this. should we? */
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, n_inputs + 1, input_blinding_key[0], output_blinding_key) != 0);
    CHECK(ecount == 11);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, NULL, output_blinding_key) == 0);
    CHECK(ecount == 12);
    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], NULL) == 0);
    CHECK(ecount == 13);

    CHECK(secp256k1_surjectionproof_generate(both, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key) != 0);
    /* check verify */
    CHECK(secp256k1_surjectionproof_verify(none, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag) == 1);
    CHECK(secp256k1_surjectionproof_verify(sign, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag) == 1);
    CHECK(secp256k1_surjectionproof_verify(vrfy, &proof, ephemeral_input_tags, n_inputs, &ephemeral_output_tag) == 1);
    CHECK(ecount == 13);

    CHECK(secp256k1_surjectionproof_verify(vrfy, NULL, ephemeral_input_tags, n_inputs, &ephemeral_output_tag) == 0);
    CHECK(ecount == 14);
    CHECK(secp256k1_surjectionproof_verify(vrfy, &proof, NULL, n_inputs, &ephemeral_output_tag) == 0);
    CHECK(ecount == 15);
    CHECK(secp256k1_surjectionproof_verify(vrfy, &proof, ephemeral_input_tags, n_inputs - 1, &ephemeral_output_tag) == 0);
    CHECK(ecount == 15);
    CHECK(secp256k1_surjectionproof_verify(vrfy, &proof, ephemeral_input_tags, n_inputs + 1, &ephemeral_output_tag) == 0);
    CHECK(ecount == 15);
    CHECK(secp256k1_surjectionproof_verify(vrfy, &proof, ephemeral_input_tags, n_inputs, NULL) == 0);
    CHECK(ecount == 16);

    /* Check serialize */
    serialized_len = sizeof(serialized_proof);
    CHECK(secp256k1_surjectionproof_serialize(none, serialized_proof, &serialized_len, &proof) != 0);
    CHECK(ecount == 16);
    serialized_len = sizeof(serialized_proof);
    CHECK(secp256k1_surjectionproof_serialize(none, NULL, &serialized_len, &proof) == 0);
    CHECK(ecount == 17);
    serialized_len = sizeof(serialized_proof);
    CHECK(secp256k1_surjectionproof_serialize(none, serialized_proof, NULL, &proof) == 0);
    CHECK(ecount == 18);
    serialized_len = sizeof(serialized_proof);
    CHECK(secp256k1_surjectionproof_serialize(none, serialized_proof, &serialized_len, NULL) == 0);
    CHECK(ecount == 19);

    serialized_len = sizeof(serialized_proof);
    CHECK(secp256k1_surjectionproof_serialize(none, serialized_proof, &serialized_len, &proof) != 0);
    /* Check parse */
    CHECK(secp256k1_surjectionproof_parse(none, &proof, serialized_proof, serialized_len) != 0);
    CHECK(ecount == 19);
    CHECK(secp256k1_surjectionproof_parse(none, NULL, serialized_proof, serialized_len) == 0);
    CHECK(ecount == 20);
    CHECK(secp256k1_surjectionproof_parse(none, &proof, NULL, serialized_len) == 0);
    CHECK(ecount == 21);
    CHECK(secp256k1_surjectionproof_parse(none, &proof, serialized_proof, 0) == 0);
    CHECK(ecount == 21);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
    secp256k1_context_destroy(sttc);
}

static void test_input_selection(size_t n_inputs) {
    unsigned char seed[32];
    size_t i;
    size_t result;
    size_t input_index;
    size_t try_count = n_inputs * 100;
    secp256k1_surjectionproof proof;
    secp256k1_fixed_asset_tag fixed_input_tags[1000];
    const size_t max_n_inputs = sizeof(fixed_input_tags) / sizeof(fixed_input_tags[0]) - 1;

    CHECK(n_inputs < max_n_inputs);
    secp256k1_testrand256(seed);

    for (i = 0; i < n_inputs + 1; i++) {
        secp256k1_testrand256(fixed_input_tags[i].data);
    }

    /* cannot match output when told to use zero keys */
    result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, 0, &fixed_input_tags[0], try_count, seed);
    CHECK(result == 0);
    CHECK(secp256k1_surjectionproof_n_used_inputs(ctx, &proof) == 0);
    CHECK(secp256k1_surjectionproof_n_total_inputs(ctx, &proof) == n_inputs);
    CHECK(secp256k1_surjectionproof_serialized_size(ctx, &proof) == 34 + (n_inputs + 7) / 8);
    if (n_inputs > 0) {
        /* succeed in 100*n_inputs tries (probability of failure e^-100) */
        result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, 1, &fixed_input_tags[0], try_count, seed);
        CHECK(result > 0);
        CHECK(result < n_inputs * 10);
        CHECK(secp256k1_surjectionproof_n_used_inputs(ctx, &proof) == 1);
        CHECK(secp256k1_surjectionproof_n_total_inputs(ctx, &proof) == n_inputs);
        CHECK(secp256k1_surjectionproof_serialized_size(ctx, &proof) == 66 + (n_inputs + 7) / 8);
        CHECK(input_index == 0);
    }

    if (n_inputs >= 3) {
        /* succeed in 10*n_inputs tries (probability of failure e^-10) */
        result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[1], try_count, seed);
        CHECK(result > 0);
        CHECK(secp256k1_surjectionproof_n_used_inputs(ctx, &proof) == 3);
        CHECK(secp256k1_surjectionproof_n_total_inputs(ctx, &proof) == n_inputs);
        CHECK(secp256k1_surjectionproof_serialized_size(ctx, &proof) == 130 + (n_inputs + 7) / 8);
        CHECK(input_index == 1);

        /* fail, key not found */
        result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, 3, &fixed_input_tags[n_inputs], try_count, seed);
        CHECK(result == 0);

        /* succeed on first try when told to use all keys */
        result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, n_inputs, &fixed_input_tags[0], try_count, seed);
        CHECK(result == 1);
        CHECK(secp256k1_surjectionproof_n_used_inputs(ctx, &proof) == n_inputs);
        CHECK(secp256k1_surjectionproof_n_total_inputs(ctx, &proof) == n_inputs);
        CHECK(secp256k1_surjectionproof_serialized_size(ctx, &proof) == 2 + 32 * (n_inputs + 1) + (n_inputs + 7) / 8);
        CHECK(input_index == 0);

        /* succeed in less than 64 tries when told to use half keys. (probability of failure 2^-64) */
        result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, n_inputs / 2, &fixed_input_tags[0], 64, seed);
        CHECK(result > 0);
        CHECK(result < 64);
        CHECK(secp256k1_surjectionproof_n_used_inputs(ctx, &proof) == n_inputs / 2);
        CHECK(secp256k1_surjectionproof_n_total_inputs(ctx, &proof) == n_inputs);
        CHECK(secp256k1_surjectionproof_serialized_size(ctx, &proof) == 2 + 32 * (n_inputs / 2 + 1) + (n_inputs + 7) / 8);
        CHECK(input_index == 0);
    }
}

/** Runs surjectionproof_initilize multiple times and records the number of times each input was used.
 */
static void test_input_selection_distribution_helper(const secp256k1_fixed_asset_tag* fixed_input_tags, const size_t n_input_tags, const size_t n_input_tags_to_use, size_t *used_inputs) {
    secp256k1_surjectionproof proof;
    size_t input_index;
    size_t i;
    size_t j;
    unsigned char seed[32];
    size_t result;
    for (i = 0; i < n_input_tags; i++) {
        used_inputs[i] = 0;
    }
    for(j = 0; j < 10000; j++) {
        secp256k1_testrand256(seed);
        result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_input_tags, n_input_tags_to_use, &fixed_input_tags[0], 64, seed);
        CHECK(result > 0);

        for (i = 0; i < n_input_tags; i++) {
            if (proof.used_inputs[i / 8] & (1 << (i % 8))) {
                used_inputs[i] += 1;
            }
        }
    }
}

/** Probabilistic test of the distribution of used_inputs after surjectionproof_initialize.
 * Each confidence interval assertion fails incorrectly with a probability of 2^-128.
 */
static void test_input_selection_distribution(void) {
    size_t i;
    size_t n_input_tags_to_use;
    const size_t n_inputs = 4;
    secp256k1_fixed_asset_tag fixed_input_tags[4];
    size_t used_inputs[4];

    for (i = 0; i < n_inputs; i++) {
        secp256k1_testrand256(fixed_input_tags[i].data);
    }

    /* If there is one input tag to use, initialize must choose the one equal to fixed_output_tag. */
    n_input_tags_to_use = 1;
    test_input_selection_distribution_helper(fixed_input_tags, n_inputs, n_input_tags_to_use, used_inputs);
    CHECK(used_inputs[0] == 10000);
    CHECK(used_inputs[1] == 0);
    CHECK(used_inputs[2] == 0);
    CHECK(used_inputs[3] == 0);

    n_input_tags_to_use = 2;
    /* The input equal to the fixed_output_tag must be included in all used_inputs sets.
     * For each fixed_input_tag != fixed_output_tag the probability that it's included
     * in the used_inputs set is P(used_input|not fixed_output_tag) = 1/3.
     */
    test_input_selection_distribution_helper(fixed_input_tags, n_inputs, n_input_tags_to_use, used_inputs);
    CHECK(used_inputs[0] == 10000);
    CHECK(used_inputs[1] > 2725 && used_inputs[1] < 3961);
    CHECK(used_inputs[2] > 2725 && used_inputs[2] < 3961);
    CHECK(used_inputs[3] > 2725 && used_inputs[3] < 3961);

    n_input_tags_to_use = 3;
    /* P(used_input|not fixed_output_tag) = 2/3 */
    test_input_selection_distribution_helper(fixed_input_tags, n_inputs, n_input_tags_to_use, used_inputs);
    CHECK(used_inputs[0] == 10000);
    CHECK(used_inputs[1] > 6039 && used_inputs[1] < 7275);
    CHECK(used_inputs[2] > 6039 && used_inputs[2] < 7275);
    CHECK(used_inputs[3] > 6039 && used_inputs[3] < 7275);


    n_input_tags_to_use = 1;
    /* Create second input tag that is equal to the output tag. Therefore, when using only
     * one input we have P(used_input|fixed_output_tag) = 1/2 and P(used_input|not fixed_output_tag) = 0
     */
    memcpy(fixed_input_tags[0].data, fixed_input_tags[1].data, 32);
    test_input_selection_distribution_helper(fixed_input_tags, n_inputs, n_input_tags_to_use, used_inputs);
    CHECK(used_inputs[0] > 4345 && used_inputs[0] < 5655);
    CHECK(used_inputs[1] > 4345 && used_inputs[1] < 5655);
    CHECK(used_inputs[2] == 0);
    CHECK(used_inputs[3] == 0);

    n_input_tags_to_use = 2;
    /* When choosing 2 inputs in initialization there are 5 possible combinations of
     * input indexes {(0, 1), (1, 2), (0, 3), (1, 3), (0, 2)}. Therefore we have
     * P(used_input|fixed_output_tag) = 3/5 and P(used_input|not fixed_output_tag) = 2/5.
     */
    test_input_selection_distribution_helper(fixed_input_tags, n_inputs, n_input_tags_to_use, used_inputs);
    CHECK(used_inputs[0] > 5352 && used_inputs[0] < 6637);
    CHECK(used_inputs[1] > 5352 && used_inputs[1] < 6637);
    CHECK(used_inputs[2] > 3363 && used_inputs[2] < 4648);
    CHECK(used_inputs[3] > 3363 && used_inputs[3] < 4648);

    n_input_tags_to_use = 3;
    /* There are 4 combinations, each with all inputs except one. Therefore we have
     * P(used_input|fixed_output_tag) = 3/4 and P(used_input|not fixed_output_tag) = 3/4.
     */
    test_input_selection_distribution_helper(fixed_input_tags, n_inputs, n_input_tags_to_use, used_inputs);
    CHECK(used_inputs[0] > 6918 && used_inputs[0] < 8053);
    CHECK(used_inputs[1] > 6918 && used_inputs[1] < 8053);
    CHECK(used_inputs[2] > 6918 && used_inputs[2] < 8053);
    CHECK(used_inputs[3] > 6918 && used_inputs[3] < 8053);
}

static void test_gen_verify(size_t n_inputs, size_t n_used) {
    unsigned char seed[32];
    secp256k1_surjectionproof proof;
    unsigned char serialized_proof[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
    unsigned char serialized_proof_trailing[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX + 1];
    size_t serialized_len = SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX;
    secp256k1_fixed_asset_tag fixed_input_tags[1000];
    secp256k1_generator ephemeral_input_tags[1000];
    unsigned char *input_blinding_key[1000];
    const size_t max_n_inputs = sizeof(fixed_input_tags) / sizeof(fixed_input_tags[0]) - 1;
    size_t try_count = n_inputs * 100;
    size_t key_index;
    size_t input_index;
    size_t i;
    int result;

    /* setup */
    CHECK(n_used <= n_inputs);
    CHECK(n_inputs < max_n_inputs);
    secp256k1_testrand256(seed);

    key_index = (((size_t) seed[0] << 8) + seed[1]) % n_inputs;

    for (i = 0; i < n_inputs + 1; i++) {
        input_blinding_key[i] = malloc(32);
        secp256k1_testrand256(input_blinding_key[i]);
        /* choose random fixed tag, except that for the output one copy from the key_index */
        if (i < n_inputs) {
            secp256k1_testrand256(fixed_input_tags[i].data);
        } else {
            memcpy(&fixed_input_tags[i], &fixed_input_tags[key_index], sizeof(fixed_input_tags[i]));
        }
        CHECK(secp256k1_generator_generate_blinded(ctx, &ephemeral_input_tags[i], fixed_input_tags[i].data, input_blinding_key[i]));
    }

    /* test */
    result = secp256k1_surjectionproof_initialize(ctx, &proof, &input_index, fixed_input_tags, n_inputs, n_used, &fixed_input_tags[key_index], try_count, seed);
    if (n_used == 0) {
        CHECK(result == 0);
        return;
    }
    CHECK(result > 0);
    CHECK(input_index == key_index);

    result = secp256k1_surjectionproof_generate(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs], input_index, input_blinding_key[input_index], input_blinding_key[n_inputs]);
    CHECK(result == 1);

    CHECK(secp256k1_surjectionproof_serialize(ctx, serialized_proof, &serialized_len, &proof));
    CHECK(serialized_len == secp256k1_surjectionproof_serialized_size(ctx, &proof));
    CHECK(serialized_len == SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(n_inputs, n_used));

    /* trailing garbage */
    memcpy(&serialized_proof_trailing, &serialized_proof, serialized_len);
    serialized_proof_trailing[serialized_len] = seed[0];
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof_trailing, serialized_len + 1) == 0);

    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof, serialized_len));
    result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs]);
    CHECK(result == 1);

    /* various fail cases */
    if (n_inputs > 1) {
        result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs - 1]);
        CHECK(result == 0);

        /* number of entries in ephemeral_input_tags array is less than proof.n_inputs */
        n_inputs -= 1;
        result = secp256k1_surjectionproof_generate(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs], input_index, input_blinding_key[input_index], input_blinding_key[n_inputs]);
        CHECK(result == 0);
        result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs - 1]);
        CHECK(result == 0);
        n_inputs += 1;
    }

    for (i = 0; i < n_inputs; i++) {
        /* flip bit */
        proof.used_inputs[i / 8] ^= (1 << (i % 8));
        result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_inputs, &ephemeral_input_tags[n_inputs]);
        CHECK(result == 0);
        /* reset the bit */
        proof.used_inputs[i / 8] ^= (1 << (i % 8));
    }

    /* cleanup */
    for (i = 0; i < n_inputs + 1; i++) {
        free(input_blinding_key[i]);
    }
}

/* check that a proof with empty n_used_inputs is invalid */
static void test_no_used_inputs_verify(void) {
    secp256k1_surjectionproof proof;
    secp256k1_fixed_asset_tag fixed_input_tag;
    secp256k1_fixed_asset_tag fixed_output_tag;
    secp256k1_generator ephemeral_input_tags[1];
    size_t n_ephemeral_input_tags = 1;
    secp256k1_generator ephemeral_output_tag;
    unsigned char blinding_key[32];
    secp256k1_ge output;
    secp256k1_sha256 sha256_e0;
    int result;

    /* Create proof that doesn't use inputs. secp256k1_surjectionproof_initialize
     * will not work here since it insists on selecting an input that matches the output. */
    proof.n_inputs = 1;
    memset(proof.used_inputs, 0, SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS / 8);

    /* create different fixed input and output tags */
    secp256k1_testrand256(fixed_input_tag.data);
    secp256k1_testrand256(fixed_output_tag.data);

    /* blind fixed output tags with random blinding key */
    secp256k1_testrand256(blinding_key);
    CHECK(secp256k1_generator_generate_blinded(ctx, &ephemeral_input_tags[0], fixed_input_tag.data, blinding_key));
    CHECK(secp256k1_generator_generate_blinded(ctx, &ephemeral_output_tag, fixed_output_tag.data, blinding_key));

    /* create "borromean signature" which is just a hash of metadata (pubkeys, etc) in this case */
    secp256k1_generator_load(&output, &ephemeral_output_tag);
    secp256k1_surjection_genmessage(proof.data, ephemeral_input_tags, 1, &ephemeral_output_tag);
    secp256k1_sha256_initialize(&sha256_e0);
    secp256k1_sha256_write(&sha256_e0, proof.data, 32);
    secp256k1_sha256_finalize(&sha256_e0, proof.data);

    result = secp256k1_surjectionproof_verify(ctx, &proof, ephemeral_input_tags, n_ephemeral_input_tags, &ephemeral_output_tag);
    CHECK(result == 0);
}

void test_bad_serialize(void) {
    secp256k1_surjectionproof proof;
    unsigned char serialized_proof[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX];
    size_t serialized_len;

    proof.n_inputs = 0;
    serialized_len = 2 + 31;
    /* e0 is one byte too short */
    CHECK(secp256k1_surjectionproof_serialize(ctx, serialized_proof, &serialized_len, &proof) == 0);
}

void test_bad_parse(void) {
    secp256k1_surjectionproof proof;
    unsigned char serialized_proof0[] = { 0x00 };
    unsigned char serialized_proof1[] = { 0x01, 0x00 };
    unsigned char serialized_proof2[33] = { 0 };

    /* Missing total input count */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof0, sizeof(serialized_proof0)) == 0);
    /* Missing bitmap */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof1, sizeof(serialized_proof1)) == 0);
    /* Missing e0 value */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, serialized_proof2, sizeof(serialized_proof2)) == 0);
}

void test_fixed_vectors(void) {
    const unsigned char tag0_ser[] = {
        0x0a,
        0x1c, 0xa3, 0xdd, 0x12, 0x48, 0xdd, 0x4d, 0xd0, 0x04, 0x30, 0x47, 0x48, 0x75, 0xf5, 0xf5, 0xff,
        0x2a, 0xd5, 0x0d, 0x1d, 0x86, 0x2b, 0xa4, 0xa4, 0x2f, 0x46, 0xe9, 0xb4, 0x54, 0x21, 0xf0, 0x85
    };
    const unsigned char tag1_ser[] = {
        0x0a,
        0x09, 0x0d, 0x5a, 0xd4, 0xed, 0xae, 0x9c, 0x0c, 0x69, 0x79, 0xf3, 0x8d, 0x22, 0x03, 0x0a, 0x3d,
        0x38, 0xd4, 0x78, 0xe1, 0x03, 0x0d, 0x70, 0x57, 0xd9, 0x9a, 0x23, 0x03, 0xf0, 0x7f, 0xfb, 0xef
    };
    const unsigned char tag2_ser[] = {
        0x0a,
        0xfd, 0xed, 0xba, 0x15, 0x20, 0x8a, 0xb2, 0xaf, 0x0b, 0x76, 0x6d, 0xd2, 0x5f, 0xd4, 0x15, 0x11,
        0x90, 0xec, 0xcb, 0x3f, 0xcd, 0x08, 0xb5, 0x35, 0xd9, 0x24, 0x18, 0xb1, 0xd3, 0x47, 0x83, 0x54
    };
    const unsigned char tag3_ser[] = {
        0x0b,
        0x8b, 0x47, 0xca, 0xee, 0x20, 0x52, 0x17, 0xbf, 0xee, 0xcc, 0x84, 0xcd, 0x34, 0x32, 0x6c, 0x36,
        0xf1, 0xd9, 0x3f, 0xe1, 0x6f, 0x77, 0xfe, 0x89, 0x3e, 0x4a, 0xc8, 0x2a, 0x75, 0xfa, 0x2d, 0x36
    };
    const unsigned char tag4_ser[] = {
        0x0b,
        0x3c, 0x5c, 0xf4, 0x61, 0x45, 0xa8, 0x53, 0xc1, 0x64, 0x32, 0x0e, 0x92, 0x68, 0x52, 0xbd, 0x12,
        0xe9, 0x45, 0x31, 0xeb, 0x04, 0x4c, 0xf4, 0xe2, 0x9e, 0x9f, 0x60, 0x26, 0x50, 0xbf, 0xd6, 0x9f
    };
    const unsigned char output_tag_ser[] = {
        0x0b,
        0xf7, 0x3c, 0x03, 0xed, 0xae, 0x83, 0xa1, 0xa6, 0x94, 0x8c, 0xe3, 0xb8, 0x54, 0x02, 0xa8, 0xbd,
        0x66, 0xca, 0x28, 0xef, 0x44, 0xf5, 0x3a, 0xcb, 0xc7, 0x5b, 0x16, 0xac, 0xce, 0x29, 0x4b, 0xc6
    };

    const unsigned char total1_used1[] = {
        0x01, 0x00, 0x01, 0x8e, 0x6b, 0x8d, 0x8b, 0x96, 0x29, 0x10, 0x29, 0xcb, 0xf8, 0x48, 0xd9, 0xc8,
        0x5b, 0x77, 0xdc, 0xdf, 0x16, 0x67, 0x19, 0xfe, 0x8d, 0xee, 0x8f, 0x56, 0x6f, 0x9c, 0xe9, 0xae,
        0xb9, 0xd9, 0x12, 0xb8, 0x95, 0x6c, 0xf1, 0x48, 0x07, 0x7d, 0x49, 0xe4, 0x3e, 0x7f, 0xc1, 0x2c,
        0xe2, 0xe1, 0x94, 0x10, 0xb1, 0xda, 0x86, 0x5f, 0xbc, 0x03, 0x59, 0xe1, 0x09, 0xd2, 0x1b, 0x18,
        0xce, 0x58, 0x15
    };
    const size_t total1_used1_len = sizeof(total1_used1);

    const unsigned char total2_used1[] = {
        0x02, 0x00, 0x01, 0x35, 0x3a, 0x29, 0x4b, 0xe4, 0x99, 0xc6, 0xbf, 0x99, 0x4d, 0x6c, 0xc8, 0x18,
        0x14, 0xad, 0x10, 0x22, 0x3a, 0xb8, 0x1c, 0xb9, 0xc5, 0x77, 0xda, 0xe0, 0x8a, 0x71, 0x2d, 0x0d,
        0x8e, 0x80, 0xf5, 0x8d, 0x74, 0xf9, 0x01, 0x6b, 0x35, 0x88, 0xf4, 0x8e, 0x43, 0xa5, 0x9c, 0x0f,
        0x7e, 0x37, 0x86, 0x77, 0x44, 0x72, 0x7c, 0xaa, 0xff, 0x14, 0x5b, 0x7a, 0x42, 0x41, 0x75, 0xb2,
        0x5e, 0x3d, 0x6c
    };
    const size_t total2_used1_len = sizeof(total2_used1);

    const unsigned char total3_used2[] = {
        0x03, 0x00, 0x03, 0xf2, 0x3f, 0xca, 0x49, 0x52, 0x05, 0xaf, 0x81, 0x83, 0x01, 0xd7, 0xf4, 0x92,
        0xc0, 0x50, 0xe3, 0x15, 0xfc, 0x94, 0xc1, 0x27, 0x10, 0xd7, 0x8f, 0x57, 0xb1, 0x23, 0xcf, 0x68,
        0x31, 0xf8, 0xcb, 0x58, 0x3d, 0xca, 0x2f, 0x7a, 0x3b, 0x0b, 0xb6, 0x10, 0x52, 0x94, 0xc8, 0x5f,
        0x0a, 0xf8, 0xca, 0x5d, 0x4c, 0x38, 0x44, 0x92, 0xb3, 0xc7, 0xe4, 0x46, 0x9f, 0x96, 0x64, 0xbd,
        0xd2, 0xda, 0x40, 0xdb, 0x63, 0x76, 0x87, 0x48, 0xdc, 0x55, 0x0b, 0x82, 0x9c, 0xa5, 0x96, 0xbe,
        0xe9, 0x0d, 0xe4, 0x98, 0x80, 0x8e, 0x58, 0x38, 0xdc, 0x13, 0x59, 0x1d, 0x5c, 0x8e, 0xda, 0x90,
        0x4c, 0xa4, 0x91
    };
    const size_t total3_used2_len = sizeof(total3_used2);

    const unsigned char total5_used3[] = {
        0x05, 0x00, 0x15, 0x36, 0x3b, 0x92, 0x97, 0x84, 0x25, 0x75, 0xd6, 0xa6, 0xaf, 0xb7, 0x32, 0x5b,
        0x2c, 0xf8, 0x31, 0xe2, 0x15, 0x3a, 0x9b, 0xb7, 0x20, 0x14, 0xc0, 0x67, 0x96, 0x7d, 0xa9, 0xc4,
        0xa2, 0xb4, 0x22, 0x57, 0x5f, 0xb8, 0x20, 0xf1, 0xe8, 0x82, 0xaf, 0xbc, 0x8a, 0xbc, 0x01, 0xc9,
        0x35, 0xf2, 0x7f, 0x6f, 0x0c, 0x0d, 0xba, 0x87, 0xa4, 0xc3, 0xec, 0x60, 0x54, 0x49, 0x35, 0xeb,
        0x1e, 0x48, 0x2c, 0xdb, 0x63, 0x76, 0x87, 0x48, 0xdc, 0x55, 0x0b, 0x82, 0x9c, 0xa5, 0x96, 0xbe,
        0xe9, 0x0d, 0xe4, 0x98, 0x80, 0x8e, 0x58, 0x38, 0xdc, 0x13, 0x59, 0x1d, 0x5c, 0x8e, 0xda, 0x90,
        0x4c, 0xa4, 0x91, 0x5e, 0x8f, 0xcf, 0x2e, 0xc7, 0x5f, 0xfc, 0xca, 0x42, 0xd8, 0x80, 0xe4, 0x3b,
        0x90, 0xa5, 0xd2, 0x07, 0x7d, 0xd1, 0xc9, 0x5c, 0x69, 0xc2, 0xd7, 0xef, 0x8a, 0xae, 0x0a, 0xee,
        0x9c, 0xf5, 0xb9
    };
    const size_t total5_used3_len = sizeof(total5_used3);

    const unsigned char total5_used5[] = {
        0x05, 0x00, 0x1f, 0xfd, 0xbb, 0xb6, 0xc2, 0x78, 0x82, 0xad, 0xe1, 0x66, 0x6d, 0x20, 0x4d, 0xfe,
        0x6b, 0xd2, 0x0b, 0x21, 0x6e, 0xa8, 0x5b, 0xc8, 0xe4, 0x88, 0x42, 0x11, 0x30, 0x3b, 0x6b, 0x02,
        0xc9, 0x7f, 0x44, 0x1c, 0xee, 0xd8, 0x37, 0x6a, 0xf8, 0xfd, 0xc8, 0x4b, 0x0b, 0xa1, 0x43, 0x1f,
        0x68, 0x77, 0x8d, 0x1b, 0xac, 0x9e, 0xc1, 0xc1, 0xda, 0x60, 0xa8, 0xcf, 0x10, 0x9d, 0x80, 0x07,
        0x90, 0x57, 0xb6, 0xdb, 0x63, 0x76, 0x87, 0x48, 0xdc, 0x55, 0x0b, 0x82, 0x9c, 0xa5, 0x96, 0xbe,
        0xe9, 0x0d, 0xe4, 0x98, 0x80, 0x8e, 0x58, 0x38, 0xdc, 0x13, 0x59, 0x1d, 0x5c, 0x8e, 0xda, 0x90,
        0x4c, 0xa4, 0x91, 0x5e, 0x8f, 0xcf, 0x2e, 0xc7, 0x5f, 0xfc, 0xca, 0x42, 0xd8, 0x80, 0xe4, 0x3b,
        0x90, 0xa5, 0xd2, 0x07, 0x7d, 0xd1, 0xc9, 0x5c, 0x69, 0xc2, 0xd7, 0xef, 0x8a, 0xae, 0x0a, 0xee,
        0x9c, 0xf5, 0xb9, 0x5a, 0xc8, 0x03, 0x8d, 0x4f, 0xe3, 0x1d, 0x79, 0x38, 0x5a, 0xfa, 0xe5, 0xa8,
        0x9d, 0x56, 0x77, 0xb3, 0xf9, 0xa8, 0x70, 0x46, 0x27, 0x26, 0x6c, 0x6e, 0x54, 0xaf, 0xf9, 0xd0,
        0x37, 0xa4, 0x86, 0x68, 0x8f, 0xac, 0x3e, 0x78, 0xaa, 0x3d, 0x83, 0x1a, 0xca, 0x05, 0xfe, 0x10,
        0x95, 0xa4, 0x6a, 0x10, 0xc6, 0x62, 0xf3, 0xf7, 0xf3, 0x4d, 0x0b, 0xd4, 0x94, 0xe5, 0x51, 0x6c,
        0x85, 0xd7, 0xc7
    };
    const size_t total5_used5_len = sizeof(total5_used5);

    unsigned char bad[sizeof(total5_used5) + 32] = { 0 };

    secp256k1_generator input_tags[5];
    secp256k1_generator output_tag;
    secp256k1_surjectionproof proof;

    CHECK(secp256k1_generator_parse(ctx, &input_tags[0], tag0_ser));
    CHECK(secp256k1_generator_parse(ctx, &input_tags[1], tag1_ser));
    CHECK(secp256k1_generator_parse(ctx, &input_tags[2], tag2_ser));
    CHECK(secp256k1_generator_parse(ctx, &input_tags[3], tag3_ser));
    CHECK(secp256k1_generator_parse(ctx, &input_tags[4], tag4_ser));
    CHECK(secp256k1_generator_parse(ctx, &output_tag, output_tag_ser));

    /* check 1-of-1 */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, total1_used1, total1_used1_len));
    CHECK(secp256k1_surjectionproof_verify(ctx, &proof, input_tags, 1, &output_tag));
    /* check 1-of-2 */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, total2_used1, total2_used1_len));
    CHECK(secp256k1_surjectionproof_verify(ctx, &proof, input_tags, 2, &output_tag));
    /* check 2-of-3 */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, total3_used2, total3_used2_len));
    CHECK(secp256k1_surjectionproof_verify(ctx, &proof, input_tags, 3, &output_tag));
    /* check 3-of-5 */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, total5_used3, total5_used3_len));
    CHECK(secp256k1_surjectionproof_verify(ctx, &proof, input_tags, 5, &output_tag));
    /* check 5-of-5 */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, total5_used5, total5_used5_len));
    CHECK(secp256k1_surjectionproof_verify(ctx, &proof, input_tags, 5, &output_tag));

    /* check invalid length fails */
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, total5_used5, total5_used3_len));
    /* check invalid keys fail */
    CHECK(secp256k1_surjectionproof_parse(ctx, &proof, total1_used1, total1_used1_len));
    CHECK(!secp256k1_surjectionproof_verify(ctx, &proof, &input_tags[1], 1, &output_tag));
    CHECK(!secp256k1_surjectionproof_verify(ctx, &proof, input_tags, 1, &input_tags[0]));

    /* Try setting 6 bits on the total5-used-5; check that parsing fails */
    memcpy(bad, total5_used5, total5_used5_len);
    bad[2] = 0x3f;  /* 0x1f -> 0x3f */
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, bad, total5_used5_len));
    /* Correct for the length */
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, bad, total5_used5_len + 32));
    /* Alternately just turn off one of the "legit" bits */
    bad[2] = 0x37;  /* 0x1f -> 0x37 */
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, bad, total5_used5_len));

    /* Similarly try setting 4 bits on the total5-used-3, with one bit out of range */
    memcpy(bad, total5_used3, total5_used3_len);
    bad[2] = 0x35;  /* 0x15 -> 0x35 */
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, bad, total5_used3_len));
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, bad, total5_used3_len + 32));
    bad[2] = 0x34;  /* 0x15 -> 0x34 */
    CHECK(!secp256k1_surjectionproof_parse(ctx, &proof, bad, total5_used3_len));
}

void run_surjection_tests(void) {
    test_surjectionproof_api();
    test_fixed_vectors();

    test_input_selection(0);
    test_input_selection(1);
    test_input_selection(5);
    test_input_selection(SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS);

    test_input_selection_distribution();
    test_gen_verify(10, 3);
    test_gen_verify(SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS, SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS);
    test_no_used_inputs_verify();
    test_bad_serialize();
    test_bad_parse();
}

#endif
