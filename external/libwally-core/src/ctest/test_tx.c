#include "config.h"

#include <wally_transaction.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static const char *p2pkh_hex =
    "0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000008b483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000";

static const char *wit_hex = "020000000001012f94ddd965758445be2dfac132c5e75c517edf5ea04b745a953d0bc04c32829901000000006aedc98002a8c500000000000022002009246bbe3beb48cf1f6f2954f90d648eb04d68570b797e104fead9e6c3c87fd40544020000000000160014c221cdfc1b867d82f19d761d4e09f3b6216d8a8304004830450221008aaa56e4f0efa1f7b7ed690944ac1b59f046a59306fcd1d09924936bd500046d02202b22e13a2ad7e16a0390d726c56dfc9f07647f7abcfac651e35e5dc9d830fc8a01483045022100e096ad0acdc9e8261d1cdad973f7f234ee84a6ee68e0b89ff0c1370896e63fe102202ec36d7554d1feac8bc297279f89830da98953664b73d38767e81ee0763b9988014752210390134e68561872313ba59e56700732483f4a43c2de24559cb8c7039f25f7faf821039eb59b267a78f1020f27a83dc5e3b1e4157e4a517774040a196e9f43f08ad17d52ae89a3b720";

static const char *coinbase_hex = "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff4b03464d0804c97bb35b642f4254432e434f4d2ffabe6d6d1a6db4ee2dab39db5d871f8ddf5eaf687a3d3f94996a328fe67e89971f80c64e01000000000000006675aeb700000000bd920000ffffffff03aeef224e0000000016001497cfc76442fe717f2a3f0cc9c175f7561b6619970000000000000000266a24aa21a9ed742e7ee7bf189ccc148c8d4e32d39fc1d3ea1340c7473094e5f8a5077716db8200000000000000002952534b424c4f434b3afe833adaeb81adc753269cdd3e4225c199637e7921996cadd94803adbe87f79c0120000000000000000000000000000000000000000000000000000000000000000000000000";

#define check_ret(r) if (r != WALLY_OK) return false

static bool tx_roundtrip(const char *tx_hex)
{
    struct wally_tx *tx;
    struct wally_tx_input *in, *new_in;
    struct wally_tx_output *out, *new_out;
    char *new_hex;
    size_t i;
    int ret;

    /* Unserialize and serialize the tx and verify they match */
    ret = wally_tx_from_hex(tx_hex, WALLY_TX_FLAG_USE_WITNESS, &tx);
    check_ret(ret);

    ret = wally_tx_to_hex(tx, WALLY_TX_FLAG_USE_WITNESS, &new_hex);
    if (ret != WALLY_OK || strcmp(tx_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    /* Test adding and removing inputs */
    in = &tx->inputs[0];
    ret = wally_tx_input_init_alloc(in->txhash, sizeof(in->txhash),
                                    in->index, in->sequence,
                                    in->script, in->script_len, in->witness,
                                    &new_in);
    check_ret(ret);

    for (i = 0; i < 5; ++i) {
        ret = wally_tx_add_input(tx, new_in);
        check_ret(ret);
    }
    ret = wally_tx_remove_input(tx, 5); /* Remove last */
    check_ret(ret);
    ret = wally_tx_add_raw_input(tx, new_in->txhash, WALLY_TXHASH_LEN,
                                 new_in->index, new_in->sequence,
                                 new_in->script, new_in->script_len,
                                 new_in->witness, 0);
    check_ret(ret);
    ret = wally_tx_remove_input(tx, 3); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_input(tx, 2); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_input(tx, 0); /* Remove first */
    check_ret(ret);

    /* Test adding and removing outputs */
    out = &tx->outputs[0];
    ret = wally_tx_output_init_alloc(out->satoshi,
                                     out->script, out->script_len, &new_out);
    check_ret(ret);

    for (i = 0; i < 5; ++i) {
        ret = wally_tx_add_output(tx, new_out);
        check_ret(ret);
    }

    ret = wally_tx_remove_output(tx, 5); /* Remove last */
    check_ret(ret);
    ret = wally_tx_add_raw_output(tx, new_out->satoshi, new_out->script, new_out->script_len, 0);
    check_ret(ret);
    ret = wally_tx_remove_output(tx, 3); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_output(tx, 2); /* Remove middle */
    check_ret(ret);
    ret = wally_tx_remove_output(tx, 0); /* Remove first */
    check_ret(ret);

    /* Clean up (for valgrind heap checking) */
    ret = wally_tx_free(tx);
    check_ret(ret);
    ret = wally_tx_input_free(new_in);
    check_ret(ret);
    ret = wally_tx_output_free(new_out);
    check_ret(ret);
    return true;
}

static bool tx_coinbase(const char *tx_hex)
{
    struct wally_tx *tx;
    char *new_hex;
    const uint32_t flags = WALLY_TX_FLAG_USE_WITNESS;
    size_t is_coinbase;
    int ret;

    /* Unserialize and serialize the tx and verify they match */
    ret = wally_tx_from_hex(tx_hex, flags, &tx);
    check_ret(ret);

    ret = wally_tx_to_hex(tx, flags, &new_hex);
    if (ret != WALLY_OK || strcmp(tx_hex, new_hex))
        return false;

    ret = wally_free_string(new_hex);
    check_ret(ret);

    ret = wally_tx_is_coinbase(tx, &is_coinbase);
    if (ret != WALLY_OK || !is_coinbase)
        return false;

    /* Clean up (for valgrind heap checking) */
    ret = wally_tx_free(tx);
    check_ret(ret);

    return true;
}

static bool test_tx_parse(void)
{
    return tx_roundtrip(p2pkh_hex) &&
           tx_roundtrip(wit_hex) &&
           tx_coinbase(coinbase_hex);
}

int main(void)
{
    bool tests_ok = true;

#define RUN(t) if (!t()) { printf(#t " test_tx() test failed!\n"); tests_ok = false; }

    RUN(test_tx_parse);

    return tests_ok ? 0 : 1;
}
