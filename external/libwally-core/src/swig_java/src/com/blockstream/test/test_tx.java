package com.blockstream.test;

import com.blockstream.libwally.Wally;

public class test_tx {

    static final String p2pkh_hex = "0100000001be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396000000008b483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9ffffffff0123ce0100000000001976a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac00000000";
    static final String p2pkh_hex_first_input_hash = "be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396";
    static final String p2pkh_hex_first_input_script = "483045022100da43201760bda697222002f56266bf65023fef2094519e13077f777baed553b102205ce35d05eabda58cd50a67977a65706347cc25ef43153e309ff210a134722e9e0141042daa93315eebbe2cb9b5c3505df4c6fb6caca8b756786098567550d4820c09db988fe9997d049d687292f815ccd6e7fb5c1b1a91137999818d17c73d0f80aef9";
    static final String wit_hex = "020000000001012f94ddd965758445be2dfac132c5e75c517edf5ea04b745a953d0bc04c32829901000000006aedc98002a8c500000000000022002009246bbe3beb48cf1f6f2954f90d648eb04d68570b797e104fead9e6c3c87fd40544020000000000160014c221cdfc1b867d82f19d761d4e09f3b6216d8a8304004830450221008aaa56e4f0efa1f7b7ed690944ac1b59f046a59306fcd1d09924936bd500046d02202b22e13a2ad7e16a0390d726c56dfc9f07647f7abcfac651e35e5dc9d830fc8a01483045022100e096ad0acdc9e8261d1cdad973f7f234ee84a6ee68e0b89ff0c1370896e63fe102202ec36d7554d1feac8bc297279f89830da98953664b73d38767e81ee0763b9988014752210390134e68561872313ba59e56700732483f4a43c2de24559cb8c7039f25f7faf821039eb59b267a78f1020f27a83dc5e3b1e4157e4a517774040a196e9f43f08ad17d52ae89a3b720";

    public test_tx() { }

    public static void assert_eq(final Object expected, final Object actual, final String message) {
        if(!expected.equals(actual)) {
            System.out.println(expected);
            System.out.println(actual);
            throw new RuntimeException(message);
        }
    }

    public void test() {
        final Object tx = Wally.tx_from_hex(p2pkh_hex, Wally.WALLY_TX_FLAG_USE_WITNESS);
        final String tx_string = Wally.tx_to_hex(tx, Wally.WALLY_TX_FLAG_USE_WITNESS);
        final byte[] tx_bytes = Wally.tx_to_bytes(tx, Wally.WALLY_TX_FLAG_USE_WITNESS);
        final Object tx_wit = Wally.tx_from_hex(wit_hex, Wally.WALLY_TX_FLAG_USE_WITNESS);
        final byte[] tx_get_input_txhash = Wally.tx_get_input_txhash(tx, 0);
        final byte[] tx_get_input_script = Wally.tx_get_input_script(tx, 0);
        final byte[] tx_get_output_script = Wally.tx_get_output_script(tx, 0);
        final Object tx_input = Wally.tx_input_init(tx_get_input_txhash, 0, 4294967295L, tx_get_input_script, Wally.tx_witness_stack_init(0L));
        final Object tx_input_wit_null = Wally.tx_input_init(tx_get_input_txhash, 0, 4294967295L, tx_get_input_script, null);
        final Object tx_out = Wally.tx_output_init(100, tx_get_output_script);
        final byte[] tx_input_get_script = Wally.tx_input_get_script(tx_input);
        final byte[] txid = Wally.tx_get_txid(tx);

        assert_eq(p2pkh_hex, tx_string, "hex ser/der doesn't match original");
        assert_eq(p2pkh_hex, h(tx_bytes), "hex(bytes) doesn't match original");
        assert_eq(1, Wally.tx_get_num_inputs(tx), "number of inputs is not 1");
        assert_eq(118307L, Wally.tx_get_total_output_satoshi(tx), "total output mismatch");
        assert_eq(1, Wally.tx_get_version(tx), "tx version mismatch");
        assert_eq(0, Wally.tx_get_locktime(tx), "tx locktime mismatch");
        assert_eq(1, Wally.tx_get_num_outputs(tx), "tx num  mismatch");
        assert_eq(p2pkh_hex_first_input_hash, h(tx_get_input_txhash), "hash of prevout 0 does not match");
        assert_eq(0, Wally.tx_get_input_index(tx, 0), "index mismatch");
        assert_eq(p2pkh_hex_first_input_script, h(tx_get_input_script), "script hex mismatch");
        assert_eq(4294967295L, Wally.tx_get_input_sequence(tx, 0), "sequence mismatch");
        assert_eq(25, tx_get_output_script.length, "output script length mismatch");
        assert_eq("76a9142bc89c2702e0e618db7d59eb5ce2f0f147b4075488ac", h(tx_get_output_script), "output script mismatch");
        assert_eq( 0, Wally.tx_get_witness_count(tx), "witness count mismatch");
        assert_eq(p2pkh_hex_first_input_hash, h(Wally.tx_input_get_txhash(tx_input)), "hash of prevout 0 from tx_input does not match");
        assert_eq(p2pkh_hex_first_input_script, h(tx_input_get_script), "script hex mismatch");
        assert_eq(4294967295L, Wally.tx_input_get_sequence(tx_input), "sequence mismatch from tx_input");
        assert_eq(118307L, Wally.tx_get_output_satoshi(tx,0), "output 0, satoshi mismatch");
        assert_eq(1, Wally.tx_get_witness_count(tx_wit), "witness count mismatch");
        assert_eq(0, Wally.tx_get_input_witness(tx_wit, 0, 0).length, "witness buffer mismatch");
        assert_eq(72, Wally.tx_get_input_witness(tx_wit, 0, 1).length, "witness buffer mismatch");
        assert_eq(h(tx_get_output_script), h(Wally.tx_output_get_script(tx_out)), "script hex mismatch");
        assert_eq(100L, Wally.tx_output_get_satoshi(tx_out), "total output mismatch");
        /* Note that the hex used here is reversed from the typical txid display order */
        assert_eq("26641caee29b3ce14d0888ad3cfdd2f73f32f0c41d3da85127639009b38f1b21", h(txid), "txid mismatch");

        Wally.tx_add_input(tx, tx_input);
        assert_eq(2, Wally.tx_get_num_inputs(tx), "after adding number of inputs is not 2");
        assert_eq(0, Wally.tx_get_input_index(tx,1), "wrong input index");
        Wally.tx_set_input_index(tx,1,1);
        assert_eq(1, Wally.tx_get_input_index(tx,1), "wrong input index");
        Wally.tx_add_input(tx, tx_input_wit_null);
        Wally.tx_set_input_index(tx,2,2);
        assert_eq(2, Wally.tx_get_input_index(tx,2), "wrong input index");
        assert_eq(3, Wally.tx_get_num_inputs(tx), "after adding number of inputs is not 3");
        Wally.tx_remove_input(tx, 1);
        assert_eq(2, Wally.tx_get_num_inputs(tx), "after removing number of inputs is not 2");
        Wally.tx_set_input_sequence(tx, 1, 2);
        assert_eq(2L, Wally.tx_get_input_sequence(tx,1), "sequence does not match after setting");
        Wally.tx_output_set_satoshi(tx_out, 12415L);
        assert_eq(12415L, Wally.tx_output_get_satoshi(tx_out), "satoshi in output doesn't match after setting");
        Wally.tx_set_output_satoshi(tx, 0, 1241257L);
        assert_eq(1241257L, Wally.tx_get_output_satoshi(tx, 0), "satoshi in output doesn't match after setting");
        Wally.tx_set_input_script(tx,0,h("00"));
        assert_eq("00", h(Wally.tx_get_input_script(tx, 0)), "set input script doesn't match");
        Wally.tx_set_output_script(tx,0,h("0100"));
        assert_eq("0100", h(Wally.tx_get_output_script(tx, 0)), "set output script doesn't match");

        Wally.cleanup();
    }

    public void test_dersigs() {
        // random values
        final String sigs[] = { "67efef0d968862524308632be6e724db29bd33e5a373fa98e4c726b753b459c33fd98e793a7926c0281423c64dd555eb6aa43db8ada5dba86a21c5121298b87e",
                                "eb6ef01ce422cda7f58e1768ba60192f1714c4af26535657fcfa058359db3446633eba147b88ba8cb52f6b2ca26f083d6c0f7e744d1f1113eb33b1c3c3c83f60" };
        final String ders[] = { "3044022067efef0d968862524308632be6e724db29bd33e5a373fa98e4c726b753b459c302203fd98e793a7926c0281423c64dd555eb6aa43db8ada5dba86a21c5121298b87e",
                                "3045022100eb6ef01ce422cda7f58e1768ba60192f1714c4af26535657fcfa058359db34460220633eba147b88ba8cb52f6b2ca26f083d6c0f7e744d1f1113eb33b1c3c3c83f60" };
        for ( int i = 0 ; i < sigs.length; ++i ) {
            assert_eq(sigs[i], h(Wally.ec_sig_from_der(h(ders[i]))), "Unexpected ec_sig_from_der() result.");
            assert_eq(ders[i], h(Wally.ec_sig_to_der(h(sigs[i]))), "Unexpected ec_sig_to_der() result.");
        }
    }

    private String h(final byte[] bytes) { return Wally.hex_from_bytes(bytes); }
    private byte[] h(final String hex) { return Wally.hex_to_bytes(hex); }

    public static void main(final String[] args) {
        final test_tx t = new test_tx();
        t.test();
        t.test_dersigs();
    }

}
