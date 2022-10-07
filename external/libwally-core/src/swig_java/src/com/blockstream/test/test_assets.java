package com.blockstream.test;

import com.blockstream.libwally.Wally;

public class test_assets {

    static final String ONES = "1111111111111111111111111111111111111111111111111111111111111111";
    static final String TWOS = "2222222222222222222222222222222222222222222222222222222222222222";

    public test_assets() { }

    public void test_blinding() {
        // hexes from local regtest testing
        final byte[] asset = h(ONES);
        final byte[] abf = h(ONES);
        final byte[] generator = Wally.asset_generator_from_bytes(asset, abf);

        final long[] values = new long[] { 20000, 4910, 13990, 1100 };
        final byte[] last_vbf = Wally.asset_final_vbf(values, 1,
                        h("7fca161c2b849a434f49065cf590f5f1909f25e252f728dfd53669c3c8f8e37100000000000000000000000000000000000000000000000000000000000000002c89075f3c8861fea27a15682d664fb643bc08598fe36dcf817fcabc7ef5cf2efdac7bbad99a45187f863cd58686a75135f2cc0714052f809b0c1f603bcdc574"),
                        h("1c07611b193009e847e5b296f05a561c559ca84e16d1edae6cbe914b73fb6904000000000000000000000000000000000000000000000000000000000000000074e4135177cd281b332bb8fceb46da32abda5d6dc4d2eef6342a5399c9fb3c48"));
        if (!h(last_vbf).equals("6996212c70fa85b82d4fd76bd262e0cebc5d8f52350a73af8d2b881a30442b9d"))
            throw new RuntimeException("Unexpected asset_final_vbf result");
    }

    public void test_blinding_keys() {
        // hexes from local regtest testing
        final byte[] seed = h("fecd7938b912091cdedb47f70d4f3742f59f77e3bac780c0c498e2aaf6f9f4ab");
        final byte[] master_blinding_key = Wally.asset_blinding_key_from_seed(seed);
        if (!h(master_blinding_key).equals("624d15c603de16a92081fece31b9f21ac53ff6cb00f4180b0021adf754b161c9aa44ecaa161502f3b9a84122179a4320524ab1807578ee291360c2133f445233"))
            throw new RuntimeException("Unexpected master_blinding_key result");

        final byte[] scriptpubkey = h("a914822866d2b6a573a313e124bb1881a2f7ac4954ec87");
        final byte[] private_blinding_key = Wally.asset_blinding_key_to_ec_private_key(master_blinding_key, scriptpubkey);
        if (!h(private_blinding_key).equals("358876bdb32f60b8cdb811e922600b36b4d2b752d1869cccd9d79c566f45d87a"))
            throw new RuntimeException("Unexpected private_blinding_key result");

        final byte[] public_blinding_key = Wally.ec_public_key_from_private_key(private_blinding_key);
        if (!h(public_blinding_key).equals("03df03058b2d4032471b0937c2401aa728e1403f4bce0fa62d917cff874c87bd45"))
            throw new RuntimeException("Unexpected public_blinding_key result");
    }

    public void test_symmetric() {
        // Just test our wrappers; the values are tested by test_blinding_keys() above
        final byte[] seed = h("fecd7938b912091cdedb47f70d4f3742f59f77e3bac780c0c498e2aaf6f9f4ab");
        final byte[] master_key = Wally.symmetric_key_from_seed(seed);
        final byte[] child_key = Wally.symmetric_key_from_parent(master_key, 0, new String("foo").getBytes());
    }

    private void test_confidential_address() {
        // hexes from local regtest testing
        final String addr = "Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6";
        final String pubkey_hex = "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623";
        final String addr_c = "VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK";

        final String new_addr = Wally.confidential_addr_to_addr(addr_c, Wally.WALLY_CA_PREFIX_LIQUID);
        if (!new_addr.equals(addr))
            throw new RuntimeException("Failed to extract address from confidential address");

        final byte[] pubkey = Wally.confidential_addr_to_ec_public_key(addr_c, Wally.WALLY_CA_PREFIX_LIQUID);
        if (!Wally.hex_from_bytes(pubkey).equals(pubkey_hex))
            throw new RuntimeException("Failed to extract pubkey from confidential address");

        final String new_addr_c = Wally.confidential_addr_from_addr(addr, Wally.WALLY_CA_PREFIX_LIQUID, pubkey);
        if (!new_addr_c.equals(addr_c))
            throw new RuntimeException("Failed to create confidential address");
    }

    private void test_confidential_values() {
        final String hex_values[] = {"010000000002faf080", "010000000002fa2d30", "01000000000000c350"};
        final long long_values[] = {50000000, 49950000, 50000};

        for (int i = 0; i < long_values.length; ++i) {
          if (!hex_values[i].equals(h(Wally.tx_confidential_value_from_satoshi(long_values[i]))))
              throw new RuntimeException("Unexpected confidential value");

          if (long_values[i] != Wally.tx_confidential_value_to_satoshi(h(hex_values[i])))
              throw new RuntimeException("Unexpected long satoshi value");
        }
    }

    private String h(final byte[] bytes) { return Wally.hex_from_bytes(bytes); }
    private byte[] h(final String hex) { return Wally.hex_to_bytes(hex); }

    public static void main(final String[] args) {
        final test_assets t = new test_assets();
        t.test_blinding();
        t.test_blinding_keys();
        t.test_symmetric();
        t.test_confidential_address();
        t.test_confidential_values();
    }
}
