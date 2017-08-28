package com.blockstream.test;

import com.blockstream.libwally.Wally;
import static com.blockstream.libwally.Wally.BIP32_FLAG_KEY_PRIVATE;
import static com.blockstream.libwally.Wally.BIP32_VER_MAIN_PRIVATE;

public class test_bip32 {

    final byte[] mSeed;

    public test_bip32() {
        mSeed = h("000102030405060708090a0b0c0d0e0f");
    }

    public void test() {
        final Object seedKey = Wally.bip32_key_from_seed(mSeed, BIP32_VER_MAIN_PRIVATE, 0);

        final String hex = "0488ade4000000000000000000873dff81c02f525623fd1fe5167eac3a55" +
            "a049de3d314bb42ee227ffed37d50800e8f32e723decf4051aefac8e2c93c9c5b214313817c" +
            "db01a1494b917c8436b35";
        final Object unserialized = Wally.bip32_key_unserialize(h(hex));

        final byte[] newSerialized = Wally.bip32_key_serialize(unserialized, BIP32_FLAG_KEY_PRIVATE);
        if (!h(newSerialized).equals(hex))
            throw new RuntimeException("BIP32 serialization did not round-trip correctly");

        final Object derivedKey = Wally.bip32_key_from_parent(seedKey, 0, BIP32_FLAG_KEY_PRIVATE);
        final String derivedChainCode = h(Wally.bip32_key_get_chain_code(derivedKey));
        if (derivedChainCode.length() != 64)
            throw new RuntimeException("BIP32 incorrect chain code");
        if (Wally.bip32_key_get_depth(derivedKey) != 1)
            throw new RuntimeException("BIP32 incorrect depth");

        Object initKey = Wally.bip32_key_init(Wally.bip32_key_get_version(derivedKey),
                                              Wally.bip32_key_get_depth(derivedKey),
                                              Wally.bip32_key_get_child_num(derivedKey),
                                              Wally.bip32_key_get_chain_code(derivedKey),
                                              Wally.bip32_key_get_pub_key(derivedKey),
                                              Wally.bip32_key_get_priv_key(derivedKey),
                                              Wally.bip32_key_get_hash160(derivedKey),
                                              Wally.bip32_key_get_parent160(derivedKey));

        final byte[] derivedSerialized = Wally.bip32_key_serialize(derivedKey, BIP32_FLAG_KEY_PRIVATE);
        final byte[] initSerialized = Wally.bip32_key_serialize(initKey, BIP32_FLAG_KEY_PRIVATE);

        if (!h(initSerialized).equals(h(derivedSerialized)))
            throw new RuntimeException("BIP32 initialisation by member failed");

        Wally.bip32_key_free(initKey);
        Wally.bip32_key_free(derivedKey);
        Wally.bip32_key_free(unserialized);
        Wally.bip32_key_free(seedKey);
    }

    private String h(final byte[] bytes) { return Wally.hex_from_bytes(bytes); }
    private byte[] h(final String hex) { return Wally.hex_to_bytes(hex); }

    public static void main(final String[] args) {
        final test_bip32 t = new test_bip32();
        t.test();
    }
}
