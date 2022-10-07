package com.blockstream.test;

import java.util.Arrays;

import com.blockstream.libwally.Wally;
import static com.blockstream.libwally.Wally.BIP32_FLAG_KEY_PRIVATE;
import static com.blockstream.libwally.Wally.BIP32_VER_MAIN_PRIVATE;
import static com.blockstream.libwally.Wally.EC_FLAG_ECDSA;
import static com.blockstream.libwally.Wally.EC_FLAG_RECOVERABLE;

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

        final byte[] message = Wally.bip32_key_get_chain_code(derivedKey);
        final byte[] signature = Wally.ec_sig_from_bytes(Wally.bip32_key_get_priv_key(derivedKey),
                                                         message,
                                                         EC_FLAG_ECDSA);

        final byte[] signatureRecoverable = Wally.ec_sig_from_bytes(Wally.bip32_key_get_priv_key(derivedKey),
                                                                    message,
                                                                    EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE);

        if (!Arrays.equals(signature, Arrays.copyOfRange(signatureRecoverable, 1, 65))) {
            throw new RuntimeException("Recoverable signature does not match");
        }

        final byte[] pubkey = Wally.bip32_key_get_pub_key(derivedKey);
        Wally.ec_sig_verify(pubkey, message, EC_FLAG_ECDSA, signature);
        Wally.ec_sig_verify(pubkey, message, EC_FLAG_ECDSA, Arrays.copyOfRange(signatureRecoverable, 1, 65));

        final byte[] pubkey_recovered = Wally.ec_sig_to_public_key(message, signatureRecoverable);
        if (!Arrays.equals(pubkey, pubkey_recovered)) {
            throw new RuntimeException("Failed to recover pubkey from signature");
        }

        // Test pubkey negation
        final byte[] pubkey_negated = Wally.ec_public_key_negate(pubkey_recovered);
        if (Arrays.equals(pubkey_recovered, pubkey_negated)) {
            throw new RuntimeException("Failed to negate pubkey");
        }

        final byte[] pubkey_unnegated = Wally.ec_public_key_negate(pubkey_negated);
        if (!Arrays.equals(pubkey_recovered, pubkey_unnegated)) {
            throw new RuntimeException("Double negation did not return original pubkey");
        }

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
