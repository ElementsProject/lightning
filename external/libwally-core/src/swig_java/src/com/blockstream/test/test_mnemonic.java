package com.blockstream.test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.blockstream.libwally.Wally;
import static com.blockstream.libwally.Wally.BIP39_ENTROPY_LEN_256;
import static com.blockstream.libwally.Wally.BIP39_SEED_LEN_512;

public class test_mnemonic {

    private final SecureRandom sr = new SecureRandom();
    private final Object wl;

    public test_mnemonic(final String lang) {
        this.wl = Wally.bip39_get_wordlist(lang);
    }

    public static String[] getLanguages() {
        return Wally.bip39_get_languages().split(" ");
    }

    public String generate(final int strength) {
        final byte[] seed = new byte[strength];
        sr.nextBytes(seed);
        return toMnemonic(seed);
    }

    public String generate() {
        return generate(BIP39_ENTROPY_LEN_256);
    }

    public byte[] toEntropy(final String mnemonics) {
        final byte[] buf = new byte[BIP39_ENTROPY_LEN_256];
        return Arrays.copyOf(buf, Wally.bip39_mnemonic_to_bytes(
                wl, mnemonics, buf));
    }

    public String toMnemonic(final byte[] data) {
        return Wally.bip39_mnemonic_from_bytes(wl, data);
    }

    public boolean check(final String mnemonic) {
        try {
            Wally.bip39_mnemonic_validate(wl, mnemonic);
            return true;
        } catch (final Exception e) {
            return false;
        }
    }

    public byte[] toSeed(final String mnemonic, final String passphrase) {
        final byte[] buf = new byte[BIP39_SEED_LEN_512];
        Wally.bip39_mnemonic_to_seed(mnemonic, passphrase, buf);
        return buf;
    }

    private static final Map<String, byte[]> testMap;
    static {
        final String m =
                "legal winner thank year wave sausage worth useful legal winner thank yellow";
        final Map<String, byte[]> aMap = new HashMap<>();
        aMap.put(m, new byte[]{});
        aMap.put(m, null);
        aMap.put("gibberish", new byte[BIP39_ENTROPY_LEN_256]);
        aMap.put("", new byte[BIP39_ENTROPY_LEN_256]);
        aMap.put(null, new byte[BIP39_ENTROPY_LEN_256]);
        testMap = Collections.unmodifiableMap(aMap);
    }

    public static void main(final String[] args) {
        for (final String lang : getLanguages()) {
            final test_mnemonic m = new test_mnemonic(lang);
            final String phrase = m.generate();
            if (!m.check(phrase) ||
                m.check(String.format("%s foo", phrase)) ||
                !Arrays.equals(m.toEntropy(phrase), m.toEntropy(phrase)) ||
                !m.toMnemonic(m.toEntropy(phrase)).equals(phrase) ||
                Arrays.equals(m.toSeed(phrase, "foo"), m.toSeed(phrase, "bar")))
                throw new RuntimeException("Mnemonic failed basic verification");
        }

        for(final Map.Entry<String, byte[]> entry : testMap.entrySet())
            try {
                Wally.bip39_mnemonic_to_bytes(null, entry.getKey(), entry.getValue());
                throw new RuntimeException("Mnemonic failed basic verification");
            } catch (final IllegalArgumentException e) {
                // pass
            }
        final byte[] data = new byte[BIP39_ENTROPY_LEN_256];

        try {
            Wally.bip39_mnemonic_from_bytes(null, data);
            throw new RuntimeException("Mnemonic failed basic verification");
        } catch (final IllegalArgumentException e) {
            // pass
        }

        try {
            Wally.bip39_mnemonic_from_bytes(new Object(), data);
            throw new RuntimeException("Mnemonic failed basic verification");
        } catch (final IllegalArgumentException e) {
            // pass
        }
    }
}
