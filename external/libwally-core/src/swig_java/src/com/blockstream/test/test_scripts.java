package com.blockstream.test;

import com.blockstream.libwally.Wally;

public class test_scripts {

  public void test_p2pkh() {
      final byte[] redeem1 = h("111111111111111111111111111111111111111111111111111111111111111111");
      if (!h(Wally.scriptpubkey_p2pkh_from_bytes(redeem1, Wally.WALLY_SCRIPT_HASH160)).equals("76a9148ec4cf3ee160b054e0abb6f5c8177b9ee56fa51e88ac"))
          throw new RuntimeException("Unexpected p2pkh result");

      final byte[] redeem2 = h("1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
      if (!h(Wally.scriptpubkey_p2pkh_from_bytes(redeem2, Wally.WALLY_SCRIPT_HASH160)).equals("76a914e723a0f62396b8b03dbd9e48e9b9efe2eb704aab88ac"))
          throw new RuntimeException("Unexpected p2pkh result");
  }

  public void test_p2sh() {
      // hexes from local regtest testing
      final byte[] redeem1 = h("0020a22f2fcda841261e29973ad0191130911c5fd95eeec58de8e9367223b5dc040e");
      if (!h(Wally.scriptpubkey_p2sh_from_bytes(redeem1, Wally.WALLY_SCRIPT_HASH160)).equals("a914822866d2b6a573a313e124bb1881a2f7ac4954ec87"))
          throw new RuntimeException("Unexpected p2sh result");

      final byte[] redeem2 = h("002028a8fc70e1299f8728f62f2fe4ab98ef3af6e1af0bd46b2b924fa22092af00b8");
      if (!h(Wally.scriptpubkey_p2sh_from_bytes(redeem2, Wally.WALLY_SCRIPT_HASH160)).equals("a914faf609ab5e82fbe8f6fcf0dcb2d4359dd044d2d387"))
          throw new RuntimeException("Unexpected p2sh result");
  }

  public void test_multisig() {
      // hexes from local regtest testing
      final byte[] pubkeys = h("0351aa9225259d7c10fe606c66e0511ec766b7861c5caf9ef6247bcd9d117d92ef03d5a4d76608543b09c0bba4f496f6d24baa8f07b9f65bdadde978e4f1208fc6a10249674f61c45b47767937f2142db44d0e87e5e9a0ada986c35bd588ac7074afae");
      if (!h(Wally.scriptpubkey_multisig_from_bytes(pubkeys, 2, 0, 3)).equals("52210351aa9225259d7c10fe606c66e0511ec766b7861c5caf9ef6247bcd9d117d92ef2103d5a4d76608543b09c0bba4f496f6d24baa8f07b9f65bdadde978e4f1208fc6a1210249674f61c45b47767937f2142db44d0e87e5e9a0ada986c35bd588ac7074afae53ae"))
          throw new RuntimeException("Unexpected multisig result");
  }

  private String h(final byte[] bytes) { return Wally.hex_from_bytes(bytes); }
  private byte[] h(final String hex) { return Wally.hex_to_bytes(hex); }

  public static void main(final String[] args) {
      final test_scripts t = new test_scripts();
      t.test_p2pkh();
      t.test_p2sh();
      t.test_multisig();
  }
}
