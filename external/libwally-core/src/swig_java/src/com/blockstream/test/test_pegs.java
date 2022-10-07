package com.blockstream.test;

import com.blockstream.libwally.Wally;

public class test_pegs {

    // All hexes taken from src/test/test_peg[in|out].py
    public void test_pak_whitelistproof() {
      final byte[] onkeys = h("031f26676db48716aff0f6ac477db463715d3280e2c706b55556425831620fdcce");
      final byte[] offkeys = h("030781ae6f87c0b3af83b7350eb38bbd22322f525046d0320f1cb45a97c05cbeb7");
      final int index = 0;
      final byte[] pub_key = h("03c58ebf2840c9321e42e1859a387d42cc78241048f81ce9c911bd57b240139e97");
      final byte[] master_online_key = h("06def06500e5efae3addf7e0ed1178074405587a95c49a3ef31367eec782319f");
      final byte[] pub_tweak = h("5d0f162bd18a271d8d219efd013f51d6fc8597d035a04b2b1e4686c05e92aaed");

      final String expected_hex = "013996e9eca65e06b3deda77fdc19b3476cd83af3ae8f543647a52b097558c33878752c52536c493ea00d446159009ce484795287aca1de8aaa52d6064b5960caa";

      final byte[] wlproof = Wally.asset_pak_whitelistproof(onkeys, offkeys, index, pub_key, master_online_key, pub_tweak);

      if (!h(wlproof).equals(expected_hex))
          throw new RuntimeException("Unexpected whitelistproof result");
    }

    public void test_pegin_contract_script() {
        final byte[] federation_script = h("745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae");

        final byte[] script_in = h("0014d712bcaf8f9384fd388efca86d77e033d5cfffd9");

        final String expected_hex = "745c87635b21039e7dc52351b81d97dde2b369f692d89b5cf938534ad503094bc89f830473796321030508eb92dccb704ac7511eb55369f2259485b50f56671ff5bf1dfd8cdf5c6c662102140052a92c55c5a0c2f960b438bba966974cdfa2c872a4702645ff6028f6b0f2210209aa6d8ab038fd00088355324c9c3fea336b2cf650d951b23c2b20ad47386daa2102328940da1f59bc214757a8fdedd86887fc48a952e0fa19c1f1959ffa826c88b42102188281e1055fb81f642a7f2ca994a8f6abaa8bbcc2720aff35c0fd263188ef7c2103ae97faefcdba436269cc36c31db7956ade6c1977b174b87174173ea92c112d332103f4a2d090f03684a65f74f5ee031d6d9bf5fd02d4e643693701f86d4e4f721ae82102d5ee27530bc9075c310e53b308a127a3ed7a90c6039355d00d2d1ea72874add72103960c1740e6ac39c15fc8fd048789fdd480b68331a49e6e557fcbec192d0b3a252103e33ae6c4b978523ff81e8f2fb2e2c0174f9483de86c186e228753715fa2228392103003d2490f282d7628a2a8efa08366f317efa6473579bb5c34b4c409e36e7b2df2102da66e69bd08a68d4c8fabefd797786bb6de16d553acab4ee85e3aceda8e48d8c2103d46bd2ba127f1666650de1e0d85f438978c28399a9ac866ea84db30cc77446c3210257fdfffaf0a360f7ee1d0c2588d931a5b51302ab5a100cd9fa54ebe1d63adbdb5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae";

        final byte[] contract_script = Wally.elements_pegin_contract_script_from_bytes(federation_script, script_in, 0);

        if (!h(contract_script).equals(expected_hex))
            throw new RuntimeException("Unexpected pegin_contract_script result");
    }

    public void test_get_pegout_script() {
        final byte[] gbh_reversed = h("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f");
        final byte[] pubkey = h("03c58ebf2840c9321e42e1859a387d42cc78241048f81ce9c911bd57b240139e97");
        final byte[] mainchain_script = Wally.scriptpubkey_p2pkh_from_bytes(pubkey, Wally.WALLY_SCRIPT_HASH160);
        final byte[] wlproof = h("013996e9eca65e06b3deda77fdc19b3476cd83af3ae8f543647a52b097558c33878752c52536c493ea00d446159009ce484795287aca1de8aaa52d6064b5960caa");

        final String expected_hex = "6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a91420f2d8c7514c601984fffee90f988f33bd87f96f88ac2103c58ebf2840c9321e42e1859a387d42cc78241048f81ce9c911bd57b240139e9741013996e9eca65e06b3deda77fdc19b3476cd83af3ae8f543647a52b097558c33878752c52536c493ea00d446159009ce484795287aca1de8aaa52d6064b5960caa";

        final byte[] pegout_script = Wally.elements_pegout_script_from_bytes(gbh_reversed, mainchain_script, pubkey, wlproof, 0);

        if (!h(pegout_script).equals(expected_hex))
            throw new RuntimeException("Unexpected pegout_script result");
    }

    private String h(final byte[] bytes) { return Wally.hex_from_bytes(bytes); }
    private byte[] h(final String hex) { return Wally.hex_to_bytes(hex); }

    public static void main(final String[] args) {
        final test_pegs t = new test_pegs();
        t.test_pak_whitelistproof();
        t.test_pegin_contract_script();
        t.test_get_pegout_script();
    }
}
