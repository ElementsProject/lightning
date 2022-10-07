import unittest
from util import *


EC_PUBLIC_KEY_LEN = 33
FLAG_KEY_PUBLIC, FLAG_KEY_TWEAK_SUM = 0x1, 0x4
SCRIPTPUBKEY_P2PKH_LEN = 25
SCRIPT_HASH160 = 0x1


class PegoutTests(unittest.TestCase):

    def path_to_c(self, path):
        c_path = (c_uint * len(path))()
        for i, n in enumerate(path):
            c_path[i] = n
        return c_path

    def derive_pub_tweak(self, parent, path):
        c_path = self.path_to_c(path)
        key_out = POINTER(ext_key)()
        fn = bip32_key_with_tweak_from_parent_path_alloc
        self.assertEqual(fn(byref(parent), c_path, len(path),
                            FLAG_KEY_PUBLIC | FLAG_KEY_TWEAK_SUM, byref(key_out)), WALLY_OK)
        return key_out[0].pub_key, key_out[0].pub_key_tweak_sum

    def generate_pegout_whitelistproof(self):
        offline_xpub = 'tpubDAY5hwtonH4NE8zY46ZMFf6B6F3fqMis7cwfNihXXpAg6XzBZNoHAdAzAZx2peoU8nTWFqvUncXwJ9qgE5VxcnUKxdut8F6mptVmKjfiwDQ'
        offline_counter = 8
        pak_list = '030781ae6f87c0b3af83b7350eb38bbd22322f525046d0320f1cb45a97c05cbeb7:031f26676db48716aff0f6ac477db463715d3280e2c706b55556425831620fdcce'
        master_online_key, master_online_key_len = make_cbuffer('06def06500e5efae3addf7e0ed1178074405587a95c49a3ef31367eec782319f')

        pub_key, pub_key_len = make_cbuffer('00'*33)
        self.assertEqual(wally_ec_public_key_from_private_key(master_online_key, master_online_key_len, pub_key, pub_key_len), WALLY_OK)
        buf, buf_len = make_cbuffer('00'*33)
        ret, written = wally_hex_to_bytes(utf8('031f26676db48716aff0f6ac477db463715d3280e2c706b55556425831620fdcce'), buf, buf_len)
        self.assertEqual(pub_key, buf)

        whitelist_index = 0

        keys = pak_list.split(':')
        offline_keys, offline_keys_len = make_cbuffer(keys[0])
        online_keys, online_keys_len = make_cbuffer(keys[1])

        key_out = ext_key()
        self.assertEqual(bip32_key_from_base58(utf8(offline_xpub), byref(key_out)), WALLY_OK)
        negated_master_pubkey, negated_master_pubkey_len = make_cbuffer('00'*EC_PUBLIC_KEY_LEN)
        self.assertEqual(wally_ec_public_key_negate(key_out.pub_key, EC_PUBLIC_KEY_LEN, negated_master_pubkey, EC_PUBLIC_KEY_LEN), WALLY_OK)
        buf, buf_len = make_cbuffer('00'*int(len(keys[0])/2))
        ret, written = wally_hex_to_bytes(utf8(keys[0]), buf, buf_len)
        self.assertEqual(negated_master_pubkey, buf)
        pub_key, pub_tweak = self.derive_pub_tweak(key_out, [0, offline_counter])

        whitelistproof, whitelistproof_len = make_cbuffer('00'*65)
        (code, written) = wally_asset_pak_whitelistproof(online_keys, online_keys_len, offline_keys,
                                                        offline_keys_len, whitelist_index, pub_key, len(pub_key),
                                                        master_online_key, master_online_key_len,
                                                        pub_tweak, len(pub_tweak), whitelistproof, whitelistproof_len)
        self.assertEqual(code, WALLY_OK)
        self.assertEqual(whitelistproof_len, written)

        return whitelistproof, whitelistproof_len, pub_key, len(pub_key)

    def generate_pegout_script(self):
        gen_wlproof, gen_wlproof_len, pub_key, pub_key_len = self.generate_pegout_whitelistproof()
        wl_proof = '013996e9eca65e06b3deda77fdc19b3476cd83af3ae8f543647a52b097558c33878752c52536c493ea00d446159009ce484795287aca1de8aaa52d6064b5960caa'
        buf, buf_len = make_cbuffer('00'*int(len(wl_proof)/2))
        ret, written = wally_hex_to_bytes(utf8(wl_proof), buf, buf_len)
        self.assertEqual(buf, gen_wlproof)

        genesis_block_hash, genesis_block_hash_len = make_cbuffer('0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206')

        mainchain_script, mainchain_script_len = make_cbuffer('00'*SCRIPTPUBKEY_P2PKH_LEN)
        self.assertEqual(wally_scriptpubkey_p2pkh_from_bytes(pub_key, pub_key_len, SCRIPT_HASH160,
                                                             mainchain_script, mainchain_script_len)[0], WALLY_OK)

        pegout_script, pegout_script_len = make_cbuffer('00'*(genesis_block_hash_len + mainchain_script_len + pub_key_len + gen_wlproof_len+5))
        self.assertEqual(wally_elements_pegout_script_from_bytes(genesis_block_hash[::-1], genesis_block_hash_len,
                                                                 mainchain_script, mainchain_script_len,
                                                                 pub_key, pub_key_len,
                                                                 gen_wlproof, gen_wlproof_len, 0,
                                                                 pegout_script, pegout_script_len)[0], WALLY_OK)
        return pegout_script, pegout_script_len

    def test_pegout(self):
        op_return_data = '6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a91420f2d8c7514c601984fffee90f988f33bd87f96f88ac2103c58ebf2840c9321e42e1859a387d42cc78241048f81ce9c911bd57b240139e9741013996e9eca65e06b3deda77fdc19b3476cd83af3ae8f543647a52b097558c33878752c52536c493ea00d446159009ce484795287aca1de8aaa52d6064b5960caa'
        buf, buf_len = make_cbuffer('00'*int(len(op_return_data)/2))
        ret, written = wally_hex_to_bytes(utf8(op_return_data), buf, buf_len)
        self.assertEqual(buf, self.generate_pegout_script()[0])

    def test_pegout_tx(self):
        tx_hex = "02000000010111b13a9bc2833fcfddb53086fffb3cf7ff1c13948c876d9bd15df872f5fdefca0000000017160014355347fd5b11a57cddd5e1576fb38280a0627cf7fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000174876e80000a06a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f1976a91420f2d8c7514c601984fffee90f988f33bd87f96f88ac2103c58ebf2840c9321e42e1859a387d42cc78241048f81ce9c911bd57b240139e9741013996e9eca65e06b3deda77fdc19b3476cd83af3ae8f543647a52b097558c33878752c52536c493ea00d446159009ce484795287aca1de8aaa52d6064b5960caa0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010007751ecdd907a20017a9140fbb8e55216381f7c4e7124eaa9070d8e8dc92c7870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000105e0000000000000000024730440220029550293885a772c04c2a462b0afc7d9dd03d0286d37e1273d60a64b333875e0220626baf165c2ba70d5ce202bf6d2212a0bab83b457188a52db67d5ce396601d5001210324a1cbd388173f0c72616a0c8fe363daf9c016a157b14aa1dabf6d19b85df95c00000000000000"
        asset, asset_len =  make_cbuffer('5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225')
        txhash, txhash_len = make_cbuffer('caeffdf572f85dd19b6d878c94131cfff73cfbff8630b5ddcf3f83c29b3ab111')

        tx = wally_tx(2)
        script_sig, script_sig_len = make_cbuffer('160014355347fd5b11a57cddd5e1576fb38280a0627cf7')
        witness_stack = wally_tx_witness_stack()
        witness, witness_len = make_cbuffer('30440220029550293885a772c04c2a462b0afc7d9dd03d0286d37e1273d60a64b333875e0220626baf165c2ba70d5ce202bf6d2212a0bab83b457188a52db67d5ce396601d5001')
        self.assertEqual(wally_tx_witness_stack_add(witness_stack, witness, witness_len), WALLY_OK)
        witness, witness_len = make_cbuffer('0324a1cbd388173f0c72616a0c8fe363daf9c016a157b14aa1dabf6d19b85df95c')
        self.assertEqual(wally_tx_witness_stack_add(witness_stack, witness, witness_len), WALLY_OK)
        self.assertEqual(wally_tx_add_elements_raw_input(tx, txhash[::-1], txhash_len,
                                                         0, 0xfffffffd, script_sig, script_sig_len, witness_stack,
                                                         None, 0, None, 0, None, 0, None, 0, None, 0, None, 0, wally_tx_witness_stack(), 0), WALLY_OK)

        unconfidential_satoshi, unconfidential_satoshi_len = make_cbuffer('00'*9)
        self.assertEqual(wally_tx_confidential_value_from_satoshi(1000*10**8, unconfidential_satoshi, unconfidential_satoshi_len), WALLY_OK)
        pegout_script, pegout_script_len = self.generate_pegout_script()
        self.assertEqual(wally_tx_add_elements_raw_output(tx, pegout_script, pegout_script_len, b'\x01'+asset[::-1], asset_len+1,
                                                          unconfidential_satoshi, unconfidential_satoshi_len, None, 0, None, 0, None, 0, 0), WALLY_OK)

        self.assertEqual(wally_tx_confidential_value_from_satoshi(2099099999995810, unconfidential_satoshi, unconfidential_satoshi_len), WALLY_OK)
        script, script_len = make_cbuffer('a9140fbb8e55216381f7c4e7124eaa9070d8e8dc92c787')
        self.assertEqual(wally_tx_add_elements_raw_output(tx, script, script_len, b'\x01'+asset[::-1], asset_len+1,
                                                          unconfidential_satoshi, unconfidential_satoshi_len, None, 0, None, 0, None, 0, 0), WALLY_OK)

        self.assertEqual(wally_tx_confidential_value_from_satoshi(4190, unconfidential_satoshi, unconfidential_satoshi_len), WALLY_OK)
        self.assertEqual(wally_tx_add_elements_raw_output(tx, None, 0, b'\x01'+asset[::-1], asset_len+1,
                                                          unconfidential_satoshi, unconfidential_satoshi_len, None, 0, None, 0, None, 0, 0), WALLY_OK)

        ret, pegout_tx_hex = wally_tx_to_hex(tx, 1)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(pegout_tx_hex, tx_hex)


if __name__ == '__main__':
    _, val = wally_is_elements_build()
    if val != 0:
        unittest.main()
