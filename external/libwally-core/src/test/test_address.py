import unittest
from util import *

VER_MAIN_PUBLIC = 0x0488B21E
VER_TEST_PUBLIC = 0x043587CF

FLAG_KEY_PUBLIC = 0x1

ADDRESS_TYPE_P2PKH       = 0x01
ADDRESS_TYPE_P2SH_P2WPKH = 0x02
ADDRESS_TYPE_P2WPKH      = 0x04

ADDRESS_VERSION_P2PKH_MAINNET = 0x00
ADDRESS_VERSION_P2PKH_TESTNET = 0x6F
ADDRESS_VERSION_P2SH_MAINNET  = 0x05
ADDRESS_VERSION_P2SH_TESTNET  = 0xC4

NETWORK_BITCOIN_MAINNET = 0x01
NETWORK_BITCOIN_TESTNET = 0x02
NETWORK_LIQUID_MAINNET  = 0x03
NETWORK_LIQUID_REGTEST  = 0x04
NETWORK_LIQUID_TESTNET  = 0x05


# Vector from test_bip32.py. We only need an xpub to derive addresses.
vec = {

    'm/0H/1': {
        # xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ
        FLAG_KEY_PUBLIC:  '0488B21E025C1BD648000000012A7857'
                          '631386BA23DACAC34180DD1983734E44'
                          '4FDBF774041578E9B6ADB37C1903501E'
                          '454BF00751F24B1B489AA925215D66AF'
                          '2234E3891C3B21A52BEDB3CD711C6F6E2AF7',

        "address_legacy": '1JQheacLPdM5ySCkrZkV66G2ApAXe1mqLj',

        # OP_DUP OP_HASH160 [pub_key_hash] OP_EQUALVERIFY OP_CHECKSIG
        'scriptpubkey_legacy': '76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac',

        "address_p2sh_segwit": '3DymAvEWH38HuzHZ3VwLus673bNZnYwNXu',

        # OP_HASH160 [script_hash] OP_EQUAL
        'scriptpubkey_p2sh_segwit': 'a91486cc442a97817c245ce90ed0d31d6dbcde3841f987',

        "address_segwit": 'bc1qhm6697d9d2224vfyt8mj4kw03ncec7a7fdafvt',

        ## OP_0 [pub_key_hash]
        'scriptpubkey_segwit': '0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe',
    },

    'm/1H/1': {
        # tpubDApXh6cD2fZ7WjtgpHd8yrWyYaneiFuRZa7fVjMkgxsmC1QzoXW8cgx9zQFJ81Jx4deRGfRE7yXA9A3STsxXj4CKEZJHYgpMYikkas9DBTP
        FLAG_KEY_PUBLIC:  '043587CF025C1BD648000000012A7857'
                          '631386BA23DACAC34180DD1983734E44'
                          '4FDBF774041578E9B6ADB37C1903501E'
                          '454BF00751F24B1B489AA925215D66AF'
                          '2234E3891C3B21A52BEDB3CD711C6F6E2AF7',

        "address_legacy": 'mxvewdhKCenLkYgNa8irv1UM2omEWPMdEE',

        # OP_DUP OP_HASH160 [pub_key_hash] OP_EQUALVERIFY OP_CHECKSIG
        'scriptpubkey_legacy': '76a914bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe88ac',

        "address_p2sh_segwit": '2N5XyEfAXtVde7mv6idZDXp5NFwajYEj9TD',

        # OP_HASH160 [script_hash] OP_EQUAL
        'scriptpubkey_p2sh_segwit': 'a91486cc442a97817c245ce90ed0d31d6dbcde3841f987',

        "address_segwit": 'tb1qhm6697d9d2224vfyt8mj4kw03ncec7a7rtx6hc',

        ## OP_0 [pub_key_hash]
        'scriptpubkey_segwit': '0014bef5a2f9a56a94aab12459f72ad9cf8cf19c7bbe',
    }

}

class AddressTests(unittest.TestCase):

    SERIALIZED_LEN = 4 + 1 + 4 + 4 + 32 + 33

    def unserialize_key(self, buf, buf_len):
        key_out = ext_key()
        ret = bip32_key_unserialize(buf, buf_len, byref(key_out))
        return ret, key_out

    def get_test_key(self, vec, path):
        buf, buf_len = make_cbuffer(vec[path][FLAG_KEY_PUBLIC])
        ret, key_out = self.unserialize_key(buf, self.SERIALIZED_LEN)
        self.assertEqual(ret, WALLY_OK)

        return key_out

    def test_address_vectors(self):
        self.do_test_vector(vec, 'm/0H/1', NETWORK_BITCOIN_MAINNET)
        self.do_test_vector(vec, 'm/1H/1', NETWORK_BITCOIN_TESTNET) # Testnet

    def do_test_vector(self, vec, path, network):
        key = self.get_test_key(vec, path)

        # Address type flag is mandatory
        version = ADDRESS_VERSION_P2PKH_MAINNET if network == NETWORK_BITCOIN_MAINNET else ADDRESS_VERSION_P2PKH_TESTNET
        ret, new_addr = wally_bip32_key_to_address(key, 0, version)
        self.assertEqual(ret, WALLY_EINVAL)

        # Obtain legacy address (P2PKH)
        ret, new_addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2PKH, version)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(new_addr, vec[path]['address_legacy'])

        # Obtain wrapped SegWit address (P2SH_P2WPKH)
        version = ADDRESS_VERSION_P2SH_MAINNET if network == NETWORK_BITCOIN_MAINNET else ADDRESS_VERSION_P2SH_TESTNET
        ret, new_addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2SH_P2WPKH, version)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(new_addr, vec[path]['address_p2sh_segwit'])

        # wally_bip32_key_to_address does not support bech32 native SegWit (P2WPKH)
        ret, new_addr = wally_bip32_key_to_address(key, ADDRESS_TYPE_P2WPKH, version)
        self.assertEqual(ret, WALLY_EINVAL)

        # Obtain native SegWit address (P2WPKH)
        bech32_prefix = 'bc' if network == NETWORK_BITCOIN_MAINNET else 'tb'
        ret, new_addr = wally_bip32_key_to_addr_segwit(key, utf8(bech32_prefix), 0)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(new_addr, vec[path]['address_segwit'])

        # Parse legacy address (P2PKH):
        out, out_len = make_cbuffer('00' * (25))
        ret, written = wally_address_to_scriptpubkey(utf8(vec[path]['address_legacy']), network, out, out_len)

        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(out[0:written]), utf8(vec[path]['scriptpubkey_legacy']))

        # Get address for P2PKH scriptPubKey
        ret, new_addr = wally_scriptpubkey_to_address(out, written, network)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(new_addr, vec[path]['address_legacy'])

        # Parse wrapped SegWit address (P2SH_P2WPKH):
        out, out_len = make_cbuffer('00' * (25))
        ret, written = wally_address_to_scriptpubkey(utf8(vec[path]['address_p2sh_segwit']), network, out, out_len)

        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(out[0:written]), utf8(vec[path]['scriptpubkey_p2sh_segwit']))

        # Get address for P2SH scriptPubKey
        ret, new_addr = wally_scriptpubkey_to_address(out, written, network)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(new_addr, vec[path]['address_p2sh_segwit'])

        # Parse native SegWit address (P2WPKH):
        out, out_len = make_cbuffer('00' * (100))
        ret, written = wally_addr_segwit_to_bytes(utf8(vec[path]['address_segwit']), utf8(bech32_prefix), 0, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(h(out[0:written]), utf8(vec[path]['scriptpubkey_segwit']))

    def test_address_scriptpubkey_liquid(self):
        """Check that addresses can be converted to and from scriptpubkeys for Liquid"""
        for addr, scriptpubkey, network in [
            ('XYtnYoGoSeE9ouMEVi6mfeujhjT2VnJncA', 'a914ec51ffb65120594389733bf8625f542446d97f7987', NETWORK_LIQUID_REGTEST),
            ('8ijSaT49UHvpdmcAuHkKPEPJBKMoLog6do', 'a9142f470bcda2c4818fd47b25b2d7ec95fda56ffca287', NETWORK_LIQUID_TESTNET),
            ('H5nswXhfo8AMt159sgA5FWT35De34hVR4o', 'a914f80278b2011573a2ac59c83fadf929b0fc57ad0187', NETWORK_LIQUID_MAINNET),
        ]:
            out, out_len = make_cbuffer('00' * (100))
            ret, written = wally_address_to_scriptpubkey(utf8(addr), network, out, out_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(h(out[0:written]), utf8(scriptpubkey))

            ret, new_addr = wally_scriptpubkey_to_address(out, written, network)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(utf8(new_addr), utf8(addr))


if __name__ == '__main__':
    unittest.main()
