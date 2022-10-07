import unittest
import hmac
import hashlib
from util import *

CA_PREFIX_LIQUID = 0x0c
CA_PREFIX_LIQUID_REGTEST = 0x04
EC_PUBLIC_KEY_LEN = 33

hrp = lambda s: s[:s.find('1')]

#   pk=02409b4d18429c6e5cbc0bd59c63b8fe7055f603190c8deed6a644bc95c9772e48
#   script=OP_HASH160 dc4af3ea14b0592621514e2bd4a0e083c7fac2f2 OP_EQUALVERIFY
#   -> a914dc4af3ea14b0592621514e2bd4a0e083c7fac2f288
#   tr hash=409b4d18429c6e5cbc0bd59c63b8fe7055f603190c8deed6a644bc95c9772e48
segwit_valid_cases = [
    [
         # p2wpkh testnet
        'ert1qu6ssk77c466kg3x9wd82dqkd9udddykyfykm9k',
        '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
        'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqpe4ppdaa3t44v3zv2u6w56pv6tc666fvgzaclqjnkz0sd',
     ], [
         # p2wpkh testnet
        'ert1qm39086s5kpvjvg23fc4afg8qs0rl4shjygphsr',
        '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
        'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqphz2704pfvzeycs4zn3t6jswpq78ltp0yd23jxpdekpau',
    ], [
        # p2wsh testnet
        'ert1qgs3lcwxkawtwvmrhrdww65m2vvmkl9367t54xh990dpmc09mehqs89mfu7',
        '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
        'el1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqq3prlsudd6ukuek8wx6ua4fk5cehd7tr4uhf2dw2276rhs7thnwpxqzalk28qxgj',
    ], [
        # p2wpkh liquidv1
        'ex1qm39086s5kpvjvg23fc4afg8qs0rl4shj76t00e',
        '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
        'lq1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqphz2704pfvzeycs4zn3t6jswpq78ltp0yxz3p90nf3npx',
    ], [
        # p2wsh liquidv1
        'ex1qgs3lcwxkawtwvmrhrdww65m2vvmkl9367t54xh990dpmc09mehqssgyt6f',
        '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
        'lq1qqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqq3prlsudd6ukuek8wx6ua4fk5cehd7tr4uhf2dw2276rhs7thnwp0vuhrqfhrklz',
    ], [
        # p2tr testnet
        'ert1pgzd56xzzn3h9e0qt6kwx8w87wp2lvqcepjx7a44xgj7ftjth9eyq0lx3wm',
        '03a398eed59a2368563bbd2bc68a7ccdbbd6dcbf43b298edc810d22edb6d761800',
        'el1pqw3e3mk4ng3ks43mh54udznuekaadh9lgwef3mwgzrfzakmdwcvqqsymf5vy98rwtj7qh4vuvwu0uuz47cp3jrydamt2v39ujhyhwtjgyxxut0a8e8ju',
    ],
]


class CATests(unittest.TestCase):

    def test_master_blinding_key(self):

        # from Trezor firmware code
        class Slip21Node:
            def __init__(self, seed = None):
                if seed is not None:
                    self.data = hmac.HMAC(b'Symmetric key seed', seed, hashlib.sha512).digest()
                else:
                    self.data = None

            def derive_path(self, path):
                for label in path:
                    h = hmac.HMAC(self.data[0:32], b'\x00', hashlib.sha512)
                    h.update(label)
                    self.data = h.digest()

            def key(self):
                return h(self.data[32:64])

        seed = create_string_buffer(64)
        bip39_mnemonic_to_seed(b' '.join([b'all'] * 12), b'', seed, 64)
        root = Slip21Node(seed = seed)
        self.assertEqual(root.key(), utf8('dbf12b44133eaab506a740f6565cc117228cbf1dd70635cfa8ddfdc9af734756'))
        root.derive_path([b'SLIP-0077'])
        master_blinding_key_hex = root.key()

        out = create_string_buffer(64)
        ret = wally_asset_blinding_key_from_seed(seed, 64, out, 64)
        self.assertEqual(ret, WALLY_OK)
        _, out_hex = wally_hex_from_bytes(out[32:], 32)
        self.assertEqual(master_blinding_key_hex, utf8(out_hex))

        unconfidential_addr = '2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr'
        script, _ = make_cbuffer('76a914a579388225827d9f2fe9014add644487808c695d88ac')
        private_blinding_key, _ = make_cbuffer('00' * 32)
        ret = wally_asset_blinding_key_to_ec_private_key(root.data, len(root.data), script, len(script), private_blinding_key, len(private_blinding_key))
        self.assertEqual(ret, WALLY_OK)
        public_blinding_key, _ = make_cbuffer('00' * 33)
        ret = wally_ec_public_key_from_private_key(private_blinding_key, len(private_blinding_key), public_blinding_key, len(public_blinding_key))
        self.assertEqual(ret, WALLY_OK)

        ret, address = wally_confidential_addr_from_addr(utf8(unconfidential_addr), CA_PREFIX_LIQUID_REGTEST, public_blinding_key, len(public_blinding_key))
        self.assertEqual(address, 'CTEkf75DFff5ReB7juTg2oehrj41aMj21kvvJaQdWsEAQohz1EDhu7Ayh6goxpz3GZRVKidTtaXaXYEJ')


    def test_confidential_addr(self):
        """Tests for confidential addresses"""

        # The (Liquid) address that is to be blinded
        addr = 'Q7qcjTLsYGoMA7TjUp97R6E6AM5VKqBik6'
        # The blinding pubkey
        pubkey_hex = '02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623'
        # The resulting confidential address
        addr_c = utf8('VTpz1bNuCALgavJKgbAw9Lpp9A72rJy64XPqgqfnaLpMjRcPh5UHBqyRUE4WMZ3asjqu7YEPVAnWw2EK')

        # Test we can extract the original address
        ret, result = wally_confidential_addr_to_addr(addr_c, CA_PREFIX_LIQUID)
        self.assertEqual((ret, result), (WALLY_OK, addr))

        # Test we can extract the blinding pubkey
        out, out_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
        ret = wally_confidential_addr_to_ec_public_key(addr_c, CA_PREFIX_LIQUID, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        _, out_hex = wally_hex_from_bytes(out, out_len)
        self.assertEqual(utf8(pubkey_hex), utf8(out_hex))

        # Test we can re-generate the confidential address from its inputs
        ret, new_addr_c = wally_confidential_addr_from_addr(utf8(addr), CA_PREFIX_LIQUID, out, out_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertEqual(utf8(new_addr_c), addr_c)

    def test_confidential_addr_segwit(self):
        """Tests for confidential segwit addresses"""

        for addr, conf_key, conf_addr in segwit_valid_cases:
            conf_key, conf_key_len = make_cbuffer(conf_key)

            # Convert the segwit address to a confidential address
            args = [addr, hrp(addr), hrp(conf_addr), conf_key, conf_key_len]
            ret, blech32 = wally_confidential_addr_from_addr_segwit(*args)
            self.assertEqual((ret, blech32), (WALLY_OK, conf_addr))

            # Convert the confidential address to a segwit address
            args = [conf_addr, hrp(conf_addr), hrp(addr)]
            ret, blech32 = wally_confidential_addr_to_addr_segwit(*args)
            self.assertEqual((ret, blech32), (WALLY_OK, addr))

            # Extract the blinding key from the confidential address
            out, out_len = make_cbuffer('00' * EC_PUBLIC_KEY_LEN)
            args = [conf_addr, hrp(conf_addr), out, out_len]
            ret = wally_confidential_addr_segwit_to_ec_public_key(*args)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(out, conf_key)


if __name__ == '__main__':
    unittest.main()
