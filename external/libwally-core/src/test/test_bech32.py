import unittest
from util import *

WALLY_WITNESSSCRIPT_MAX_LEN = 42

valid_cases = {
    # https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4':
        ['bc', 0, '0014751e76e8199196d454941c45d1b3a323f1433bd6'],
    'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7':
        ['tb', 0, '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262'],
    'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y':
        ['bc', 1, '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6'],
    'BC1SW50QGDZ25J':
        ['bc', 16, '6002751e'],
    'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs':
        ['bc', 2, '5210751e76e8199196d454941c45d1b3a323'],
    'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy':
        ['tb', 0, '0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
    'tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c':
        ['tb', 1, '5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433'],
    'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0':
        ['bc', 1, '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798']
}

invalid_cases = [
    # https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki,
    # (Excluding invalid cases listed in BIP350 below)
    ['tb', 'tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty'], # Invalid human-readable part
    ['bc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5'], # Invalid checksum
    ['bc', 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2'], # Invalid witness version
    ['bc', 'bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ss52r5n8'], # Invalid witness version v1
    ['bc', 'bc1rw5uspcuh'], # Invalid program length
    ['bc', 'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90'], # Invalid program length
    ['tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7'], # Mixed case
    ['bc', 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du'], # zero padding of more than 4 bits
    ['tb', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv'], # Non-zero padding in 8-to-5 conversion
    ['bc', 'bc1gmk9yu'], # Empty data section

    # https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    ['tb', 'tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut'], # Invalid HRP
    ['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd'], # Invalid checksum algorithm (bech32 instead of bech32m)
    ['tb', 'tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf'], # Invalid checksum algorithm (bech32 instead of bech32m)
    ['bc', 'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL'], # Invalid checksum algorithm (bech32m instead of bech32)
    ['bc', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh'], # Invalid checksum algorithm (bech32m instead of bech32)
    ['tb', 'tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47'], # Invalid checksum algorithm (bech32m instead of bech32)
    ['bc', 'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4'], # Invalid character in checksum
    ['bc', 'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R'], # Invalid witness version
    ['bc', 'bc1pw5dgrnzv'], # Invalid program length
    ['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav'], # Invalid program length (41 bytes)
    ['bc', 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P'], # Invalid program length for witness version 0 (per BIP141)
    ['tb', 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq'], # Mixed case
    ['bc', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf'], # more than 4 bit padding
    ['tb', 'tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j'], # Non-zero padding in 8-to-5 conversion

    # Formerly valid under BIP 173, now invalid under BIP 350:
    ['bc', 'BC1SW50QA3JX3S'], # Invalid checksum
    ['bc', 'bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj'], # Invalid checksum

    # https://blockstream.info/address/bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx
    ['bc', 'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx'] # V > 0 must be bech32m
]

class Bech32Tests(unittest.TestCase):

    def decode(self, addr, family):
        out, out_len = make_cbuffer('00' * WALLY_WITNESSSCRIPT_MAX_LEN)
        addr, family = utf8(addr), utf8(family)
        ret, written = wally_addr_segwit_to_bytes(addr, family, 0, out, out_len)
        ret_n, written_n = wally_addr_segwit_n_to_bytes(addr, len(addr), family, len(family), 0, out, out_len)
        ver_ret, ver = wally_addr_segwit_get_version(addr, family, 0)
        ver_ret_n, ver_n = wally_addr_segwit_n_get_version(addr, len(addr), family, len(family), 0)
        self.assertEqual(ret, ver_ret)
        self.assertEqual(ret_n, ver_ret_n)
        if ret != WALLY_OK:
            return ret, None, ver
        return ret, h(out[:written]), ver

    def test_segwit_address(self):
        """Tests for encoding and decoding segwit addresses"""
        # Valid cases
        lower = [(addr.lower(), data) for addr, data in valid_cases.items()]
        upper = [(addr.upper(), data) for addr, data in valid_cases.items()]
        for addr, data in lower + upper:
            # Decode the address
            family, script_ver, script_hex = data[0], data[1], data[2]

            ret, result_script_hex, result_ver = self.decode(addr, family)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(result_ver, script_ver)
            self.assertEqual(result_script_hex, utf8(script_hex))

            # Encode the script and make sure the address matches
            script_buf, script_len = make_cbuffer(script_hex)
            ret, retstr = wally_addr_segwit_from_bytes(script_buf, script_len, utf8(family), 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(retstr.lower(), addr.lower())

        # Invalid cases
        for family, addr in invalid_cases:
            ret, result_script_hex, result_ver = self.decode(addr, family)
            self.assertEqual(ret, WALLY_EINVAL)
            self.assertEqual(result_ver, 0)

        out, out_len = make_cbuffer('00' * (32 + 2))
        bad = utf8('abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefg')
        tb = utf8('tb')
        ret, written = wally_addr_segwit_to_bytes(bad, tb, 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_EINVAL, 0))
        ret, written = wally_addr_segwit_n_to_bytes(bad, len(bad), tb, len(tb), 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_EINVAL, 0))

        # _n versions: bad lengths
        addr = 'BC1SW50QGDZ25J'
        family, _, _ = valid_cases[addr]
        addr, family = utf8(addr), utf8(family)

        ret, written = wally_addr_segwit_n_to_bytes(addr, 0,
                                                    family, len(family), 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_EINVAL, 0)) # Bad addr length
        ret, written = wally_addr_segwit_n_to_bytes(addr, len(addr),
                                                    family, 0, 0, out, out_len)
        self.assertEqual((ret, written), (WALLY_EINVAL, 0)) # Bad family length

        ret, ver = wally_addr_segwit_n_get_version(addr, 0, family, len(family), 0)
        self.assertEqual(ret, WALLY_EINVAL) # Bad addr length
        ret, ver = wally_addr_segwit_n_get_version(addr, len(addr), family, 0, 0)
        self.assertEqual(ret, WALLY_EINVAL) # Bad family length

if __name__ == '__main__':
    unittest.main()
