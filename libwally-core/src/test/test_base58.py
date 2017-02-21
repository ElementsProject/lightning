import unittest
from util import *

class AddressCase(object):
    def __init__(self, lines):
        # https://github.com/ThePiachu/Bitcoin-Unit-Tests/blob/master/Address
        self.ripemd_network = lines[4]
        self.checksummed = lines[8]
        self.base58 = lines[9]

class Base58Tests(unittest.TestCase):

    FLAG_CHECKSUM = 0x1
    CHECKSUM_LEN = 4

    def setUp(self):
        if not hasattr(self, 'cases'):
            # Test cases from https://github.com/ThePiachu/Bitcoin-Unit-Tests/
            self.cases = []
            cur = []
            with open(root_dir + 'src/data/address_vectors.txt', 'r') as f:
                for l in f.readlines():
                    if len(l.strip()):
                        cur.append(l.strip())
                    else:
                        self.cases.append(AddressCase(cur))
                        cur = []

    def encode(self, hex_in, flags):
        buf, buf_len = make_cbuffer(hex_in)
        ret, base58 = wally_base58_from_bytes(buf, buf_len, flags)
        self.assertEqual(ret, WALLY_EINVAL if base58 is None else WALLY_OK)
        return base58

    def decode(self, str_in, flags):
        buf, buf_len = make_cbuffer('00' * 1024)
        ret, buf_len = wally_base58_to_bytes(utf8(str_in), flags, buf, buf_len)
        self.assertEqual(ret, WALLY_OK)
        self.assertNotEqual(buf_len, 0)
        # Check that just computing the size returns us the actual size
        ret, bin_len = wally_base58_get_length(utf8(str_in))
        self.assertEqual(ret, WALLY_OK)
        if flags == self.FLAG_CHECKSUM:
            bin_len -= self.CHECKSUM_LEN
        self.assertEqual(bin_len, buf_len)
        return h(buf)[0:buf_len * 2].upper()


    def test_address_vectors(self):
        """Tests for encoding and decoding with and without checksums"""

        for c in self.cases:
            # Checksummed should match directly in base 58
            base58 = self.encode(c.checksummed, 0)
            self.assertEqual(base58, c.base58)
            # Decode it and make sure it matches checksummed again
            decoded = self.decode(c.base58, 0)
            self.assertEqual(decoded, utf8(c.checksummed))

            # Compute the checksum in the call
            base58 = self.encode(c.ripemd_network, self.FLAG_CHECKSUM)
            self.assertEqual(base58, c.base58)

            # Decode without checksum validation/stripping, should match
            # checksummed value
            decoded = self.decode(c.base58, 0)
            self.assertEqual(decoded, utf8(c.checksummed))

            # Decode with checksum validation/stripping and compare
            # to original ripemd + network
            decoded = self.decode(c.base58, self.FLAG_CHECKSUM)
            self.assertEqual(decoded, utf8(c.ripemd_network))


    def test_to_bytes(self):
        buf, buf_len = make_cbuffer('00' * 1024)

        # Bad input base58 strings
        for bad in [ '',        # Empty string can't be represented
                     '0',       # Forbidden ASCII character
                     'x0',      # Forbidden ASCII character, internal
                     '\x80',    # High bit set
                     'x\x80x',  # High bit set, internal
                   ]:
            ret, _ = wally_base58_to_bytes(utf8(bad), 0, buf, buf_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # Bad checksummed base58 strings
        for bad in [ # libbase58: decode-b58c-fail
                    '19DXstMaV43WpYg4ceREiiTv2UntmoiA9a',
                    # libbase58: decode-b58c-toolong
                    '1119DXstMaV43WpYg4ceREiiTv2UntmoiA9a',
                    # libbase58: decode-b58c-tooshort
                    '111111111111111111114oLvT2']:
            ret, _ = wally_base58_to_bytes(utf8(bad), self.FLAG_CHECKSUM, buf, buf_len)
            self.assertEqual(ret, WALLY_EINVAL)

        for base58 in ['BXvDbH', '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM']:
            ret, out_len = wally_base58_get_length(utf8(base58))
            # Output buffer too small returns OK and the number of bytes required
            ret, bin_len = wally_base58_to_bytes(utf8(base58), 0, buf, out_len - 1)
            self.assertEqual((ret, bin_len), (WALLY_OK, out_len))
            # Unknown flags
            ret, _ = wally_base58_to_bytes(utf8(base58), 0x7, buf, buf_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # If we ask for checksum validation/removal the output buffer
        # must have room for a checksum.
        ret, bin_len = wally_base58_to_bytes(utf8('1'), self.FLAG_CHECKSUM,
                                             buf, self.CHECKSUM_LEN)
        self.assertEqual(ret, WALLY_EINVAL)

        # Leading ones become zeros
        for i in range(1, 10):
            self.assertEqual(self.decode('1' * i, 0), utf8('00' * i))

        # Vectors from https://github.com/bitcoinj/bitcoinj/
        self.assertEqual(self.decode('16Ho7Hs', 0), utf8('00CEF022FA'))
        self.assertEqual(self.decode('4stwEBjT6FYyVV', self.FLAG_CHECKSUM),
                                     utf8('45046252208D'))
        base58 = '93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T'
        ret = self.decode(base58, self.FLAG_CHECKSUM)
        expected = 'EFFB309E964684B54E6069F146E2CD6DA' \
                   'E936B711A7A98DF4097156B9FC9B344EB'
        self.assertEqual(ret, utf8(expected))


    def test_from_bytes(self):

        # Leading zeros become ones
        for i in range(1, 10):
            self.assertEqual(self.encode('00' * i, 0), '1' * i)

        # Invalid flags
        self.assertEqual(self.encode('00', 0x7), None)

        buf, buf_len = make_cbuffer('00' * 8)

        FAIL_RET = (WALLY_EINVAL, None)
        # O length buffer, no checksum -> NULL
        self.assertEqual(wally_base58_from_bytes(buf, 0, 0), FAIL_RET)

        # O length buffer, append checksum -> NULL
        self.assertEqual(wally_base58_from_bytes(buf, 0, self.FLAG_CHECKSUM), FAIL_RET)

        # Vectors from https://github.com/bitcoinj/bitcoinj/
        self.assertEqual(self.encode('00CEF022FA', 0), '16Ho7Hs')
        self.assertEqual(self.encode('45046252208D', self.FLAG_CHECKSUM),
                                     '4stwEBjT6FYyVV')



if __name__ == '__main__':
    unittest.main()
