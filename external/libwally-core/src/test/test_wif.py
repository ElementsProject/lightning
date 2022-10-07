import unittest
from util import *


PRV_HEX = utf8('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D')
PRV_WIF_UNCOMPRESS = utf8('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
PRV_WIF_COMPRESS = utf8('KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617')
PREFIX = 0x80
VERSION = 0x00


class WIFTests(unittest.TestCase):

    def test_wif_from_bytes(self):
        prv, prv_len = make_cbuffer(PRV_HEX)

        invalid_args = [
            (None, prv_len, PREFIX, 0),  # Missing private key
            (prv, 0, PREFIX, 0),  # Incorrect len
            (prv, 0, 0x100, 0),  # Unsupported PREFIX
            (prv, prv_len, PREFIX, 2),  # Unsupported flag
        ]

        for args in invalid_args:
            ret, out = wally_wif_from_bytes(*args)
            self.assertEqual(ret, WALLY_EINVAL)

        for flag, expected_wif in [
            (0, PRV_WIF_COMPRESS),
            (1, PRV_WIF_UNCOMPRESS),
        ]:
            ret, wif = wally_wif_from_bytes(prv, prv_len, PREFIX, flag)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(utf8(wif), expected_wif)

    def test_wif_to_bytes(self):
        buf, buf_len = make_cbuffer('00'*32)

        # wif_to_bytes
        invalid_args = [
            (None, PREFIX, 0, buf, buf_len),  # Empty wif
            (PRV_WIF_COMPRESS, 0x81, 0, buf, buf_len),  # Not matching PREFIX
            (PRV_WIF_COMPRESS, 0x100, 0, buf, buf_len),  # Unsupported PREFIX
            (PRV_WIF_COMPRESS, PREFIX, 2, buf, buf_len),  # Unsupported flag
            (PRV_WIF_COMPRESS, PREFIX, 1, buf, buf_len),  # Inconsistent flag
            (PRV_WIF_COMPRESS, PREFIX, 0, None, buf_len),  # Empty output
            (PRV_WIF_COMPRESS, PREFIX, 0, buf, 31),  # Unsupported len
        ]

        for args in invalid_args:
            self.assertEqual(wally_wif_to_bytes(*args), WALLY_EINVAL)

        # wif_is_uncompressed
        invalid_args = [
            '',  # Empty
            '11111',  # Incorrect checksum
            'yNb7j1viLcZunrTHozyfJPTZJrprRSPpY485Lwzq1CFQPxF7A',  # Invalid length
            'KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73NUBByJr',  # Unexpected ending byte (not 0x01)
        ]

        for wif in invalid_args:
            ret, _ = wally_wif_is_uncompressed(utf8(wif))
            self.assertEqual(ret, WALLY_EINVAL)

        # wif_to_public_key
        pub, pub_len = make_cbuffer('00' * 65)

        invalid_args = [
            (None, PREFIX, pub, pub_len),  # Empty wif
            (PRV_WIF_COMPRESS, 0x100, pub, pub_len),  # Empty wif
            (PRV_WIF_COMPRESS, PREFIX, None, pub_len),  # Empty pubkey
        ]

        for args in invalid_args:
            self.assertEqual(wally_wif_to_public_key(*args), (WALLY_EINVAL, 0))

        # If the output length is incorrect, the correct one is returned
        invalid_len = [
            (PRV_WIF_COMPRESS, PREFIX, pub, 32),
            (PRV_WIF_UNCOMPRESS, PREFIX, pub, 64),
        ]

        for args in invalid_len:
            self.assertEqual(wally_wif_to_public_key(*args), (WALLY_OK, args[3] + 1))

        # Valid args
        for is_uncompressed, wif in [
            (1, PRV_WIF_UNCOMPRESS),
            (0, PRV_WIF_COMPRESS),
        ]:
            self.assertEqual(wally_wif_is_uncompressed(wif), (WALLY_OK, is_uncompressed))
            self.assertEqual(wally_wif_to_bytes(wif, PREFIX, is_uncompressed, buf, buf_len), WALLY_OK)
            self.assertEqual(h(buf).upper(), PRV_HEX)

            pub, pub_len = make_cbuffer('00' * (1 + 32 * (is_uncompressed + 1)))
            ret, written = wally_wif_to_public_key(wif, PREFIX, pub, pub_len)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(written, pub_len)
            self.assertEqual(pub, self.private_to_public(buf, is_uncompressed))

            exp_addr = self.public_to_address(pub, VERSION)
            ret, addr = wally_wif_to_address(wif, PREFIX, VERSION)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(addr, exp_addr)

    def private_to_public(self, prv, is_uncompressed):
        pub, pub_len = make_cbuffer('00' * 33)
        self.assertEqual(wally_ec_public_key_from_private_key(prv, 32, pub, pub_len), WALLY_OK)
        if not is_uncompressed:
            return pub
        _pub, _pub_len = make_cbuffer('00' * 65)
        self.assertEqual(wally_ec_public_key_decompress(pub, pub_len, _pub, _pub_len), WALLY_OK)
        return _pub

    def public_to_address(self, pub, version):
        h, h_len = make_cbuffer('00' * 20)
        wally_hash160(pub, len(pub), h, h_len)
        return wally_base58_from_bytes(bytes(bytearray([version])) + h, 21, 1)[1]


if __name__ == '__main__':
    unittest.main()
