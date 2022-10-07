import unittest
from util import *


class ECDHTests(unittest.TestCase):

    def priv_to_pub(self, priv):
        pub, _ = make_cbuffer('00'*33)
        ret = wally_ec_public_key_from_private_key(priv, len(priv), pub, len(pub))
        self.assertEqual(ret, WALLY_OK)
        return pub

    def test_ecdh(self):
        """Tests for ECDH"""

        priv1, _ = make_cbuffer('aa'*32)
        priv2, _ = make_cbuffer('bb'*32)
        pub1 = self.priv_to_pub(priv1)
        pub2 = self.priv_to_pub(priv2)

        out12, _ = make_cbuffer('00'*32)
        out21, _ = make_cbuffer('00'*32)
        ret = wally_ecdh(pub1, len(pub1), priv2, len(priv2), out12, len(out12))
        self.assertEqual(ret, WALLY_OK)
        ret = wally_ecdh(pub2, len(pub2), priv1, len(priv1), out21, len(out21))
        self.assertEqual(ret, WALLY_OK)

        self.assertEqual(out12, out21)

        out, _ = make_cbuffer('00'*32)
        priv_bad, _ = make_cbuffer('00'*32)
        pub_bad, _ = make_cbuffer('02' + '00'*32)

        for args in [
            (None, 32, pub1, 32, out, 32),      # Missing private key
            (priv_bad, 32, pub1, 33, out, 32),  # Invalid private key
            (priv1, 31, pub1, 32, out, 32),     # Invalid private key length
            (priv1, 32, None, 33, out, 32),     # Missing public key
            (priv1, 32, pub_bad, 33, out, 32),  # Invalid public key
            (priv1, 32, pub1, 32, out, 32),     # Invalid public key length
            (priv1, 32, pub1, 32, None, 32),    # Missing output
            (priv1, 32, pub1, 33, out, 31),     # Invalid output length
        ]:
            self.assertEqual(WALLY_EINVAL, wally_ecdh(*args))
            self.assertEqual(h(out), utf8('00'*32))


if __name__ == '__main__':
    unittest.main()
