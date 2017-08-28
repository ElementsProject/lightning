import unittest
from util import *
from ctypes import create_string_buffer

# HMAC vectors from https://tools.ietf.org/html/rfc4231
hmac_cases = [
    ['0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', '4869205468657265',

     'b0344c61d8db38535ca8afceaf0bf12b 881dc200c9833da726e9376c2e32cff7',
     '87aa7cdea5ef619d4ff0b4241a1d6cb0 2379f4e2ce4ec2787ad0b30545e17cde'
     'daa833b7d6b8a702038b274eaea3f4e4 be9d914eeb61f1702e696c203a126854'],

    ['4a656665', '7768617420646f2079612077616e7420666f72206e6f7468696e673f',

     '5bdcc146bf60754e6a042426089575c7 5a003f089d2739839dec58b964ec3843',
     '164b7a7bfcf819e2e395fbe73b56e0a3 87bd64222e831fd610270cd7ea250554'
     '9758bf75c05a994a6d034f65f8f0e6fd caeab1a34d4a6b4b636e070a38bce737'],

    ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
     'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
     'dddddddddddddddddddddddddddddddddddd',

     '773ea91e36800e46854db8ebd09181a7 2959098b3ef8c122d9635514ced565fe',
     'fa73b0089d56a284efb0f0756c890be9 b1b5dbdd8ee81a3655f83e33b2279d39'
     'bf3e848279a722c806b485a47e67c807 b946a337bee8942674278859e13292fb'],

    ['0102030405060708090a0b0c0d0e0f10111213141516171819',
     'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd'
     'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',

     '82558a389a443c0ea4cc819899f2083a 85f0faa3e578f8077a2e3ff46729665b',
     'b0ba465637458c6990e5a8c5f61d4af7 e576d97ff94b872de76f8050361ee3db'
     'a91ca5c11aa25eb4d679275cc5788063 a5f19741120c4f2de2adebeb10a298dd'],

    ['0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c',
     '546573742057697468205472756e636174696f6e',

     'a3b6167473100ee06e0c796c2955552b',
     '415fad6271580a531d4179bc891d87a6'],

    ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaa',
     '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a'
     '65204b6579202d2048617368204b6579204669727374',

     '60e431591ee0b67f0d8a26aacbf5b77f 8e0bc6213728c5140546040f0ee37f54',
     '80b24263c7c1a3ebb71493c1dd7be8b4 9b46d1f41b4aeec1121b013783f8f352'
     '6b56d037e05f2598bd0fd2215d6a1e52 95e64f73f63f0aec8b915a985d786598'],

    ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
     'aaaaaa',
     '5468697320697320612074657374207573696e672061206c6172676572207468'
     '616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074'
     '68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565'
     '647320746f20626520686173686564206265666f7265206265696e6720757365'
     '642062792074686520484d414320616c676f726974686d2e',

     '9b09ffa71b942fcb27635fbcd5b0e944 bfdc63644f0713938a7f51535c3a35e2',
     'e37b6a775dc87dbaa4dfa9f96e5e3ffd debd71f8867289865df5a32d20cdc944'
     'b6022cac3c4982b10d5eeb55c3e4de15 134676fb6de0446065c97440fa8c6a58']
]

class HMACTests(unittest.TestCase):

    def doHMAC(self, fn, key_in, msg_in):
        key, key_len = make_cbuffer(key_in)
        msg, msg_len = make_cbuffer(msg_in)
        buf_len = 64 if fn == wally_hmac_sha512 else 32
        buf = create_string_buffer(buf_len)
        ret = fn(key, key_len, msg, msg_len, buf, buf_len)
        return ret, h(buf)


    def test_vectors(self):

        for test in hmac_cases:
            k, msg = test[0], test[1]
            for fn, expected in [(wally_hmac_sha256, test[2]),
                                 (wally_hmac_sha512, test[3])]:
                ret, result = self.doHMAC(fn, k, msg)
                self.assertEqual(ret, 0)
                expected = utf8(expected.replace(' ', ''))
                # Note we truncate the result as one of the test vectors has
                # a truncated result in the RFC
                self.assertEqual(result[0:len(expected)], expected)


if __name__ == '__main__':
    unittest.main()
