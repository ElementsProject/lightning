import unittest
from util import *

K_MAIN, K_TEST, K_COMP, K_EC, K_CHECK, K_RAW, K_ORDER = 0, 7, 256, 512, 1024, 2048, 4096

# BIP38 Vectors from
# https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
cases = [
    [ 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
      'TestingOneTwoThree',
      K_MAIN,
      '6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg' ],
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      'Satoshi',
      K_MAIN,
      '6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq' ],
    [ '64EEAB5F9BE2A01A8365A579511EB3373C87C40DA6D2A25F05BDA68FE077B66E',
      unhexlify('cf9300f0909080f09f92a9'),
      K_MAIN,
      '6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn' ],
    [ 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5',
      'TestingOneTwoThree',
      K_MAIN + K_COMP,
      '6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo' ],
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      'Satoshi',
      K_MAIN + K_COMP,
      '6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7' ],
    # Raw vectors
    [ '09C2686880095B1A4C249EE3AC4EEA8A014F11E6F986D0B5025AC1F39AFBD9AE',
      'Satoshi',
      K_MAIN + K_COMP + K_RAW,
      '0142E00B76EA60B62F66F0AF93D8B5380652AF51D1A3902EE00726CCEB70CA636B5B57CE6D3E2F' ],
    [ '3CBC4D1E5C5248F81338596C0B1EE025FBE6C112633C357D66D2CE0BE541EA18',
      'jon',
      K_MAIN + K_COMP + K_RAW + K_ORDER,
      '0142E09F8EE6E3A2FFCB13A99AA976AEDA5A2002ED3DF97FCB9957CD863357B55AA2072D3EB2F9' ],
]


class BIP38Tests(unittest.TestCase):

    def from_priv(self, priv_key, passwd, flags):
        priv, p_len = make_cbuffer(priv_key)
        if flags > K_RAW:
            out_buf, out_len = make_cbuffer('00' * 39)
            ret = bip38_raw_from_private_key(priv, p_len, passwd, len(passwd),
                                             flags, out_buf, out_len)
            return ret, h(out_buf).upper()
        else:
            return bip38_from_private_key(priv, p_len, passwd, len(passwd), flags)

    def to_priv(self, bip38, passwd, flags):
        priv, priv_len = make_cbuffer('00' * 32)
        bip38 = utf8(bip38)
        if flags > K_RAW:
            raw, raw_len = make_cbuffer(bip38)
            ret = bip38_raw_to_private_key(raw, raw_len, passwd, len(passwd),
                                           flags, priv, priv_len)
        else:
            ret = bip38_to_private_key(bip38, passwd, len(passwd), flags,
                                       priv, priv_len)
        return ret, priv


    def test_bip38(self):

        for case in cases:
            priv_key, passwd, flags, expected = case
            passwd = utf8(passwd) if type(passwd) is not bytes else passwd
            ret, bip38 = self.from_priv(priv_key, passwd, flags)
            self.assertEqual(ret, WALLY_OK)
            bip38 = bip38.decode('utf-8') if type(bip38) is bytes else bip38
            self.assertEqual(bip38, expected)

            ret, new_priv_key = self.to_priv(bip38, passwd, flags)
            self.assertEqual(ret, WALLY_OK)
            self.assertEqual(h(new_priv_key).upper(), utf8(priv_key))
            ret, new_priv_key = self.to_priv(bip38, '', flags + K_CHECK)
            self.assertEqual(ret, WALLY_OK)


    def test_bip38_invalid(self):
        priv_key = 'CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5'
        passwd = utf8('TestingInvalidFlags')
        K_RES1 = 0x10 # BIP38_FLAG_RESERVED1

        for flags, expected in [(0,            WALLY_OK),
                                (K_RES1,       WALLY_EINVAL),
                                (K_RAW,        WALLY_OK),
                                (K_RAW+K_RES1, WALLY_EINVAL)]:
            ret, _ = self.from_priv(priv_key, passwd, K_MAIN + flags)
            self.assertEqual(ret, expected)


if __name__ == '__main__':
    unittest.main()
