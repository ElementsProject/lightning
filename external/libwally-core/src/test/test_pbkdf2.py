import unittest
from util import *
from binascii import unhexlify

PBKDF2_HMAC_SHA256_LEN, PBKDF2_HMAC_SHA512_LEN = 32, 64
FLAG_BLOCK_RESERVED = 0x1

class PBKDF2Case(object):
    def __init__(self, items):
        # Format: HMAC_SHA_TYPE, PASSWORD, SALT, COST, EXPECTED
        self.typ = int(items[0])
        assert self.typ in [256, 512]
        self.passwd = unhexlify(items[1])
        self.salt = items[2]
        self.cost = int(items[3])
        self.expected, self.expected_len = make_cbuffer(items[4])


class PBKDF2Tests(unittest.TestCase):

    def setUp(self):
        if not hasattr(self, 'wally_pbkdf2_hmac_sha256'):
            self.cases = []
            with open(root_dir + 'src/data/pbkdf2_hmac_sha_vectors.txt', 'r') as f:
                for l in f.readlines():
                    l = l.strip()
                    if len(l) == 0 or l.startswith('#'):
                        continue
                    self.cases.append(PBKDF2Case(l.split(',')))


    def test_pbkdf2_hmac_sha(self):

        # Some test vectors are nuts (e.g. 2097152 cost), so only run the
        # first few. set these to -1 to run the whole suite (only needed
        # when refactoring the impl)
        num_crazy_256, num_crazy_512 = 8, 8

        for case in self.cases:

            if case.typ == 256:
                fn = wally_pbkdf2_hmac_sha256
                mult = PBKDF2_HMAC_SHA256_LEN
                if case.cost > 100:
                    if num_crazy_256 == 0:
                         continue
                    num_crazy_256 -= 1
            else:
                fn = wally_pbkdf2_hmac_sha512
                mult = PBKDF2_HMAC_SHA512_LEN
                if case.cost > 100:
                    if num_crazy_512 == 0:
                        continue
                    num_crazy_512 -= 1

            out_buf, out_len = make_cbuffer('00' * case.expected_len)
            if case.expected_len % mult != 0:
                # We only support output multiples of the hmac length
                continue

            # Test both providing extra bytes and having them allocated for us
            for flags in [0, FLAG_BLOCK_RESERVED]:
                extra_bytes = '00000000' if flags else ''
                salt, salt_len = make_cbuffer(case.salt + extra_bytes)

                ret = fn(case.passwd, len(case.passwd), salt, salt_len,
                         flags, case.cost, out_buf, out_len)

                self.assertEqual(ret, 0)
                self.assertEqual(h(out_buf), h(case.expected))


    def _pbkdf2_hmac_sha_malloc_fail(self, fn, len):
        fake_buf, fake_len = make_cbuffer('aabbccdd')
        out_buf, out_len = make_cbuffer('00' * len)
        ret = fn(fake_buf, fake_len, fake_buf, fake_len, 0, 1, out_buf, out_len)
        self.assertEqual(ret, WALLY_ENOMEM)


    @malloc_fail([1])
    def test_pbkdf2_hmac_sha256_malloc(self):
        self._pbkdf2_hmac_sha_malloc_fail(wally_pbkdf2_hmac_sha256, PBKDF2_HMAC_SHA256_LEN)


    @malloc_fail([1])
    def test_pbkdf2_hmac_sha512_malloc(self):
        self._pbkdf2_hmac_sha_malloc_fail(wally_pbkdf2_hmac_sha512, PBKDF2_HMAC_SHA512_LEN)


if __name__ == '__main__':
    unittest.main()
