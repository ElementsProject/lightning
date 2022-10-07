import unittest
from util import *

ENTROPY_LEN_128, ENTROPY_LEN_256, ENTROPY_LEN_512 = 16, 32, 64
HMAC_SHA512_LEN = 64

class SymmetricTests(unittest.TestCase):

    def test_symmetric_key(self):
        seed128, seed128_len = make_cbuffer('01' * ENTROPY_LEN_128)
        seed256, seed256_len = make_cbuffer('01' * ENTROPY_LEN_256)
        seed512, seed512_len = make_cbuffer('01' * ENTROPY_LEN_512)
        label, label_len = make_cbuffer('0f0000')
        key_out, key_out_len = make_cbuffer('00' * HMAC_SHA512_LEN)

        # wally_symmetric_key_from_seed
        # Invalid args
        cases = [
            (None,    seed128_len,   key_out, key_out_len),   # Null bytes
            (seed128, 0,             key_out, key_out_len),   # 0 Length bytes
            (seed128, seed128_len-1, key_out, key_out_len),   # Bad bytes length
            (seed128, seed128_len,   None,    key_out_len),   # Null dest
            (seed128, seed128_len,   key_out, 0),             # 0 length dest
            (seed128, seed128_len,   key_out, key_out_len+1), # Bad dest length
        ]
        for bytes_in, bytes_len, out, out_len in cases:
            ret = wally_symmetric_key_from_seed(bytes_in, bytes_len, out, out_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # Valid args
        for bytes_in, bytes_len in [(seed128, seed128_len),
                                    (seed256, seed256_len),
                                    (seed512, seed512_len)]:
            ret = wally_symmetric_key_from_seed(bytes_in, bytes_len, key_out, key_out_len)
            self.assertEqual(ret, WALLY_OK)

        # wally_symmetric_key_from_parent
        key_in, key_len = make_cbuffer('01' * HMAC_SHA512_LEN)
        # Invalid args
        cases = [
            (None,   key_len,   0, label, label_len, key_out, key_out_len),   # Null key
            (key_in, 0,         0, label, label_len, key_out, key_out_len),   # 0 Length key
            (key_in, key_len-1, 1, label, label_len, key_out, key_out_len),   # Bad key length
            (key_in, key_len,   1, label, label_len, key_out, key_out_len),   # Bad version
            (key_in, key_len,   0, None,  label_len, key_out, key_out_len),   # Null label
            (key_in, key_len,   0, label, 0,         key_out, key_out_len),   # Bad label length
            (key_in, key_len,   0, label, label_len, None,    key_out_len),   # Null dest
            (key_in, key_len,   0, label, label_len, key_out, 0),             # 0 length dest
            (key_in, key_len,   0, label, label_len, key_out, key_out_len+1), # Bad dest length
        ]
        for bytes_in, bytes_len, ver, l, l_len, out, out_len in cases:
            ret = wally_symmetric_key_from_parent(bytes_in, bytes_len, ver, l, l_len, out, out_len)
            self.assertEqual(ret, WALLY_EINVAL)

        # Valid args
        ret = wally_symmetric_key_from_parent(key_in, key_len, 0, label, label_len, key_out, key_out_len)
        self.assertEqual(ret, WALLY_OK)

        # Check labels around length LABEL_SIZE (64)
        label, label_len = make_cbuffer('0f' * 65)
        for l_len in (label_len-1, label_len, label_len+1):
            ret = wally_symmetric_key_from_parent(key_in, key_len, 0, label, l_len, key_out, key_out_len)
            self.assertEqual(ret, WALLY_OK)


if __name__ == '__main__':
    unittest.main()
