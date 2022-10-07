import unittest
from util import *

ROUND_TRIP_CASES = [
    # RFC 4648
    ('f', 'Zg=='),
    ('fo', 'Zm8='),
    ('foo', 'Zm9v'),
    ('foob', 'Zm9vYg=='),
    ('fooba', 'Zm9vYmE='),
    ('foobar', 'Zm9vYmFy'),
    # Cases from https://commons.apache.org/proper/commons-codec/xref-test/org/apache/commons/codec/binary/Base64Test.html
    ('Hello World', 'SGVsbG8gV29ybGQ='),
    ('A', 'QQ=='),
    ('AA', 'QUE='),
    ('AAA', 'QUFB'),
    ('The quick brown fox jumped over the lazy dogs.',
        'VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2dzLg=='),
    ('It was the best of times, it was the worst of times.',
        'SXQgd2FzIHRoZSBiZXN0IG9mIHRpbWVzLCBpdCB3YXMgdGhlIHdvcnN0IG9mIHRpbWVzLg=='),
    ('http://jakarta.apache.org/commmons', 'aHR0cDovL2pha2FydGEuYXBhY2hlLm9yZy9jb21tbW9ucw=='),
    ('AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz',
        'QWFCYkNjRGRFZUZmR2dIaElpSmpLa0xsTW1Obk9vUHBRcVJyU3NUdFV1VnZXd1h4WXlaeg=='),
    ('xyzzy!', 'eHl6enkh'),
]

class Base64Tests(unittest.TestCase):

    def test_vectors(self):
        """Tests for encoding and decoding a base 64 string"""

        buf, buf_len = make_cbuffer('00' * 1024)
        for str_in, b64_in in ROUND_TRIP_CASES:
            ret, max_len = wally_base64_get_maximum_length(b64_in, 0)
            self.assertEqual(ret, WALLY_OK)
            self.assertTrue(max_len >= len(str_in))

            ret, b64_out = wally_base64_from_bytes(utf8(str_in), len(str_in), 0)
            self.assertEqual((ret, b64_out), (WALLY_OK, b64_in))

            ret, written = wally_base64_to_bytes(utf8(b64_in), 0, buf, max_len)
            self.assertEqual((ret, buf[:written]), (WALLY_OK, utf8(str_in)))

    def test_get_maximum_length(self):
        # Invalid args
        valid_b64 = utf8(ROUND_TRIP_CASES[0][1])

        for args in [(None,      0), # Null base64 string
                     (bytes(),   0), # Zero-length base64 string
                     (valid_b64, 1), # Invalid flags
            ]:
            ret, max_len = wally_base64_get_maximum_length(*args)
            self.assertEqual((ret, max_len), (WALLY_EINVAL, 0))

    def test_base64_from_bytes(self):
        # Invalid args
        valid_str = utf8(ROUND_TRIP_CASES[0][0])
        valid_str_len = len(valid_str)

        for args in [
            (None,      valid_str_len, 0), # Null input bytes
            (valid_str, 0,             0), # Zero-length input bytes
            (valid_str, valid_str_len, 1), # Invalid flags
            ]:
            ret, b64_out = wally_base64_from_bytes(*args)
            self.assertEqual((ret, b64_out), (WALLY_EINVAL, None))

    def test_base64_to_bytes(self):
        # Invalid args
        buf, buf_len = make_cbuffer('00' * 1024)
        valid_b64 = utf8(ROUND_TRIP_CASES[0][1])
        _, max_len = wally_base64_get_maximum_length(valid_b64, 0)

        for args in [
            (None,      0, buf,  max_len),   # Null base64 string
            (valid_b64, 1, buf,  max_len),   # Invalid flags
            (valid_b64, 0, None, max_len),   # Null output buffer
            (valid_b64, 0, buf,  0),         # Zero output length
            ]:
            ret, written = wally_base64_to_bytes(*args)
            self.assertEqual((ret, written), (WALLY_EINVAL, 0))

        # Too short output length returns the number of bytes needed
        ret, written = wally_base64_to_bytes(valid_b64, 0, buf,  max_len-1)
        self.assertEqual((ret, written), (WALLY_OK, max_len))

if __name__ == '__main__':
    unittest.main()
