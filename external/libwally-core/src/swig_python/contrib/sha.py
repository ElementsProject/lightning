"""Tests for shas incl wrong types passed"""
import sys
import unittest
from wallycore import *

b2h = hex_from_bytes
h2b = hex_to_bytes

class SHA_tests(unittest.TestCase):

    def test_sha256(self):
        self.assertEqual(b2h(sha256("This is a test message to hash".encode())), "726ca2c10e9d8b76e5b79f2961c3069a09fdd0a3b9bf8650e091e39b3c6c35be")

        self.assertEqual(b2h(sha256(h2b("3e8379862d658e168c71f083bc05169b3b58ca3212e11c838b08629c5ca48a42"))), "2f7d292595788655c5288b6e1dc698440d9c12559e3bc1e3cc38005a4add132f")


    def test_sha256d(self):
        self.assertEqual(b2h(sha256d("This is a test message to hash".encode())), "29e04e90a1075caaa06573ea701913148d99fb0b7d6928e33f1aabe6032761a0")

        self.assertEqual(b2h(sha256d(h2b("3e8379862d658e168c71f083bc05169b3b58ca3212e11c838b08629c5ca48a42"))), "26e30f19dc2b29d8c220766fd5835d8256c87c32804d19b8307e21d6685c9d3e")


    def test_sha512(self):
        self.assertEqual(b2h(sha512("This is a test message to hash".encode())), "2ed34644ddfcf76ca4de13e4632aa61376fbce813fecc5a043a479daaab17b2f8c3f376468d4637cb2e7c9e2b99ad08b8cb56fe6e724e476826f2aa210872c32")

        self.assertEqual(b2h(sha512(h2b("3e8379862d658e168c71f083bc05169b3b58ca3212e11c838b08629c5ca48a42"))), "d51342efcb114c11045c12f7fede6f9a5fdb11051032bd520a99d79023423f4ac3ab706ce5fa88c0aac46bbbf15bde720cf49eae5be0def3b39e6d3abb29a67b")


    def _test_wrong_types_py2(self):
        # Python2 implicitly converts/decodes
        self.assertEqual(b2h(sha256('not bytes')), "b6cb5f25b258630497a18528fb8f73a64034e94e1ead857a8151e3f30a9835ae")

        self.assertEqual(b2h(sha256d('not bytes')), "878eb992aeb736646ecf2c76f562c5d411a487d62ac172d098a83afb023d1b53")

        self.assertEqual(b2h(sha512('not bytes')), "981e82b6ccc079c455cd3fd37b9e04f52f084ffb268a07c47b0447910e2d6280ccbaa5be3f8f062e3e284c98f52039bbddee150a06183ff8d9cb243ef35e3f57")


    def _test_wrong_types_py3(self):
        # Python3 raises TypeError
        for shaX in [sha256, sha256d, sha512]:
            with self.assertRaises(TypeError):
                shaX('not bytes')


    def test_wrong_types(self):
        if sys.version_info.major < 3:
            # Python2 implicitly converts/decodes
            self._test_wrong_types_py2()
        else:
            # Python3 raises TypeError
            self._test_wrong_types_py3()


    def test_pass_none(self):
        self.assertEqual(b2h(sha256(None)), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(b2h(sha256d(None)), "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
        self.assertEqual(b2h(sha512(None)), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")


if __name__ == '__main__':
    unittest.main()

