import unittest
from util import *
import json


class BIP39Tests(unittest.TestCase):

    cases = None
    langs = { 'en': 'english',
              'es': 'spanish',
              'fr': 'french',
              'it': 'italian',
              'jp': 'japanese',
              'zhs': 'chinese_simplified',
              'zht': 'chinese_traditional' }

    def get_wordlist(self, lang):
        out = c_void_p()
        bip39_get_wordlist(lang, byref(out))
        return out

    def setUp(self):
        if self.cases is None:
            with open(root_dir + 'src/data/wordlists/vectors.json', 'r') as f:
                cases = json.load(f)['english']
                conv = lambda case: [utf8(x) for x in case]
                self.cases = [conv(case) for case in cases]

            gwl = lambda lang: self.get_wordlist(utf8(lang))
            self.wordlists = {l: gwl(l) for l in list(self.langs.keys())}


    def test_all_langs(self):

        ret, all_langs = bip39_get_languages()
        self.assertEqual(ret, 0)
        all_langs = all_langs.split()

        for lang in all_langs:
            self.assertTrue(lang in self.langs)

        self.assertEqual(len(all_langs), len(list(self.langs.keys())))


    def test_bip39_wordlists(self):

        for lang, wl in self.wordlists.items():
            self.assertIsNotNone(wl)

        def_wl = self.get_wordlist(None)
        en_wl = self.wordlists['en']
        self.assertEqual(def_wl.value, en_wl.value)


    def test_all_lookups(self):

        for lang in list(self.langs.keys()):
            wl = self.wordlists[lang]
            words_list, _ = load_words(self.langs[lang])
            for i in range(2048):
                ret, word = bip39_get_word(wl, i)
                word = word.encode('utf-8')
                self.assertEqual(ret, 0)
                self.assertEqual(word, utf8(words_list[i]))
                if wordlist_lookup_word is not None:
                    idx = wordlist_lookup_word(wl, word)
                    self.assertEqual(i, idx - 1)

        self.assertEqual(bip39_get_word(wl, 2048), (WALLY_EINVAL, None))


    def test_bip39_vectors(self):
        """Test conversion to and from the BIP39 specification vectors"""
        wl = self.get_wordlist(None)

        for case in self.cases:
            hex_input, mnemonic = case[0], case[1]
            buf, buf_len = make_cbuffer(hex_input)

            ret, result = bip39_mnemonic_from_bytes(wl, buf, buf_len)
            self.assertEqual(ret, 0)
            result = utf8(result)
            self.assertEqual(result, mnemonic)
            self.assertEqual(bip39_mnemonic_validate(wl, mnemonic), 0)

            out_buf = create_string_buffer(buf_len)
            ret, rlen = bip39_mnemonic_to_bytes(wl, result, out_buf, buf_len)
            self.assertEqual(ret, 0)
            self.assertEqual(rlen, buf_len)
            self.assertEqual(buf, out_buf.raw)


    def test_288(self):
        """ Test a 288 bit (27 word) mnemonic phrase """
        mnemonic = 'panel jaguar rib echo witness mean please festival ' \
                   'issue item notable divorce conduct page tourist '    \
                   'west off salmon ghost grit kitten pull marine toss ' \
                   'dirt oak gloom'
        self.assertEqual(bip39_mnemonic_validate(None, utf8(mnemonic)), 0)

        out_buf = create_string_buffer(36)
        ret, rlen = bip39_mnemonic_to_bytes(None, utf8(mnemonic), out_buf, 36)
        self.assertEqual(ret, 0)
        self.assertEqual(rlen, 36)
        expected = '9F8EE6E3A2FFCB13A99AA976AEDA5A2002ED' \
                   '3DF97FCB9957CD863357B55AA2072D3EB2F9'
        self.assertEqual(h(out_buf).upper(), utf8(expected))


    def test_mnemonic_to_seed(self):

        for case in self.cases:
            mnemonic, seed = case[1], case[2]

            buf = create_string_buffer(64)
            ret, count = bip39_mnemonic_to_seed(mnemonic, b'TREZOR', buf, 64)
            self.assertEqual(ret, 0)
            self.assertEqual(count, 64)
            self.assertEqual(h(buf), seed)


if __name__ == '__main__':
    unittest.main()
