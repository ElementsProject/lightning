"""A wallycore version of https://github.com/trezor/python-mnemonic"""
import wallycore

BIP39_ENTROPY_LEN_128 = wallycore.BIP39_ENTROPY_LEN_128
BIP39_ENTROPY_LEN_160 = wallycore.BIP39_ENTROPY_LEN_160
BIP39_ENTROPY_LEN_192 = wallycore.BIP39_ENTROPY_LEN_192
BIP39_ENTROPY_LEN_224 = wallycore.BIP39_ENTROPY_LEN_224
BIP39_ENTROPY_LEN_256 = wallycore.BIP39_ENTROPY_LEN_256

class Mnemonic(object):

    def __init__(self, language):
        self.wordlist = wallycore.bip39_get_wordlist(language)


    @staticmethod
    def list_languages():
        return wallycore.bip39_get_languages().split()


    def generate(self, strength = wallycore.BIP39_ENTROPY_LEN_128):
        from os import urandom
        return self.to_mnemonic(bytearray(urandom(strength)))


    def to_entropy(self, words):
        if isinstance(words, list):
            words = ' '.join(words)
        buf = bytearray(BIP39_ENTROPY_LEN_256)
        length = wallycore.bip39_mnemonic_to_bytes(self.wordlist, words, buf)
        return bytearray(buf)[0:length]


    def to_mnemonic(self, data):
        return wallycore.bip39_mnemonic_from_bytes(self.wordlist, data)


    def check(self, mnemonic):
        wallycore.bip39_mnemonic_validate(self.wordlist, mnemonic)


    def to_seed(self, mnemonic, passphrase = ''):
        buf = bytearray(wallycore.BIP39_SEED_LEN_512)
        wallycore.bip39_mnemonic_to_seed(mnemonic, passphrase, buf)
        return buf


if __name__ == "__main__":
    # Just make sure the basics work
    for lang in Mnemonic.list_languages():
        m = Mnemonic(lang)
        phrase = m.generate()
        m.check(phrase)
        try:
            m.generate(BIP39_ENTROPY_LEN_256 - 1)
            assert False
        except:
            pass
        try:
            m.check(phrase + ' foo')
            assert False
        except:
            pass
        assert m.to_entropy(phrase) == m.to_entropy(phrase.split())
        assert m.to_mnemonic(m.to_entropy(phrase)) == phrase
        assert m.to_seed(phrase, 'foo') != m.to_seed(phrase, 'bar')

