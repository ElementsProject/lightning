"""A simple example of signing and verifying a message as in Bitcoin Core"""
import unittest
import base64
from wallycore import *


class SignMessageTest(unittest.TestCase):

    WIF_PREFIX = 0xef
    ADD_PREFIX = 0x6f

    def signmessage(self, priv_key_wif, message):
        priv_key = wif_to_bytes(priv_key_wif, self.WIF_PREFIX, WALLY_WIF_FLAG_COMPRESSED)
        msg_fmt = format_bitcoin_message(message, BITCOIN_MESSAGE_FLAG_HASH)
        sig_bytes = ec_sig_from_bytes(priv_key, msg_fmt, EC_FLAG_ECDSA | EC_FLAG_RECOVERABLE)
        return base64.b64encode(sig_bytes)

    def verifymessage(self, address, signature, message):
        msg_fmt = format_bitcoin_message(message, BITCOIN_MESSAGE_FLAG_HASH)
        sig_bytes = base64.b64decode(signature)
        pub_key_rec = ec_sig_to_public_key(msg_fmt, sig_bytes)
        address_rec = base58check_from_bytes(bytearray([self.ADD_PREFIX]) + hash160(pub_key_rec))
        return address == address_rec

    def test_signmessage(self):
        # values from Bitcoin Core tests
        message = 'This is just a test message'.encode('ascii')
        priv_key_wif = 'cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N'
        address = 'mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB'
        expected_signature = 'INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALhWybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0=' 

        signature = self.signmessage(priv_key_wif, message)
        self.assertTrue(self.verifymessage(address, signature, message))


if __name__ == '__main__':
    unittest.main()
