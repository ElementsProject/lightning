import unittest
from util import *

FLAG_ECDSA = 1

class AntiExfilTests(unittest.TestCase):

    def cbufferize(self, values):
        conv = lambda v: make_cbuffer(v)[0] if type(v) is str else v
        return [conv(v) for v in values]

    def test_anti_exfil(self):
        entropy, host_commitment, signer_commitment, priv_key, pub_key, msg, sig = self.cbufferize(
            ['11' * 32, '00' * 32, '00' * 33, '22' * 32, '00' * 33, '33' * 32, '00' * 64])

        flags = FLAG_ECDSA

        ret = wally_ec_public_key_from_private_key(priv_key, 32, pub_key, 33);
        self.assertEqual(WALLY_OK, ret)

        ret = wally_ae_host_commit_from_bytes(entropy, 32, flags, host_commitment, 32)
        self.assertEqual(WALLY_OK, ret)

        ret = wally_ae_signer_commit_from_bytes(priv_key, 32, msg, 32, host_commitment, 32, flags, signer_commitment, 33)
        self.assertEqual(WALLY_OK, ret)

        ret = wally_ae_sig_from_bytes(priv_key, 32, msg, 32, entropy, 32, flags, sig, 64)
        self.assertEqual(WALLY_OK, ret)

        ret = wally_ae_verify(pub_key, 33, msg, 32, entropy, 32, signer_commitment, 33, flags, sig, 64)
        self.assertEqual(WALLY_OK, ret)

        # Invalid cases
        for args in [
            (None,    32, flags, host_commitment, 32), # Missing host randomness
            (entropy, 31, flags, host_commitment, 32), # Incorrect host randomness length
            (entropy, 31, 0,     host_commitment, 32), # Unsupported flag
            (entropy, 31, flags, None,            32), # Missing host commitment
            (entropy, 31, flags, host_commitment, 31), # Incorrect host commitment length
            ]:
            self.assertEqual(WALLY_EINVAL, wally_ae_host_commit_from_bytes(*args))

        for args in [
            (None,     32, msg,  32, host_commitment, 32, flags, signer_commitment, 33), # Missing privkey
            (priv_key, 31, msg,  32, host_commitment, 32, flags, signer_commitment, 33), # Incorrect privkey length
            (priv_key, 32, None, 32, host_commitment, 32, flags, signer_commitment, 33), # Missing message
            (priv_key, 32, msg,  31, host_commitment, 32, flags, signer_commitment, 33), # Incorrect message length
            (priv_key, 32, msg,  32, None,            32, flags, signer_commitment, 33), # Missing host commitment
            (priv_key, 32, msg,  32, host_commitment, 31, flags, signer_commitment, 33), # Incorrect host commitment length
            (priv_key, 32, msg,  32, host_commitment, 32, 0,     signer_commitment, 33), # Unsupported flag
            (priv_key, 32, msg,  32, host_commitment, 32, flags, None,              33), # Missing signer commitment
            (priv_key, 32, msg,  32, host_commitment, 32, flags, signer_commitment, 32), # Incorrect signer commitment length
            ]:
            self.assertEqual(WALLY_EINVAL, wally_ae_signer_commit_from_bytes(*args))

        for args in [
            (None,     32, msg,  32, entropy, 32, flags, sig,  64), # Missing privkey
            (priv_key, 31, msg,  32, entropy, 32, flags, sig,  64), # Incorrect privkey length
            (priv_key, 32, None, 32, entropy, 32, flags, sig,  64), # Missing message
            (priv_key, 32, msg,  31, entropy, 32, flags, sig,  64), # Incorrect message length
            (priv_key, 32, msg,  32, None,    32, flags, sig,  64), # Missing host randomness
            (priv_key, 32, msg,  32, entropy, 31, flags, sig,  64), # Incorrect host randomness length
            (priv_key, 32, msg,  32, entropy, 32, 0,     sig,  64), # Unsupported flags
            (priv_key, 32, msg,  32, entropy, 32, flags, None, 64), # Missing sig
            (priv_key, 32, msg,  32, entropy, 32, flags, sig,  63), # Incorrect sig length
            ]:
            self.assertEqual(WALLY_EINVAL, wally_ae_sig_from_bytes(*args))

        inv_pub, inv_msg, inv_rand, inv_opening, inv_sig = self.cbufferize(
            ['02' * 33, 'ff' * 32, 'ff' * 32, 'ff' * 33, 'ff' * 64])

        for args in [
            (None,    32, msg,     32, entropy, 32, signer_commitment, 33, flags, sig,     64), # Missing pubkey
            (pub_key, 31, msg,     32, entropy, 32, signer_commitment, 33, flags, sig,     64), # Incorrect pubkey length
            (inv_pub, 32, msg,     32, entropy, 32, signer_commitment, 33, flags, sig,     64), # Invalud pubkey
            (pub_key, 32, None,    32, entropy, 32, signer_commitment, 33, flags, sig,     64), # Missing message
            (pub_key, 32, msg,     31, entropy, 32, signer_commitment, 33, flags, sig,     64), # Incorrect message length
            (pub_key, 32, inv_msg, 32, entropy, 32, signer_commitment, 33, flags, sig,     64), # Invalid message
            (pub_key, 32, msg,     32, None,    32, signer_commitment, 33, flags, sig,     64), # Missing host randomness
            (pub_key, 32, msg,     32, entropy, 31, signer_commitment, 33, flags, sig,     64), # Incorrect host randomness length
            (pub_key, 32, msg,     32, inv_rand, 32, signer_commitment, 33, flags, sig,     64), # Invalid host randomness
            (pub_key, 32, msg,     32, entropy,  32, None,              33, flags, sig,     64), # Missing opening
            (pub_key, 32, msg,     32, entropy,  32, signer_commitment, 32, flags, sig,     64), # Incorrect opening length
            (pub_key, 32, msg,     32, entropy,  32, inv_opening,       33, flags, sig,     64), # Invalid opening
            (pub_key, 32, msg,     32, entropy,  32, signer_commitment, 33, 0,     sig,     64), # Unsupported flags
            (pub_key, 32, msg,     32, entropy,  32, signer_commitment, 33, flags, None,    64), # Missing sig
            (pub_key, 32, msg,     32, entropy,  32, signer_commitment, 33, flags, sig,     64), # Incorrect sig length
            (pub_key, 32, msg,     32, entropy,  32, signer_commitment, 33, flags, inv_sig, 64), # Invalid sig
            ]:
            self.assertEqual(WALLY_EINVAL, wally_ae_verify(*args))


if __name__ == '__main__':
    unittest.main()
