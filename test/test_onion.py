#!/usr/bin/env python

import sys

from pyelliptic import ecc
from pyelliptic import Cipher
from pyelliptic.hash import hmac_sha256
from hashlib import sha256

hexlify = ecc.hexlify
unhexlify = ecc.unhexlify

## pyelliptic doesn't support compressed pubkey representations
## so we have to add some code...
from pyelliptic.openssl import OpenSSL
import ctypes

OpenSSL.EC_POINT_set_compressed_coordinates_GFp = \
        OpenSSL._lib.EC_POINT_set_compressed_coordinates_GFp
OpenSSL.EC_POINT_set_compressed_coordinates_GFp.restype = ctypes.c_int
OpenSSL.EC_POINT_set_compressed_coordinates_GFp.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
    ctypes.c_void_p]

def get_pos_y_for_x(pubkey_x, yneg=0):
    key = pub_key = pub_key_x = pub_key_y = None
    try:
        key = OpenSSL.EC_KEY_new_by_curve_name(OpenSSL.get_curve('secp256k1'))
        group = OpenSSL.EC_KEY_get0_group(key)
        pub_key_x = OpenSSL.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
        pub_key = OpenSSL.EC_POINT_new(group)

        if OpenSSL.EC_POINT_set_compressed_coordinates_GFp(group, pub_key,
                                                           pub_key_x, yneg, 0) == 0:
            raise Exception("[OpenSSL] EC_POINT_set_compressed_coordinates_GFp FAIL ... " + OpenSSL.get_error())


        pub_key_y = OpenSSL.BN_new()
        if (OpenSSL.EC_POINT_get_affine_coordinates_GFp(group, pub_key,
                                                        pub_key_x,
                                                        pub_key_y, 0
                                                       )) == 0:
            raise Exception("[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())

        pubkeyy = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(pub_key_y))
        OpenSSL.BN_bn2bin(pub_key_y, pubkeyy)
        pubkeyy = pubkeyy.raw
        field_size = OpenSSL.EC_GROUP_get_degree(OpenSSL.EC_KEY_get0_group(key))
        secret_len = int((field_size + 7) / 8)
        if len(pubkeyy) < secret_len:
            pubkeyy = pubkeyy.rjust(secret_len, b'\0')
        return pubkeyy
    finally:
        if key is not None: OpenSSL.EC_KEY_free(key)
        if pub_key is not None: OpenSSL.EC_POINT_free(pub_key)
        if pub_key_x is not None: OpenSSL.BN_free(pub_key_x)
        if pub_key_y is not None: OpenSSL.BN_free(pub_key_y)

class Onion(object):
    HMAC_LEN = 32
    PKEY_LEN = 32
    MSG_LEN = 128
    ZEROES = b"\x00" * (HMAC_LEN + PKEY_LEN + MSG_LEN)

    def __init__(self, onion, my_ecc):
        self.my_ecc = my_ecc

        hmac_end = len(onion)
        pkey_end = hmac_end - self.HMAC_LEN
        self.msg_end = pkey_end - self.PKEY_LEN
        self.fwd_end = self.msg_end - self.MSG_LEN

        self.onion = onion
        self.pkey = onion[self.msg_end:pkey_end]
        self.hmac = onion[pkey_end:hmac_end]

        self.get_secrets()

    def padding(self):
        ctx = Cipher(self.enckey, self.pad_iv, 1, ciphername='aes-128-ctr')
        self.pad = ctx.ciphering(self.ZEROES)

    def decrypt(self):
        self.padding()

        ctx = Cipher(self.enckey, self.iv, 0, ciphername='aes-128-ctr')
        self.fwd = self.pad + ctx.ciphering(self.onion[:self.fwd_end])
        self.msg = ctx.ciphering(self.onion[self.fwd_end:self.msg_end])

    def tweak_sha(self, sha, d):
        sha = sha.copy()
        sha.update(d)
        return sha.digest()

    def get_secrets(self):
        pkey_x = self.pkey
        pkey_y = get_pos_y_for_x(pkey_x)
        pkey = unhexlify('04') + pkey_x + pkey_y
        tmp_key = ecc.ECC(curve='secp256k1', pubkey=pkey)
        sec_x = self.my_ecc.get_ecdh_key(tmp_key.get_pubkey())
        sec_1 = sha256(sha256(b"\x02" + sec_x).digest())
        sec_2 = sha256(sha256(b"\x03" + sec_x).digest())

        sec = None
        if self.check_hmac(self.tweak_sha(sec_1, b'\x01')):
            sec = sec_1
        if self.check_hmac(self.tweak_sha(sec_2, b'\x01')):
            sec = sec_2
        if sec is None:
            raise Exception("HMAC did not verify")

        self.enckey = self.tweak_sha(sec, b'\x00')
        self.iv     = self.tweak_sha(sec, b'\x02')
        self.pad_iv = self.tweak_sha(sec, b'\x03')

    def check_hmac(self, hmac_key):
        calc = hmac_sha256(hmac_key, self.onion[:-self.HMAC_LEN])
        return calc == self.hmac

if __name__ == "__main__":
    keys = []
    msg = ""
    for ln in sys.stdin.readlines():
        if ln.startswith(" * Keypair "):
            w = ln.strip().split()
            idx = int(w[2].strip(":"))
            priv = unhexlify(w[3])
            pub = unhexlify(w[4])
            assert idx == len(keys)
            keys.append(ecc.ECC(privkey=priv, pubkey=pub, curve='secp256k1'))
        elif ln.startswith(" * Message:"):
            msg = unhexlify(ln[11:].strip())
        elif ln.startswith("Decrypting"):
            pass
        else:
            print ln
            assert ln.strip() == ""

    assert msg != ""
    for k in keys:
        o = Onion(msg, k)
        o.decrypt()
        print o.msg
        msg = o.fwd

    print "done"
