#!/usr/bin/env python

import argparse
import sys
import time

from hashlib import sha256
from binascii import hexlify, unhexlify
import hmac
import random

from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.backends import default_backend
# http://cryptography.io

from pyelliptic import ecc

class MyEx(Exception): pass

def hmac_sha256(k, m):
    return hmac.new(k, m, sha256).digest()






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

def ecc_ecdh_key(sec, pub):
    assert isinstance(sec, ecc.ECC)
    if isinstance(pub, ecc.ECC):
        pub = pub.get_pubkey()
    #return sec.get_ecdh_key(pub)

    pubkey_x, pubkey_y = ecc.ECC._decode_pubkey(pub, 'binary')

    other_key = other_pub_key_x = other_pub_key_y = other_pub_key = None
    own_priv_key = res = res_x = res_y = None
    try:
            other_key = OpenSSL.EC_KEY_new_by_curve_name(sec.curve)
            if other_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            other_pub_key_x = OpenSSL.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
            other_pub_key_y = OpenSSL.BN_bin2bn(pubkey_y, len(pubkey_y), 0)

            other_group = OpenSSL.EC_KEY_get0_group(other_key)
            other_pub_key = OpenSSL.EC_POINT_new(other_group)
            if (other_pub_key == None):
                raise Exception("[OpenSSl] EC_POINT_new FAIL ... " + OpenSSL.get_error())

            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(other_group,
                                                            other_pub_key,
                                                            other_pub_key_x,
                                                            other_pub_key_y,
                                                            0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ..." + OpenSSL.get_error())

            own_priv_key = OpenSSL.BN_bin2bn(sec.privkey, len(sec.privkey), 0)

            res = OpenSSL.EC_POINT_new(other_group)
            if (OpenSSL.EC_POINT_mul(other_group, res, 0, other_pub_key, own_priv_key, 0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_mul FAIL ..." + OpenSSL.get_error())

            res_x = OpenSSL.BN_new()
            res_y = OpenSSL.BN_new()

            if (OpenSSL.EC_POINT_get_affine_coordinates_GFp(other_group, res,
                                                            res_x,
                                                            res_y, 0
                                                            )) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())

            resx = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(res_x))
            resy = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(res_y))

            OpenSSL.BN_bn2bin(res_x, resx)
            resx = resx.raw
            OpenSSL.BN_bn2bin(res_y, resy)
            resy = resy.raw

            return resx, resy

    finally:
            if other_key: OpenSSL.EC_KEY_free(other_key)
            if other_pub_key_x: OpenSSL.BN_free(other_pub_key_x)
            if other_pub_key_y: OpenSSL.BN_free(other_pub_key_y)
            if other_pub_key: OpenSSL.EC_POINT_free(other_pub_key)
            if own_priv_key: OpenSSL.BN_free(own_priv_key)
            if res: OpenSSL.EC_POINT_free(res)
            if res_x: OpenSSL.BN_free(res_x)
            if res_y: OpenSSL.BN_free(res_y)

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

def ec_decompress(pubkey, curve='secp256k1'):
    if pubkey[0] == '\x02' or pubkey[0] == '\x03':
        yneg = ord(pubkey[0]) & 1
        pubkey = "\x04" + pubkey[1:] + get_pos_y_for_x(pubkey[1:], yneg=yneg)
    elif pubkey[0] == '\x04':
        pass
    else:
        raise Exception("Unrecognised pubkey format: %s" % (pubkey,))
    return pubkey

class Onion(object):
    HMAC_LEN = 32
    PKEY_LEN = 32
    MSG_LEN = 128
    ZEROES = b"\x00" * (HMAC_LEN + PKEY_LEN + MSG_LEN)

    @staticmethod
    def tweak_sha(sha, d):
        sha = sha.copy()
        sha.update(d)
        return sha.digest()

    @classmethod
    def get_ecdh_secrets(cls, sec, pkey_x, pkey_y):
        pkey = unhexlify('04') + pkey_x + pkey_y
        tmp_key = ecc.ECC(curve='secp256k1', pubkey=pkey)
        sec_x, sec_y = ecc_ecdh_key(sec, tmp_key)

        b = '\x02' if ord(sec_y[-1]) % 2 == 0 else '\x03'
        sec = sha256(sha256(b + sec_x).digest())

        enckey = cls.tweak_sha(sec, b'\x00')[:16]
        hmac   = cls.tweak_sha(sec, b'\x01')
        iv     = cls.tweak_sha(sec, b'\x02')[:16]
        pad_iv = cls.tweak_sha(sec, b'\x02')[16:]

        return enckey, hmac, iv, pad_iv

    def enc_pad(self, enckey, pad_iv):
        aes = Cipher(AES(enckey), CTR(pad_iv),
                     default_backend()).encryptor()
        return aes.update(self.ZEROES)

class OnionDecrypt(Onion):
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

    def decrypt(self):
        pad = self.enc_pad(self.enckey, self.pad_iv)

        aes = Cipher(AES(self.enckey), CTR(self.iv),
                     default_backend()).decryptor()
        self.fwd = pad + aes.update(self.onion[:self.fwd_end])
        self.msg = aes.update(self.onion[self.fwd_end:self.msg_end])

    def get_secrets(self):
        pkey_x = self.pkey
        pkey_y = get_pos_y_for_x(pkey_x) # always positive by design
        enckey, hmac, iv, pad_iv = self.get_ecdh_secrets(self.my_ecc, pkey_x, pkey_y)
        if not self.check_hmac(hmac):
            raise Exception("HMAC did not verify")
        self.enckey = enckey
        self.iv     = iv
        self.pad_iv = pad_iv

    def check_hmac(self, hmac_key):
        calc = hmac_sha256(hmac_key, self.onion[:-self.HMAC_LEN])
        return calc == self.hmac

class OnionEncrypt(Onion):
    def __init__(self, msgs, pubkeys):
        assert len(msgs) == len(pubkeys)
        assert 0 < len(msgs) <= 20
        assert all( len(m) <= self.MSG_LEN for m in msgs )

        msgs = [m + "\0"*(self.MSG_LEN - len(m)) for m in msgs]
        pubkeys = [ecc.ECC(pubkey=pk, curve='secp256k1') for pk in pubkeys]
        n = len(msgs)

        tmpkeys = []
        tmppubkeys = []
        for i in range(n):
            while True:
                t = ecc.ECC(curve='secp256k1')
                if ord(t.pubkey_y[-1]) % 2 == 0:
                    break
                # or do the math to "flip" the secret key and pub key
            tmpkeys.append(t)
            tmppubkeys.append(t.pubkey_x)

        enckeys, hmacs, ivs, pad_ivs = zip(*[self.get_ecdh_secrets(tmpkey, pkey.pubkey_x, pkey.pubkey_y)
            for tmpkey, pkey in zip(tmpkeys, pubkeys)])

        # padding takes the form:
        #  E_(n-1)(0000s)
        #  D_(n-1)(
        #      E(n-2)(0000s)
        #      D(n-2)(
        #          ...
        #      )
        #  )

        padding = ""
        for i in range(n-1):
             pad = self.enc_pad(enckeys[i], pad_ivs[i])
             aes = Cipher(AES(enckeys[i]), CTR(ivs[i]),
                     default_backend()).decryptor()
             padding = pad + aes.update(padding)

        if n < 20:
            padding += str(bytearray(random.getrandbits(8)
                             for _ in range(len(self.ZEROES) * (20-n))))

        # to encrypt the message we need to bump the counter past all
        # the padding, then just encrypt the final message
        aes = Cipher(AES(enckeys[-1]), CTR(ivs[-1]),
            default_backend()).encryptor()
        aes.update(padding) # don't care about cyphertext
        msgenc = aes.update(msgs[-1])

        msgenc = padding + msgenc + tmppubkeys[-1]
        del padding
        msgenc += hmac_sha256(hmacs[-1], msgenc)

        # *PHEW*
        # now iterate

        for i in reversed(range(n-1)):
            # drop the padding this node will add
            msgenc = msgenc[len(self.ZEROES):]
            # adding the msg
            msgenc += msgs[i]
            # encrypt it
            aes = Cipher(AES(enckeys[i]), CTR(ivs[i]),
                default_backend()).encryptor()
            msgenc = aes.update(msgenc)
            # add the tmp key
            msgenc += tmppubkeys[i]
            # add the hmac
            msgenc += hmac_sha256(hmacs[i], msgenc)
        self.onion = msgenc

def generate(args):
    server_keys = []
    msgs = []
    for k in args.pubkeys:
        k = unhexlify(k)
        msgs.append("Message for %s..." % (hexlify(k[1:21]),))
        k = ec_decompress(k)
        server_keys.append(k)
    o = OnionEncrypt(msgs, server_keys)
    sys.stdout.write(o.onion)
    return

def decode(args):
    msg = sys.stdin.read()
    key = ecc.ECC(privkey=unhexlify(args.seckey),
                  pubkey=ec_decompress(unhexlify(args.pubkey)),
                  curve='secp256k1')
    o = OnionDecrypt(msg, key)
    o.decrypt()
    #sys.stderr.write("Message: \"%s\"\n" % (o.msg,))
    want_msg = "Message for %s..." % (args.pubkey[2:42])
    if o.msg != want_msg + "\0"*(Onion.MSG_LEN - len(want_msg)):
        raise Exception("Unexpected message: \"%s\" (wanted: %s)" % (o.msg, want_msg))

    sys.stdout.write(o.fwd)

def main(argv):
    parser = argparse.ArgumentParser(description="Process some integers.")
    sp = parser.add_subparsers()
    p = sp.add_parser("generate")
    p.add_argument("pubkeys", nargs='+', help="public keys of recipients")
    p.set_defaults(func=generate)

    p = sp.add_parser("decode")
    p.add_argument("seckey", help="secret key for router")
    p.add_argument("pubkey", help="public key for router")
    p.set_defaults(func=decode)

    args = parser.parse_args(argv)

    return args.func(args)




if __name__ == "__main__":
    main(sys.argv[1:])
    sys.exit(0)

