from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .primitives import Secret, PrivateKey, PublicKey
from hashlib import sha256
from typing import Tuple
import coincurve
import os
import socket
import socks
import struct
import threading


__all__ = [
    'PrivateKey',
    'PublicKey',
    'Secret',
    'LightningConnection',
    'LightningServerSocket',
    'connect'
]


def hkdf(ikm, salt=b"", info=b""):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=info,
        backend=default_backend())

    return hkdf.derive(ikm)


def hkdf_two_keys(ikm, salt):
    t = hkdf(ikm, salt)
    return t[:32], t[32:]


def ecdh(k, rk):
    k = coincurve.PrivateKey(secret=k.rawkey)
    rk = coincurve.PublicKey(data=rk.serializeCompressed())
    a = k.ecdh(rk.public_key)
    return Secret(a)


def encryptWithAD(k, n, ad, plaintext):
    chacha = ChaCha20Poly1305(k)
    return chacha.encrypt(n, plaintext, ad)


def decryptWithAD(k, n, ad, ciphertext):
    chacha = ChaCha20Poly1305(k)
    return chacha.decrypt(n, ciphertext, ad)


class Sha256Mixer(object):
    def __init__(self, base):
        self.hash = sha256(base).digest()

    def update(self, data):
        h = sha256(self.hash)
        h.update(data)
        self.hash = h.digest()
        return self.hash

    def digest(self):
        return self.hash

    def __str__(self):
        return "Sha256Mixer[0x{}]".format(self.hash.hex())


class LightningConnection(object):
    def __init__(self, connection, remote_pubkey, local_privkey, is_initiator):
        self.connection = connection
        self.chaining_key = None
        self.handshake_hash = None
        self.local_privkey = local_privkey
        self.local_pubkey = self.local_privkey.public_key()
        self.remote_pubkey = remote_pubkey
        self.is_initiator = is_initiator
        self.init_handshake()
        self.rn, self.sn = 0, 0
        self.send_lock, self.recv_lock = threading.Lock(), threading.Lock()

    @classmethod
    def nonce(cls, n):
        """Transforms a numeric nonce into a byte formatted one

        Nonce n encoded as 32 zero bits, followed by a little-endian 64-bit
        value. Note: this follows the Noise Protocol convention, rather than
        our normal endian.
        """
        return b'\x00' * 4 + struct.pack("<Q", n)

    def init_handshake(self):
        h = sha256(b'Noise_XK_secp256k1_ChaChaPoly_SHA256').digest()
        self.chaining_key = h
        h = sha256(h + b'lightning').digest()

        if self.is_initiator:
            responder_pubkey = self.remote_pubkey
        else:
            responder_pubkey = self.local_pubkey
        h = sha256(h + responder_pubkey.serializeCompressed()).digest()

        self.handshake = {
            'h': h,
            'e': PrivateKey(os.urandom(32)),
        }

    def handshake_act_one_initiator(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(self.handshake['e'].public_key().serializeCompressed())
        es = ecdh(self.handshake['e'], self.remote_pubkey)
        t = hkdf(salt=self.chaining_key, ikm=es.data, info=b'')
        assert(len(t) == 64)
        self.chaining_key, temp_k1 = t[:32], t[32:]
        c = encryptWithAD(temp_k1, self.nonce(0), h.digest(), b'')
        self.handshake['h'] = h.update(c)
        pk = self.handshake['e'].public_key().serializeCompressed()
        m = b'\x00' + pk + c
        return m

    def handshake_act_one_responder(self, m):
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))

        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(re.serializeCompressed())
        es = ecdh(self.local_privkey, re)
        self.handshake['re'] = re
        t = hkdf(salt=self.chaining_key, ikm=es.data, info=b'')
        self.chaining_key, temp_k1 = t[:32], t[32:]

        try:
            decryptWithAD(temp_k1, self.nonce(0), h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed, remote peer doesn't know "
                       "our node ID.")
        h.update(c)
        self.handshake['h'] = h.digest()

    def handshake_act_two_responder(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(self.handshake['e'].public_key().serializeCompressed())
        ee = ecdh(self.handshake['e'], self.handshake['re'])
        t = hkdf(salt=self.chaining_key, ikm=ee.data, info=b'')
        assert(len(t) == 64)
        self.chaining_key, self.temp_k2 = t[:32], t[32:]
        c = encryptWithAD(self.temp_k2, self.nonce(0), h.digest(), b'')
        h.update(c)
        self.handshake['h'] = h.digest()
        pk = self.handshake['e'].public_key().serializeCompressed()
        m = b'\x00' + pk + c
        return m

    def handshake_act_two_initiator(self, m):
        v, re, c = m[0], PublicKey(m[1:34]), m[34:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        self.re = re
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        h.update(re.serializeCompressed())
        ee = ecdh(self.handshake['e'], re)
        self.chaining_key, self.temp_k2 = hkdf_two_keys(
            salt=self.chaining_key, ikm=ee.data
        )
        try:
            decryptWithAD(self.temp_k2, self.nonce(0), h.digest(), c)
        except InvalidTag:
            ValueError("Verification of tag failed.")
        h.update(c)
        self.handshake['h'] = h.digest()

    def handshake_act_three_initiator(self):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        pk = self.local_pubkey.serializeCompressed()
        c = encryptWithAD(self.temp_k2, self.nonce(1), h.digest(), pk)
        h.update(c)
        se = ecdh(self.local_privkey, self.re)

        self.chaining_key, self.temp_k3 = hkdf_two_keys(
            salt=self.chaining_key, ikm=se.data
        )
        t = encryptWithAD(self.temp_k3, self.nonce(0), h.digest(), b'')
        m = b'\x00' + c + t
        t = hkdf(salt=self.chaining_key, ikm=b'', info=b'')

        self.sk, self.rk = hkdf_two_keys(salt=self.chaining_key, ikm=b'')
        self.rn, self.sn = 0, 0
        return m

    def handshake_act_three_responder(self, m):
        h = Sha256Mixer(b'')
        h.hash = self.handshake['h']
        v, c, t = m[0], m[1:50], m[50:]
        if v != 0:
            raise ValueError("Unsupported handshake version {}, only version "
                             "0 is supported.".format(v))
        rs = decryptWithAD(self.temp_k2, self.nonce(1), h.digest(), c)
        self.remote_pubkey = PublicKey(rs)
        h.update(c)
        se = ecdh(self.handshake['e'], self.remote_pubkey)

        self.chaining_key, self.temp_k3 = hkdf_two_keys(
            se.data, self.chaining_key
        )
        decryptWithAD(self.temp_k3, self.nonce(0), h.digest(), t)
        self.rn, self.sn = 0, 0

        self.rk, self.sk = hkdf_two_keys(salt=self.chaining_key, ikm=b'')

    def read_message(self):
        with self.recv_lock:
            lc = self.connection.recv(18)
            if len(lc) != 18:
                raise ValueError(
                    "Short read reading the message length: 18 != {}".format(
                        len(lc))
                )
            length = decryptWithAD(self.rk, self.nonce(self.rn), b'', lc)
            length, = struct.unpack("!H", length)
            self.rn += 1

            mc = self.connection.recv(length + 16)
            if len(mc) < length + 16:
                raise ValueError(
                    "Short read reading the message: {} != {}".format(
                        length + 16, len(lc)
                    )
                )
            m = decryptWithAD(self.rk, self.nonce(self.rn), b'', mc)
            self.rn += 1
            assert(self.rn % 2 == 0)
            self._maybe_rotate_keys()

        return m

    def send_message(self, m):
        length = struct.pack("!H", len(m))
        with self.send_lock:
            lc = encryptWithAD(self.sk, self.nonce(self.sn), b'', length)
            mc = encryptWithAD(self.sk, self.nonce(self.sn + 1), b'', m)
            self.sn += 2
            self.connection.send(lc)
            self.connection.send(mc)
            assert(self.sn % 2 == 0)
            self._maybe_rotate_keys()

    def _maybe_rotate_keys(self):
        if self.sn == 1000:
            self.sck, self.sk = hkdf_two_keys(salt=self.sck, ikm=self.sk)
            self.sn = 0
        if self.rn == 1000:
            self.rck, self.rk = hkdf_two_keys(salt=self.rck, ikm=self.rk)
            self.rn = 0

    def shake(self):
        if self.is_initiator:
            m = self.handshake_act_one_initiator()
            self.connection.send(m)
            m = self.connection.recv(50)
            if len(m) != 50:
                raise ValueError(
                    "Short read from peer reading act2: 50 != {}".format(
                        len(m))
                )
            self.handshake_act_two_initiator(m)
            m = self.handshake_act_three_initiator()
            self.connection.send(m)
        else:
            m = self.connection.recv(50)
            if len(m) != 50:
                raise ValueError(
                    "Short read from peer reading act1: 50 != {}".format(
                        len(m))
                )
            self.handshake_act_one_responder(m)
            m = self.handshake_act_two_responder()
            self.connection.send(m)
            m = self.connection.recv(66)
            if len(m) != 66:
                raise ValueError(
                    "Short read from peer reading act3: 66 != {}".format(
                        len(m))
                )
            self.handshake_act_three_responder(m)

        self.sck = self.chaining_key
        self.rck = self.chaining_key


class LightningServerSocket(socket.socket):
    def __init__(self, local_privkey):
        socket.socket.__init__(self)
        self.local_privkey = local_privkey
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def accept(self):
        conn, address = socket.socket.accept(self)
        lconn = LightningConnection(
            conn, remote_pubkey=None,
            local_privkey=self.local_privkey,
            is_initiator=False)
        lconn.shake()
        return (lconn, address)


def connect(local_privkey, node_id, host: str, port: int = 9735,
            socks_addr: Tuple[str, int] = None):
    if isinstance(node_id, bytes) and len(node_id) == 33:
        remote_pubkey = PublicKey(node_id)
    elif isinstance(node_id, ec.EllipticCurvePublicKey):
        remote_pubkey = PublicKey(node_id)
    elif isinstance(node_id, PublicKey):
        remote_pubkey = node_id
    else:
        raise ValueError(
            "node_id must be either a 33 byte array, or a PublicKey"
        )

    if socks_addr is None:
        conn = socket.create_connection((host, port))
    else:
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, *socks_addr, True)
        conn = socks.socksocket()
        conn.connect((host, port))
    lconn = LightningConnection(conn, remote_pubkey, local_privkey,
                                is_initiator=True)
    lconn.shake()
    return lconn
