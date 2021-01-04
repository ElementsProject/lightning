"""Pure-python implementation of the sphinx onion routing format

Warning: This implementation is not intended to be used in production, rather
it is geared towards testing and experimenting. It may have several critical
issues, including being susceptible to timing attacks and crashes. You have
been warned!

"""
from .primitives import varint_decode, varint_encode, Secret
from .wire import PrivateKey, PublicKey, ecdh
from binascii import hexlify, unhexlify
from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from hashlib import sha256
from io import BytesIO, SEEK_CUR
from typing import List, Optional, Union, Tuple
import coincurve
import io
import os
import struct


class OnionPayload(object):

    @classmethod
    def from_bytes(cls, b):
        if isinstance(b, bytes):
            b = BytesIO(b)

        realm = b.read(1)
        b.seek(-1, SEEK_CUR)

        if realm == b'\x00':
            return LegacyOnionPayload.from_bytes(b)
        elif realm != b'\x01':
            return TlvPayload.from_bytes(b, skip_length=False)
        else:
            raise ValueError("Onion payloads with realm 0x01 are unsupported")

    @classmethod
    def from_hex(cls, s):
        if isinstance(s, str):
            s = s.encode('ASCII')
        return cls.from_bytes(bytes(unhexlify(s)))

    def to_bytes(self, include_prefix):
        raise ValueError("OnionPayload is an abstract class, use "
                         "LegacyOnionPayload or TlvPayload instead")

    def to_hex(self):
        return hexlify(self.to_bytes()).decode('ASCII')


class LegacyOnionPayload(OnionPayload):

    def __init__(self, amt_to_forward, outgoing_cltv_value,
                 short_channel_id=None, padding=None):
        assert(padding is None or len(padding) == 12)
        self.padding = b'\x00' * 12 if padding is None else padding

        if isinstance(amt_to_forward, str):
            self.amt_to_forward = int(amt_to_forward)
        else:
            self.amt_to_forward = amt_to_forward

        self.outgoing_cltv_value = outgoing_cltv_value

        if isinstance(short_channel_id, str) and 'x' in short_channel_id:
            # Convert the short_channel_id from its string representation to
            # its numeric representation
            block, tx, out = short_channel_id.split('x')
            num_scid = int(block) << 40 | int(tx) << 16 | int(out)
            self.short_channel_id = num_scid
        elif isinstance(short_channel_id, int):
            self.short_channel_id = short_channel_id
        else:
            raise ValueError(
                "short_channel_id format cannot be recognized: {}".format(
                    short_channel_id
                )
            )

    @classmethod
    def from_bytes(cls, b):
        if isinstance(b, bytes):
            b = BytesIO(b)

        assert(b.read(1) == b'\x00')

        s, a, o = struct.unpack("!QQL", b.read(20))
        padding = b.read(12)
        return LegacyOnionPayload(a, o, s, padding)

    def to_bytes(self, include_prefix=True):
        b = b''
        if include_prefix:
            b += b'\x00'

        b += struct.pack("!Q", self.short_channel_id)
        b += struct.pack("!Q", self.amt_to_forward)
        b += struct.pack("!L", self.outgoing_cltv_value)
        b += self.padding
        assert(len(b) == 32 + include_prefix)
        return b

    def to_hex(self, include_prefix=True):
        return hexlify(self.to_bytes(include_prefix)).decode('ASCII')

    def __str__(self):
        return ("LegacyOnionPayload[scid={self.short_channel_id}, "
                "amt_to_forward={self.amt_to_forward}, "
                "outgoing_cltv={self.outgoing_cltv_value}]").format(self=self)


class TlvPayload(OnionPayload):

    def __init__(self, fields=None):
        self.fields = [] if fields is None else fields

    @classmethod
    def from_bytes(cls, b, skip_length=False):
        if isinstance(b, str):
            b = b.encode('ASCII')
        if isinstance(b, bytes):
            b = BytesIO(b)

        if skip_length:
            # Consume the entire remainder of the buffer.
            payload_length = len(b.getvalue()) - b.tell()
        else:
            payload_length = varint_decode(b)

        instance = TlvPayload()

        start = b.tell()
        while b.tell() < start + payload_length:
            typenum = varint_decode(b)
            if typenum is None:
                break
            length = varint_decode(b)
            if length is None:
                raise ValueError(
                    "Unable to read length at position {}".format(b.tell())
                )

            elif length > start + payload_length - b.tell():
                b.seek(start + payload_length)
                raise ValueError("Failed to parse TLV payload: value length "
                                 "is longer than available bytes.")

            val = b.read(length)

            # Get the subclass that is the correct interpretation of this
            # field. Default to the binary field type.
            c = tlv_types.get(typenum, (TlvField, "unknown"))
            cls = c[0]
            field = cls.from_bytes(typenum=typenum, b=val, description=c[1])
            instance.fields.append(field)

        return instance

    @classmethod
    def from_hex(cls, h):
        return cls.from_bytes(unhexlify(h))

    def add_field(self, typenum, value):
        self.fields.append(TlvField(typenum=typenum, value=value))

    def get(self, key, default=None):
        for f in self.fields:
            if f.typenum == key:
                return f
        return default

    def to_bytes(self, include_prefix=True) -> bytes:
        ser = [f.to_bytes() for f in self.fields]
        b = BytesIO()
        if include_prefix:
            varint_encode(sum([len(b) for b in ser]), b)
        for f in ser:
            b.write(f)
        return b.getvalue()

    def __str__(self):
        return "TlvPayload[" + ', '.join([str(f) for f in self.fields]) + "]"


class RawPayload(OnionPayload):
    """A payload that doesn't deserialize correctly as TLV stream.

    Mainly used if TLV parsing fails, but we still want access to the raw
    payload.

    """

    def __init__(self):
        self.content: Optional[bytes] = None

    @classmethod
    def from_bytes(cls, b):
        if isinstance(b, str):
            b = b.encode('ASCII')
        if isinstance(b, bytes):
            b = BytesIO(b)

        self = cls()
        payload_length = varint_decode(b)
        self.content = b.read(payload_length)
        return self

    def to_bytes(self, include_prefix=True) -> bytes:
        b = BytesIO()
        if self.content is None:
            raise ValueError("Cannot serialize empty TLV payload")

        if include_prefix:
            varint_encode(len(self.content), b)
        b.write(self.content)
        return b.getvalue()


class TlvField(object):

    def __init__(self, typenum, value=None, description=None):
        self.typenum = typenum
        self.value = value
        self.description = description

    @classmethod
    def from_bytes(cls, typenum, b, description=None):
        return TlvField(typenum=typenum, value=b, description=description)

    def __str__(self):
        return "TlvField[{description},{num}={hex}]".format(
            description=self.description,
            num=self.typenum,
            hex=hexlify(self.value).decode('ASCII')
        )

    def to_bytes(self):
        b = BytesIO()
        varint_encode(self.typenum, b)
        varint_encode(len(self.value), b)
        b.write(self.value)
        return b.getvalue()


class Tu32Field(TlvField):
    def to_bytes(self):
        raw = struct.pack("!I", self.value)
        while len(raw) > 1 and raw[0] == 0:
            raw = raw[1:]
        b = BytesIO()
        varint_encode(self.typenum, b)
        varint_encode(len(raw), b)
        b.write(raw)
        return b.getvalue()


class Tu64Field(TlvField):
    def to_bytes(self):
        raw = struct.pack("!Q", self.value)
        while len(raw) > 1 and raw[0] == 0:
            raw = raw[1:]
        b = BytesIO()
        varint_encode(self.typenum, b)
        varint_encode(len(raw), b)
        b.write(raw)
        return b.getvalue()


class ShortChannelIdField(TlvField):
    pass


class TextField(TlvField):

    @classmethod
    def from_bytes(cls, typenum, b, description=None):
        val = b.decode('UTF-8')
        return TextField(typenum, value=val, description=description)

    def to_bytes(self):
        b = BytesIO()
        val = self.value.encode('UTF-8')
        varint_encode(self.typenum, b)
        varint_encode(len(val), b)
        b.write(val)
        return b.getvalue()

    def __str__(self):
        return "TextField[{description},{num}=\"{val}\"]".format(
            description=self.description,
            num=self.typenum,
            val=self.value,
        )


class HashField(TlvField):
    pass


class SignatureField(TlvField):
    pass


VERSION_SIZE = 1
REALM_SIZE = 1
HMAC_SIZE = 32
PUBKEY_SIZE = 33
ROUTING_INFO_SIZE = 1300
TOTAL_PACKET_SIZE = VERSION_SIZE + PUBKEY_SIZE + HMAC_SIZE + ROUTING_INFO_SIZE


class RoutingOnion(object):
    def __init__(
            self, version: int,
            ephemeralkey: PublicKey,
            payloads: bytes,
            hmac: bytes
    ):
        assert(len(payloads) == ROUTING_INFO_SIZE)
        self.version = version
        self.payloads = payloads
        self.ephemeralkey = ephemeralkey
        self.hmac = hmac

    @classmethod
    def from_bin(cls, b: bytes):
        if len(b) != TOTAL_PACKET_SIZE:
            raise ValueError(
                "Encoded binary RoutingOnion size mismatch: {} != {}".format(
                    len(b), TOTAL_PACKET_SIZE
                )
            )

        version = int(b[0])
        ephemeralkey = PublicKey(b[1:34])
        payloads = b[34:1334]
        hmac = b[1334:]

        assert(len(payloads) == ROUTING_INFO_SIZE
               and len(hmac) == HMAC_SIZE)
        return cls(version=version, ephemeralkey=ephemeralkey,
                   payloads=payloads, hmac=hmac)

    @classmethod
    def from_hex(cls, s: str):
        return cls.from_bin(unhexlify(s))

    def to_bin(self) -> bytes:
        ephkey = self.ephemeralkey.to_bytes()

        return struct.pack("b", self.version) + \
            ephkey + \
            self.payloads + \
            self.hmac

    def to_hex(self):
        return hexlify(self.to_bin())

    def unwrap(self, privkey: PrivateKey, assocdata: Optional[bytes]) \
            -> Tuple[OnionPayload, Optional['RoutingOnion']]:
        shared_secret = ecdh(privkey, self.ephemeralkey)
        keys = generate_keyset(shared_secret)

        h = hmac.HMAC(keys.mu, hashes.SHA256(),
                      backend=default_backend())
        h.update(self.payloads)
        if assocdata is not None:
            h.update(assocdata)
        hh = h.finalize()

        if hh != self.hmac:
            raise ValueError("HMAC does not match, onion might have been "
                             "tampered with: {hh} != {hmac}".format(
                                 hh=hexlify(hh).decode('ascii'),
                                 hmac=hexlify(self.hmac).decode('ascii'),
                             ))

        # Create the scratch twice as large as the original packet, since we
        # need to left-shift a single payload off, which may itself be up to
        # ROUTING_INFO_SIZE in length.
        payloads = bytearray(2 * ROUTING_INFO_SIZE)
        payloads[:ROUTING_INFO_SIZE] = self.payloads
        chacha20_stream(keys.rho, payloads)

        r = io.BytesIO(payloads)
        start = r.tell()

        try:
            payload = OnionPayload.from_bytes(r)
        except ValueError:
            r.seek(start)
            payload = RawPayload.from_bytes(r)

        next_hmac = r.read(32)
        shift_size = r.tell()

        if next_hmac == bytes(32):
            return payload, None
        else:
            b = blind(self.ephemeralkey, shared_secret)
            ek = blind_group_element(self.ephemeralkey, b)
            payloads = payloads[shift_size:shift_size + ROUTING_INFO_SIZE]
            return payload, RoutingOnion(
                version=self.version,
                ephemeralkey=ek,
                payloads=payloads,
                hmac=next_hmac,
            )


KeySet = namedtuple('KeySet', ['rho', 'mu', 'um', 'pad', 'gamma', 'pi', 'ammag'])


def xor_inplace(d: Union[bytearray, memoryview],
                a: Union[bytearray, memoryview],
                b: Union[bytearray, memoryview]):
    """Compute a xor b and store the result in d
    """
    assert(len(a) == len(b) and len(d) == len(b))
    for i in range(len(a)):
        d[i] = a[i] ^ b[i]


def xor(a: Union[bytearray, memoryview],
        b: Union[bytearray, memoryview]) -> bytearray:
    assert(len(a) == len(b))
    d = bytearray(len(a))
    xor_inplace(d, a, b)
    return d


def generate_key(secret: bytes, prefix: bytes):
    h = hmac.HMAC(prefix, hashes.SHA256(), backend=default_backend())
    h.update(secret)
    return h.finalize()


def generate_keyset(secret: Secret) -> KeySet:
    types = [bytes(f, 'ascii') for f in KeySet._fields]
    keys = [generate_key(secret.data, t) for t in types]
    return KeySet(*keys)


class SphinxHopParam(object):
    def __init__(self, secret: Secret, ephemeralkey: PublicKey):
        self.secret = secret
        self.ephemeralkey = ephemeralkey
        self.blind = blind(self.ephemeralkey, self.secret)
        self.keys = generate_keyset(self.secret)


class SphinxHop(object):
    def __init__(self, pubkey: PublicKey, payload: bytes):
        self.pubkey = pubkey
        self.payload = payload
        self.hmac: Optional[bytes] = None

    def __len__(self):
        return len(self.payload) + HMAC_SIZE


def blind(pubkey, sharedsecret) -> Secret:
    m = sha256()
    m.update(pubkey.to_bytes())
    m.update(sharedsecret.to_bytes())
    return Secret(m.digest())


def blind_group_element(pubkey, blind: Secret) -> PublicKey:
    pubkey = coincurve.PublicKey(data=pubkey.to_bytes())
    blinded = pubkey.multiply(blind.to_bytes(), update=False)
    return PublicKey(blinded.format(compressed=True))


def chacha20_stream(key: bytes, dest: Union[bytearray, memoryview]):
    algorithm = algorithms.ChaCha20(key, b'\x00' * 16)
    cipher = Cipher(algorithm, None, backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.update_into(dest, dest)


class SphinxPath(object):
    def __init__(self, hops: List[SphinxHop], assocdata: bytes = None,
                 session_key: Optional[Secret] = None):
        self.hops = hops
        self.assocdata: Optional[bytes] = assocdata
        if session_key is not None:
            self.session_key = session_key
        else:
            self.session_key = Secret(os.urandom(32))

    def get_filler(self) -> memoryview:
        filler_size = sum(len(h) for h in self.hops[1:])
        filler = memoryview(bytearray(filler_size))
        params = self.get_hop_params()

        for i in range(len(self.hops[:-1])):
            h = self.hops[i]
            p = params[i]
            filler_offset = sum(len(sph) for sph in self.hops[:i])

            filler_start = ROUTING_INFO_SIZE - filler_offset
            filler_end = ROUTING_INFO_SIZE + len(h)
            filler_len = filler_end - filler_start
            stream = bytearray(filler_end)
            chacha20_stream(p.keys.rho, stream)
            xor_inplace(filler[:filler_len], filler[:filler_len],
                        stream[filler_start:filler_end])

        return filler

    def compile(self) -> RoutingOnion:
        buf = bytearray(ROUTING_INFO_SIZE)

        # Prefill the buffer with the pseudorandom stream to avoid telling the
        # last hop the real payload size through zero ranges.
        padkey = generate_key(self.session_key.data, b'pad')
        params = self.get_hop_params()
        chacha20_stream(padkey, buf)

        filler = self.get_filler()
        nexthmac = bytes(32)
        for i, h, p in zip(
                range(len(self.hops)),
                reversed(self.hops),
                reversed(params)):
            h.hmac = nexthmac
            shift_size = len(h)
            assert(shift_size == len(h.payload) + HMAC_SIZE)
            buf[shift_size:] = buf[:ROUTING_INFO_SIZE - shift_size]
            buf[:shift_size] = h.payload + h.hmac

            # Encrypt
            chacha20_stream(p.keys.rho, buf)

            if i == 0:
                # Place the filler at the correct position
                buf[ROUTING_INFO_SIZE - len(filler):] = filler

            # Finally compute the hmac that the next hop will use to verify
            # the onion's integrity.
            hh = hmac.HMAC(p.keys.mu, hashes.SHA256(),
                           backend=default_backend())
            hh.update(buf)
            if self.assocdata is not None:
                hh.update(self.assocdata)
            nexthmac = hh.finalize()

        return RoutingOnion(
            version=0,
            ephemeralkey=params[0].ephemeralkey,
            hmac=nexthmac,
            payloads=buf,
        )

    def get_hop_params(self) -> List[SphinxHopParam]:
        assert(self.session_key is not None)
        secret = ecdh(PrivateKey(self.session_key.data),
                      self.hops[0].pubkey)
        sph = SphinxHopParam(
            ephemeralkey=PrivateKey(self.session_key.data).public_key(),
            secret=secret,
        )

        params = [sph]
        for i, h in enumerate(self.hops[1:]):
            prev = params[-1]
            ek = blind_group_element(prev.ephemeralkey,
                                     prev.blind)

            # Start by blinding the current hop's pubkey with the session_key
            temp = blind_group_element(h.pubkey, self.session_key)

            # Then apply blind for all previous hops
            for p in params:
                temp = blind_group_element(temp, p.blind)

            # Finally hash the compressed resulting pubkey to get the secret
            secret = Secret(sha256(temp.to_bytes()).digest())

            sph = SphinxHopParam(secret=secret, ephemeralkey=ek)
            params.append(sph)

        return params


# A mapping of known TLV types
tlv_types = {
    2: (Tu64Field, 'amt_to_forward'),
    4: (Tu32Field, 'outgoing_cltv_value'),
    6: (ShortChannelIdField, 'short_channel_id'),
    34349334: (TextField, 'noise_message_body'),
    34349336: (SignatureField, 'noise_message_signature'),
}
