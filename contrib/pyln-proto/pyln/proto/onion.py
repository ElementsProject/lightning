from .primitives import varint_decode, varint_encode
from io import BytesIO, SEEK_CUR
from binascii import hexlify, unhexlify
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

    def to_bytes(self):
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
            # Convert the short_channel_id from its string representation to its numeric representation
            block, tx, out = short_channel_id.split('x')
            num_scid = int(block) << 40 | int(tx) << 16 | int(out)
            self.short_channel_id = num_scid
        elif isinstance(short_channel_id, int):
            self.short_channel_id = short_channel_id
        else:
            raise ValueError("short_channel_id format cannot be recognized: {}".format(short_channel_id))

    @classmethod
    def from_bytes(cls, b):
        if isinstance(b, bytes):
            b = BytesIO(b)

        assert(b.read(1) == b'\x00')

        s, a, o = struct.unpack("!QQL", b.read(20))
        padding = b.read(12)
        return LegacyOnionPayload(a, o, s, padding)

    def to_bytes(self, include_realm=True):
        b = b''
        if include_realm:
            b += b'\x00'

        b += struct.pack("!Q", self.short_channel_id)
        b += struct.pack("!Q", self.amt_to_forward)
        b += struct.pack("!L", self.outgoing_cltv_value)
        b += self.padding
        assert(len(b) == 32 + include_realm)
        return b

    def to_hex(self, include_realm=True):
        return hexlify(self.to_bytes(include_realm)).decode('ASCII')

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

    def to_bytes(self):
        ser = [f.to_bytes() for f in self.fields]
        b = BytesIO()
        varint_encode(sum([len(b) for b in ser]), b)
        for f in ser:
            b.write(f)
        return b.getvalue()

    def __str__(self):
        return "TlvPayload[" + ', '.join([str(f) for f in self.fields]) + "]"


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


# A mapping of known TLV types
tlv_types = {
    2: (Tu64Field, 'amt_to_forward'),
    4: (Tu32Field, 'outgoing_cltv_value'),
    6: (ShortChannelIdField, 'short_channel_id'),
    34349334: (TextField, 'noise_message_body'),
    34349336: (SignatureField, 'noise_message_signature'),
}
