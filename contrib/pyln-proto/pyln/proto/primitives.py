import coincurve
import struct


def compactsize_encode(i, w):
    """Encode an integer `i` into the writer `w`
    """
    if i < 0xFD:
        w.write(struct.pack("!B", i))
    elif i <= 0xFFFF:
        w.write(struct.pack("!BH", 0xFD, i))
    elif i <= 0xFFFFFFFF:
        w.write(struct.pack("!BL", 0xFE, i))
    else:
        w.write(struct.pack("!BQ", 0xFF, i))


def compactsize_decode(r):
    """Decode an integer from reader `r`
    """
    raw = r.read(1)
    if len(raw) != 1:
        return None

    i, = struct.unpack("!B", raw)
    if i < 0xFD:
        return i
    elif i == 0xFD:
        return struct.unpack("!H", r.read(2))[0]
    elif i == 0xFE:
        return struct.unpack("!L", r.read(4))[0]
    else:
        return struct.unpack("!Q", r.read(8))[0]


def varint_encode(i, w):
    return compactsize_encode(i, w)


def varint_decode(r):
    return compactsize_decode(r)


class ShortChannelId(object):
    def __init__(self, block, txnum, outnum):
        self.block = block
        self.txnum = txnum
        self.outnum = outnum

    @classmethod
    def from_bytes(cls, b):
        assert(len(b) == 8)
        i, = struct.unpack("!Q", b)
        return cls.from_int(i)

    @classmethod
    def from_int(cls, i):
        block = (i >> 40) & 0xFFFFFF
        txnum = (i >> 16) & 0xFFFFFF
        outnum = (i >> 0) & 0xFFFF
        return cls(block=block, txnum=txnum, outnum=outnum)

    @classmethod
    def from_str(self, s):
        block, txnum, outnum = s.split('x')
        return ShortChannelId(block=int(block), txnum=int(txnum),
                              outnum=int(outnum))

    def to_int(self):
        return self.block << 40 | self.txnum << 16 | self.outnum

    def to_bytes(self):
        return struct.pack("!Q", self.to_int())

    def __str__(self):
        return "{self.block}x{self.txnum}x{self.outnum}".format(self=self)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ShortChannelId):
            return False

        return (
            self.block == other.block
            and self.txnum == other.txnum
            and self.outnum == other.outnum
        )


class Secret(object):
    def __init__(self, data: bytes) -> None:
        assert(len(data) == 32)
        self.data = data

    def to_bytes(self) -> bytes:
        return self.data

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and self.data == other.data

    def __str__(self):
        return "Secret[0x{}]".format(self.data.hex())


class PrivateKey(object):
    def __init__(self, rawkey) -> None:
        if not isinstance(rawkey, bytes):
            raise TypeError(f"rawkey must be bytes, {type(rawkey)} received")
        elif len(rawkey) != 32:
            raise ValueError(f"rawkey must be 32-byte long. {len(rawkey)} received")

        self.rawkey = rawkey
        self.key = coincurve.PrivateKey(rawkey)

    def serializeCompressed(self):
        return self.key.secret

    def public_key(self):
        return PublicKey(self.key.public_key)


class PublicKey(object):
    def __init__(self, innerkey):
        # We accept either 33-bytes raw keys, or an EC PublicKey as returned
        # by coincurve
        if isinstance(innerkey, bytes):
            if innerkey[0] in [2, 3] and len(innerkey) == 33:
                innerkey = coincurve.PublicKey(innerkey)
            else:
                raise ValueError(
                    "Byte keys must be 33-byte long starting from either 02 or 03"
                )

        elif not isinstance(innerkey, coincurve.keys.PublicKey):
            raise ValueError(
                "Key must either be bytes or coincurve.keys.PublicKey"
            )
        self.key = innerkey

    def serializeCompressed(self):
        return self.key.format(compressed=True)

    def to_bytes(self) -> bytes:
        return self.serializeCompressed()

    def __str__(self):
        return "PublicKey[0x{}]".format(
            self.serializeCompressed().hex()
        )


def Keypair(object):
    def __init__(self, priv, pub):
        self.priv, self.pub = priv, pub
