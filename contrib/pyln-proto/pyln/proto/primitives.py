import struct


def varint_encode(i, w):
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


def varint_decode(r):
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

    def __eq__(self, other):
        return self.block == other.block and self.txnum == other.txnum and self.outnum == other.outnum
