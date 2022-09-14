from binascii import hexlify
from pathlib import Path

import io
import os
import logging
import struct


class GossipStore(object):
    """A pythonic way to interact/introspect the gossip_store"""

    def __init__(self, path: Path):
        self.fd = None
        self.version = None
        self.path = path
        self.log = logging.getLogger("GossipStore")

    def open(self):
        self.fd = self.path.open(mode="rb")
        self.version = ord(self.fd.read(1))
        if self.version < 3:
            raise ValueError(
                f"gossip_store below version 3 is not supported: {self.version}"
            )

    def reset(self):
        """Seek back to the beginning of the store."""
        self.log.debug("Resetting file position to 1")
        self.fd.seek(1, os.SEEK_SET)

    @classmethod
    def maybe_parse(cls, msg: bytes):
        parsers = {
            256: ChannelAnnouncement,
            257: NodeAnnouncement,
            258: ChannelUpdate,
            4104: LocalChannelAnnouncement,
            4102: LocalChannelUpdate,
        }

        (typ,) = struct.unpack_from("!H", msg)
        parser = parsers.get(typ, None)
        logging.debug(f"Picking parser for type={typ} -> {parser}")
        if parser is not None:
            return parser.from_bytes(io.BytesIO(msg[2:]))
        else:
            return msg

    def __next__(self):
        hdr = self.fd.read(12)
        if len(hdr) < 12:
            raise StopIteration
        length, crc, timestamp = struct.unpack("!III", hdr)

        # deleted = (length & 0x80000000 != 0)
        # important = (length & 0x40000000 != 0)
        length = length & (~0x80000000) & (~0x40000000)
        print(f"Reading message length={length} at position={self.fd.tell()}")

        msg = self.fd.read(length)

        if len(msg) != length:
            raise ValueError(
                f"Incomplete gossip_store: expected {length} bytes, got {len(msg)} at pos {self.fd.tell()}"
            )

        return GossipStore.maybe_parse(msg)

    def __iter__(self):
        """Return a copy of ourselves as iterator."""
        inst = GossipStore(self.path)
        inst.open()
        return inst


class ChannelAnnouncement(object):
    def __init__(self):
        self.num_short_channel_id = None
        self.node_signatures = [None, None]
        self.bitcoin_signatures = [None, None]
        self.features = None
        self.chain_hash = None
        self.node_ids = [None, None]
        self.bitcoin_keys = [None, None]

    @classmethod
    def from_bytes(cls, b: io.BytesIO) -> "ChannelAnnouncement":
        ca = cls()
        ca.node_signatures = (b.read(64), b.read(64))
        ca.bitcoin_signatures = (b.read(64), b.read(64))
        (flen,) = struct.unpack("!H", b.read(2))
        ca.features = b.read(flen)
        ca.chain_hash = b.read(32)[::-1]
        (ca.num_short_channel_id,) = struct.unpack("!Q", b.read(8))
        ca.node_ids = (b.read(33), b.read(33))
        ca.bitcoin_keys = (b.read(33), b.read(33))
        return ca

    @property
    def short_channel_id(self):
        return "{}x{}x{}".format(
            (self.num_short_channel_id >> 40) & 0xFFFFFF,
            (self.num_short_channel_id >> 16) & 0xFFFFFF,
            (self.num_short_channel_id >> 00) & 0xFFFF,
        )

    def __eq__(self, other):
        return (
            self.num_short_channel_id == other.num_short_channel_id
            and self.bitcoin_keys == other.bitcoin_keys
            and self.chain_hash == other.chain_hash
            and self.node_ids == other.node_ids
            and self.features == other.features
        )

    def __str__(self):
        na = hexlify(self.node_ids[0]).decode("ASCII")
        nb = hexlify(self.node_ids[1]).decode("ASCII")
        return f"ChannelAnnouncement(scid={self.short_channel_id}, nodes=[{na},{nb}])"


class NodeAnnouncement(object):
    def __init__(self):
        self.signature = None
        self.features = ""
        self.timestamp = None
        self.node_id = None
        self.rgb_color = None
        self.alias = None
        self.addresses = None

    @classmethod
    def from_bytes(cls, b: io.BytesIO) -> "NodeAnnouncement":
        na = cls()
        na.signature = b.read(64)
        (flen,) = struct.unpack("!H", b.read(2))
        na.features = b.read(flen)
        (na.timestamp,) = struct.unpack("!I", b.read(4))
        na.node_id = b.read(33)
        na.rgb_color = b.read(3)
        na.alias = b.read(32)
        (alen,) = struct.unpack("!H", b.read(2))
        abytes = io.BytesIO(b.read(alen))
        na.addresses = []
        while True:
            addr = Address.from_bytes(abytes)
            if addr is None:
                break
            else:
                na.addresses.append(addr)
        return na

    def __str__(self):
        return f"NodeAnnouncement(id={hexlify(self.node_id)}, alias={self.alias}, color={self.rgb_color})"

    def __eq__(self, other):
        return (
            self.features == other.features
            and self.timestamp == other.timestamp
            and self.node_id == other.node_id
            and self.rgb_color == other.rgb_color
            and self.alias == other.alias
        )


class Address(object):
    def __init__(self, typ=None, addr=None, port=None):
        self.typ = typ
        self.addr = addr
        self.port = port

    @classmethod
    def from_bytes(cls, b: io.BytesIO) -> "Address":
        a = cls()

        t = b.read(1)
        if len(t) != 1:
            return None
        (a.typ,) = struct.unpack("!B", t)

        if a.typ == 1:
            a.addr = b.read(4)
        elif a.typ == 2:
            a.addr = b.read(16)
        elif a.typ == 3:
            a.addr = b.read(10)
        elif a.typ == 4:
            a.addr = b.read(35)
        else:
            print(f"Unknown address type {a.typ}")
            return None
        (a.port,) = struct.unpack("!H", b.read(2))
        return a

    def __eq__(self, other):
        return (
            self.typ == other.typ
            and self.addr == other.addr
            and self.port == other.port
        )

    def __len__(self):
        l = {
            1: 6,
            2: 18,
            3: 12,
            4: 37,
        }
        return l[self.typ] + 1

    def __str__(self):
        addr = self.addr
        if self.typ == 1:
            addr = ".".join([str(c) for c in addr])

        protos = {
            1: "ipv4",
            2: "ipv6",
            3: "torv2",
            4: "torv3",
        }

        return f"{protos[self.typ]}://{addr}:{self.port}"


class ChannelUpdate(object):
    def __init__(self):
        self.signature = None
        self.chain_hash = None
        self.num_short_channel_id = None
        self.timestamp = None
        self.message_flags = None
        self.channel_flags = None
        self.cltv_expiry_delta = None
        self.htlc_minimum_msat = None
        self.fee_base_msat = None
        self.fee_proportional_millionths = None
        self.htlc_maximum_msat = None

    @classmethod
    def from_bytes(cls, b: io.BytesIO) -> "ChannelUpdate":
        cu = ChannelUpdate()
        cu.signature = b.read(64)
        cu.chain_hash = b.read(32)[::-1]
        (cu.num_short_channel_id,) = struct.unpack("!Q", b.read(8))
        (cu.timestamp,) = struct.unpack("!I", b.read(4))
        cu.message_flags = b.read(1)
        cu.channel_flags = b.read(1)
        (cu.cltv_expiry_delta,) = struct.unpack("!H", b.read(2))
        (cu.htlc_minimum_msat,) = struct.unpack("!Q", b.read(8))
        (cu.fee_base_msat,) = struct.unpack("!I", b.read(4))
        (cu.fee_proportional_millionths,) = struct.unpack("!I", b.read(4))
        (cu.htlc_maximum_msat,) = struct.unpack("!Q", b.read(8))

        return cu

    @property
    def short_channel_id(self):
        return "{}x{}x{}".format(
            (self.num_short_channel_id >> 40) & 0xFFFFFF,
            (self.num_short_channel_id >> 16) & 0xFFFFFF,
            (self.num_short_channel_id >> 00) & 0xFFFF,
        )

    @property
    def direction(self):
        (b,) = struct.unpack("!B", self.channel_flags)
        return b & 0x01

    def serialize(self):
        raise ValueError()

    def __str__(self):
        return "ChannelUpdate(scid={short_channel_id}, timestamp={timestamp})".format(
            timestamp=self.timestamp, short_channel_id=self.short_channel_id
        )

    def __eq__(self, other):
        return (
            self.chain_hash == other.chain_hash
            and self.num_short_channel_id == other.num_short_channel_id
            and self.timestamp == other.timestamp
            and self.message_flags == other.message_flags
            and self.channel_flags == other.channel_flags
            and self.cltv_expiry_delta == other.cltv_expiry_delta
            and self.htlc_minimum_msat == other.htlc_minimum_msat
            and self.fee_base_msat == other.fee_base_msat
            and self.fee_proportional_millionths == other.fee_proportional_millionths
            and self.htlc_maximum_msat == other.htlc_maximum_msat
        )


class LocalChannelAnnouncement(object):
    def __init__(self):
        self.inner = None
        self.satoshis = None

    @classmethod
    def from_bytes(cls, b: io.BytesIO) -> "LocalChannelAnnouncement":
        lca = LocalChannelAnnouncement()
        (lca.satoshis,) = struct.unpack("!Q", b.read(8))
        b.read(4)  # Skip length prefix
        lca.inner = ChannelAnnouncement.from_bytes(b)
        return lca

    def __str__(self):
        return f"LocalChannelAnnouncement[satoshis={self.satoshis},inner={self.inner}]"


class LocalChannelUpdate(object):
    def __init__(self):
        self.inner = None

    @classmethod
    def from_bytes(cls, b: io.BytesIO) -> "LocalChannelUpdate":
        b.read(2)  # Skip length prefix
        lcu = LocalChannelUpdate()
        lcu.inner = ChannelUpdate.from_bytes(b)
        return lcu

    def __str__(self):
        return f"LocalChannelUpdate[inner={self.inner}]"


def test_gossip_store():
    from binascii import unhexlify

    a = io.BytesIO(
        unhexlify(
            "09000001bc55786b7f00000000100800000000000f315901b0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f4101dd37cfe5d2c2022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d590266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f000001bc0209e6ea00000000100800000000000f315901b0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f80294ac02207027d022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d590266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0000008eb7783081000000001006008a01022924a3f31a937ddf122181b7e9753316b66330afd88ab297d82efb4d4d7065de5e2dd9a234a9f3c6604ca2027f6a2d2d752d795cf915eea6ab40765e6d20cf4206226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f80294ac02207027d628e5c04010100060000000000000000000000010000000a000000003ac0d9080000008ece416a0a000000001006008a010207a76fac2089f27cd3b088291930bc1c95d739e01fea38fbbc6d2712b112579f34b8320f566155eb1cb7d34f2f2114d4004b3c6200f706c882a5659f16a16f0406226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f4101dd37cfe5d2c2628e5c04010000060000000000000000000000010000000a000000003ac0d908"
        )
    )

    a.read(1)
    a.read(12)
    assert a.read(2) == b"\x10\x08"

    ca = LocalChannelAnnouncement.from_bytes(a)
    print(ca)
    a.read(12)
    assert a.read(2) == b"\x10\x08"
    ca = LocalChannelAnnouncement.from_bytes(a)
    print(ca)

    a.read(12)
    assert a.read(2) == b"\x10\x06"
    cu = LocalChannelUpdate.from_bytes(a)
    print(cu)

    a.read(12)
    assert a.read(2) == b"\x10\x06"
    cu = LocalChannelUpdate.from_bytes(a)
    print(cu)
