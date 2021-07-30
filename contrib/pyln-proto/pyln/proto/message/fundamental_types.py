import struct
from io import BufferedIOBase
import sys
from typing import Dict, Optional, Tuple, List, Any


def try_unpack(name: str,
               io_out: BufferedIOBase,
               structfmt: str,
               empty_ok: bool) -> Optional[int]:
    """Unpack a single value using struct.unpack.

If need_all, never return None, otherwise returns None if EOF."""
    b = io_out.read(struct.calcsize(structfmt))
    if len(b) == 0 and empty_ok:
        return None
    elif len(b) < struct.calcsize(structfmt):
        raise ValueError("{}: not enough bytes", name)

    return struct.unpack(structfmt, b)[0]


def split_field(s: str) -> Tuple[str, str]:
    """Helper to split string into first part and remainder"""
    def len_without(s, delim):
        pos = s.find(delim)
        if pos == -1:
            return len(s)
        return pos

    firstlen = min([len_without(s, d) for d in (',', '}', ']')])
    return s[:firstlen], s[firstlen:]


class FieldType(object):
    """A (abstract) class representing the underlying type of a field.
These are further specialized.

    """
    def __init__(self, name: str):
        self.name = name

    def only_at_tlv_end(self) -> bool:
        """Some types only make sense inside a tlv, at the end"""
        return False

    def name_and_val(self, name: str, v: Any) -> str:
        """This is overridden by LengthFieldType to return nothing"""
        return " {}={}".format(name, self.val_to_str(v, {}))

    def is_optional(self) -> bool:
        """Overridden for tlv fields and optional fields"""
        return False

    def len_fields_bad(self, fieldname: str, fieldvals: Dict[str, Any]) -> List[str]:
        """Overridden by length fields for arrays"""
        return []

    def val_to_str(self, v: Any, otherfields: Dict[str, Any]) -> str:
        raise NotImplementedError()

    def val_from_str(self, s: str) -> Tuple[Any, str]:
        raise NotImplementedError()

    def write(self, io_out: BufferedIOBase, v: Any, otherfields: Dict[str, Any]) -> None:
        raise NotImplementedError()

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> Any:
        raise NotImplementedError()

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> Any:
        """Convert to a python object: for simple fields, this means a string"""
        return self.val_to_str(v, otherfields)

    def __str__(self):
        return self.name

    def __repr__(self):
        return 'FieldType({})'.format(self.name)


class IntegerType(FieldType):
    def __init__(self, name: str, bytelen: int, structfmt: str):
        super().__init__(name)
        self.bytelen = bytelen
        self.structfmt = structfmt

    def val_to_str(self, v: int, otherfields: Dict[str, Any]):
        return "{}".format(int(v))

    def val_from_str(self, s: str) -> Tuple[int, str]:
        a, b = split_field(s)
        return int(a), b

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> Any:
        """Convert to a python object: for integer fields, this means an int"""
        return int(v)

    def write(self, io_out: BufferedIOBase, v: int, otherfields: Dict[str, Any]) -> None:
        io_out.write(struct.pack(self.structfmt, v))

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> Optional[int]:
        return try_unpack(self.name, io_in, self.structfmt, empty_ok=True)


class ShortChannelIDType(IntegerType):
    """short_channel_id has a special string representation, but is
basically a u64.

    """
    def __init__(self, name):
        super().__init__(name, 8, '>Q')

    def val_to_str(self, v: int, otherfields: Dict[str, Any]) -> str:
        # See BOLT #7: ## Definition of `short_channel_id`
        return "{}x{}x{}".format(v >> 40, (v >> 16) & 0xFFFFFF, v & 0xFFFF)

    def val_from_str(self, s: str) -> Tuple[int, str]:
        a, b = split_field(s)
        parts = a.split('x')
        if len(parts) != 3:
            raise ValueError("short_channel_id should be NxNxN")
        return ((int(parts[0]) << 40)
                | (int(parts[1]) << 16)
                | (int(parts[2]))), b

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> str:
        # Unlike a normal int, this returns a str.
        return self.val_to_str(v, otherfields)


class TruncatedIntType(FieldType):
    """Truncated integer types"""
    def __init__(self, name: str, maxbytes: int):
        super().__init__(name)
        self.maxbytes = maxbytes

    def val_to_str(self, v: int, otherfields: Dict[str, Any]) -> str:
        return "{}".format(int(v))

    def only_at_tlv_end(self) -> bool:
        """These only make sense at the end of a TLV"""
        return True

    def val_from_str(self, s: str) -> Tuple[int, str]:
        a, b = split_field(s)
        if int(a) >= (1 << (self.maxbytes * 8)):
            raise ValueError('{} exceeds maximum {} capacity'
                             .format(a, self.name))
        return int(a), b

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> int:
        """Convert to a python object: for integer fields, this means an int"""
        return int(v)

    def write(self, io_out: BufferedIOBase, v: int, otherfields: Dict[str, Any]) -> None:
        binval = struct.pack('>Q', v)
        while len(binval) != 0 and binval[0] == 0:
            binval = binval[1:]
        if len(binval) > self.maxbytes:
            raise ValueError('{} exceeds maximum {} capacity'
                             .format(v, self.name))
        io_out.write(binval)

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> None:
        binval = io_in.read()
        if len(binval) > self.maxbytes:
            raise ValueError('{} is too long for {}'.format(binval.hex(), self.name))
        if len(binval) > 0 and binval[0] == 0:
            raise ValueError('{} encoding is not minimal: {}'
                             .format(self.name, binval.hex()))
        # Pad with zeroes and convert as u64
        return struct.unpack_from('>Q', bytes(8 - len(binval)) + binval)[0]


class FundamentalHexType(FieldType):
    """The remaining fundamental types are simply represented as hex strings"""
    def __init__(self, name: str, bytelen: int):
        super().__init__(name)
        self.bytelen = bytelen

    def val_to_str(self, v: bytes, otherfields: Dict[str, Any]) -> str:
        if len(bytes(v)) != self.bytelen:
            raise ValueError("Length of {} != {}", v, self.bytelen)
        return v.hex()

    def val_from_str(self, s: str) -> Tuple[bytes, str]:
        a, b = split_field(s)
        ret = bytes.fromhex(a)
        if len(ret) != self.bytelen:
            raise ValueError("Length of {} != {}", a, self.bytelen)
        return ret, b

    def write(self, io_out: BufferedIOBase, v: bytes, otherfields: Dict[str, Any]) -> None:
        if len(bytes(v)) != self.bytelen:
            raise ValueError("Length of {} != {}", v, self.bytelen)
        io_out.write(v)

    def read(self, io_in: BufferedIOBase, otherfields: Dict[str, Any]) -> Optional[bytes]:
        val = io_in.read(self.bytelen)
        if len(val) == 0:
            return None
        elif len(val) != self.bytelen:
            raise ValueError('{}: not enough remaining'.format(self))
        return val


class BigSizeType(FieldType):
    """BigSize type, mainly used to encode TLV headers"""
    def __init__(self, name):
        super().__init__(name)

    def val_from_str(self, s: str) -> Tuple[int, str]:
        a, b = split_field(s)
        return int(a), b

    # For the convenience of TLV header parsing
    @staticmethod
    def write(io_out: BufferedIOBase, v: int, otherfields: Dict[str, Any] = {}) -> None:
        if v < 253:
            io_out.write(bytes([v]))
        elif v < 2**16:
            io_out.write(bytes([253]) + struct.pack('>H', v))
        elif v < 2**32:
            io_out.write(bytes([254]) + struct.pack('>I', v))
        else:
            io_out.write(bytes([255]) + struct.pack('>Q', v))

    @staticmethod
    def read(io_in: BufferedIOBase, otherfields: Dict[str, Any] = {}) -> Optional[int]:
        "Returns value, or None on EOF"
        b = io_in.read(1)
        if len(b) == 0:
            return None
        if b[0] < 253:
            return int(b[0])
        elif b[0] == 253:
            return try_unpack('BigSize', io_in, '>H', empty_ok=False)
        elif b[0] == 254:
            return try_unpack('BigSize', io_in, '>I', empty_ok=False)
        else:
            return try_unpack('BigSize', io_in, '>Q', empty_ok=False)

    def val_to_str(self, v: int, otherfields: Dict[str, Any]) -> str:
        return "{}".format(int(v))

    def val_to_py(self, v: Any, otherfields: Dict[str, Any]) -> int:
        """Convert to a python object: for integer fields, this means an int"""
        return int(v)


def fundamental_types() -> List[FieldType]:
    # BOLT #1:
    # Various fundamental types are referred to in the message specifications:
    #
    # * `byte`: an 8-bit byte
    # * `u16`: a 2 byte unsigned integer
    # * `u32`: a 4 byte unsigned integer
    # * `u64`: an 8 byte unsigned integer
    #
    # Inside TLV records which contain a single value, leading zeros in
    # integers can be omitted:
    #
    # * `tu16`: a 0 to 2 byte unsigned integer
    # * `tu32`: a 0 to 4 byte unsigned integer
    # * `tu64`: a 0 to 8 byte unsigned integer
    #
    # The following convenience types are also defined:
    #
    # * `chain_hash`: a 32-byte chain identifier (see [BOLT
    #   #0](00-introduction.md#glossary-and-terminology-guide))
    # * `channel_id`: a 32-byte channel_id (see [BOLT
    #   #2](02-peer-protocol.md#definition-of-channel-id))
    # * `sha256`: a 32-byte SHA2-256 hash
    # * `signature`: a 64-byte bitcoin Elliptic Curve signature
    # * `point`: a 33-byte Elliptic Curve point (compressed encoding as per
    #   [SEC 1 standard](http://www.secg.org/sec1-v2.pdf#subsubsection.2.3.3))
    # * `short_channel_id`: an 8 byte value identifying a channel (see [BOLT
    #   #7](07-routing-gossip.md#definition-of-short-channel-id))
    # * `bigsize`: a variable-length, unsigned integer similar to Bitcoin's
    #   CompactSize encoding, but big-endian.  Described in
    #   [BigSize](#appendix-a-bigsize-test-vectors).
    return [IntegerType('byte', 1, 'B'),
            IntegerType('u16', 2, '>H'),
            IntegerType('u32', 4, '>I'),
            IntegerType('u64', 8, '>Q'),
            TruncatedIntType('tu16', 2),
            TruncatedIntType('tu32', 4),
            TruncatedIntType('tu64', 8),
            FundamentalHexType('chain_hash', 32),
            FundamentalHexType('channel_id', 32),
            FundamentalHexType('sha256', 32),
            FundamentalHexType('point', 33),
            ShortChannelIDType('short_channel_id'),
            FundamentalHexType('signature', 64),
            BigSizeType('bigsize'),
            # Extra types added in offers draft:
            IntegerType('utf8', 1, 'B'),
            FundamentalHexType('bip340sig', 64),
            FundamentalHexType('point32', 32),
            ]


# Expose these as native types.
mod = sys.modules[FieldType.__module__]
for m in fundamental_types():
    setattr(mod, m.name, m)
