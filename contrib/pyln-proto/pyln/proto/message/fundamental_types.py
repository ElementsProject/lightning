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


def fundamental_types():
    # From 01-messaging.md#fundamental-types:
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
            # FIXME: See https://github.com/lightningnetwork/lightning-rfc/pull/778
            BigSizeType('varint'),
            # FIXME
            IntegerType('u8', 1, 'B'),
            ]


# Expose these as native types.
mod = sys.modules[FieldType.__module__]
for m in fundamental_types():
    setattr(mod, m.name, m)
