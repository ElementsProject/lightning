#! /usr/bin/python3
import struct


def split_field(s):
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
    def __init__(self, name):
        self.name = name

    def only_at_tlv_end(self):
        """Some types only make sense inside a tlv, at the end"""
        return False

    def name_and_val(self, name, v):
        """This is overridden by LengthFieldType to return nothing"""
        return " {}={}".format(name, self.val_to_str(v, None))

    def is_optional(self):
        """Overridden for tlv fields and optional fields"""
        return False

    def len_fields_bad(self, fieldname, fieldvals):
        """Overridden by length fields for arrays"""
        return []

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class IntegerType(FieldType):
    def __init__(self, name, bytelen, structfmt):
        super().__init__(name)
        self.bytelen = bytelen
        self.structfmt = structfmt

    def val_to_str(self, v, otherfields):
        return "{}".format(int(v))

    def val_from_str(self, s):
        a, b = split_field(s)
        return int(a), b

    def val_to_bin(self, v, otherfields):
        return struct.pack(self.structfmt, v)

    def val_from_bin(self, bytestream, otherfields):
        "Returns value, bytesused"
        if self.bytelen > len(bytestream):
            raise ValueError('{}: not enough remaining to read'.format(self))
        return struct.unpack_from(self.structfmt,
                                  bytestream)[0], self.bytelen


class ShortChannelIDType(IntegerType):
    """short_channel_id has a special string representation, but is
basically a u64.

    """
    def __init__(self, name):
        super().__init__(name, 8, '>Q')

    def val_to_str(self, v, otherfields):
        # See BOLT #7: ## Definition of `short_channel_id`
        return "{}x{}x{}".format(v >> 40, (v >> 16) & 0xFFFFFF, v & 0xFFFF)

    def val_from_str(self, s):
        a, b = split_field(s)
        parts = a.split('x')
        if len(parts) != 3:
            raise ValueError("short_channel_id should be NxNxN")
        return ((int(parts[0]) << 40)
                | (int(parts[1]) << 16)
                | (int(parts[2]))), b


class TruncatedIntType(FieldType):
    """Truncated integer types"""
    def __init__(self, name, maxbytes):
        super().__init__(name)
        self.maxbytes = maxbytes

    def val_to_str(self, v, otherfields):
        return "{}".format(int(v))

    def only_at_tlv_end(self):
        """These only make sense at the end of a TLV"""
        return True

    def val_from_str(self, s):
        a, b = split_field(s)
        if int(a) >= (1 << (self.maxbytes * 8)):
            raise ValueError('{} exceeds maximum {} capacity'
                             .format(a, self.name))
        return int(a), b

    def val_to_bin(self, v, otherfields):
        binval = struct.pack('>Q', v)
        while len(binval) != 0 and binval[0] == 0:
            binval = binval[1:]
        if len(binval) > self.maxbytes:
            raise ValueError('{} exceeds maximum {} capacity'
                             .format(v, self.name))
        return binval

    def val_from_bin(self, bytestream, otherfields):
        "Returns value, bytesused"
        binval = bytes()
        while len(binval) < len(bytestream):
            if len(binval) == 0 and bytestream[len(binval)] == 0:
                raise ValueError('{} encoding is not minimal: {}'
                                 .format(self.name, bytestream))
            binval += bytes([bytestream[len(binval)]])

        if len(binval) > self.maxbytes:
            raise ValueError('{} is too long for {}'.format(binval, self.name))

        # Pad with zeroes and convert as u64
        return (struct.unpack_from('>Q', bytes(8 - len(binval)) + binval)[0],
                len(binval))


class FundamentalHexType(FieldType):
    """The remaining fundamental types are simply represented as hex strings"""
    def __init__(self, name, bytelen):
        super().__init__(name)
        self.bytelen = bytelen

    def val_to_str(self, v, otherfields):
        if len(bytes(v)) != self.bytelen:
            raise ValueError("Length of {} != {}", v, self.bytelen)
        return v.hex()

    def val_from_str(self, s):
        a, b = split_field(s)
        ret = bytes.fromhex(a)
        if len(ret) != self.bytelen:
            raise ValueError("Length of {} != {}", a, self.bytelen)
        return ret, b

    def val_to_bin(self, v, otherfields):
        if len(bytes(v)) != self.bytelen:
            raise ValueError("Length of {} != {}", v, self.bytelen)
        return bytes(v)

    def val_from_bin(self, bytestream, otherfields):
        "Returns value, size from bytestream"
        if self.bytelen > len(bytestream):
            raise ValueError('{}: not enough remaining'.format(self))
        return bytestream[:self.bytelen], self.bytelen


class BigSizeType(FieldType):
    """BigSize type, mainly used to encode TLV headers"""
    def __init__(self, name):
        super().__init__(name)

    def val_from_str(self, s):
        a, b = split_field(s)
        return int(a), b

    # For the convenience of TLV header parsing
    @staticmethod
    def to_bin(v):
        if v < 253:
            return bytes([v])
        elif v < 2**16:
            return bytes([253]) + struct.pack('>H', v)
        elif v < 2**32:
            return bytes([254]) + struct.pack('>I', v)
        else:
            return bytes([255]) + struct.pack('>Q', v)

    @staticmethod
    def from_bin(bytestream):
        "Returns value, bytesused"
        if bytestream[0] < 253:
            return int(bytestream[0]), 1
        elif bytestream[0] == 253:
            return struct.unpack_from('>H', bytestream[1:])[0], 3
        elif bytestream[0] == 254:
            return struct.unpack_from('>I', bytestream[1:])[0], 5
        else:
            return struct.unpack_from('>Q', bytestream[1:])[0], 9

    def val_to_str(self, v, otherfields):
        return "{}".format(int(v))

    def val_to_bin(self, v, otherfields):
        return self.to_bin(v)

    def val_from_bin(self, bytestream, otherfields):
        return self.from_bin(bytestream)


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
            ]
