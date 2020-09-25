from .bech32 import bech32_encode, bech32_decode, CHARSET
from binascii import hexlify, unhexlify
from decimal import Decimal
from io import BufferedReader, BytesIO
import base58
import bitstring
import hashlib
import re
import coincurve
import time
import struct


# BOLT #11:
#
# A writer MUST encode `amount` as a positive decimal integer with no
# leading zeroes, SHOULD use the shortest representation possible.
def shorten_amount(amount):
    """ Given an amount in bitcoin, shorten it
    """
    # Convert to pico initially
    amount = int(amount * 10**12)
    units = ['p', 'n', 'u', 'm', '']
    for unit in units:
        if amount % 1000 == 0:
            amount //= 1000
        else:
            break
    return str(amount) + unit


def unshorten_amount(amount):
    """ Given a shortened amount, convert it into a decimal
    """
    # BOLT #11:
    # The following `multiplier` letters are defined:
    #
    # * `m` (milli): multiply by 0.001
    # * `u` (micro): multiply by 0.000001
    # * `n` (nano): multiply by 0.000000001
    # * `p` (pico): multiply by 0.000000000001
    units = {
        'p': 10**12,
        'n': 10**9,
        'u': 10**6,
        'm': 10**3,
    }
    unit = str(amount)[-1]
    # BOLT #11:
    # A reader SHOULD fail if `amount` contains a non-digit, or is followed by
    # anything except a `multiplier` in the table above.
    if not re.fullmatch(r'\d+[pnum]?', str(amount)):
        raise ValueError("Invalid amount '{}'".format(amount))

    if unit in units.keys():
        return Decimal(amount[:-1]) / units[unit]
    else:
        return Decimal(amount)


# Bech32 spits out array of 5-bit values.  Shim here.
def u5_to_bitarray(arr: bytes):
    ret = bitstring.BitArray()
    for a in arr:
        ret += bitstring.pack("uint:5", a)
    return ret


def bitarray_to_u5(barr) -> bytes:
    assert barr.len % 5 == 0
    ret = []
    s = bitstring.ConstBitStream(barr)
    while s.pos != s.len:
        ret.append(s.read(5).uint)
    return bytes(ret)


def encode_fallback(fallback, currency):
    """ Encode all supported fallback addresses.
    """
    if currency == 'bc' or currency == 'tb':
        fbhrp, witness = bech32_decode(fallback)
        if fbhrp:
            if fbhrp != currency:
                raise ValueError("Not a bech32 address for this currency")
            wver = witness[0]
            if wver > 16:
                raise ValueError("Invalid witness version {}".format(witness[0]))
            wprog = u5_to_bitarray(witness[1:])
        else:
            addr = base58.b58decode_check(fallback)
            if is_p2pkh(currency, addr[0]):
                wver = 17
            elif is_p2sh(currency, addr[0]):
                wver = 18
            else:
                raise ValueError("Unknown address type for {}".format(currency))
            wprog = addr[1:]
        return tagged('f', bitstring.pack("uint:5", wver) + wprog)
    else:
        raise NotImplementedError("Support for currency {} not implemented".format(currency))


def parse_fallback(fallback, currency):
    if currency == 'bc' or currency == 'tb':
        wver = fallback[0:5].uint
        if wver == 17:
            addr = base58.b58encode_check(bytes([base58_prefix_map[currency][0]])
                                          + fallback[5:].tobytes())
        elif wver == 18:
            addr = base58.b58encode_check(bytes([base58_prefix_map[currency][1]])
                                          + fallback[5:].tobytes())
        elif wver <= 16:
            addr = bech32_encode(currency, bitarray_to_u5(fallback))
        else:
            return None
    else:
        addr = fallback.tobytes()
    return addr


# Map of classical and witness address prefixes
base58_prefix_map = {
    'bc': (0, 5),
    'tb': (111, 196)
}


def is_p2pkh(currency, prefix):
    return prefix == base58_prefix_map[currency][0]


def is_p2sh(currency, prefix):
    return prefix == base58_prefix_map[currency][1]


# Tagged field containing BitArray
def tagged(char, l):
    # Tagged fields need to be zero-padded to 5 bits.
    while l.len % 5 != 0:
        l.append('0b0')
    return bitstring.pack("uint:5, uint:5, uint:5",
                          CHARSET.find(char),
                          (l.len / 5) / 32, (l.len / 5) % 32) + l


# Tagged field containing bytes
def tagged_bytes(char, l):
    return tagged(char, bitstring.BitArray(l))


# Discard trailing bits, convert to bytes.
def trim_to_bytes(barr):
    # Adds a byte if necessary.
    b = barr.tobytes()
    if barr.len % 8 != 0:
        return b[:-1]
    return b


# Try to pull out tagged data: returns tag, tagged data and remainder.
def pull_tagged(stream):
    tag = stream.read(5).uint
    length = stream.read(5).uint * 32 + stream.read(5).uint
    return (CHARSET[tag], stream.read(length * 5), stream)


class Invoice(object):
    def __init__(self, paymenthash=None, amount=None, currency='bc', tags=None, date=None):
        self.date = int(time.time()) if not date else int(date)
        self.tags = [] if not tags else tags
        self.unknown_tags = []
        self.paymenthash = paymenthash
        self.signature = None
        self.pubkey = None
        self.currency = currency
        self.amount = amount
        self.min_final_cltv_expiry = None
        self.route_hints = None

    def __str__(self):
        return "Invoice[{}, amount={}{} tags=[{}]]".format(
            hexlify(self.pubkey.format()).decode('utf-8'),
            self.amount, self.currency,
            ", ".join([k + '=' + str(v) for k, v in self.tags])
        )

    @property
    def hexpubkey(self):
        return hexlify(self.pubkey.format()).decode('ASCII')

    @property
    def hexpaymenthash(self):
        return hexlify(self.paymenthash).decode('ASCII')

    def _get_tagged(self, tag):
        return [t[1] for t in self.tags + self.unknown_tags if t[0] == tag]

    @property
    def featurebits(self):
        features = self._get_tagged('9')
        assert(len(features) <= 1)
        if features == []:
            return 0
        else:
            return features[0]

    def encode(self, privkey):
        if self.amount:
            amount = Decimal(str(self.amount))
            # We can only send down to millisatoshi.
            if amount * 10**12 % 10:
                raise ValueError("Cannot encode {}: too many decimal places".format(
                    self.amount))

            amount = self.currency + shorten_amount(amount)
        else:
            amount = self.currency if self.currency else ''

        hrp = 'ln' + amount

        # Start with the timestamp
        data = bitstring.pack('uint:35', self.date)

        # Payment hash
        data += tagged_bytes('p', self.paymenthash)
        tags_set = set()

        if self.route_hints is not None:
            for rh in self.route_hints.route_hints:
                data += tagged_bytes('r', rh.to_bytes())

        for k, v in self.tags:

            # BOLT #11:
            #
            # A writer MUST NOT include more than one `d`, `h`, `n` or `x` fields,
            if k in ('d', 'h', 'n', 'x'):
                if k in tags_set:
                    raise ValueError("Duplicate '{}' tag".format(k))

            if k == 'r':
                pubkey, channel, fee, cltv = v
                route = bitstring.BitArray(pubkey) + bitstring.BitArray(channel) + bitstring.pack('intbe:64', fee) + bitstring.pack('intbe:16', cltv)
                data += tagged('r', route)
            elif k == 'f':
                data += encode_fallback(v, self.currency)
            elif k == 'd':
                data += tagged_bytes('d', v.encode())
            elif k == 'x':
                # Get minimal length by trimming leading 5 bits at a time.
                expirybits = bitstring.pack('intbe:64', v)[4:64]
                while expirybits.startswith('0b00000'):
                    expirybits = expirybits[5:]
                data += tagged('x', expirybits)
            elif k == 'h':
                data += tagged_bytes('h', hashlib.sha256(v.encode('utf-8')).digest())
            elif k == 'n':
                data += tagged_bytes('n', v)
            else:
                # FIXME: Support unknown tags?
                raise ValueError("Unknown tag {}".format(k))

            tags_set.add(k)

        # BOLT #11:
        #
        # A writer MUST include either a `d` or `h` field, and MUST NOT include
        # both.
        if 'd' in tags_set and 'h' in tags_set:
            raise ValueError("Cannot include both 'd' and 'h'")
        if 'd' not in tags_set and 'h' not in tags_set:
            raise ValueError("Must include either 'd' or 'h'")

        # We actually sign the hrp, then data (padded to 8 bits with zeroes).
        privkey = coincurve.PrivateKey(secret=bytes(unhexlify(privkey)))
        data += privkey.sign_recoverable(bytearray([ord(c) for c in hrp]) + data.tobytes())

        return bech32_encode(hrp, bitarray_to_u5(data))

    @classmethod
    def decode(cls, b):
        hrp, data = bech32_decode(b)
        if not hrp:
            raise ValueError("Bad bech32 checksum")

        # BOLT #11:
        #
        # A reader MUST fail if it does not understand the `prefix`.
        if not hrp.startswith('ln'):
            raise ValueError("Does not start with ln")

        data = u5_to_bitarray(data)

        # Final signature 65 bytes, split it off.
        if len(data) < 65 * 8:
            raise ValueError("Too short to contain signature")
        sigdecoded = data[-65 * 8:].tobytes()
        data = bitstring.ConstBitStream(data[:-65 * 8])

        inv = Invoice()
        inv.pubkey = None

        m = re.search(r'[^\d]+', hrp[2:])
        if m:
            inv.currency = m.group(0)
            amountstr = hrp[2 + m.end():]
            # BOLT #11:
            #
            # A reader SHOULD indicate if amount is unspecified, otherwise it MUST
            # multiply `amount` by the `multiplier` value (if any) to derive the
            # amount required for payment.
            if amountstr != '':
                inv.amount = unshorten_amount(amountstr)

        inv.date = data.read(35).uint

        while data.pos != data.len:
            tag, tagdata, data = pull_tagged(data)

            # BOLT #11:
            #
            # A reader MUST skip over unknown fields, an `f` field with unknown
            # `version`, or a `p`, `h`, `n` or `r` field which does not have
            # `data_length` 52, 52, 53 or 82 respectively.
            data_length = len(tagdata) / 5

            if tag == 'r':
                inv.route_hints = RouteHintSet.from_bytes(trim_to_bytes(tagdata))
                continue
                if data_length != 82:
                    inv.unknown_tags.append((tag, tagdata))
                    continue

                tagbytes = trim_to_bytes(tagdata)

                inv.tags.append(('r', (
                    tagbytes[0:33],
                    tagbytes[33:41],
                    tagdata[41 * 8:49 * 8].intbe,
                    tagdata[49 * 8:51 * 8].intbe
                )))
            elif tag == 'f':
                fallback = parse_fallback(tagdata, inv.currency)
                if fallback:
                    inv.tags.append(('f', fallback))
                else:
                    # Incorrect version.
                    inv.unknown_tags.append((tag, tagdata))
                    continue

            elif tag == 'd':
                inv.tags.append(('d', trim_to_bytes(tagdata).decode('utf-8')))

            elif tag == 'h':
                if data_length != 52:
                    inv.unknown_tags.append((tag, tagdata))
                    continue
                inv.tags.append(('h', trim_to_bytes(tagdata)))

            elif tag == 'x':
                inv.tags.append(('x', tagdata.uint))

            elif tag == 'p':
                if data_length != 52:
                    inv.unknown_tags.append((tag, tagdata))
                    continue
                inv.paymenthash = trim_to_bytes(tagdata)

            elif tag == 'n':
                if data_length != 53:
                    inv.unknown_tags.append((tag, tagdata))
                    continue
                inv.pubkey = coincurve.PublicKey(trim_to_bytes(tagdata))

            elif tag == 'c':
                inv.min_final_cltv_expiry = tagdata.uint
            else:
                inv.unknown_tags.append((tag, tagdata))

        # BOLT #11:
        #
        # A reader MUST check that the `signature` is valid (see the `n` tagged
        # field specified below).
        if inv.pubkey:  # Specified by `n`
            # BOLT #11:
            #
            # A reader MUST use the `n` field to validate the signature instead of
            # performing signature recovery if a valid `n` field is provided.
            inv.signature = inv.pubkey.ecdsa_deserialize_compact(sigdecoded[0:64])
            if not inv.pubkey.ecdsa_verify(bytearray([ord(c) for c in hrp]) + data.tobytes(), inv.signature):
                raise ValueError('Invalid signature')
        else:  # Recover pubkey from signature.
            inv.signature = coincurve.ecdsa.deserialize_recoverable(
                sigdecoded[0:65])
            inv.pubkey = coincurve.PublicKey.from_signature_and_message(
                sigdecoded[0:65],
                bytearray([ord(c) for c in hrp]) + data.tobytes())

        return inv


class RouteHint(object):
    length = 33 + 8 + 4 + 4 + 2

    def __init__(self):
        self.pubkey = None
        self.short_channel_id = None
        self.fee_base_msat = None
        self.fee_proportional_millionths = None
        self.cltv_expiry_delta = None

    @classmethod
    def from_bytes(cls, b):
        inst = RouteHint()

        inst.pubkey = b.read(33)

        inst.short_channel_id, = struct.unpack("!Q", b.read(8))
        inst.fee_base_msat, inst.fee_proportional_millionths, inst.cltv_expiry_delta = struct.unpack("!IIH", b.read(10))
        return inst

    def to_bytes(self):
        return self.pubkey + struct.pack(
            "!QIIH", self.short_channel_id, self.fee_base_msat,
            self.fee_proportional_millionths, self.cltv_expiry_delta
        )

    def __str__(self):
        pubkey = hexlify(self.pubkey).decode('ASCII')
        return f"RouteHint<pubkey={pubkey}, short_channel_id={self.short_channel_id}, fee_base_msat={self.fee_base_msat}, fee_prop={self.fee_proportional_millionths}, cltv_expiry_delta={self.cltv_expiry_delta}>"


class RouteHintSet(object):
    def __init__(self):
        self.route_hints = []

    @classmethod
    def from_bytes(cls, b):
        if isinstance(b, bytes):
            b = BufferedReader(BytesIO(b))

        if not isinstance(b, BufferedReader):
            raise TypeError('from_bytes can only read from bytes-arrays or BufferedReader')

        if len(b.raw.getvalue()) % RouteHint.length != 0:
            raise TypeError("byte string is not a multiple of the route hint size: {}".format(
                len(b.raw.getvalue())
            ))

        instance = RouteHintSet()
        while b.peek():
            instance.route_hints.append(RouteHint.from_bytes(b))

        return instance

    def to_bytes(self):
        return b''.join([rh.to_bytes() for rh in self.route_hints])

    def __str__(self):
        return "RouteHintSet[{}]".format(
            ", ".join([str(rh) for rh in self.route_hints])
        )

    def add(self, rh: RouteHint):
        self.route_hints.append(rh)
