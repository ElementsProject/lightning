import bitstring  # type: ignore


zbase32_chars = b'ybndrfg8ejkmcpqxot1uwisza345h769'
zbase32_revchars = [
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 18, 255, 25, 26, 27, 30, 29, 7, 31, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 24, 1, 12, 3, 8, 5, 6, 28, 21, 9, 10, 255, 11, 2,
    16, 13, 14, 4, 22, 17, 19, 255, 20, 15, 0, 23, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255
]


def _message_to_bitarray(message):
    barr = bitstring.ConstBitStream(message)
    padding_len = 5 - (len(barr) % 5)
    if padding_len < 5:
        # The bitarray length has to be multiple of 5. If not, it is right-padded with zeros.
        barr = bitstring.ConstBitStream(bin="{}{}".format(barr.bin, '0' * padding_len))
    return barr


def _bitarray_to_message(barr):
    padding_len = len(barr) % 8
    if padding_len > 0:
        return bitstring.Bits(bin=barr.bin[:-padding_len]).bytes
    else:
        return barr.bytes


def _bitarray_to_u5(barr):
    ret = []
    while barr.pos != barr.len:
        ret.append(barr.read(5).uint)
    return ret


def _u5_to_bitarray(arr):
    ret = bitstring.BitArray()
    for a in arr:
        ret += bitstring.pack("uint:5", a)
    return ret


def is_zbase32_encoded(message):
    if isinstance(message, str):
        message = message.encode("ASCII")
    elif not isinstance(message, bytes):
        raise TypeError("message must be string or bytes")
    return set(message).issubset(zbase32_chars)


def encode(message):
    if isinstance(message, str):
        message = message.encode('ASCII')
    elif not isinstance(message, bytes):
        raise TypeError("message must be string or bytes")

    barr = _message_to_bitarray(message)
    uint5s = _bitarray_to_u5(barr)
    res = [zbase32_chars[c] for c in uint5s]
    return bytes(res)


def decode(message):
    if isinstance(message, str):
        message = message.encode('ASCII')
    elif not isinstance(message, bytes):
        raise TypeError("message must be string or bytes")

    if not is_zbase32_encoded(message):
        raise ValueError("message is not zbase32 encoded")

    uint5s = []
    for c in message:
        uint5s.append(zbase32_revchars[c])
    dec = _u5_to_bitarray(uint5s)
    return _bitarray_to_message(dec)
