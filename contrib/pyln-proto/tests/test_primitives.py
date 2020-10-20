from binascii import unhexlify
from pyln.proto.primitives import ShortChannelId


def test_short_channel_id():
    num = 618150934845652992
    b = unhexlify(b'08941d00090d0000')
    s = '562205x2317x0'
    s1 = ShortChannelId.from_int(num)
    s2 = ShortChannelId.from_str(s)
    s3 = ShortChannelId.from_bytes(b)
    expected = ShortChannelId(block=562205, txnum=2317, outnum=0)

    assert(s1 == expected)
    assert(s2 == expected)
    assert(s3 == expected)

    assert(expected.to_bytes() == b)
    assert(str(expected) == s)
    assert(expected.to_int() == num)
