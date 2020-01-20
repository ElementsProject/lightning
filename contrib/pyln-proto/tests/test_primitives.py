from binascii import hexlify, unhexlify
from pyln.proto import zbase32
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


def test_zbase32():
    zb32 = b'd75qtmgijm79rpooshmgzjwji9gj7dsdat8remuskyjp9oq1ugkaoj6orbxzhuo4njtyh96e3aq84p1tiuz77nchgxa1s4ka4carnbiy'
    b = zbase32.decode(zb32)
    assert(hexlify(b) == b'1f76e8acd54afbf23610b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d0205f7e4e1a12620e7fc8ce1c7d3651acefde899c33f12b6958d3304106a0')

    enc = zbase32.encode(b)
    assert(enc == zb32)
