from binascii import unhexlify
from pyln.proto.primitives import ShortChannelId
import pytest


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


def test_short_channel_id_from_str_bounds():
    scid = ShortChannelId.from_str('16777215x16777215x65535')
    assert scid == ShortChannelId(block=0xFFFFFF, txnum=0xFFFFFF, outnum=0xFFFF)
    assert ShortChannelId.from_int(scid.to_int()) == scid

    # Out of range elements used to spill into the next field, so
    # e.g. '1x0x65536' had the same to_int() as '1x1x0'.
    for bad in ['16777216x0x0', '0x16777216x0', '1x0x65536', '1x-1x0',
                '1x2', '1x2x3x4']:
        with pytest.raises(ValueError):
            ShortChannelId.from_str(bad)
