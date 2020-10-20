import pytest
import bitstring
from pyln.proto import zbase32

not_str_bytes = [1, dict(), None, 3.4, object()]
messages = [b'this', b'is', b'a', b'split', b'message:', b'lightning', b'rocks']
zbase32_messages = [b'qtwg1ha', b'pf3o', b'cr', b'qpaga4mw', b'pi1zgh5bc71uw', b'ptwsq4dwp3wsh3a', b'qjzsg45u']
not_zbase32_messages = ['00', '[]', 'vv', '1234']


def test_message_to_bitarray():
    # This is an internal function and the input is supposed to be bytes. Not testing unexpected inputs.
    dummy_messages = [b'a' * i for i in range(1, 6)]
    for message in dummy_messages:
        not_padded_barr = bitstring.Bits(message)
        barr = zbase32._message_to_bitarray(message)
        assert isinstance(barr, bitstring.ConstBitStream)

        for i in range(len(barr)):
            # Then first len(not_padded_barr) bits are equal
            if i < len(not_padded_barr):
                assert not_padded_barr.bin[i] == barr.bin[i]
            # The remaining are zeros
            else:
                assert barr.bin[i] == '0'


def test_bitarray_to_message():
    # This is an internal function and the input is supposed to be BitArray. Not testing unexpected inputs.
    dummy_messages = [b'b' * i for i in range(1, 6)]

    for message in dummy_messages:
        barr = bitstring.Bits(message)
        not_padded_message = zbase32._bitarray_to_message(bitstring.BitArray(message))
        assert isinstance(not_padded_message, bytes)

        not_padded_barr = bitstring.Bits(not_padded_message)
        for i in range(len(not_padded_barr)):
            # Then first len(pre_padded_barr) bits are equal
            if i < len(not_padded_barr):
                assert not_padded_barr.bin[i] == barr.bin[i]
            # The remaining are zeros
            else:
                assert barr.bin[i] == '0'


def test_bitarray_to_u5():
    # This is an internal function and the input is supposed to be ConstBitStream of length multiple of 5.
    # Not testing unexpected inputs.
    barrs = [zbase32._message_to_bitarray(message) for message in messages]

    for barr in barrs:
        u5 = zbase32._bitarray_to_u5(barr)
        assert isinstance(u5, list)
        assert all(x in range(0, 31) for x in u5)


def test_u5_to_bitarray():
    # This is an internal function and the input is supposed to be a list of ints 0-31. Not testing unexpected inputs.
    u5s = [[0, 1, 2, 3, 4, 5], [15, 30, 24, 17, 8, 3, 21], [0], [28, 11]]

    for u5 in u5s:
        bitarray = zbase32._u5_to_bitarray(u5)
        assert isinstance(bitarray, bitstring.BitArray)


def test_is_zbase32_encoded():
    for message in zbase32_messages:
        assert zbase32.is_zbase32_encoded(message)

    for message in not_zbase32_messages:
        assert not zbase32.is_zbase32_encoded(message)


def test_encode():
    message = '1f76e8acd54afbf23610b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d0205f7e4e1a12620e7fc8ce1c7d3651acefde899c33f12b6958d3304106a0'
    zbase32_message = b'd75qtmgijm79rpooshmgzjwji9gj7dsdat8remuskyjp9oq1ugkaoj6orbxzhuo4njtyh96e3aq84p1tiuz77nchgxa1s4ka4carnbiy'
    assert(zbase32.encode(bytes.fromhex(message)) == zbase32_message)

    for message, expected_zbase32_message in zip(messages, zbase32_messages):
        zbase32_message = zbase32.encode(message)
        assert isinstance(zbase32_message, bytes)
        assert zbase32_message == expected_zbase32_message


def test_encode_wrong_inputs():
    # Message must be either str or bytes, any other type will be rejected
    for m in not_str_bytes:
        with pytest.raises(TypeError, match='message must be string or bytes'):
            zbase32.encode(m)


def test_decode():
    zbase32_message = b'd75qtmgijm79rpooshmgzjwji9gj7dsdat8remuskyjp9oq1ugkaoj6orbxzhuo4njtyh96e3aq84p1tiuz77nchgxa1s4ka4carnbiy'
    message = '1f76e8acd54afbf23610b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d0205f7e4e1a12620e7fc8ce1c7d3651acefde899c33f12b6958d3304106a0'
    assert(zbase32.decode(zbase32_message) == bytes.fromhex(message))

    for expected_message, zbase32_message in zip(messages, zbase32_messages):
        message = zbase32.decode(zbase32_message)
        assert isinstance(message, bytes)
        assert message == expected_message


def test_decode_wrong_inputs():
    # Message must be either str or bytes, any other type will be rejected

    for m in not_str_bytes:
        with pytest.raises(TypeError, match='message must be string or bytes'):
            zbase32.decode(m)

    # Message must also be zbase32 encoded, otherwise it will be rejected
    for m in not_zbase32_messages:
        with pytest.raises(ValueError, match='message is not zbase32 encoded'):
            zbase32.decode(m)
