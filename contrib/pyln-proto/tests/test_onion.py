from binascii import unhexlify

from pyln.proto import onion


def test_legacy_payload():
    legacy = unhexlify(
        b'00000067000001000100000000000003e800000075000000000000000000000000'
    )
    payload = onion.OnionPayload.from_bytes(legacy)
    assert(payload.to_bytes(include_realm=True) == legacy)


def test_tlv_payload():
    tlv = unhexlify(
        b'58fe020c21160c48656c6c6f20776f726c6421fe020c21184076e8acd54afbf2361'
        b'0b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d0205f7e4e1a12620e'
        b'7fc8ce1c7d3651acefde899c33f12b6958d3304106a0'
    )
    payload = onion.OnionPayload.from_bytes(tlv)
    assert(payload.to_bytes() == tlv)

    fields = payload.fields
    assert(len(fields) == 2)
    assert(isinstance(fields[0], onion.TextField))
    assert(fields[0].typenum == 34349334 and fields[0].value == "Hello world!")
    assert(fields[1].typenum == 34349336 and fields[1].value == unhexlify(
        b'76e8acd54afbf23610b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d'
        b'0205f7e4e1a12620e7fc8ce1c7d3651acefde899c33f12b6958d3304106a0'
    ))

    assert(payload.to_bytes() == tlv)


def test_tu_fields():
    pairs = [
        (0, b'\x01\x01\x00'),
        (1 << 8, b'\x01\x02\x01\x00'),
        (1 << 16, b'\x01\x03\x01\x00\x00'),
        (1 << 24, b'\x01\x04\x01\x00\x00\x00'),
        ((1 << 32) - 1, b'\x01\x04\xFF\xFF\xFF\xFF'),
    ]

    # These should work for Tu32
    for i, o in pairs:
        f = onion.Tu32Field(1, i)
        assert(f.to_bytes() == o)

    # And these should work for Tu64
    pairs += [
        (1 << 32, b'\x01\x05\x01\x00\x00\x00\x00'),
        (1 << 40, b'\x01\x06\x01\x00\x00\x00\x00\x00'),
        (1 << 48, b'\x01\x07\x01\x00\x00\x00\x00\x00\x00'),
        (1 << 56, b'\x01\x08\x01\x00\x00\x00\x00\x00\x00\x00'),
        ((1 << 64) - 1, b'\x01\x08\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'),
    ]

    for i, o in pairs:
        f = onion.Tu64Field(1, i)
        assert(f.to_bytes() == o)
