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
