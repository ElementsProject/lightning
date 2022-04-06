from io import BytesIO
from pyln.proto import onion
from typing import Tuple
import json
import os
import unittest


def test_legacy_payload():
    legacy = bytes.fromhex(
        '00000067000001000100000000000003e800000075000000000000000000000000'
    )
    payload = onion.OnionPayload.from_bytes(legacy)
    assert(payload.to_bytes(include_prefix=True) == legacy)


def test_tlv_payload():
    tlv = bytes.fromhex(
        '58fe020c21160c48656c6c6f20776f726c6421fe020c21184076e8acd54afbf2361'
        '0b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d0205f7e4e1a12620e'
        '7fc8ce1c7d3651acefde899c33f12b6958d3304106a0'
    )
    payload = onion.OnionPayload.from_bytes(tlv)
    assert(payload.to_bytes() == tlv)

    fields = payload.fields
    assert(len(fields) == 2)
    assert(isinstance(fields[0], onion.TextField))
    assert(fields[0].typenum == 34349334 and fields[0].value == "Hello world!")
    assert(fields[1].typenum == 34349336 and fields[1].value == bytes.fromhex(
        '76e8acd54afbf23610b7166ba689afcc9e8ec3c44e442e765012dfc1d299958827d'
        '0205f7e4e1a12620e7fc8ce1c7d3651acefde899c33f12b6958d3304106a0'
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


dirname = os.path.dirname(__file__)
vector_base = os.path.join(dirname, '..', 'vectors')
have_vectors = os.path.exists(os.path.join(vector_base, 'onion-test-v0.json'))


def get_vector(filename):
    fullname = os.path.join(vector_base, filename)
    return json.load(open(fullname, 'r'))


@unittest.skipIf(not have_vectors, "Need the test vectors")
def test_onion_parse():
    """Make sure we parse the serialized onion into its components.
    """
    vec = get_vector('onion-test-v0.json')
    o = vec['onion']
    o = onion.RoutingOnion.from_hex(o)

    assert(o.version == 0)
    assert(bytes.hex(o.hmac) == 'b8640887e027e946df96488b47fbc4a4fadaa8beda4abe446fafea5403fae2ef')

    assert(o.to_bin() == bytes.fromhex(vec['onion']))


def test_generate_keyset():
    secret = onion.Secret(bytes.fromhex(
        '53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66'
    ))
    keys = onion.generate_keyset(secret)

    expected = onion.KeySet(
        rho=bytes.fromhex('ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986'),
        mu=bytes.fromhex('b57061dc6d0a2b9f261ac410c8b26d64ac5506cbba30267a649c28c179400eba'),
        um=bytes.fromhex('3ca76e96fad1a0300928639d203b4369e81254032156c936179077b08091ca49'),
        pad=bytes.fromhex('3c348715f933c32b5571e2c9136b17c4da2e8fd13e35b7092deff56650eea958'),
        gamma=bytes.fromhex('c5b96917bc536aff7c2d6584bd60cf3b99151ccac18f173133f1fd0bdcae08b5'),
        pi=bytes.fromhex('3a70333f46a4fd1b3f72acae87760b147b07fe4923131066906a4044d4f1ddd1'),
        ammag=bytes.fromhex('3761ba4d3e726d8abb16cba5950ee976b84937b61b7ad09e741724d7dee12eb5'),
    )
    assert(keys == expected)


def test_blind():
    tests = [
        ('02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619',
         '53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66',
         '2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36'),
        ('028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2',
         'a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae',
         'bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f'),
        ('03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0',
         '3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc',
         'a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5'),
        ('031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595',
         '21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d',
         '7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262'),
        ('03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4',
         'b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328',
         'c96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205'),
    ]

    for pubkey, sharedsecret, expected in tests:
        expected = onion.Secret(bytes.fromhex(expected))
        pubkey = onion.PublicKey(bytes.fromhex(pubkey))
        sharedsecret = onion.Secret(bytes.fromhex(sharedsecret))

        res = onion.blind(pubkey, sharedsecret)
        assert(res == expected)


def test_blind_group_element():
    tests = [
        ('031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595',
         '7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262',
         '03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4'),

        ('028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2',
         'bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f',
         '03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0'),

        ('03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0',
         'a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5',
         '031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595'),

        ('031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595',
         '7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262',
         '03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4'),
    ]
    for pubkey, blind, expected in tests:
        expected = onion.PublicKey(bytes.fromhex(expected))
        pubkey = onion.PublicKey(bytes.fromhex(pubkey))
        blind = onion.Secret(bytes.fromhex(blind))

        res = onion.blind_group_element(pubkey, blind)
        assert(res.to_bytes() == expected.to_bytes())


def test_xor():
    tab = [
        (b'\x01', b'\x01', b'\x00'),
        (b'\x01', b'\x00', b'\x01'),
        (b'\x00', b'\x01', b'\x01'),
        (b'\x00', b'\x00', b'\x00'),
        (b'\xa0', b'\x01', b'\xa1'),
    ]

    for a, b, expected in tab:
        assert(bytearray(expected) == onion.xor(a, b))

        d = bytearray(len(a))
        onion.xor_inplace(d, a, b)
        assert(d == expected)


def sphinx_path_from_test_vector(filename: str) -> Tuple[onion.SphinxPath, dict]:
    """Loads a sphinx test vector from the repo root.
    """
    path = os.path.dirname(__file__)
    root = os.path.join(path, '..')
    filename = os.path.join(root, filename)
    v = json.load(open(filename, 'r'))
    session_key = onion.Secret(bytes.fromhex(v['generate']['session_key']))
    associated_data = bytes.fromhex(v['generate']['associated_data'])
    hops = []

    for h in v['generate']['hops']:
        payload = bytes.fromhex(h['payload'])
        if h['type'] == 'raw' or h['type'] == 'tlv':
            b = BytesIO()
            onion.varint_encode(len(payload), b)
            payload = b.getvalue() + payload
        elif h['type'] == 'legacy':
            padlen = 32 - len(payload)
            payload = b'\x00' + payload + (b'\x00' * padlen)
            assert(len(payload) == 33)

        pubkey = onion.PublicKey(bytes.fromhex(h['pubkey']))
        hops.append(onion.SphinxHop(
            pubkey=pubkey,
            payload=payload,
        ))

    return onion.SphinxPath(hops=hops, session_key=session_key,
                            assocdata=associated_data), v


def test_hop_params():
    """Test that we generate the onion parameters correctly.

    Extracted from running the Core Lightning implementation:

    ```bash
    devtools/onion runtest tests/vectors/onion-test-multi-frame.json
    ```
    """
    sp, v = sphinx_path_from_test_vector(
        'tests/vectors/onion-test-multi-frame.json'
    )

    params = sp.get_hop_params()

    expected = [(
        '02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619',
        '53eb63ea8a3fec3b3cd433b85cd62a4b145e1dda09391b348c4e1cd36a03ea66',
        '2ec2e5da605776054187180343287683aa6a51b4b1c04d6dd49c45d8cffb3c36'
    ), (
        '028f9438bfbf7feac2e108d677e3a82da596be706cc1cf342b75c7b7e22bf4e6e2',
        'a6519e98832a0b179f62123b3567c106db99ee37bef036e783263602f3488fae',
        'bf66c28bc22e598cfd574a1931a2bafbca09163df2261e6d0056b2610dab938f'
    ), (
        '03bfd8225241ea71cd0843db7709f4c222f62ff2d4516fd38b39914ab6b83e0da0',
        '3a6b412548762f0dbccce5c7ae7bb8147d1caf9b5471c34120b30bc9c04891cc',
        'a1f2dadd184eb1627049673f18c6325814384facdee5bfd935d9cb031a1698a5'
    ), (
        '031dde6926381289671300239ea8e57ffaf9bebd05b9a5b95beaf07af05cd43595',
        '21e13c2d7cfe7e18836df50872466117a295783ab8aab0e7ecc8c725503ad02d',
        '7cfe0b699f35525029ae0fa437c69d0f20f7ed4e3916133f9cacbb13c82ff262'
    ), (
        '03a214ebd875aab6ddfd77f22c5e7311d7f77f17a169e599f157bbcdae8bf071f4',
        'b5756b9b542727dbafc6765a49488b023a725d631af688fc031217e90770c328',
        'c96e00dddaf57e7edcd4fb5954be5b65b09f17cb6d20651b4e90315be5779205'
    )]
    assert(len(params) == len(sp.hops))

    for a, b in zip(expected, params):
        assert(a[0] == bytes.hex(b.ephemeralkey.to_bytes()))
        assert(a[1] == bytes.hex(b.secret.to_bytes()))
        assert(a[2] == bytes.hex(b.blind.to_bytes()))


def test_filler():
    """Generate the filler from a sphinx path

    The expected filler was generated using the following test vector, and by
    instrumenting the sphinx code:

    ```bash
    devtools/onion runtest tests/vectors/onion-test-multi-frame.json
    ```
    """
    expected = (
        'b77d99c935d3f32469844f7e09340a91ded147557bdd0456c369f7e449587c0f566'
        '6faab58040146db49024db88553729bce12b860391c29c1779f022ae48a9cb314ca'
        '35d73fc91addc92632bcf7ba6fd9f38e6fd30fabcedbd5407b6648073c38331ee7a'
        'b0332f41f550c180e1601f8c25809ed75b3a1e78635a2ef1b828e92c9658e76e49f'
        '995d72cf9781eec0c838901d0bdde3ac21c13b4979ac9e738a1c4d0b9741d58e777'
        'ad1aed01263ad1390d36a18a6b92f4f799dcf75edbb43b7515e8d72cb4f827a9af0'
        'e7b9338d07b1a24e0305b5535f5b851b1144bad6238b9d9482b5ba6413f1aafac3c'
        'dde5067966ed8b78f7c1c5f916a05f874d5f17a2b7d0ae75d66a5f1bb6ff932570d'
        'c5a0cf3ce04eb5d26bc55c2057af1f8326e20a7d6f0ae644f09d00fac80de60f20a'
        'ceee85be41a074d3e1dda017db79d0070b99f54736396f206ee3777abd4c00a4bb9'
        '5c871750409261e3b01e59a3793a9c20159aae4988c68397a1443be6370fd9614e4'
        '6108291e615691729faea58537209fa668a172d066d0efff9bc77c2bd34bd77870a'
        'd79effd80140990e36731a0b72092f8d5bc8cd346762e93b2bf203d00264e4bc136'
        'fc142de8f7b69154deb05854ea88e2d7506222c95ba1aab065c8a'
    )

    sp, v = sphinx_path_from_test_vector(
        'tests/vectors/onion-test-multi-frame.json'
    )
    filler = sp.get_filler()
    assert(2 * len(filler) == len(expected))
    assert(bytes.hex(bytes(filler)) == expected)


def test_chacha20_stream():
    """Test that we can generate a correct stream for encryption/decryption
    """
    tests = [(
        'ce496ec94def95aadd4bec15cdb41a740c9f2b62347c4917325fcc6fb0453986',
        'e5f14350c2a76fc232b5e46d421e9615471ab9e0bc887beff8c95fdb878f7b3a'
    ), (
        '450ffcabc6449094918ebe13d4f03e433d20a3d28a768203337bc40b6e4b2c59',
        '03455084337a8dbe5d5bfa27f825f3a9ae4f431f6f7a16ad786704887cbd85bd'
    ), (
        '11bf5c4f960239cb37833936aa3d02cea82c0f39fd35f566109c41f9eac8deea',
        'e22ea443b8a275174533abc584fae578e80ed4c1851d0554235171e45e1e2a18'
    ), (
        'cbe784ab745c13ff5cffc2fbe3e84424aa0fd669b8ead4ee562901a4a4e89e9e',
        '35de88a5f7e63d2c0072992046827fc997c3312b54591844fc713c0cca433626'
    )]

    for a, b in tests:
        stream = bytearray(32)
        onion.chacha20_stream(bytes.fromhex(a), stream)
        assert(bytes.hex(bytes(stream)) == b)

        # And since we're at it make sure we can actually encrypt inplace on a
        # memoryview.
        stream = memoryview(bytearray(64))
        onion.chacha20_stream(bytes.fromhex(a), memoryview(stream[16:-16]))
        assert(bytes.hex(bytes(stream)) == '00' * 16 + b + '00' * 16)


def test_sphinx_path_compile():
    f = 'tests/vectors/onion-test-multi-frame.json'
    sp, v = sphinx_path_from_test_vector(f)
    o = sp.compile()

    assert(o.to_bin() == bytes.fromhex(v['onion']))


def test_unwrap():
    f = 'tests/vectors/onion-test-multi-frame.json'
    sp, v = sphinx_path_from_test_vector(f)
    o = onion.RoutingOnion.from_hex(v['onion'])
    assocdata = bytes.fromhex(v['generate']['associated_data'])
    privkeys = [onion.PrivateKey(bytes.fromhex(h)) for h in v['decode']]

    for pk, h in zip(privkeys, v['generate']['hops']):
        pl, o = o.unwrap(pk, assocdata=assocdata)

        b = bytes.hex(pl.to_bytes(include_prefix=False))
        if h['type'] == 'legacy':
            assert(b == h['payload'] + '00' * 12)
        else:
            assert(b == h['payload'])
    assert(o is None)
