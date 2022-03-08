import subprocess
import pytest
import os
from fixtures import *  # noqa: F401,F403


@pytest.fixture
def oniontool():
    path = os.path.join(os.path.dirname(__file__), "..", "devtools", "onion")
    return path


privkeys = [
    '4141414141414141414141414141414141414141414141414141414141414141',
    '4242424242424242424242424242424242424242424242424242424242424242',
    '4343434343434343434343434343434343434343434343434343434343434343',
    '4444444444444444444444444444444444444444444444444444444444444444',
    '4545454545454545454545454545454545454545454545454545454545454545'
]

pubkeys = [
    '02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619',
    '0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c',
    '027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007',
    '032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991',
    '02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145'
]


def test_onion(directory, oniontool):
    """ Generate a 5 hop onion and then decode it.
    """
    tempfile = os.path.join(directory, 'onion')
    out = subprocess.check_output(
        [oniontool, 'generate'] + pubkeys
    ).decode('ASCII').strip().split('\n')
    assert(len(out) == 1)

    def store_onion(o):
        with open(tempfile, 'w') as f:
            f.write(o)

    store_onion(out[0])

    for i, pk in enumerate(privkeys):
        out = subprocess.check_output([oniontool, 'decode', tempfile, pk]).decode('ASCII').strip().split('\n')
        store_onion(out[-1][5:])

    # Final payload:
    # amt_to_forward=4,outgoing_cltv_value=4
    assert(out == ['payload=06020104040104'])


def test_rendezvous_onion(directory, oniontool):
    """Create a compressed onion, decompress it at the RV node and then forward normally.
    """
    tempfile = os.path.join(directory, 'onion')
    out = subprocess.check_output(
        [oniontool, '--rendezvous-id', pubkeys[0], 'generate'] + pubkeys
    ).decode('ASCII').strip().split('\n')
    assert(len(out) == 2)
    compressed = out[0].split(' ')[-1]
    uncompressed = out[1]

    assert(len(compressed) < len(uncompressed))

    # Now decompress the onion to get back the original onion
    out2 = subprocess.check_output(
        [oniontool, 'decompress', privkeys[0], compressed]
    ).decode('ASCII').strip().split('\n')
    decompressed = out2[-1].split(' ')[-1]

    assert(uncompressed == decompressed)

    # And now just for safety make sure the following nodes can still process
    # and forward the onion.
    def store_onion(o):
        with open(tempfile, 'w') as f:
            f.write(o)

    store_onion(decompressed)

    for i, pk in enumerate(privkeys):
        out = subprocess.check_output([oniontool, 'decode', tempfile, pk]).decode('ASCII').strip().split('\n')
        store_onion(out[-1][5:])

    # Final payload:
    # amt_to_forward=4,outgoing_cltv_value=4
    assert(out == ['payload=06020104040104'])
