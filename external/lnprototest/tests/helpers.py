import logging
import traceback

import bitcoin.core
import coincurve
from typing import Tuple, Union, Sequence, List
from lnprototest import privkey_expand, KeySet, Runner, Event

# Here are the keys to spend funds, derived from BIP32 seed
# `0000000000000000000000000000000000000000000000000000000000000001`:
#
#    pubkey 0/0/1: 02d6a3c2d0cf7904ab6af54d7c959435a452b24a63194e1c4e7c337d3ebbb3017b
#    privkey 0/0/1: 76edf0c303b9e692da9cb491abedef46ca5b81d32f102eb4648461b239cb0f99
#    WIF 0/0/1: cRZtHFwyrV3CS1Muc9k4sXQRDhqA1Usgi8r7NhdEXLgM5CUEZufg
#    P2WPKH 0/0/1: bcrt1qsdzqt93xsyewdjvagndw9523m27e52er5ca7hm
#    UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/1 (0.01BTC)
#
#    pubkey 0/0/2: 038f1573b4238a986470d250ce87c7a91257b6ba3baf2a0b14380c4e1e532c209d
#    privkey 0/0/2: bc2f48a76a6b8815940accaf01981d3b6347a68fbe844f81c50ecbadf27cd179
#    WIF 0/0/2: cTtWRYC39drNzaANPzDrgoYsMgs5LkfE5USKH9Kr9ySpEEdjYt3E
#    P2WPKH 0/0/2: bcrt1qlkt93775wmf33uacykc49v2j4tayn0yj25msjn
#    UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/0 (0.02BTC)
#
#    pubkey 0/0/3: 02ffef0c295cf7ca3a4ceb8208534e61edf44c606e7990287f389f1ea055a1231c
#    privkey 0/0/3: 16c5027616e940d1e72b4c172557b3b799a93c0582f924441174ea556aadd01c
#    WIF 0/0/3: cNLxnoJSQDRzXnGPr4ihhy2oQqRBTjdUAM23fHLHbZ2pBsNbqMwb
#    P2WPKH 0/0/3: bcrt1q2ng546gs0ylfxrvwx0fauzcvhuz655en4kwe2c
#    UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/3 (0.03BTC)
#
#    pubkey 0/0/4: 026957e53b46df017bd6460681d068e1d23a7b027de398272d0b15f59b78d060a9
#    privkey 0/0/4: 53ac43309b75d9b86bef32c5bbc99c500910b64f9ae089667c870c2cc69e17a4
#    WIF 0/0/4: cQPMJRjxse9i1jDeCo8H3khUMHYfXYomKbwF5zUqdPrFT6AmtTbd
#    P2WPKH 0/0/4: bcrt1qrdpwrlrmrnvn535l5eldt64lxm8r2nwkv0ruxq
#    UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/4 (0.04BTC)
#
#    pubkey 0/0/5: 03a9f795ff2e4c27091f40e8f8277301824d1c3dfa6b0204aa92347314e41b1033
#    privkey 0/0/5: 16be98a5d4156f6f3af99205e9bc1395397bca53db967e50427583c94271d27f
#    WIF 0/0/5: cNLuxyjvR6ga2q6fdmSKxAd1CPQDShKV9yoA7zFKT7GJwZXr9MmT
#    P2WPKH 0/0/5: bcrt1q622lwmdzxxterumd746eu3d3t40pq53p62zhlz
#    UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/2 (48.89994700BTC)
#
#
# We add another UTXO which is solely spendable by the test framework, and not accessible to the
# runner -- needed for dual-funded tests.
#
#    pubkey: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
#    privkey: 0000000000000000000000000000000000000000000000000000000000000002
#    P2WPKH : bcrt1qq6hag67dl53wl99vzg42z8eyzfz2xlkvwk6f7m
#    UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/5 (0.005BTC)
#
# UTXO with a 1-of-5 multisig (results in a long/expensive witness)
# -- needed for dual-funded tests.
#
#   pubkey_1: 0253cdf835e328346a4f19de099cf3d42d4a7041e073cd4057a1c4fd7cdbb1228f
#   privkey_1: cPToYwmZxXaAaAw6XHi8aEVefYAoYxPs8TCFpsAF6JVWbg1NSaZE
#   pubkey_2: 03ae903722f21f85e651b8f9b18fc854084fb90eeb76452bdcfd0cb43a16a382a2
#   privkey_2: cMsCoM96my8y5DDHLJfpGzFo7EhnhNFscbARtNS8mz7vTV5PiVR3
#   pubkey_3: 036c264d68a9727afdc75949f7d7fa71910ae9ae8001a1fbffa6f7ce000976597c
#   privkey_3: cQE1RbQyGcecfzTurwayy9vJtapRmM9isUG6AVTxYf2seiBHcNMp
#   pubkey_4: 036429fa8a4ef0b2b1d5cb553e34eeb90a32ab19fae1f0024f332ab4f74283a728
#   privkey_4: cVKnBoJ294xQyzRWFkxSmxMr1PFdHxGgTVBrMWpSF6o8KoJhWbNY
#   pubkey_5: 03d4232f19ea85051e7b76bf5f01d03e17eea8751463dee36d71413a739de1a927
#   privkey_5: cRboxysVFZUxZQ3DdvoTRuBKfStQ46MAA5HTVgVQW6VKF88HrC4H
#   script: 51210253cdf835e328346a4f19de099cf3d42d4a7041e073cd4057a1c4fd7cdbb1228f2103ae903722f21f85e651b8f9b18fc854084fb90eeb76452bdcfd0cb43a16a382a221036c264d68a9727afdc75949f7d7fa71910ae9ae8001a1fbffa6f7ce000976597c21036429fa8a4ef0b2b1d5cb553e34eeb90a32ab19fae1f0024f332ab4f74283a7282103d4232f19ea85051e7b76bf5f01d03e17eea8751463dee36d71413a739de1a92755ae
#   P2WSH: bcrt1qug62lyrfd7khs7welgu28y66zzuq5nc4t9gdnyx3rjm9fud2f7gqm0ksxn
#   UTXO: d3fb780146954eb42e371c80cbee1725f8ae330848522f105bda24e1fb1fc010/6 (0.06BTC)
#
tx_spendable = "0200000000010184591a56720aabc8023cecf71801c5e0f9d049d0c550ab42412ad12a67d89f3a0000000000feffffff0780841e0000000000160014fd9658fbd476d318f3b825b152b152aafa49bc9240420f000000000016001483440596268132e6c99d44dae2d151dabd9a2b232c180a2901000000160014d295f76da2319791f36df5759e45b15d5e105221c0c62d000000000016001454d14ae910793e930d8e33d3de0b0cbf05aa533300093d00000000001600141b42e1fc7b1cd93a469fa67ed5eabf36ce354dd620a107000000000016001406afd46bcdfd22ef94ac122aa11f241244a37ecc808d5b000000000022002000b068df6e0e0542e776cea5ebe8f5f1a9b40b531ddd8e94b1a7ff9829b5bbaa024730440220367b9bfed0565bad2137124f736373626fa3135e59b20a7b5c1d8f2b8f1b26bb02202f664de39787082a376d222487f02ef19e45696c041044a6d579eecabb68e94501210356609a904a7026c7391d3fbf71ad92a00e04b4cd2fb6a8d1e69cbc0998f6690a65000000"


def utxo(index: int = 0) -> Tuple[str, int, int, str, int]:
    """Helper to get a P2WPKH UTXO, amount, privkey and fee from the tx_spendable transaction"""

    amount = (index + 1) * 1000000
    if index == 0:
        txout = 1
        key = "76edf0c303b9e692da9cb491abedef46ca5b81d32f102eb4648461b239cb0f99"
    elif index == 1:
        txout = 0
        key = "bc2f48a76a6b8815940accaf01981d3b6347a68fbe844f81c50ecbadf27cd179"
    elif index == 2:
        txout = 3
        key = "16c5027616e940d1e72b4c172557b3b799a93c0582f924441174ea556aadd01c"
    elif index == 3:
        txout = 4
        key = "53ac43309b75d9b86bef32c5bbc99c500910b64f9ae089667c870c2cc69e17a4"
    elif index == 4:
        txout = 2
        key = "16be98a5d4156f6f3af99205e9bc1395397bca53db967e50427583c94271d27f"
        amount = 4983494700
    elif index == 5:
        txout = 5
        key = "0000000000000000000000000000000000000000000000000000000000000002"
        amount = 500000
    elif index == 6:
        txout = 6
        key = "38204720bc4f9647fd58c6d0a4bd3a6dd2be16d8e4273c4d1bdd5774e8c51eaf"
        amount = 6000000
    else:
        raise ValueError("index must be 0-6 inclusive")

    # Reasonable funding fee in sats
    reasonable_funding_fee = 200

    return txid_raw(tx_spendable), txout, amount, key, reasonable_funding_fee


def tx_out_for_index(index: int = 0) -> int:
    _, txout, _, _, _ = utxo(index)
    return txout


def privkey_for_index(index: int = 0) -> str:
    _, _, _, privkey, _ = utxo(index)
    return privkey


def utxo_amount(index: int = 0) -> int:
    """How much is this utxo worth"""
    _, _, amt, _, _ = utxo(index)
    return amt


def funding_amount_for_utxo(index: int = 0) -> int:
    """How much can we fund a channel for using utxo #index?"""
    _, _, amt, _, fee = utxo(index)
    return amt - fee


def txid_raw(tx: str) -> str:
    """Helper to get the txid of a tx: note this is in wire protocol order, not bitcoin order!"""
    return bitcoin.core.CTransaction.deserialize(bytes.fromhex(tx)).GetTxid().hex()


def pubkey_of(privkey: str) -> str:
    """Return the public key corresponding to this privkey"""
    return (
        coincurve.PublicKey.from_secret(privkey_expand(privkey).secret).format().hex()
    )


def gen_random_keyset(counter: int = 20) -> KeySet:
    """Helper function to generate a random keyset."""
    return KeySet(
        revocation_base_secret=f"{counter + 1}",
        payment_base_secret=f"{counter + 2}",
        htlc_base_secret=f"{counter + 3}",
        delayed_payment_base_secret=f"{counter + 4}",
        shachain_seed="00" * 32,
    )


def get_traceback(e: Exception) -> str:
    lines = traceback.format_exception(type(e), e, e.__traceback__)
    return "".join(lines)


def run_runner(runner: Runner, test: Union[Sequence, List[Event], Event]) -> None:
    """
    The pytest using the assertion as safe failure, and the exception it is only
    an event that must not happen.

    From design, lnprototest fails with an exception, and for this reason, if the
    lnprototest throws an exception, we catch it, and we fail with an assent.
    """
    try:
        runner.run(test)
    except Exception as ex:
        runner.stop(print_logs=True)
        logging.error(get_traceback(ex))
        assert False, ex


def merge_events_sequences(
    pre: Union[Sequence, List[Event], Event], post: Union[Sequence, List[Event], Event]
) -> Union[Sequence, List[Event], Event]:
    """Merge the two list in the pre-post order"""
    pre.extend(post)
    return pre
