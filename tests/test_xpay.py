from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import (
    TIMEOUT, first_scid, GenChannel, generate_gossip_store
)

import os
import pytest
import subprocess
import sys
from hashlib import sha256
import tempfile
import unittest


def test_pay_fakenet(node_factory):
    hash1 = sha256(bytes.fromhex('00' + '00' * 31)).hexdigest()
    hash2 = sha256(bytes.fromhex('01' + '00' * 31)).hexdigest()
    failhash = '00' * 32

    # Create gossip map of channels from l2 (aka nodemap[0])
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=100_000),
                                             GenChannel(1, 2, capacity_sats=100_000),
                                             GenChannel(2, 3, capacity_sats=200_000)],
                                            nodemap={0: '022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59'})

    # l2 will warn l1 about its invalid gossip: ignore.
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'gossip_store_file': gsfile.name,
                                            'subdaemon': 'channeld:../tests/plugins/channeld_fakenet',
                                            'allow_warning': True}, {}])

    # l1 needs to know l2's shaseed for the channel so it can make revocations
    hsmfile = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    # Needs peer node id and channel dbid (1, it's the first channel), prints out:
    # "shaseed: xxxxxxx\n"
    shaseed = subprocess.check_output(["tools/hsmtool", "dumpcommitments", l1.info['id'], "1", "0", hsmfile]).decode('utf-8').strip().partition(": ")[2]
    l1.rpc.dev_peer_shachain(l2.info['id'], shaseed)

    # Failure from final (unknown payment hash)
    l1.rpc.sendpay(route=[{'id': l2.info['id'],
                           'channel': first_scid(l1, l2),
                           'delay': 18 + 6,
                           'amount_msat': 1000001},
                          {'id': nodemap[1],
                           'channel': '0x1x0',
                           'delay': 18,
                           'amount_msat': 100000}],
                   payment_hash=failhash)

    with pytest.raises(RpcError, match="WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS") as err:
        l1.rpc.waitsendpay(payment_hash=failhash, timeout=TIMEOUT)

    assert err.value.error['data']['erring_node'] == nodemap[1]

    # Success from final (known payment hash)
    l1.rpc.sendpay(route=[{'id': l2.info['id'],
                           'channel': first_scid(l1, l2),
                           'delay': 18 + 6,
                           'amount_msat': 1000001},
                          {'id': nodemap[1],
                           'channel': '0x1x0',
                           'delay': 18,
                           'amount_msat': 100000}],
                   payment_hash=hash1)
    l1.rpc.waitsendpay(payment_hash=hash1, timeout=TIMEOUT)

    # Failure from node 2 (unknown scid)
    l1.rpc.sendpay(route=[{'id': l2.info['id'],
                           'channel': first_scid(l1, l2),
                           'delay': 18 + 6 + 6,
                           'amount_msat': 1000002},
                          {'id': nodemap[1],
                           'channel': '0x1x0',
                           'delay': 18 + 6,
                           'amount_msat': 1000001},
                          {'id': nodemap[2],
                           'channel': '1x1x0',
                           'delay': 18,
                           'amount_msat': 1000000},
                          {'id': nodemap[3],
                           'channel': '0x1x0',
                           'delay': 18,
                           'amount_msat': 100000}],
                   payment_hash=failhash)

    with pytest.raises(RpcError, match="WIRE_UNKNOWN_NEXT_PEER"):
        l1.rpc.waitsendpay(payment_hash=failhash, timeout=TIMEOUT)

    # MPP test
    l1.rpc.sendpay(partid=1,
                   amount_msat=200000,
                   route=[{'id': l2.info['id'],
                           'channel': first_scid(l1, l2),
                           'delay': 18 + 6,
                           'amount_msat': 1000001},
                          {'id': nodemap[1],
                           'channel': '0x1x0',
                           'delay': 18,
                           'amount_msat': 100000}],
                   payment_hash=hash2,
                   payment_secret=hash2)
    with pytest.raises(RpcError, match="WIRE_MPP_TIMEOUT"):
        l1.rpc.waitsendpay(payment_hash=hash2, timeout=60 + TIMEOUT, partid=1)

    # This one will actually work.
    l1.rpc.sendpay(partid=2,
                   groupid=2,
                   amount_msat=200000,
                   route=[{'id': l2.info['id'],
                           'channel': first_scid(l1, l2),
                           'delay': 18 + 6,
                           'amount_msat': 1000001},
                          {'id': nodemap[1],
                           'channel': '0x1x0',
                           'delay': 18,
                           'amount_msat': 100000}],
                   payment_hash=hash2,
                   payment_secret=hash2)

    l1.rpc.sendpay(partid=3,
                   groupid=2,
                   amount_msat=200000,
                   route=[{'id': l2.info['id'],
                           'channel': first_scid(l1, l2),
                           'delay': 18 + 6,
                           'amount_msat': 1000001},
                          {'id': nodemap[1],
                           'channel': '0x1x0',
                           'delay': 18,
                           'amount_msat': 100000}],
                   payment_hash=hash2,
                   payment_secret=hash2)

    l1.rpc.waitsendpay(payment_hash=hash2, timeout=TIMEOUT, partid=2)
    l1.rpc.waitsendpay(payment_hash=hash2, timeout=TIMEOUT, partid=3)


def test_xpay_simple(node_factory):
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts={'experimental-offers': None,
                                                     'may_reconnect': True})
    node_factory.join_nodes([l1, l2, l3], wait_for_announce=True)
    node_factory.join_nodes([l3, l4], announce_channels=False)

    # BOLT 11, direct peer
    b11 = l2.rpc.invoice('10000msat', 'test_xpay_simple', 'test_xpay_simple bolt11')['bolt11']
    ret = l1.rpc.xpay(b11)
    assert ret['failed_parts'] == 0
    assert ret['successful_parts'] == 1
    assert ret['amount_msat'] == 10000
    assert ret['amount_sent_msat'] == 10000

    # Fails if we try to pay again
    b11_paid = b11
    with pytest.raises(RpcError, match="Already paid"):
        l1.rpc.xpay(b11_paid)

    # BOLT 11, indirect peer
    b11 = l3.rpc.invoice('10000msat', 'test_xpay_simple', 'test_xpay_simple bolt11')['bolt11']
    ret = l1.rpc.xpay(b11)
    assert ret['failed_parts'] == 0
    assert ret['successful_parts'] == 1
    assert ret['amount_msat'] == 10000
    assert ret['amount_sent_msat'] == 10001

    # BOLT 11, routehint
    b11 = l4.rpc.invoice('10000msat', 'test_xpay_simple', 'test_xpay_simple bolt11')['bolt11']
    l1.rpc.xpay(b11)

    # BOLT 12.
    offer = l3.rpc.offer('any')['bolt12']
    b12 = l1.rpc.fetchinvoice(offer, '100000msat')['invoice']
    l1.rpc.xpay(b12)

    # Failure from l4.
    b11 = l4.rpc.invoice('10000msat', 'test_xpay_simple2', 'test_xpay_simple2 bolt11')['bolt11']
    l4.rpc.delinvoice('test_xpay_simple2', 'unpaid')
    with pytest.raises(RpcError, match="Destination said it doesn't know invoice"):
        l1.rpc.xpay(b11)

    offer = l4.rpc.offer('any')['bolt12']
    b12 = l1.rpc.fetchinvoice(offer, '100000msat')['invoice']

    # Failure from l3 (with routehint)
    l4.stop()
    with pytest.raises(RpcError, match=r"Failed after 1 attempts\. We got temporary_channel_failure for the invoice's route hint \([0-9x]*/[01]\), assuming it can't carry 10000msat\. Then routing failed: We could not find a usable set of paths\.  The shortest path is [0-9x]*->[0-9x]*->[0-9x]*, but [0-9x]*/[01]\ layer xpay-6 says max is 9999msat"):
        l1.rpc.xpay(b11)

    # Failure from l3 (with blinded path)
    # FIXME: We return wrong error here!
    with pytest.raises(RpcError, match=r"Failed after 1 attempts\. Unexpected error \(invalid_onion_payload\) from intermediate node: disabling the invoice's blinded path \(0x0x0/[01]\) for this payment\. Then routing failed: We could not find a usable set of paths\.  The destination has disabled 1 of 1 channels, leaving capacity only 0msat of 10605000msat\."):
        l1.rpc.xpay(b12)

    # Restart, try pay already paid one again.
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match="Already paid"):
        l1.rpc.xpay(b11_paid)


@pytest.mark.slow_test
@unittest.skipIf(TEST_NETWORK != 'regtest', '29-way split for node 17 is too dusty on elements')
def test_xpay_fake_channeld(node_factory, bitcoind, chainparams):
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress',
                                       'decompress',
                                       '--node-map=3301=022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59',
                                       'tests/data/gossip-store-2024-09-22.compressed',
                                       outfile.name]).decode('utf-8').splitlines()
    AMOUNT = 100_000_000

    # l2 will warn l1 about its invalid gossip: ignore.
    # We throttle l1's gossip to avoid massive log spam.
    l1, l2 = node_factory.line_graph(2,
                                     # This is in sats, so 1000x amount we send.
                                     fundamount=AMOUNT,
                                     opts=[{'gossip_store_file': outfile.name,
                                            'subdaemon': 'channeld:../tests/plugins/channeld_fakenet',
                                            'allow_warning': True,
                                            'dev-throttle-gossip': None},
                                           {'allow_bad_gossip': True}])

    # l1 needs to know l2's shaseed for the channel so it can make revocations
    hsmfile = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    # Needs peer node id and channel dbid (1, it's the first channel), prints out:
    # "shaseed: xxxxxxx\n"
    shaseed = subprocess.check_output(["tools/hsmtool", "dumpcommitments", l1.info['id'], "1", "0", hsmfile]).decode('utf-8').strip().partition(": ")[2]
    l1.rpc.dev_peer_shachain(l2.info['id'], shaseed)

    for n in range(0, 100):
        if n in (62, 76, 80, 97):
            continue

        print(f"PAYING Node #{n}")

        preimage_hex = bytes([n]).hex() + '00' * 31
        hash_hex = sha256(bytes.fromhex(preimage_hex)).hexdigest()
        inv = subprocess.check_output(["devtools/bolt11-cli",
                                       "encode",
                                       n.to_bytes(length=8, byteorder=sys.byteorder).hex() + '01' * 24,
                                       f"currency={chainparams['bip173_prefix']}",
                                       f"p={hash_hex}",
                                       f"s={'00' * 32}",
                                       f"d=Paying node {n}",
                                       f"amount={AMOUNT}msat"]).decode('utf-8').strip()
        assert l1.rpc.decode(inv)['payee'] == nodeids[n]
        l1.rpc.xpay(inv)
