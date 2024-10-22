from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import (
    TIMEOUT, first_scid, GenChannel, generate_gossip_store
)

import os
import pytest
import subprocess
from hashlib import sha256


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
