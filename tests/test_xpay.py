from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from pyln.testing.utils import FUNDAMOUNT, only_one
from utils import (
    TIMEOUT, first_scid, GenChannel, generate_gossip_store, wait_for
)

import os
import pytest
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
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
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts={'may_reconnect': True})
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
    with pytest.raises(RpcError, match=r"Failed after 1 attempts. We got an error from inside the blinded path 0x0x0/1: we assume it means insufficient capacity. Then routing failed: We could not find a usable set of paths.  The shortest path is [0-9x]*->[0-9x]*->0x0x0, but 0x0x0/1 layer xpay-7 says max is 99999msat"):
        l1.rpc.xpay(b12)

    # Restart, try pay already paid one again.
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match="Already paid"):
        l1.rpc.xpay(b11_paid)


def test_xpay_selfpay(node_factory):
    l1 = node_factory.get_node()

    b11 = l1.rpc.invoice(1000, "test_xpay_selfpay1", "test_xpay_selfpay1")['bolt11']
    offer = l1.rpc.offer('any')
    b12 = l1.rpc.fetchinvoice(offer['bolt12'], '1000msat')['invoice']

    l1.rpc.xpay(b11)
    l1.rpc.xpay(b12)


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

    failed_parts = []
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
        failed_parts.append(l1.rpc.xpay(inv)['failed_parts'])

    # Should be no reservations left (clean up happens after return though)
    wait_for(lambda: l1.rpc.askrene_listreservations() == {'reservations': []})

    # It should remember the information it learned across restarts!
    # FIXME: channeld_fakenet doesn't restart properly, so just redo xpay.
    layers = l1.rpc.askrene_listlayers()
    # Temporary layers should be gone.
    assert len(layers['layers']) == 1

    l1.rpc.plugin_stop("cln-askrene")
    l1.rpc.plugin_start(os.path.join(os.getcwd(), 'plugins/cln-askrene'))
    layers_after = l1.rpc.askrene_listlayers()
    assert layers == layers_after

    failed_parts_retry = []
    for n in range(0, 100):
        if n in (62, 76, 80, 97):
            continue

        print(f"PAYING Node #{n}")

        preimage_hex = bytes([n + 100]).hex() + '00' * 31
        hash_hex = sha256(bytes.fromhex(preimage_hex)).hexdigest()
        inv = subprocess.check_output(["devtools/bolt11-cli",
                                       "encode",
                                       n.to_bytes(length=8, byteorder=sys.byteorder).hex() + '01' * 24,
                                       f"p={hash_hex}",
                                       f"s={'00' * 32}",
                                       f"d=Paying node {n}",
                                       f"amount={AMOUNT}msat"]).decode('utf-8').strip()
        assert l1.rpc.decode(inv)['payee'] == nodeids[n]
        failed_parts_retry.append(l1.rpc.xpay(inv)['failed_parts'])

    # At least some will have improved!
    assert failed_parts_retry != failed_parts

    # Now, we should be as good *or better* than the first time, since we remembered!
    for p in zip(failed_parts_retry, failed_parts):
        assert p[0] <= p[1]


def test_xpay_timeout(node_factory, executor):
    #         ->l3->
    # l1->l2<        >l4
    #         ->l5->
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5, opts={'dev-no-reconnect': None})

    node_factory.join_nodes([l1, l2, l3, l4], wait_for_announce=True)
    node_factory.join_nodes([l2, l5, l4], fundamount=FUNDAMOUNT // 2, wait_for_announce=True)

    # Make sure l1 sees both paths.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 5 * 2)

    # Break l3->l4
    l3.rpc.disconnect(l4.info['id'], force=True)

    b11 = l4.rpc.invoice('100000sat', 'test_xpay_timeout', 'test_xpay_timeout')['bolt11']
    fut = executor.submit(l1.rpc.xpay, invstring=b11, retry_for=0)

    with pytest.raises(RpcError, match=r"Timed out after after 1 attempts"):
        fut.result(TIMEOUT)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_xpay_partial_msat(node_factory, executor):
    l1, l2, l3 = node_factory.line_graph(3)

    inv = l3.rpc.invoice(100000000, "inv", "inv")

    with pytest.raises(RpcError, match="partial_msat must be less or equal to total amount 10000000"):
        l2.rpc.xpay(invstring=inv['bolt11'], partial_msat=100000001)

    # This will fail with an MPP timeout.
    with pytest.raises(RpcError, match=r"Timed out after after 1 attempts\. Payment of 90000000msat reached destination, but timed out before the rest arrived\."):
        l2.rpc.xpay(invstring=inv['bolt11'], partial_msat=90000000)

    # This will work like normal.
    l2.rpc.xpay(invstring=inv['bolt11'], partial_msat=100000000)

    # Make sure l3 can pay to l2 now.
    wait_for(lambda: only_one(l3.rpc.listpeerchannels()['channels'])['spendable_msat'] > 1001)

    # Now we can combine together to pay l2:
    inv = l2.rpc.invoice('any', "inv", "inv")

    # If we specify different totals, this *won't work*
    l1pay = executor.submit(l1.rpc.xpay, invstring=inv['bolt11'], amount_msat=10000, partial_msat=9000)
    l3pay = executor.submit(l3.rpc.xpay, invstring=inv['bolt11'], amount_msat=10001, partial_msat=1001)

    # BOLT #4:
    # - SHOULD fail the entire HTLC set if `total_msat` is not
    #   the same for all HTLCs in the set.
    with pytest.raises(RpcError, match=r"Unexpected error \(final_incorrect_htlc_amount\) from final node"):
        l3pay.result(TIMEOUT)
    with pytest.raises(RpcError, match=r"Unexpected error \(final_incorrect_htlc_amount\) from final node"):
        l1pay.result(TIMEOUT)

    # But same amount, will combine forces!
    l1pay = executor.submit(l1.rpc.xpay, invstring=inv['bolt11'], amount_msat=10000, partial_msat=9000)
    l3pay = executor.submit(l3.rpc.xpay, invstring=inv['bolt11'], amount_msat=10000, partial_msat=1000)

    l1pay.result(TIMEOUT)
    l3pay.result(TIMEOUT)


def test_xpay_takeover(node_factory, executor):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts={'xpay-handle-pay': True})

    # xpay does NOT look like pay!
    l1.rpc.jsonschemas = {}
    l2.rpc.jsonschemas = {}

    # Simple bolt11/bolt12 payment.
    inv = l3.rpc.invoice(100000, "test_xpay_takeover1", "test_xpay_takeover1")['bolt11']
    l1.rpc.pay(inv)
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    # Array version
    inv = l3.rpc.invoice(100000, "test_xpay_takeover2", "test_xpay_takeover2")['bolt11']
    subprocess.check_output(['cli/lightning-cli',
                             '--network={}'.format(TEST_NETWORK),
                             '--lightning-dir={}'
                             .format(l1.daemon.lightning_dir),
                             'pay',
                             inv])
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    offer = l3.rpc.offer(100000, "test_xpay_takeover2")['bolt12']
    b12 = l1.rpc.fetchinvoice(offer)['invoice']
    l1.rpc.pay(b12)
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    # BOLT11 with amount.
    inv = l3.rpc.invoice('any', "test_xpay_takeover3", "test_xpay_takeover3")['bolt11']
    l1.rpc.pay(inv, amount_msat=10000)
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    # Array version
    inv = l3.rpc.invoice('any', "test_xpay_takeover4", "test_xpay_takeover4")['bolt11']
    subprocess.check_output(['cli/lightning-cli',
                             '--network={}'.format(TEST_NETWORK),
                             '--lightning-dir={}'
                             .format(l1.daemon.lightning_dir),
                             'pay',
                             inv, "10000"])
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    # retry_for, maxfee and partial_msat all work
    inv = l3.rpc.invoice('any', "test_xpay_takeover5", "test_xpay_takeover5")['bolt11']

    fut1 = executor.submit(l1.rpc.pay, bolt11=inv, amount_msat=2000, retry_for=0, maxfee=100, partial_msat=1000)
    l1.daemon.wait_for_log('Redirecting pay->xpay')
    fut2 = executor.submit(l2.rpc.pay, bolt11=inv, amount_msat=2000, retry_for=0, maxfee=0, partial_msat=1000)
    l2.daemon.wait_for_log('Redirecting pay->xpay')
    fut1.result(TIMEOUT)
    fut2.result(TIMEOUT)

    # Three-array-arg replacements don't work.
    inv = l3.rpc.invoice('any', "test_xpay_takeover6", "test_xpay_takeover6")['bolt11']
    subprocess.check_output(['cli/lightning-cli',
                             '--network={}'.format(TEST_NETWORK),
                             '--lightning-dir={}'
                             .format(l1.daemon.lightning_dir),
                             'pay',
                             inv, "10000", 'label'])
    l1.daemon.wait_for_log(r'Not redirecting pay \(only handle 1 or 2 args\): ')

    # Other args fail.
    inv = l3.rpc.invoice('any', "test_xpay_takeover7", "test_xpay_takeover7")
    l1.rpc.pay(inv['bolt11'], amount_msat=10000, label='test_xpay_takeover7')
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg \\"label\\"\)')

    inv = l3.rpc.invoice('any', "test_xpay_takeover8", "test_xpay_takeover8")
    l1.rpc.pay(inv['bolt11'], amount_msat=10000, riskfactor=1)
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg \\"riskfactor\\"\)')

    inv = l3.rpc.invoice('any', "test_xpay_takeover9", "test_xpay_takeover9")
    l1.rpc.pay(inv['bolt11'], amount_msat=10000, maxfeepercent=1)
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg \\"maxfeepercent\\"\)')

    inv = l3.rpc.invoice('any', "test_xpay_takeover10", "test_xpay_takeover10")
    l1.rpc.pay(inv['bolt11'], amount_msat=10000, maxdelay=200)
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg \\"maxdelay\\"\)')

    inv = l3.rpc.invoice('any', "test_xpay_takeover11", "test_xpay_takeover11")
    l1.rpc.pay(inv['bolt11'], amount_msat=10000, exemptfee=1)
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg \\"exemptfee\\"\)')

    # Test that it's really dynamic.
    l1.rpc.setconfig('xpay-handle-pay', False)

    # There's no log for this though!
    inv = l3.rpc.invoice(100000, "test_xpay_takeover12", "test_xpay_takeover12")['bolt11']
    l1.rpc.pay(inv)
    assert not l1.daemon.is_in_log('Redirecting pay->xpay',
                                   start=l1.daemon.logsearch_start)

    l1.rpc.setconfig('xpay-handle-pay', True)
    inv = l3.rpc.invoice(100000, "test_xpay_takeover13", "test_xpay_takeover13")['bolt11']
    l1.rpc.pay(inv)
    l1.daemon.wait_for_log('Redirecting pay->xpay')


def test_xpay_preapprove(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'dev-hsmd-fail-preapprove': None})

    inv = l2.rpc.invoice(100000, "test_xpay_preapprove", "test_xpay_preapprove")['bolt11']

    with pytest.raises(RpcError, match=r"invoice was declined"):
        l1.rpc.check('xpay', invstring=inv)

    with pytest.raises(RpcError, match=r"invoice was declined"):
        l1.rpc.xpay(inv)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'too dusty on elements')
def test_xpay_maxfee(node_factory, bitcoind, chainparams):
    """Test which shows that we don't excees maxfee"""
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    subprocess.check_output(['devtools/gossmap-compress',
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

    # This one triggers the bug!
    n = 59
    maxfee = 57966
    preimage_hex = bytes([n + 100]).hex() + '00' * 31
    hash_hex = sha256(bytes.fromhex(preimage_hex)).hexdigest()
    inv = subprocess.check_output(["devtools/bolt11-cli",
                                   "encode",
                                   n.to_bytes(length=8, byteorder=sys.byteorder).hex() + '01' * 24,
                                   f"currency={chainparams['bip173_prefix']}",
                                   f"p={hash_hex}",
                                   f"s={'00' * 32}",
                                   f"d=Paying node {n} with maxfee",
                                   f"amount={AMOUNT}msat"]).decode('utf-8').strip()

    ret = l1.rpc.xpay(invstring=inv, maxfee=maxfee)
    fee = ret['amount_sent_msat'] - ret['amount_msat']
    assert fee <= maxfee


def test_xpay_unannounced(node_factory):
    l1, l2 = node_factory.line_graph(2, announce_channels=False)

    # BOLT 11, direct peer
    b11 = l2.rpc.invoice('10000msat', 'test_xpay_unannounced', 'test_xpay_unannounced bolt11')['bolt11']
    ret = l1.rpc.xpay(b11)
    assert ret['failed_parts'] == 0
    assert ret['successful_parts'] == 1
    assert ret['amount_msat'] == 10000
    assert ret['amount_sent_msat'] == 10000

    # BOLT 12, direct peer
    offer = l2.rpc.offer('any')['bolt12']
    b12 = l1.rpc.fetchinvoice(offer, '100000msat')['invoice']
    l1.rpc.xpay(b12)


def test_xpay_zeroconf(node_factory):
    zeroconf_plugin = Path(__file__).parent / "plugins" / "zeroconf-selective.py"
    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{},
                                          {'plugin': zeroconf_plugin,
                                           'zeroconf-allow': 'any'}])

    l1.fundwallet(FUNDAMOUNT * 2)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], amount=FUNDAMOUNT, announce=False, mindepth=0)

    wait_for(lambda: all([c['state'] == 'CHANNELD_NORMAL' for c in l1.rpc.listpeerchannels()['channels'] + l2.rpc.listpeerchannels()['channels']]))

    # BOLT 11, direct peer
    b11 = l2.rpc.invoice('10000msat', 'test_xpay_unannounced', 'test_xpay_unannounced bolt11')['bolt11']
    ret = l1.rpc.xpay(b11)
    assert ret['failed_parts'] == 0
    assert ret['successful_parts'] == 1
    assert ret['amount_msat'] == 10000
    assert ret['amount_sent_msat'] == 10000

    # BOLT 12, direct peer
    offer = l2.rpc.offer('any')['bolt12']
    b12 = l1.rpc.fetchinvoice(offer, '100000msat')['invoice']
    l1.rpc.xpay(b12)
