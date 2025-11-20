from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from pyln.testing.utils import FUNDAMOUNT, only_one
from utils import (
    TIMEOUT, first_scid, GenChannel, generate_gossip_store, wait_for,
    sync_blockheight,
)

import ast
import os
import pytest
import re
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
@pytest.mark.parametrize("slow_mode", [False, True])
def test_xpay_fake_channeld(node_factory, bitcoind, chainparams, slow_mode):
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress',
                                       'decompress',
                                       '--node-map=3301=022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59',
                                       'tests/data/gossip-store-2024-09-22.compressed',
                                       outfile.name]).decode('utf-8').splitlines()
    AMOUNT = 100_000_000

    # l2 will warn l1 about its invalid gossip: ignore.
    # We throttle l1's gossip to avoid massive log spam.
    # Suppress debug and below because logs are huge
    l1, l2 = node_factory.line_graph(2,
                                     # This is in sats, so 1000x amount we send.
                                     fundamount=AMOUNT,
                                     opts=[{'gossip_store_file': outfile.name,
                                            'subdaemon': 'channeld:../tests/plugins/channeld_fakenet',
                                            'allow_warning': True,
                                            'dev-throttle-gossip': None,
                                            'log-level': 'info',
                                            # xpay gets upset if it's aging when we remove cln-askrene!
                                            'dev-xpay-no-age': None,
                                            },
                                           {'allow_bad_gossip': True,
                                            'log-level': 'info',
                                            }])

    # l1 needs to know l2's shaseed for the channel so it can make revocations
    hsmfile = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    # Needs peer node id and channel dbid (1, it's the first channel), prints out:
    # "shaseed: xxxxxxx\n"
    shaseed = subprocess.check_output(["tools/hsmtool", "dumpcommitments", l1.info['id'], "1", "0", hsmfile]).decode('utf-8').strip().partition(": ")[2]
    l1.rpc.dev_peer_shachain(l2.info['id'], shaseed)

    # Toggle whether we wait for all the parts to finish.
    l1.rpc.setconfig('xpay-slow-mode', slow_mode)
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
                                       "9=020000",  # option_basic_mpp
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
                                       "9=020000",  # option_basic_mpp
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

    # Simple bolt11/bolt12 payment.
    inv = l3.rpc.invoice(100000, "test_xpay_takeover1", "test_xpay_takeover1")['bolt11']
    l1.rpc.pay(inv)
    l1.daemon.wait_for_log('Calling rpc_command hook of plugin cln-xpay')
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    # Quickly test that xpay does NOT receive other commands now.
    l1.rpc.help()
    assert not l1.daemon.is_in_log('Calling rpc_command hook of plugin cln-xpay',
                                   start=l1.daemon.logsearch_start)

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
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg "label"\)')

    inv = l3.rpc.invoice('any', "test_xpay_takeover8", "test_xpay_takeover8")
    l1.rpc.pay(inv['bolt11'], amount_msat=10000, riskfactor=1)
    l1.daemon.wait_for_log(r'Not redirecting pay \(unknown arg "riskfactor"\)')

    # Test that it's really dynamic.
    l1.rpc.setconfig('xpay-handle-pay', False)

    # There's no log for this though!
    inv = l3.rpc.invoice(100000, "test_xpay_takeover12", "test_xpay_takeover12")['bolt11']
    realpay = l1.rpc.pay(inv)
    assert not l1.daemon.is_in_log('Redirecting pay->xpay',
                                   start=l1.daemon.logsearch_start)

    l1.rpc.setconfig('xpay-handle-pay', True)
    inv = l3.rpc.invoice(100000, "test_xpay_takeover13", "test_xpay_takeover13")['bolt11']
    xpay = l1.rpc.pay(inv)
    l1.daemon.wait_for_log('Redirecting pay->xpay')

    # They should look the same!  Same keys, same types
    assert {k: type(v) for k, v in realpay.items()} == {k: type(v) for k, v in xpay.items()}
    for f in ('created_at', 'payment_hash', 'payment_preimage'):
        del realpay[f]
        del xpay[f]
    assert xpay == {'amount_msat': 100000,
                    'amount_sent_msat': 100002,
                    'destination': l3.info['id'],
                    'parts': 1,
                    'status': 'complete'}
    assert realpay == xpay

    # We get destination and amount_msat in listsendpays and listpays.
    ret = only_one(l1.rpc.listsendpays(inv)['payments'])
    assert ret['destination'] == l3.info['id']
    assert ret['amount_msat'] == 100000
    assert ret['amount_sent_msat'] > 100000

    ret = only_one(l1.rpc.listpays(inv)['pays'])
    assert ret['destination'] == l3.info['id']
    assert ret['amount_msat'] == 100000
    assert ret['amount_sent_msat'] > 100000

    # Test maxfeepercent.
    inv = l3.rpc.invoice(100000, "test_xpay_takeover14", "test_xpay_takeover14")['bolt11']
    with pytest.raises(RpcError, match=r"Could not find route without excessive cost"):
        l1.rpc.pay(bolt11=inv, maxfeepercent=0.001, exemptfee=0)
    l1.daemon.wait_for_log('plugin-cln-xpay: Converted maxfeepercent=0.001, exemptfee=0 to maxfee 1msat')

    # Exemptfee default more than covers it.
    l1.rpc.pay(bolt11=inv, maxfeepercent=0.25)
    l1.daemon.wait_for_log('Converted maxfeepercent=0.25, exemptfee=UNSET to maxfee 5000msat')


def test_xpay_takeover_null_parms(node_factory, executor):
    """Test passing through RPC a list of parameters some of which have null
    json value."""
    l1, l2, l3 = node_factory.line_graph(
        3, wait_for_announce=True, opts={"xpay-handle-pay": True}
    )

    # Amount argument is null.
    inv = l3.rpc.invoice(100000, "test_xpay_takeover1", "test_xpay_takeover1")["bolt11"]
    l1.rpc.call("pay", [inv, None])
    l1.daemon.wait_for_log("Redirecting pay->xpay")

    # Amount argument is given
    inv = l3.rpc.invoice("any", "test_xpay_takeover2", "test_xpay_takeover2")["bolt11"]
    l1.rpc.call("pay", [inv, "100sat"])
    l1.daemon.wait_for_log("Redirecting pay->xpay")

    # bolt11 invoice cannot be NULL
    with pytest.raises(RpcError, match=r"missing required parameter: bolt11"):
        l1.rpc.call("pay", [None, "100sat"])
    l1.daemon.wait_for_log(r"Not redirecting pay \(missing bolt11 parameter\)")


def test_xpay_preapprove(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'dev-hsmd-fail-preapprove': None})

    inv = l2.rpc.invoice(100000, "test_xpay_preapprove", "test_xpay_preapprove")['bolt11']

    with pytest.raises(RpcError, match=r"invoice was declined"):
        l1.rpc.check('xpay', invstring=inv)

    with pytest.raises(RpcError, match=r"invoice was declined"):
        l1.rpc.xpay(inv)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'too dusty on elements')
@pytest.mark.slow_test
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
                                   "9=020000",  # option_basic_mpp
                                   f"s={'00' * 32}",
                                   f"d=Paying node {n} with maxfee",
                                   f"amount={AMOUNT}msat"]).decode('utf-8').strip()

    ret = l1.rpc.xpay(invstring=inv, maxfee=maxfee)
    fee = ret['amount_sent_msat'] - ret['amount_msat']
    assert fee <= maxfee


def test_xpay_maxdelay(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    inv = l2.rpc.invoice('10000msat', 'test_xpay_maxdelay', 'test_xpay_maxdelay')["bolt11"]

    with pytest.raises(RpcError, match=r"Could not find route without excessive delays"):
        l1.rpc.xpay(invstring=inv, maxdelay=1)


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
                                           'zeroconf_allow': 'any'}])

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


def test_xpay_no_mpp(node_factory, chainparams):
    """Suppress mpp, resulting in a single payment part"""
    l1, l2, l3, l4 = node_factory.get_nodes(4)
    node_factory.join_nodes([l1, l2, l3], wait_for_announce=True)
    node_factory.join_nodes([l1, l4, l3], wait_for_announce=True)

    # Amount needs to be enought that it bothers splitting, but not
    # so much that it can't pay without mpp.
    AMOUNT = 500000000

    # We create a version of this which doesn't support MPP
    no_mpp = l3.rpc.invoice(AMOUNT, 'test_xpay_no_mpp2', 'test_xpay_no_mpp without mpp')
    b11_no_mpp = subprocess.check_output(["devtools/bolt11-cli",
                                          "encode",
                                          # secret for l3
                                          "dae24b3853e1443a176daba5544ee04f7db33ebe38e70bdfdb1da34e89512c10",
                                          f"currency={chainparams['bip173_prefix']}",
                                          f"p={no_mpp['payment_hash']}",
                                          f"s={no_mpp['payment_secret']}",
                                          f"d=Paying l3 without mpp",
                                          f"amount={AMOUNT}"]).decode('utf-8').strip()

    # This should not mpp!
    ret = l1.rpc.xpay(b11_no_mpp)
    assert ret['failed_parts'] == 0
    assert ret['successful_parts'] == 1
    assert ret['amount_msat'] == AMOUNT
    assert ret['amount_sent_msat'] == AMOUNT + AMOUNT // 100000 + 1


@pytest.mark.parametrize("deprecations", [False, True])
def test_xpay_bolt12_no_mpp(node_factory, chainparams, deprecations):
    """In deprecated mode, we use MPP even if BOLT12 invoice doesn't say we should"""
    # l4 needs dev-allow-localhost so it considers itself to have an advertized address, and doesn't create a blinded path from l2/l4.
    opts = [{}, {}, {'dev-force-features': -17, 'dev-allow-localhost': None}, {}]
    if deprecations is True:
        for o in opts:
            o['allow-deprecated-apis'] = True
            o['broken_log'] = 'DEPRECATED API USED: xpay.ignore_bolt12_mpp'

    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)
    node_factory.join_nodes([l1, l2, l3], wait_for_announce=True)
    node_factory.join_nodes([l1, l4, l3], wait_for_announce=True)

    # Amount needs to be enought that it bothers splitting, but not
    # so much that it can't pay without mpp.
    AMOUNT = 800000000

    # l2 will advertize mpp, l3 won't.
    l2offer = l2.rpc.offer(AMOUNT, 'test_xpay_bolt12_no_mpp')
    invl2 = l1.rpc.fetchinvoice(l2offer['bolt12'])
    l3offer = l3.rpc.offer(AMOUNT, 'test_xpay_bolt12_no_mpp')
    invl3 = l1.rpc.fetchinvoice(l3offer['bolt12'])

    assert l1.rpc.decode(invl2['invoice'])['invoice_features'] == "020000"
    assert l1.rpc.decode(invl3['invoice'])['invoice_features'] == ""

    ret = l1.rpc.xpay(invl3['invoice'])
    assert ret['failed_parts'] == 0
    if deprecations:
        assert ret['successful_parts'] == 2
        assert ret['amount_sent_msat'] == AMOUNT + AMOUNT // 100000 + 2
    else:
        assert ret['successful_parts'] == 1
        assert ret['amount_sent_msat'] == AMOUNT + AMOUNT // 100000 + 1
    assert ret['amount_msat'] == AMOUNT


def test_xpay_slow_mode(node_factory, bitcoind):
    # l1 -> l2 -> l3 -> l5
    #         \-> l4 -/^
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5, opts=[{'xpay-slow-mode': True},
                                                         {}, {}, {}, {}])
    node_factory.join_nodes([l2, l3, l5])
    node_factory.join_nodes([l2, l4, l5])

    # Make sure l1 can see all paths.
    node_factory.join_nodes([l1, l2])
    bitcoind.generate_block(5)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 10)

    # First try an MPP which fails
    inv = l5.rpc.invoice(800000000, 'test_xpay_slow_mode_fail', 'test_xpay_slow_mode_fail', preimage='01' * 32)['bolt11']
    l5.rpc.delinvoice('test_xpay_slow_mode_fail', status='unpaid')

    with pytest.raises(RpcError, match=r"Destination said it doesn't know invoice: incorrect_or_unknown_payment_details"):
        l1.rpc.xpay(inv)

    # Now a successful one
    inv = l5.rpc.invoice(800000000, 'test_xpay_slow_mode', 'test_xpay_slow_mode', preimage='00' * 32)['bolt11']

    assert l1.rpc.xpay(inv) == {'payment_preimage': '00' * 32,
                                'amount_msat': 800000000,
                                'amount_sent_msat': 800016004,
                                'failed_parts': 0,
                                'successful_parts': 2}


@pytest.mark.parametrize("slow_mode", [False, True])
def test_fail_after_success(node_factory, bitcoind, executor, slow_mode):
    # l1 -> l2 -> l3 -> l5
    #         \-> l4 -/^
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5, opts=[{'xpay-slow-mode': slow_mode},
                                                         {},
                                                         {},
                                                         {'disconnect': ['-WIRE_UPDATE_FULFILL_HTLC']},
                                                         {}])
    node_factory.join_nodes([l2, l3, l5])
    node_factory.join_nodes([l2, l4, l5])

    # Make sure l1 can see all paths.
    node_factory.join_nodes([l1, l2])
    bitcoind.generate_block(5)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 10)

    inv = l5.rpc.invoice(800000000, 'test_xpay_slow_mode', 'test_xpay_slow_mode', preimage='00' * 32)['bolt11']
    fut = executor.submit(l1.rpc.xpay, invstring=inv, retry_for=0)

    # Part via l3 is fine.  Part via l4 is stuck, so we kill l4 and mine
    # blocks to make l2 force close.
    l4.daemon.wait_for_log('dev_disconnect: -WIRE_UPDATE_FULFILL_HTLC')
    l4.stop()

    # Normally, we return as soon as first part succeeds.
    if slow_mode is False:
        assert fut.result(TIMEOUT) == {'payment_preimage': '00' * 32,
                                       'amount_msat': 800000000,
                                       'amount_sent_msat': 800016004,
                                       'failed_parts': 0,
                                       'successful_parts': 2}

    # Time it out, l2 will collect it.
    bitcoind.generate_block(13)
    l2.daemon.wait_for_log('Peer permanent failure in CHANNELD_NORMAL: Offered HTLC 0 SENT_ADD_ACK_REVOCATION cltv 124 hit deadline')
    bitcoind.generate_block(3, wait_for_mempool=1)

    l1.daemon.wait_for_log(r"UNUSUAL.*Destination accepted partial payment, failed a part \(Error permanent_channel_failure for path ->022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59->0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199->032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e, from 022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59\)")
    # Could be either way around, check both
    line = l1.daemon.is_in_log(r"UNUSUAL.*Destination accepted partial payment, failed a part")
    assert re.search(r'but accepted only .* of 800000000msat\.  Winning\?!', line)

    if slow_mode is True:
        # Now it succeeds, but notes that it only sent one part!
        res = fut.result(TIMEOUT)
        # Some variation due to floating point.
        assert res['amount_sent_msat'] < 800000000
        assert res == {'payment_preimage': '00' * 32,
                       'amount_msat': 800000000,
                       'amount_sent_msat': res['amount_sent_msat'],
                       'failed_parts': 1,
                       'successful_parts': 1}


def test_xpay_twohop_bug(node_factory, bitcoind):
    """From https://github.com/ElementsProject/lightning/issues/8119:
    Oh, interesting! I tried again and got a two-hop blinded path. xpay returned the same error you saw while pay was successful.

lightning-cli xpay lni1qqgv5nalmz08ukj4av074kyk6pepq93pqvvhnlnvurnfanndnxjtcjnmxrkj92xtsupa6lwjm7hkr8s8zflqk5sz82v9gqzcyypu03lyetn3ayp8p5798mz4der4xexkxxxu8ck0m25gmjaaj3n5scaql5q0uquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upaypvngk89elemj7cvu9v57r28k65e4jtlsr0vd66yzwrw2uzyvjczq0sd8fk6vazvrxvnks7hdqkl3lar4ff4a2ccjpltacz8z6tw6lunvqzrlrvyu3rkyylgd0splzr0xs3cccmzmfllyu7k06gclf9wx5n463z5arlwz2frk9a6lnfrvjdh3znsppxc4v8ahdy7e0y3us5rww0lcdxqj6psx87tgwvm3u260gc25frw9c4t368cecy3f5flll87tgk2uva09mncqqe9qqq0vdm023df0eetknvgcxk5yuupg8j5a5jtdmpj0u5unp8f3g2gskpma8l53sd5vmsfcrlr4rm7y9n2y8qqqqp7sqqqq8espgsqqqqqqqqqqqqqqqqqqqqq73qqqqq2gpr8hefjt2pqdgsfqcr3r5kcckf6sgtmkwuds8wp5uc7j0zcj0d9lsgl47vl95y25q36nzhqxqsqqzczzqce08lxec8xnm8xmxdyh398kv8dy25vhpcrm47a9ha0vx0qwyn7p0cyqt925k662c9kelq545l944k3j9gdvmkfm2ev2pqpnslmx8qvuwx3jqg4u8ful39aq0tlzujjd2yagjndcd2q42r5hvydx0lxe58mdrgs
{
   "code": 209,
   "message": "Failed after 1 attempts. We got an error from inside the blinded path 0x0x0/1: we assume it means insufficient capacity. Then routing failed: We could not find a usable set of paths.  The shortest path is 858132x1647x1->861005x2291x1->0x0x0, but 0x0x0/1 layer xpay-0 says max is 14999msat"
}
lightning-cli pay lni1qqgv5nalmz08ukj4av074kyk6pepq93pqvvhnlnvurnfanndnxjtcjnmxrkj92xtsupa6lwjm7hkr8s8zflqk5sz82v9gqzcyypu03lyetn3ayp8p5798mz4der4xexkxxxu8ck0m25gmjaaj3n5scaql5q0uquxfmcztl0gldv8mxy3sm8x5jscdz27u39fy6luxu8zcdn9j73l3upaypvngk89elemj7cvu9v57r28k65e4jtlsr0vd66yzwrw2uzyvjczq0sd8fk6vazvrxvnks7hdqkl3lar4ff4a2ccjpltacz8z6tw6lunvqzrlrvyu3rkyylgd0splzr0xs3cccmzmfllyu7k06gclf9wx5n463z5arlwz2frk9a6lnfrvjdh3znsppxc4v8ahdy7e0y3us5rww0lcdxqj6psx87tgwvm3u260gc25frw9c4t368cecy3f5flll87tgk2uva09mncqqe9qqq0vdm023df0eetknvgcxk5yuupg8j5a5jtdmpj0u5unp8f3g2gskpma8l53sd5vmsfcrlr4rm7y9n2y8qqqqp7sqqqq8espgsqqqqqqqqqqqqqqqqqqqqq73qqqqq2gpr8hefjt2pqdgsfqcr3r5kcckf6sgtmkwuds8wp5uc7j0zcj0d9lsgl47vl95y25q36nzhqxqsqqzczzqce08lxec8xnm8xmxdyh398kv8dy25vhpcrm47a9ha0vx0qwyn7p0cyqt925k662c9kelq545l944k3j9gdvmkfm2ev2pqpnslmx8qvuwx3jqg4u8ful39aq0tlzujjd2yagjndcd2q42r5hvydx0lxe58mdrgs
{
   "destination": "031979fe6ce0e69ece6d99a4bc4a7b30ed22a8cb8703dd7dd2dfaf619e07127e0b",
   "payment_hash": "6a209060711d2d8c593a8217bb3b8d81dc1a731e93c5893da5fc11faf99f2d08",
   "created_at": 1740526413.632475833,
   "parts": 1,
   "amount_msat": 16007,
   "amount_sent_msat": 16010,
   "payment_preimage": "c6c75b93dbbdbc5082350a4396afec0232ff4400ea0c9f053b977f4389f501bf",
   "status": "complete"
}
    """
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{'cltv-delta': 50},
                                               {'cltv-delta': 100},
                                               {'cltv-delta': 200}])

    # Connect l3->l4 via private channel, to force blinded path
    l4 = node_factory.get_node(options={'cltv-final': 400})
    node_factory.join_nodes([l3, l4], announce_channels=False)

    # Make sure l4 sees all the gossip
    wait_for(lambda: len(l4.rpc.listchannels()['channels']) == 2 * 2)

    offer = l4.rpc.offer('any')
    inv = l1.rpc.fetchinvoice(offer['bolt12'], '15000msat')['invoice']

    # Inserts a blinded path
    path = only_one(l1.rpc.decode(inv)['invoice_paths'])
    assert path['first_node_id'] == l3.info['id']
    assert len(path['path']) == 2
    assert path['payinfo']['cltv_expiry_delta'] == 200 + 400

    # Make sure l1 is on correct height, so CLTV is as expected.
    sync_blockheight(bitcoind, [l1])

    # This works.
    l1.rpc.pay(inv)
    # CLTV is blockheight (110) + 1 + 100 + 200 + 400
    l1.daemon.wait_for_log(f'Adding HTLC 0 amount=15002msat cltv={110 + 1 + 100 + 200 + 400}')

    inv = l1.rpc.fetchinvoice(offer['bolt12'], '15000msat')['invoice']
    # This doesn't!
    l1.rpc.xpay(inv)
    l1.daemon.wait_for_log(f'Adding HTLC 1 amount=15002msat cltv={110 + 1 + 100 + 200 + 400}')


def test_attempt_notifications(node_factory):
    def zero_fields(obj, fieldnames):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in fieldnames:
                    obj[k] = 0
                else:
                    zero_fields(v, fieldnames)
        elif isinstance(obj, list):
            for item in obj:
                zero_fields(item, fieldnames)
        # other types are ignored
        return obj

    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/custom_notifications.py')
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{"plugin": plugin_path}, {}, {}])

    scid12 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    scid12_dir = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['direction']
    scid23 = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['short_channel_id']
    scid23_dir = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['direction']
    inv1 = l3.rpc.invoice(5000000, 'test_attempt_notifications1', 'test_attempt_notifications1')
    l1.rpc.xpay(inv1['bolt11'])

    line = l1.daemon.wait_for_log("plugin-custom_notifications.py: Got pay_part_start: ")
    dict_str = line.split("Got pay_part_start: ", 1)[1]
    data = zero_fields(ast.literal_eval(dict_str), ['groupid'])
    expected = {'pay_part_start':
                {'payment_hash': inv1['payment_hash'],
                 'groupid': 0,
                 'partid': 1,
                 'total_payment_msat': 5000000,
                 'attempt_msat': 5000000,
                 'hops': [{'next_node': l2.info['id'],
                           'short_channel_id': scid12,
                           'direction': scid12_dir,
                           'channel_in_msat': 5000051,
                           'channel_out_msat': 5000051},
                          {'next_node': l3.info['id'],
                           'short_channel_id': scid23,
                           'direction': scid23_dir,
                           'channel_in_msat': 5000051,
                           'channel_out_msat': 5000000}]}}
    assert data == expected

    line = l1.daemon.wait_for_log("plugin-custom_notifications.py: Got pay_part_end: ")
    dict_str = line.split("Got pay_part_end: ", 1)[1]
    data = zero_fields(ast.literal_eval(dict_str), ('duration', 'groupid'))
    expected = {'pay_part_end':
                {'payment_hash': inv1['payment_hash'],
                 'status': 'success',
                 'duration': 0,
                 'groupid': 0,
                 'partid': 1}}
    assert data == expected

    inv2 = l3.rpc.invoice(10000000, 'test_attempt_notifications2', 'test_attempt_notifications2')
    l3.rpc.delinvoice('test_attempt_notifications2', "unpaid")

    # Final node failure
    with pytest.raises(RpcError, match=r"Destination said it doesn't know invoice: incorrect_or_unknown_payment_details"):
        l1.rpc.xpay(inv2['bolt11'])

    line = l1.daemon.wait_for_log("plugin-custom_notifications.py: Got pay_part_start: ")
    dict_str = line.split("Got pay_part_start: ", 1)[1]
    data = zero_fields(ast.literal_eval(dict_str), ['groupid'])
    expected = {'pay_part_start':
                {'payment_hash': inv2['payment_hash'],
                 'groupid': 0,
                 'partid': 1,
                 'total_payment_msat': 10000000,
                 'attempt_msat': 10000000,
                 'hops': [{'next_node': l2.info['id'],
                           'short_channel_id': scid12,
                           'direction': scid12_dir,
                           'channel_in_msat': 10000101,
                           'channel_out_msat': 10000101},
                          {'next_node': l3.info['id'],
                           'short_channel_id': scid23,
                           'direction': scid23_dir,
                           'channel_in_msat': 10000101,
                           'channel_out_msat': 10000000}]}}
    assert data == expected

    line = l1.daemon.wait_for_log("plugin-custom_notifications.py: Got pay_part_end: ")
    dict_str = line.split("Got pay_part_end: ", 1)[1]
    data = zero_fields(ast.literal_eval(dict_str), ('duration', 'groupid'))
    expected = {'pay_part_end':
                {'payment_hash': inv2['payment_hash'],
                 'status': 'failure',
                 'duration': 0,
                 'groupid': 0,
                 'partid': 1,
                 'failed_msg': '400f00000000009896800000006c',
                 'failed_node_id': l3.info['id'],
                 'error_code': 16399,
                 'error_message': 'incorrect_or_unknown_payment_details'}}
    assert data == expected

    # Intermediary node failure
    l3.stop()
    with pytest.raises(RpcError, match=r"Failed after 1 attempts"):
        l1.rpc.xpay(inv2['bolt11'])

    line = l1.daemon.wait_for_log("plugin-custom_notifications.py: Got pay_part_start: ")
    dict_str = line.split("Got pay_part_start: ", 1)[1]
    data = zero_fields(ast.literal_eval(dict_str), ['groupid'])
    expected = {'pay_part_start':
                {'payment_hash': inv2['payment_hash'],
                 'groupid': 0,
                 'partid': 1,
                 'total_payment_msat': 10000000,
                 'attempt_msat': 10000000,
                 'hops': [{'next_node': l2.info['id'],
                           'short_channel_id': scid12,
                           'direction': scid12_dir,
                           'channel_in_msat': 10000101,
                           'channel_out_msat': 10000101},
                          {'next_node': l3.info['id'],
                           'short_channel_id': scid23,
                           'direction': scid23_dir,
                           'channel_in_msat': 10000101,
                           'channel_out_msat': 10000000}]}}
    assert data == expected

    line = l1.daemon.wait_for_log("plugin-custom_notifications.py: Got pay_part_end: ")
    dict_str = line.split("Got pay_part_end: ", 1)[1]
    data = zero_fields(ast.literal_eval(dict_str), ('duration', 'groupid', 'failed_msg'))
    expected = {'pay_part_end':
                {'payment_hash': inv2['payment_hash'],
                 'status': 'failure',
                 'duration': 0,
                 'groupid': 0,
                 'partid': 1,
                 # This includes the channel update: just zero it out
                 'failed_msg': 0,
                 'failed_direction': 0,
                 'failed_node_id': l2.info['id'],
                 'failed_short_channel_id': scid23,
                 'error_code': 4103,
                 'error_message': 'temporary_channel_failure'}}
    assert data == expected


def test_xpay_offer(node_factory):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    offer1 = l3.rpc.offer('any')['bolt12']
    offer2 = l3.rpc.offer('5sat', "5sat donation")['bolt12']

    with pytest.raises(RpcError, match=r"Must specify amount for this offer"):
        l1.rpc.xpay(offer1)

    l1.rpc.xpay(offer1, 100)

    with pytest.raises(RpcError, match=r"Offer amount is 5000msat, you tried to pay 1000msat"):
        l1.rpc.xpay(offer2, 1000)

    l1.rpc.xpay(offer2)
    l1.rpc.xpay(offer2, 5000)


def test_xpay_bip353(node_factory):
    fakebip353_plugin = Path(__file__).parent / "plugins" / "fakebip353.py"

    l1 = node_factory.get_node()
    offer = l1.rpc.offer('any')['bolt12']

    l2 = node_factory.get_node(options={'disable-plugin': 'cln-bip353',
                                        'plugin': fakebip353_plugin,
                                        'bip353offer': offer})

    node_factory.join_nodes([l2, l1])
    l2.rpc.xpay('fake@fake.com', 100)


def test_xpay_limited_max_accepted_htlcs(node_factory):
    """xpay should try to reduce flows to 6 if there is an unannounced channel, and only try more if that fails"""
    CHANNEL_SIZE_SATS = 10**6
    l1, l2 = node_factory.line_graph(2,
                                     fundamount=CHANNEL_SIZE_SATS * 20,
                                     opts=[{}, {'max-concurrent-htlcs': 6}],
                                     announce_channels=False)

    # We want 10 paths between l3 and l1.
    l3 = node_factory.get_node()
    nodes = node_factory.get_nodes(10)
    for n in nodes:
        node_factory.join_nodes([l3, n, l1], fundamount=CHANNEL_SIZE_SATS)

    # We don't want to use up capacity, so we make payment fail.
    inv1 = l1.rpc.invoice(f"{CHANNEL_SIZE_SATS * 5}sat",
                          'test_xpay_limited_max_accepted_htlcs',
                          'test_xpay_limited_max_accepted_htlcs')['bolt11']
    l1.rpc.delinvoice('test_xpay_limited_max_accepted_htlcs', 'unpaid')

    with pytest.raises(RpcError, match="Destination said it doesn't know invoice"):
        l3.rpc.xpay(inv1)

    # 7 flows.
    l3.daemon.wait_for_log('Final answer has 7 flows')

    # Make sure xpay has completely finished!
    wait_for(lambda: l3.rpc.askrene_listreservations() == {'reservations': []})

    # If we have a routehint, it will squeeze into 6.
    inv2 = l2.rpc.invoice(f"{CHANNEL_SIZE_SATS * 5}sat",
                          'test_xpay_limited_max_accepted_htlcs',
                          'test_xpay_limited_max_accepted_htlcs')['bolt11']
    l2.rpc.delinvoice('test_xpay_limited_max_accepted_htlcs', 'unpaid')
    with pytest.raises(RpcError, match="Destination said it doesn't know invoice"):
        l3.rpc.xpay(inv2)

    # 6 flows.
    l3.daemon.wait_for_log('Final answer has 6 flows')

    # Make sure xpay has completely finished!
    wait_for(lambda: l3.rpc.askrene_listreservations() == {'reservations': []})

    # If we force it, it will use more flows.  And fail on 7th part!
    inv2 = l2.rpc.invoice(f"{CHANNEL_SIZE_SATS * 6}sat",
                          'test_xpay_limited_max_accepted_htlcs2',
                          'test_xpay_limited_max_accepted_htlcs2')['bolt11']
    with pytest.raises(RpcError, match="We got temporary_channel_failure"):
        l3.rpc.xpay(inv2)
    l3.daemon.wait_for_log('Final answer has 7 flows')


def test_xpay_blockheight_mismatch(node_factory, bitcoind, executor):
    """We should wait a (reasonable) amount if the final node gives us a blockheight that would explain our failure."""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)
    sync_blockheight(bitcoind, [l1, l2, l3])

    # Pin `send` at the current height. by not returning the next
    # blockhash. This error is special-cased not to count as the
    # backend failing since it is used to poll for the next block.
    def mock_getblockhash(req):
        return {
            "id": req['id'],
            "error": {
                "code": -8,
                "message": "Block height out of range"
            }
        }

    l1.daemon.rpcproxy.mock_rpc('getblockhash', mock_getblockhash)
    bitcoind.generate_block(4)
    sync_blockheight(bitcoind, [l2, l3])
    l1_height = l1.rpc.getinfo()['blockheight']
    l3_height = l3.rpc.getinfo()['blockheight']

    inv = l3.rpc.invoice(42, 'lbl', 'desc')['bolt11']

    # This will wait, then fail.
    with pytest.raises(RpcError, match=f'Timed out waiting for blockheight {l3_height}'):
        l1.rpc.xpay(invstring=inv, retry_for=10)

    # This will succeed, because we wait for the blocks.
    fut = executor.submit(l1.rpc.xpay, invstring=inv, retry_for=60)
    l1.daemon.wait_for_log(fr"Our blockheight may be too low: waiting .* seconds for height {l3_height} \(we are at {l1_height}\)")

    # Now let it catch up, and it will retry, and succeed.
    l1.daemon.rpcproxy.mock_rpc('getblockhash')
    fut.result(TIMEOUT)
