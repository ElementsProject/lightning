from binascii import hexlify
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from flaky import flaky  # noqa: F401
from io import BytesIO
from pyln.client import RpcError, Millisatoshi
from pyln.proto.onion import TlvPayload
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND, FUNDAMOUNT
from utils import (
    DEVELOPER, wait_for, only_one, sync_blockheight, TIMEOUT,
    EXPERIMENTAL_FEATURES, env, VALGRIND, mine_funding_to_announce
)
import copy
import os
import pytest
import random
import re
import string
import struct
import subprocess
import time
import unittest


@pytest.mark.developer("needs to deactivate shadow routing")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_pay(node_factory):
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(123000, 'test_pay', 'description')['bolt11']
    before = int(time.time())
    details = l1.rpc.dev_pay(inv, use_shadow=False)
    after = time.time()
    preimage = details['payment_preimage']
    assert details['status'] == 'complete'
    assert details['msatoshi'] == 123000
    assert details['destination'] == l2.info['id']
    assert details['created_at'] >= before
    assert details['created_at'] <= after

    invoices = l2.rpc.listinvoices('test_pay')['invoices']
    assert len(invoices) == 1
    invoice = invoices[0]
    assert invoice['status'] == 'paid' and invoice['paid_at'] >= before and invoice['paid_at'] <= after

    # Repeat payments are NOPs (if valid): we can hand null.
    l1.rpc.dev_pay(inv, use_shadow=False)
    # This won't work: can't provide an amount (even if correct!)
    with pytest.raises(RpcError):
        l1.rpc.pay(inv, 123000)
    with pytest.raises(RpcError):
        l1.rpc.pay(inv, 122000)

    # Check pay_index is not null
    outputs = l2.db_query('SELECT pay_index IS NOT NULL AS q FROM invoices WHERE label="label";')
    assert len(outputs) == 1 and outputs[0]['q'] != 0

    # Check payment of any-amount invoice.
    for i in range(5):
        label = "any{}".format(i)
        inv2 = l2.rpc.invoice("any", label, 'description')['bolt11']
        # Must provide an amount!
        with pytest.raises(RpcError):
            l1.rpc.pay(inv2)
        l1.rpc.dev_pay(inv2, random.randint(1000, 999999), use_shadow=False)

    # Should see 6 completed payments
    assert len(l1.rpc.listsendpays()['payments']) == 6

    # Test listsendpays indexed by bolt11.
    payments = l1.rpc.listsendpays(inv)['payments']
    assert len(payments) == 1 and payments[0]['payment_preimage'] == preimage


@pytest.mark.developer("needs to deactivate shadow routing")
def test_pay_amounts(node_factory):
    l1, l2 = node_factory.line_graph(2)
    inv = l2.rpc.invoice(Millisatoshi("123sat"), 'test_pay_amounts', 'description')['bolt11']

    invoice = only_one(l2.rpc.listinvoices('test_pay_amounts')['invoices'])

    assert isinstance(invoice['amount_msat'], Millisatoshi)
    assert invoice['amount_msat'] == Millisatoshi(123000)

    l1.rpc.dev_pay(inv, use_shadow=False)

    invoice = only_one(l2.rpc.listinvoices('test_pay_amounts')['invoices'])
    assert isinstance(invoice['amount_received_msat'], Millisatoshi)
    assert invoice['amount_received_msat'] >= Millisatoshi(123000)


@pytest.mark.developer("needs to deactivate shadow routing")
def test_pay_limits(node_factory, compat):
    """Test that we enforce fee max percentage and max delay"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    # FIXME: pylightning should define these!
    PAY_STOPPED_RETRYING = 210

    inv = l3.rpc.invoice("any", "any", 'description')

    # Fee too high.
    err = r'Fee exceeds our fee budget: [1-9]msat > 0msat, discarding route'
    with pytest.raises(RpcError, match=err) as err:
        l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'msatoshi': 100000, 'maxfeepercent': 0.0001, 'exemptfee': 0})

    assert err.value.error['code'] == PAY_STOPPED_RETRYING

    # It should have retried two more times (one without routehint and one with routehint)
    status = l1.rpc.call('paystatus', {'bolt11': inv['bolt11']})['pay'][0]['attempts']

    # We have an internal test to see if we can reach the destination directly
    # without a routehint, that will enable a NULL-routehint. We will then try
    # with the provided routehint, and the NULL routehint, resulting in 2
    # attempts.
    assert(len(status) == 2)
    assert(status[0]['failure']['code'] == 205)

    failmsg = r'CLTV delay exceeds our CLTV budget'
    # Delay too high.
    with pytest.raises(RpcError, match=failmsg) as err:
        l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'msatoshi': 100000, 'maxdelay': 0})

    assert err.value.error['code'] == PAY_STOPPED_RETRYING
    # Should also have retried two more times.
    status = l1.rpc.call('paystatus', {'bolt11': inv['bolt11']})['pay'][1]['attempts']

    assert(len(status) == 2)
    assert(status[0]['failure']['code'] == 205)

    # This works, because fee is less than exemptfee.
    l1.rpc.dev_pay(inv['bolt11'], msatoshi=100000, maxfeepercent=0.0001,
                   exemptfee=2000, use_shadow=False)
    status = l1.rpc.call('paystatus', {'bolt11': inv['bolt11']})['pay'][2]['attempts']
    assert len(status) == 1
    assert status[0]['strategy'] == "Initial attempt"


@pytest.mark.developer("Gossip is too slow without developer")
def test_pay_exclude_node(node_factory, bitcoind):
    """Test excluding the node if there's the NODE-level error in the failure_code
    """
    # FIXME: Remove our reliance on HTLCs failing on startup and the need for
    #        this plugin
    opts = [
        {'disable-mpp': None},
        {'plugin': os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')},
        {},
        {'fee-base': 100, 'fee-per-satoshi': 1000},
        {}
    ]
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5, opts=opts)
    node_factory.join_nodes([l1, l2, l3], wait_for_announce=True)
    amount = 10**8

    inv = l3.rpc.invoice(amount, "test1", 'description')['bolt11']
    with pytest.raises(RpcError):
        l1.rpc.pay(inv)

    # It should have retried (once without routehint, too)
    status = l1.rpc.call('paystatus', {'bolt11': inv})['pay'][0]['attempts']

    # Excludes channel, then ignores routehint which includes that, then
    # it excludes other channel.
    assert len(status) == 2
    assert status[0]['strategy'] == "Initial attempt"
    assert status[0]['failure']['data']['failcodename'] == 'WIRE_TEMPORARY_NODE_FAILURE'
    assert 'failure' in status[1]

    # Get a fresh invoice, but do it before other routes exist, so routehint
    # will be via l2.
    inv = l3.rpc.invoice(amount, "test2", 'description')['bolt11']
    assert only_one(l1.rpc.decodepay(inv)['routes'])[0]['pubkey'] == l2.info['id']

    # l1->l4->l5->l3 is the longer route. This makes sure this route won't be
    # tried for the first pay attempt. Just to be sure we also raise the fees
    # that l4 leverages.
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
    l4.rpc.connect(l5.info['id'], 'localhost', l5.port)
    l5.rpc.connect(l3.info['id'], 'localhost', l3.port)
    scid14, _ = l1.fundchannel(l4, 10**6, wait_for_active=False)
    scid45, _ = l4.fundchannel(l5, 10**6, wait_for_active=False)
    scid53, _ = l5.fundchannel(l3, 10**6, wait_for_active=False)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5])

    l1.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scid14),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid14),
                             r'update for channel {}/0 now ACTIVE'
                             .format(scid45),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid45),
                             r'update for channel {}/0 now ACTIVE'
                             .format(scid53),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid53)])

    # This `pay` will work
    l1.rpc.pay(inv)

    # It should have retried (once without routehint, too)
    status = l1.rpc.call('paystatus', {'bolt11': inv})['pay'][0]['attempts']

    # Excludes channel, then ignores routehint which includes that, then
    # it excludes other channel.
    assert len(status) == 2
    assert status[0]['strategy'] == "Initial attempt"
    assert status[0]['failure']['data']['failcodename'] == 'WIRE_TEMPORARY_NODE_FAILURE'
    assert 'success' in status[1]


def test_pay0(node_factory):
    """Test paying 0 amount
    """
    l1, l2 = node_factory.line_graph(2)
    chanid = l1.get_channel_scid(l2)

    # Get any-amount invoice
    inv = l2.rpc.invoice("any", "any", 'description')
    rhash = inv['payment_hash']

    routestep = {
        'msatoshi': 0,
        'id': l2.info['id'],
        'delay': 10,
        'channel': chanid
    }

    # Amount must be nonzero!
    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'WIRE_AMOUNT_BELOW_MINIMUM'):
        l1.rpc.waitsendpay(rhash)


@pytest.mark.developer("needs DEVELOPER=1")
def test_pay_disconnect(node_factory, bitcoind):
    """If the remote node has disconnected, we fail payment, but can try again when it reconnects"""
    l1, l2 = node_factory.line_graph(2, opts={'dev-max-fee-multiplier': 5,
                                              'may_reconnect': True,
                                              'allow_warning': True})

    # Dummy payment to kick off update_fee messages
    l1.pay(l2, 1000)

    inv = l2.rpc.invoice(123000, 'test_pay_disconnect', 'description')
    rhash = inv['payment_hash']

    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])

    # Can't use `pay` since that'd notice that we can't route, due to disabling channel_update
    route = l1.rpc.getroute(l2.info['id'], 123000, 1)["route"]

    l2.stop()
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)

    # Can't pay while its offline.
    with pytest.raises(RpcError, match=r'failed: WIRE_TEMPORARY_CHANNEL_FAILURE \(First peer not ready\)'):
        l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])

    l2.start()
    l1.daemon.wait_for_log('peer_out WIRE_CHANNEL_REESTABLISH')

    # Make l2 upset by asking for crazy fee.
    l1.set_feerates((10**6, 10**6, 10**6, 10**6), False)

    # Wait for l1 notice
    l1.daemon.wait_for_log(r'Peer transient failure in CHANNELD_NORMAL: channeld WARNING: .*: update_fee \d+ outside range 1875-75000')

    # Make l2 fail hard.
    l2.rpc.close(l1.info['id'], unilateraltimeout=1)
    l2.daemon.wait_for_log('sendrawtx exit')
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])

    # Should fail due to permenant channel fail
    with pytest.raises(RpcError, match=r'WIRE_UNKNOWN_NEXT_PEER'):
        l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])

    assert not l1.daemon.is_in_log('Payment is still in progress')

    # After it sees block, someone should close channel.
    l1.daemon.wait_for_log('ONCHAIN')


@pytest.mark.developer("needs DEVELOPER=1 for dev_suppress_gossip")
def test_pay_get_error_with_update(node_factory):
    """We should process an update inside a temporary_channel_failure"""
    l1, l2, l3 = node_factory.line_graph(3, opts={'log-level': 'io'}, fundchannel=True, wait_for_announce=True)
    chanid2 = l2.get_channel_scid(l3)

    inv = l3.rpc.invoice(123000, 'test_pay_get_error_with_update', 'description')

    # Make sure l2 doesn't tell l1 directly that channel is disabled.
    l2.rpc.dev_suppress_gossip()
    l3.stop()

    # Make sure that l2 has seen disconnect, considers channel disabled.
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels(chanid2)['channels']] == [False, False])

    assert(l1.is_channel_active(chanid2))
    with pytest.raises(RpcError, match=r'WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.pay(inv['bolt11'])

    # Make sure we get an onionreply, without the type prefix of the nested
    # channel_update, and it should patch it to include a type prefix. The
    # prefix 0x0102 should be in the channel_update, but not in the
    # onionreply (negation of 0x0102 in the RE)
    l1.daemon.wait_for_log(r'Extracted channel_update 0102.*from onionreply 1007008a[0-9a-fA-F]{276}$')

    # And now monitor for l1 to apply the channel_update we just extracted
    wait_for(lambda: not l1.is_channel_active(chanid2))


@pytest.mark.developer("needs to deactivate shadow routing")
def test_pay_optional_args(node_factory, compat):
    l1, l2 = node_factory.line_graph(2)

    inv1 = l2.rpc.invoice(123000, 'test_pay', 'desc')['bolt11']
    l1.rpc.dev_pay(inv1, label='desc', use_shadow=False)
    payment1 = l1.rpc.listsendpays(inv1)['payments']
    assert len(payment1) and payment1[0]['msatoshi_sent'] == 123000
    assert payment1[0]['label'] == 'desc'

    inv2 = l2.rpc.invoice(321000, 'test_pay2', 'description')['bolt11']
    l1.rpc.dev_pay(inv2, riskfactor=5.0, use_shadow=False)
    payment2 = l1.rpc.listsendpays(inv2)['payments']
    assert(len(payment2) == 1)
    # The pay plugin uses `sendonion` since 0.9.0 and `lightningd` doesn't
    # learn about the amount we intended to send (that's why we annotate the
    # root of a payment tree with the bolt11 invoice).

    anyinv = l2.rpc.invoice('any', 'any_pay', 'desc')['bolt11']
    l1.rpc.dev_pay(anyinv, label='desc', msatoshi='500', use_shadow=False)
    payment3 = l1.rpc.listsendpays(anyinv)['payments']
    assert len(payment3) == 1
    assert payment3[0]['label'] == 'desc'

    # Should see 3 completed transactions
    assert len(l1.rpc.listsendpays()['payments']) == 3


@pytest.mark.developer("needs to deactivate shadow routing")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_payment_success_persistence(node_factory, bitcoind, executor):
    # Start two nodes and open a channel.. die during payment.
    # Feerates identical so we don't get gratuitous commit to update them
    disconnect = ['+WIRE_COMMITMENT_SIGNED']
    if EXPERIMENTAL_DUAL_FUND:
        # We have to add an extra 'wire-commitment-signed' because
        # dual funding uses this for channel establishment also
        disconnect = ['=WIRE_COMMITMENT_SIGNED'] + disconnect

    l1 = node_factory.get_node(disconnect=disconnect,
                               options={'dev-no-reconnect': None},
                               may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    chanid, _ = l1.fundchannel(l2, 100000)

    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')

    # Fire off a pay request, it'll get interrupted by a restart
    executor.submit(l1.rpc.dev_pay, inv1['bolt11'], use_shadow=False)

    l1.daemon.wait_for_log(r'dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    print("Killing l1 in mid HTLC")
    l1.daemon.kill()

    # Restart l1, without disconnect stuff.
    del l1.daemon.opts['dev-no-reconnect']
    del l1.daemon.opts['dev-disconnect']

    # Should reconnect, and sort the payment out.
    l1.start()

    wait_for(lambda: l1.rpc.listsendpays()['payments'][0]['status'] != 'pending')

    payments = l1.rpc.listsendpays()['payments']
    invoices = l2.rpc.listinvoices('inv1')['invoices']
    assert len(payments) == 1 and payments[0]['status'] == 'complete'
    assert len(invoices) == 1 and invoices[0]['status'] == 'paid'

    l1.wait_channel_active(chanid)

    # A duplicate should succeed immediately (nop) and return correct preimage.
    preimage = l1.rpc.dev_pay(inv1['bolt11'],
                              use_shadow=False)['payment_preimage']
    assert l1.rpc.dev_rhash(preimage)['rhash'] == inv1['payment_hash']


@pytest.mark.developer("needs DEVELOPER=1")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_payment_failed_persistence(node_factory, executor):
    # Start two nodes and open a channel.. die during payment.
    # Feerates identical so we don't get gratuitous commit to update them
    disconnect = ['+WIRE_COMMITMENT_SIGNED']
    if EXPERIMENTAL_DUAL_FUND:
        # We have to add an extra 'wire-commitment-signed' because
        # dual funding uses this for channel establishment also
        disconnect = ['=WIRE_COMMITMENT_SIGNED'] + disconnect
    l1 = node_factory.get_node(disconnect=disconnect,
                               options={'dev-no-reconnect': None},
                               may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 100000)

    # Expires almost immediately, so it will fail.
    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1', 5)

    # Fire off a pay request, it'll get interrupted by a restart
    executor.submit(l1.rpc.pay, inv1['bolt11'])

    l1.daemon.wait_for_log(r'dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    print("Killing l1 in mid HTLC")
    l1.daemon.kill()

    # Restart l1, without disconnect stuff.
    del l1.daemon.opts['dev-no-reconnect']
    del l1.daemon.opts['dev-disconnect']

    # Make sure invoice has expired.
    time.sleep(5 + 1)

    # Should reconnect, and fail the payment
    l1.start()

    wait_for(lambda: l1.rpc.listsendpays()['payments'][0]['status'] != 'pending')

    payments = l1.rpc.listsendpays()['payments']
    invoices = l2.rpc.listinvoices('inv1')['invoices']
    assert len(invoices) == 1 and invoices[0]['status'] == 'expired'
    assert len(payments) == 1 and payments[0]['status'] == 'failed'

    # Another attempt should also fail.
    with pytest.raises(RpcError):
        l1.rpc.pay(inv1['bolt11'])


@pytest.mark.developer("needs DEVELOPER=1")
def test_payment_duplicate_uncommitted(node_factory, executor):
    # We want to test two payments at the same time, before we send commit
    l1 = node_factory.get_node(options={'dev-disable-commit-after': 0})
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 100000)

    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')

    # Start first payment, but not yet in db.
    fut = executor.submit(l1.rpc.pay, inv1['bolt11'])

    # Make sure that's started...
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_ADD_HTLC')

    # We should see it in listsendpays
    payments = l1.rpc.listsendpays()['payments']
    assert len(payments) == 1
    assert payments[0]['status'] == 'pending' and payments[0]['payment_hash'] == inv1['payment_hash']

    # Second one will succeed eventually.
    fut2 = executor.submit(l1.rpc.pay, inv1['bolt11'])

    # Now, let it commit.
    l1.rpc.dev_reenable_commit(l2.info['id'])

    # These should succeed.
    fut.result(TIMEOUT)
    fut2.result(TIMEOUT)


@pytest.mark.developer("Too slow without --dev-fast-gossip")
def test_pay_maxfee_shadow(node_factory):
    """Test that we respect maxfeepercent for shadow routing."""
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=True,
                                         wait_for_announce=True)
    # We use this to search for shadow routes
    wait_for(
        lambda: len(l1.rpc.listchannels(source=l2.info["id"])["channels"]) > 1
    )

    # shadow routes are random, so run multiple times.
    for i in range(5):
        # A tiny amount, we must not add the base_fee between l2 and l3
        amount = 2
        bolt11 = l2.rpc.invoice(amount, "tiny.{}".format(i), "tiny")["bolt11"]
        pay_status = l1.rpc.pay(bolt11)
        assert pay_status["amount_msat"] == Millisatoshi(amount)

    # shadow routes are random, so run multiple times.
    for i in range(5):
        # A bigger amount, shadow routing could have been used but we set a low
        # maxfeepercent.
        amount = 20000
        bolt11 = l2.rpc.invoice(amount, "big.{}".format(i), "bigger")["bolt11"]
        pay_status = l1.rpc.pay(bolt11, maxfeepercent="0.000001")
        assert pay_status["amount_msat"] == Millisatoshi(amount)


def test_sendpay(node_factory):
    l1, l2 = node_factory.line_graph(2, fundamount=10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'testpayment2', 'desc')
    rhash = inv['payment_hash']

    def invoice_unpaid(dst, label):
        invoices = dst.rpc.listinvoices(label)['invoices']
        return len(invoices) == 1 and invoices[0]['status'] == 'unpaid'

    routestep = {
        'msatoshi': amt,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    # Insufficient funds.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] - 1
        l1.rpc.sendpay([rs], rhash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Gross overpayment (more than factor of 2)
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] * 2 + 1
        l1.rpc.sendpay([rs], rhash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Insufficient delay.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['delay'] = rs['delay'] - 2
        l1.rpc.sendpay([rs], rhash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Bad ID.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['id'] = '00000000000000000000000000000000'
        l1.rpc.sendpay([rs], rhash, payment_secret=inv['payment_secret'])
    assert invoice_unpaid(l2, 'testpayment2')

    # Bad payment_secret
    l1.rpc.sendpay([routestep], rhash, payment_secret="00" * 32)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Missing payment_secret
    l1.rpc.sendpay([routestep], rhash)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # FIXME: test paying via another node, should fail to pay twice.
    p1 = l1.rpc.getpeer(l2.info['id'], 'info')
    p2 = l2.rpc.getpeer(l1.info['id'], 'info')
    assert only_one(p1['channels'])['msatoshi_to_us'] == 10**6 * 1000
    assert only_one(p1['channels'])['msatoshi_total'] == 10**6 * 1000
    assert only_one(p2['channels'])['msatoshi_to_us'] == 0
    assert only_one(p2['channels'])['msatoshi_total'] == 10**6 * 1000

    # This works.
    before = int(time.time())
    details = l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    after = int(time.time())
    preimage = l1.rpc.waitsendpay(rhash)['payment_preimage']
    # Check details
    assert details['payment_hash'] == rhash
    assert details['destination'] == l2.info['id']
    assert details['msatoshi'] == amt
    assert details['created_at'] >= before
    assert details['created_at'] <= after
    # Check receiver
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['pay_index'] == 1
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['msatoshi_received'] == rs['msatoshi']
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['payment_preimage'] == preimage

    # Balances should reflect it.
    def check_balances():
        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        return (
            only_one(p1['channels'])['msatoshi_to_us'] == 10**6 * 1000 - amt
            and only_one(p1['channels'])['msatoshi_total'] == 10**6 * 1000
            and only_one(p2['channels'])['msatoshi_to_us'] == amt
            and only_one(p2['channels'])['msatoshi_total'] == 10**6 * 1000
        )
    wait_for(check_balances)

    # Repeat will "succeed", but won't actually send anything (duplicate)
    assert not l1.daemon.is_in_log('Payment ./.: .* COMPLETE')
    details = l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    assert details['status'] == "complete"
    preimage2 = details['payment_preimage']
    assert preimage == preimage2
    l1.daemon.wait_for_log('Payment ./.: .* COMPLETE')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['msatoshi_received'] == rs['msatoshi']

    # Overpaying by "only" a factor of 2 succeeds.
    inv = l2.rpc.invoice(amt, 'testpayment3', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['status'] == 'unpaid'
    routestep = {'msatoshi': amt * 2, 'id': l2.info['id'], 'delay': 5, 'channel': '1x1x1'}
    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    preimage3 = l1.rpc.waitsendpay(rhash)['payment_preimage']
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['msatoshi_received'] == amt * 2

    # Test listsendpays
    payments = l1.rpc.listsendpays()['payments']
    assert len(payments) == 7  # Failed attempts also create entries, but with a different groupid

    invoice2 = only_one(l2.rpc.listinvoices('testpayment2')['invoices'])
    payments = l1.rpc.listsendpays(payment_hash=invoice2['payment_hash'])['payments']
    assert len(payments) == 6  # Failed attempts also create entries, but with a different groupid

    assert payments[-1]['status'] == 'complete'
    assert payments[-1]['payment_preimage'] == preimage2

    invoice3 = only_one(l2.rpc.listinvoices('testpayment3')['invoices'])
    payments = l1.rpc.listsendpays(payment_hash=invoice3['payment_hash'])['payments']
    assert len(payments) == 1

    assert payments[-1]['status'] == 'complete'
    assert payments[-1]['payment_preimage'] == preimage3


@unittest.skipIf(TEST_NETWORK != 'regtest', "The reserve computation is bitcoin specific")
def test_sendpay_cant_afford(node_factory):
    # Set feerates the same so we don't have to wait for update.
    l1, l2 = node_factory.line_graph(2, fundamount=10**6,
                                     opts={'feerates': (15000, 15000, 15000, 15000)})

    # Can't pay more than channel capacity.
    with pytest.raises(RpcError):
        l1.pay(l2, 10**9 + 1)

    # Reserve is 1%.
    reserve = 10**7

    # # This is how we recalc constants (v. v. slow!)
    # minimum = 1
    # maximum = 10**9
    # while maximum - minimum > 1:
    #     l1, l2 = node_factory.line_graph(2, fundamount=10**6,
    #                                      opts={'feerates': (15000, 15000, 15000, 15000)})
    #     try:
    #         l1.pay(l2, (minimum + maximum) // 2)
    #         minimum = (minimum + maximum) // 2
    #     except RpcError:
    #         maximum = (minimum + maximum) // 2
    #     print("{} - {}".format(minimum, maximum))
    # assert False

    # This is the fee, which needs to be taken into account for l1.
    if EXPERIMENTAL_FEATURES:
        # option_anchor_outputs
        available = 10**9 - 44700000
    else:
        available = 10**9 - 32040000

    # Can't pay past reserve.
    with pytest.raises(RpcError):
        l1.pay(l2, available)
    with pytest.raises(RpcError):
        l1.pay(l2, available - reserve + 1)

    # Can pay up to reserve (1%)
    l1.pay(l2, available - reserve)

    # And now it can't pay back, due to its own reserve.
    with pytest.raises(RpcError):
        l2.pay(l1, available - reserve)

    # But this should work.
    l2.pay(l1, available - reserve * 2)


def test_decodepay(node_factory):
    l1 = node_factory.get_node()

    # BOLT #11:
    # > ### Please make a donation of any amount using payment_hash 0001020304050607080900010203040506070809000102030405060708090102 to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
    # > lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash
    #   * `p5`: `data_length` (`p` = 1, `5` = 20. 1 * 32 + 20 == 52)
    #   * `qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq`: payment hash 0001020304050607080900010203040506070809000102030405060708090102
    # * `d`: short description
    #   * `pl`: `data_length` (`p` = 1, `l` = 31. 1 * 32 + 31 == 63)
    #   * `2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq`: 'Please consider supporting this project'
    # * `32vjcgqxyuj7nqphl3xmmhls2rkl3t97uan4j0xa87gj5779czc8p0z58zf5wpt9ggem6adl64cvawcxlef9djqwp2jzzfvs272504sp`: signature
    # * `0lkg3c`: Bech32 checksum
    b11 = l1.rpc.decodepay(
        'lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd'
        'pl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rk'
        'x3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatg'
        'ddc6k63n7erqz25le42c4u4ecky03ylcqca784w'
    )
    assert b11['currency'] == 'bc'
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['description'] == 'Please consider supporting this project'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'

    # BOLT #11:
    # > ### Please send $3 for a cup of coffee to the same peer, within 1 minute
    # > lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `2500u`: amount (2500 micro-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `d`: short description
    #   * `q5`: `data_length` (`q` = 0, `5` = 20. 0 * 32 + 20 == 20)
    #   * `xysxxatsyp3k7enxv4js`: '1 cup coffee'
    # * `x`: expiry time
    #   * `qz`: `data_length` (`q` = 0, `z` = 2. 0 * 32 + 2 == 2)
    #   * `pu`: 60 seconds (`p` = 1, `u` = 28.  1 * 32 + 28 == 60)
    # * `azh8qt5w7qeewkmxtv55khqxvdfs9zzradsvj7rcej9knpzdwjykcq8gv4v2dl705pjadhpsc967zhzdpuwn5qzjm0s4hqm2u0vuhhqq`: signature
    # * `7vc09u`: Bech32 checksum
    b11 = l1.rpc.decodepay(
        'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf'
        'qypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cq'
        'v3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rsp'
        'fj9srp'
    )
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 2500 * 10**11 // 1000000
    assert b11['amount_msat'] == Millisatoshi(2500 * 10**11 // 1000000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['description'] == '1 cup coffee'
    assert b11['expiry'] == 60
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'

    # BOLT #11:
    # > ### Now send $24 for an entire list of things (hashed)
    # > lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `20m`: amount (20 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `h`: tagged field: hash of description
    # * `p5`: `data_length` (`p` = 1, `5` = 20. 1 * 32 + 20 == 52)
    # * `8yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs`: SHA256 of 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon'
    # * `vjfls3ljx9e93jkw0kw40yxn4pevgzflf83qh2852esjddv4xk4z70nehrdcxa4fk0t6hlcc6vrxywke6njenk7yzkzw0quqcwxphkcp`: signature
    # * `vam37w`: Bech32 checksum
    b11 = l1.rpc.decodepay(
        'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy'
        'pqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jr'
        'c5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf'
        '4sefvf9sygkshp5zfem29trqq2yxxz7',
        'One piece of chocolate cake, one icecream cone, one pickle, one slic'
        'e of swiss cheese, one slice of salami, one lollypop, one piece of c'
        'herry pie, one sausage, one cupcake, and one slice of watermelon'
    )
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 20 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(str(20 * 10**11 // 1000) + 'msat')
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'

    # > ### The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP
    # > lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t
    #
    # Breakdown:
    #
    # * `lntb`: prefix, lightning on bitcoin testnet
    # * `20m`: amount (20 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `f`: tagged field: fallback address
    # * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
    # * `3x9et2e20v6pu37c5d9vax37wxq72un98`: `3` = 17, so P2PKH address
    # * `h`: tagged field: hash of description...
    # * `qh84fmvn2klvglsjxfy0vq2mz6t9kjfzlxfwgljj35w2kwa60qv49k7jlsgx43yhs9nuutllkhhnt090mmenuhp8ue33pv4klmrzlcqp`: signature
    # * `us2s2r`: Bech32 checksum
    b11 = l1.rpc.decodepay(
        'lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahr'
        'qspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e2'
        '0v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8r'
        'exnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t',
        'One piece of chocolate cake, one icecream cone, one pickle, one slic'
        'e of swiss cheese, one slice of salami, one lollypop, one piece of c'
        'herry pie, one sausage, one cupcake, and one slice of watermelon'
    )
    assert b11['currency'] == 'tb'
    assert b11['msatoshi'] == 20 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(20 * 10**11 // 1000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert len(b11['fallbacks']) == 1
    assert b11['fallbacks'][0]['type'] == 'P2PKH'
    assert b11['fallbacks'][0]['addr'] == 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'

    # > ### On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing info to go via nodes 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255 then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255
    # > lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `20m`: amount (20 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `h`: tagged field: hash of description...
    # * `f`: tagged field: fallback address
    #   * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
    #   * `3` = 17, so P2PKH address
    #   * `qjmp7lwpagxun9pygexvgpjdc4jdj85f`: 160 bit P2PKH address
    # * `r`: tagged field: route information
    #   * `9y`: `data_length` (`9` = 5, `y` = 4.  5 * 32 + 4 = 164)
    #     `q20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqqqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqqqqqqq7qqzq`: pubkey `029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`, `short_channel_id` 0102030405060708, `fee_base_msat` 1 millisatoshi, `fee_proportional_millionths` 20, `cltv_expiry_delta` 3.  pubkey `039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`, `short_channel_id` 030405060708090a, `fee_base_msat` 2 millisatoshi, `fee_proportional_millionths` 30, `cltv_expiry_delta` 4.
    # * `j9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qq`: signature
    # * `dhhwkj`: Bech32 checksum
    b11 = l1.rpc.decodepay('lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 20 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(20 * 10**11 // 1000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert len(b11['fallbacks']) == 1
    assert b11['fallbacks'][0]['type'] == 'P2PKH'
    assert b11['fallbacks'][0]['addr'] == '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'
    assert len(b11['routes']) == 1
    assert len(b11['routes'][0]) == 2
    assert b11['routes'][0][0]['pubkey'] == '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
    # 0x010203:0x040506:0x0708
    assert b11['routes'][0][0]['short_channel_id'] == '66051x263430x1800'
    assert b11['routes'][0][0]['fee_base_msat'] == 1
    assert b11['routes'][0][0]['fee_proportional_millionths'] == 20
    assert b11['routes'][0][0]['cltv_expiry_delta'] == 3

    assert b11['routes'][0][1]['pubkey'] == '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
    # 0x030405:0x060708:0x090a
    assert b11['routes'][0][1]['short_channel_id'] == '197637x395016x2314'
    assert b11['routes'][0][1]['fee_base_msat'] == 2
    assert b11['routes'][0][1]['fee_proportional_millionths'] == 30
    assert b11['routes'][0][1]['cltv_expiry_delta'] == 4

    # > ### On mainnet, with fallback (P2SH) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
    # > lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `20m`: amount (20 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `f`: tagged field: fallback address.
    # * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
    # * `j3a24vwu6r8ejrss3axul8rxldph2q7z9`: `j` = 18, so P2SH address
    # * `h`: tagged field: hash of description...
    # * `2jhz8j78lv2jynuzmz6g8ve53he7pheeype33zlja5azae957585uu7x59w0f2l3rugyva6zpu394y4rh093j6wxze0ldsvk757a9msq`: signature
    # * `mf9swh`: Bech32 checksum
    b11 = l1.rpc.decodepay('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 20 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(20 * 10**11 // 1000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert len(b11['fallbacks']) == 1
    assert b11['fallbacks'][0]['type'] == 'P2SH'
    assert b11['fallbacks'][0]['addr'] == '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'

    # > ### On mainnet, with fallback (P2WPKH) address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    # > lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `20m`: amount (20 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `f`: tagged field: fallback address.
    # * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
    # * `q`: 0, so witness version 0.
    # * `qw508d6qejxtdg4y5r3zarvary0c5xw7k`: 160 bits = P2WPKH.
    # * `h`: tagged field: hash of description...
    # * `gw6tk8z0p0qdy9ulggx65lvfsg3nxxhqjxuf2fvmkhl9f4jc74gy44d5ua9us509prqz3e7vjxrftn3jnk7nrglvahxf7arye5llphgq`: signature
    # * `qdtpa4`: Bech32 checksum
    b11 = l1.rpc.decodepay('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 20 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(20 * 10**11 // 1000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert len(b11['fallbacks']) == 1
    assert b11['fallbacks'][0]['type'] == 'P2WPKH'
    assert b11['fallbacks'][0]['addr'] == 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'

    # > ### On mainnet, with fallback (P2WSH) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
    # > lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava
    #
    # * `lnbc`: prefix, lightning on bitcoin mainnet
    # * `20m`: amount (20 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `f`: tagged field: fallback address.
    # * `p4`: `data_length` (`p` = 1, `4` = 21. 1 * 32 + 21 == 53)
    # * `q`: 0, so witness version 0.
    # * `rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q`: 260 bits = P2WSH.
    # * `h`: tagged field: hash of description...
    # * `5yps56lmsvgcrf476flet6js02m93kgasews8q3jhtp7d6cqckmh70650maq4u65tk53ypszy77v9ng9h2z3q3eqhtc3ewgmmv2grasp`: signature
    # * `akvd7y`: Bech32 checksum
    b11 = l1.rpc.decodepay('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 20 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(20 * 10**11 // 1000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert len(b11['fallbacks']) == 1
    assert b11['fallbacks'][0]['type'] == 'P2WSH'
    assert b11['fallbacks'][0]['addr'] == 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'

    # > ### Please send $30 for coffee beans to the same peer, which supports features 1 and 9
    # > lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzsze992adudgku8p05pstl6zh7av6rx2f297pv89gu5q93a0hf3g7lynl3xq56t23dpvah6u7y9qey9lccrdml3gaqwc6nxsl5ktzm464sq73t7cl
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, Lightning on Bitcoin mainnet
    # * `25m`: amount (25 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `d`: short description
    #   * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
    #   * `vdhkven9v5sxyetpdees`: 'coffee beans'
    # * `9`: features
    #   * `qz`: `data_length` (`q` = 0, `z` = 2; 0 * 32 + 2 == 2)
    #   * `sz`: b1000000010
    # * `e992adudgku8p05pstl6zh7av6rx2f297pv89gu5q93a0hf3g7lynl3xq56t23dpvah6u7y9qey9lccrdml3gaqwc6nxsl5ktzm464sq`: signature
    # * `73t7cl`: Bech32 checksum
    b11 = l1.rpc.decodepay('lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzsze992adudgku8p05pstl6zh7av6rx2f297pv89gu5q93a0hf3g7lynl3xq56t23dpvah6u7y9qey9lccrdml3gaqwc6nxsl5ktzm464sq73t7cl')
    assert b11['currency'] == 'bc'
    assert b11['msatoshi'] == 25 * 10**11 // 1000
    assert b11['amount_msat'] == Millisatoshi(25 * 10**11 // 1000)
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['description'] == 'coffee beans'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert b11['features'] == '0202'

    # > # Same, but using invalid unknown feature 100
    # > lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9q4pqqqqqqqqqqqqqqqqqqszk3ed62snp73037h4py4gry05eltlp0uezm2w9ajnerhmxzhzhsu40g9mgyx5v3ad4aqwkmvyftzk4k9zenz90mhjcy9hcevc7r3lx2sphzfxz7
    #
    # Breakdown:
    #
    # * `lnbc`: prefix, Lightning on Bitcoin mainnet
    # * `25m`: amount (25 milli-bitcoin)
    # * `1`: Bech32 separator
    # * `pvjluez`: timestamp (1496314658)
    # * `p`: payment hash...
    # * `d`: short description
    #   * `q5`: `data_length` (`q` = 0, `5` = 20; 0 * 32 + 20 == 20)
    #   * `vdhkven9v5sxyetpdees`: 'coffee beans'
    # * `9`: features
    #   * `q4`: `data_length` (`q` = 0, `4` = 21; 0 * 32 + 21 == 21)
    #   * `pqqqqqqqqqqqqqqqqqqsz`: b00001...(90 zeroes)...1000000010
    # * `k3ed62snp73037h4py4gry05eltlp0uezm2w9ajnerhmxzhzhsu40g9mgyx5v3ad4aqwkmvyftzk4k9zenz90mhjcy9hcevc7r3lx2sp`: signature
    # * `hzfxz7`: Bech32 checksum
    with pytest.raises(RpcError, match='unknown feature.*100'):
        l1.rpc.decodepay('lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9q4pqqqqqqqqqqqqqqqqqqszk3ed62snp73037h4py4gry05eltlp0uezm2w9ajnerhmxzhzhsu40g9mgyx5v3ad4aqwkmvyftzk4k9zenz90mhjcy9hcevc7r3lx2sphzfxz7')

    # Example of an invoice without a multiplier suffix to the amount. This
    # should then be interpreted as 7 BTC according to the spec:
    #
    #   `amount`: optional number in that currency, followed by an optional
    #   `multiplier` letter. The unit encoded here is the 'social' convention of
    #   a payment unit -- in the case of Bitcoin the unit is 'bitcoin' NOT
    #   satoshis.
    b11 = "lnbcrt71p0g4u8upp5xn4k45tsp05akmn65s5k2063d5fyadhjse9770xz5sk7u4x6vcmqdqqcqzynxqrrssx94cf4p727jamncsvcd8m99n88k423ruzq4dxwevfatpp5gx2mksj2swshjlx4pe3j5w9yed5xjktrktzd3nc2a04kq8yu84l7twhwgpxjn3pw"
    b11 = l1.rpc.decodepay(b11)
    sat_per_btc = 10**8
    assert(b11['msatoshi'] == 7 * sat_per_btc * 1000)

    with pytest.raises(RpcError):
        l1.rpc.decodepay('1111111')


@pytest.mark.developer("Too slow without --dev-fast-gossip")
def test_forward(node_factory, bitcoind):
    # Connect 1 -> 2 -> 3.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    # If they're at different block heights we can get spurious errors.
    sync_blockheight(bitcoind, [l1, l2, l3])

    chanid1 = only_one(l1.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id']
    chanid2 = only_one(l2.rpc.getpeer(l3.info['id'])['channels'])['short_channel_id']
    assert only_one(l2.rpc.getpeer(l1.info['id'])['channels'])['short_channel_id'] == chanid1
    assert only_one(l3.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id'] == chanid2

    inv = l3.rpc.invoice(100000000, 'testpayment1', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l3.rpc.listinvoices('testpayment1')['invoices'])['status'] == 'unpaid'

    # Fee for node2 is 10 millionths, plus 1.
    amt = 100000000
    fee = amt * 10 // 1000000 + 1

    baseroute = [{'msatoshi': amt + fee,
                  'id': l2.info['id'],
                  'delay': 12,
                  'channel': chanid1},
                 {'msatoshi': amt,
                  'id': l3.info['id'],
                  'delay': 6,
                  'channel': chanid2}]

    # Unknown other peer
    route = copy.deepcopy(baseroute)
    route[1]['id'] = '031a8dc444e41bb989653a4501e11175a488a57439b0c4947704fd6e3de5dca607'
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # Delay too short (we always add one internally anyway, so subtract 2 here).
    route = copy.deepcopy(baseroute)
    route[0]['delay'] = 8
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # Final delay too short
    route = copy.deepcopy(baseroute)
    route[1]['delay'] = 3
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # This one works
    route = copy.deepcopy(baseroute)
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(rhash)


@pytest.mark.developer("needs --dev-fast-gossip")
def test_forward_different_fees_and_cltv(node_factory, bitcoind):
    # FIXME: Check BOLT quotes here too
    # BOLT #7:
    # ```
    #    B
    #   / \
    #  /   \
    # A     C
    #  \   /
    #   \ /
    #    D
    # ```
    #
    # Each advertises the following `cltv_expiry_delta` on its end of every
    # channel:
    #
    # 1. A: 10 blocks
    # 2. B: 20 blocks
    # 3. C: 30 blocks
    # 4. D: 40 blocks
    #
    # C also uses a minimum `cltv_expiry` of 9 (the default) when requesting
    # payments.
    #
    # Also, each node has the same fee scheme which it uses for each of its
    # channels:
    #
    # 1. A: 100 base + 1000 millionths
    # 1. B: 200 base + 2000 millionths
    # 1. C: 300 base + 3000 millionths
    # 1. D: 400 base + 4000 millionths

    # We don't do D yet.
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'cltv-delta': 10, 'fee-base': 100, 'fee-per-satoshi': 1000},
                                                 {'cltv-delta': 20, 'fee-base': 200, 'fee-per-satoshi': 2000},
                                                 {'cltv-delta': 30, 'cltv-final': 9, 'fee-base': 300, 'fee-per-satoshi': 3000}])

    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('Handed peer, entering loop')
    l2.daemon.wait_for_log('Handed peer, entering loop')

    ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    assert ret['id'] == l3.info['id']

    l2.daemon.wait_for_log('Handed peer, entering loop')
    l3.daemon.wait_for_log('Handed peer, entering loop')

    c1, _ = l1.fundchannel(l2, 10**6)
    c2, _ = l2.fundchannel(l3, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Make sure l1 has seen announce for all channels.
    l1.wait_channel_active(c1)
    l1.wait_channel_active(c2)

    # BOLT #7:
    #
    # If B were to send 4,999,999 millisatoshi directly to C, it wouldn't
    # charge itself a fee nor add its own `cltv_expiry_delta`, so it would
    # use C's requested `cltv_expiry` of 9.  We also assume it adds a
    # "shadow route" to give an extra CLTV of 42.  It could also add extra
    # cltv deltas at other hops, as these values are a minimum, but we don't
    # here for simplicity:

    # FIXME: Add shadow route
    shadow_route = 0
    route = l2.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 1

    # BOLT #7:
    #
    #    * `amount_msat`: 4999999
    #    * `cltv_expiry`: current-block-height + 9 + 42
    #    * `onion_routing_packet`:
    #      * `amt_to_forward` = 4999999
    #      * `outgoing_cltv_value` = current-block-height + 9 + 42
    #
    assert route[0]['msatoshi'] == 4999999
    assert route[0]['delay'] == 9 + shadow_route

    # BOLT #7:
    # If A were to send 4,999,999 millisatoshi to C via B, it needs to
    # pay B the fee it specified in the B->C `channel_update`, calculated as
    # per [HTLC Fees](#htlc_fees):
    #
    # 200 + 4999999 * 2000 / 1000000 = 10199
    #
    # Similarly, it would need to add the `cltv_expiry` from B->C's
    # `channel_update` (20), plus C's requested minimum (9), plus 42 for the
    # "shadow route".  Thus the `update_add_htlc` message from A to B would
    # be:
    #
    #    * `amount_msat`: 5010198
    #    * `cltv_expiry`: current-block-height + 20 + 9 + 42
    #    * `onion_routing_packet`:
    #      * `amt_to_forward` = 4999999
    #      * `outgoing_cltv_value` = current-block-height + 9 + 42
    route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 2

    assert route[0]['msatoshi'] == 5010198
    assert route[0]['delay'] == 20 + 9 + shadow_route
    assert route[1]['msatoshi'] == 4999999
    assert route[1]['delay'] == 9 + shadow_route

    inv = l3.rpc.invoice(4999999, 'test_forward_different_fees_and_cltv', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'])['status'] == 'unpaid'

    # This should work.
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(rhash)

    # We add one to the blockcount for a bit of fuzz (FIXME: Shadowroute would fix this!)
    shadow_route = 1
    l1.daemon.wait_for_log("Adding HTLC 0 amount=5010198msat cltv={} gave CHANNEL_ERR_ADD_OK"
                           .format(bitcoind.rpc.getblockcount() + 20 + 9 + shadow_route))
    l2.daemon.wait_for_log("Adding HTLC 0 amount=4999999msat cltv={} gave CHANNEL_ERR_ADD_OK"
                           .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
    l3.daemon.wait_for_log("Resolved invoice 'test_forward_different_fees_and_cltv' with amount 4999999msat")
    assert only_one(l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'])['status'] == 'paid'

    # Check that we see all the channels
    shortids = set(c['short_channel_id'] for c in l2.rpc.listchannels()['channels'])
    for scid in shortids:
        c = l1.rpc.listchannels(scid)['channels']
        # We get one entry for each direction.
        assert len(c) == 2
        assert c[0]['short_channel_id'] == scid
        assert c[1]['short_channel_id'] == scid
        assert c[0]['source'] == c[1]['destination']
        assert c[1]['source'] == c[0]['destination']


@pytest.mark.developer("too slow without --dev-fast-gossip")
def test_forward_pad_fees_and_cltv(node_factory, bitcoind):
    """Test that we are allowed extra locktime delta, and fees"""

    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'cltv-delta': 10, 'fee-base': 100, 'fee-per-satoshi': 1000},
                                                 {'cltv-delta': 20, 'fee-base': 200, 'fee-per-satoshi': 2000},
                                                 {'cltv-delta': 30, 'cltv-final': 9, 'fee-base': 300, 'fee-per-satoshi': 3000}])

    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('Handed peer, entering loop')
    l2.daemon.wait_for_log('Handed peer, entering loop')

    ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    assert ret['id'] == l3.info['id']

    l2.daemon.wait_for_log('Handed peer, entering loop')
    l3.daemon.wait_for_log('Handed peer, entering loop')

    c1, _ = l1.fundchannel(l2, 10**6)
    c2, _ = l2.fundchannel(l3, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Make sure l1 has seen announce for all channels.
    l1.wait_channel_active(c1)
    l1.wait_channel_active(c2)

    route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 2

    assert route[0]['msatoshi'] == 5010198
    assert route[0]['delay'] == 20 + 9
    assert route[1]['msatoshi'] == 4999999
    assert route[1]['delay'] == 9

    # Modify so we overpay, overdo the cltv.
    route[0]['msatoshi'] += 2000
    route[0]['amount_msat'] = Millisatoshi(route[0]['msatoshi'])
    route[0]['delay'] += 20
    route[1]['msatoshi'] += 1000
    route[1]['amount_msat'] = Millisatoshi(route[1]['msatoshi'])
    route[1]['delay'] += 10

    # This should work.
    inv = l3.rpc.invoice(4999999, 'test_forward_pad_fees_and_cltv', 'desc')
    rhash = inv['payment_hash']
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(rhash)
    assert only_one(l3.rpc.listinvoices('test_forward_pad_fees_and_cltv')['invoices'])['status'] == 'paid'


@pytest.mark.developer("needs DEVELOPER=1 for dev_ignore_htlcs")
def test_forward_stats(node_factory, bitcoind):
    """Check that we track forwarded payments correctly.

    We wire up the network to have l1 as payment initiator, l2 as
    forwarded (the one we check) and l3-l5 as payment recipients. l3
    accepts correctly, l4 rejects (because it doesn't know the payment
    hash) and l5 will keep the HTLC dangling by disconnecting.

    """
    amount = 10**5
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5, opts=[{}] * 4 + [{'may_fail': True}])
    node_factory.join_nodes([l1, l2, l3], wait_for_announce=False)
    l2.openchannel(l4, 10**6, wait_for_announce=False)
    l2.openchannel(l5, 10**6, wait_for_announce=False)

    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5])

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 8)

    inv = l3.rpc.invoice(amount, "first", "desc")
    payment_hash = inv['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(payment_hash)

    # l4 rejects since it doesn't know the payment_hash
    route = l1.rpc.getroute(l4.info['id'], amount, 1)['route']
    payment_hash = "F" * 64
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(payment_hash)

    # l5 will hold the HTLC hostage.
    l5.rpc.dev_ignore_htlcs(id=l2.info['id'], ignore=True)
    route = l1.rpc.getroute(l5.info['id'], amount, 1)['route']
    inv = l5.rpc.invoice(amount, "first", "desc")
    payment_hash = inv['payment_hash']
    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    l5.daemon.wait_for_log(r'their htlc .* dev_ignore_htlcs')

    # Select all forwardings, ordered by htlc_id to ensure the order
    # matches below
    forwardings = l2.db_query("SELECT *, in_msatoshi - out_msatoshi as fee "
                              "FROM forwarded_payments "
                              "ORDER BY in_htlc_id;")
    assert(len(forwardings) == 3)
    states = [f['state'] for f in forwardings]
    assert(states == [1, 2, 0])  # settled, failed, offered

    inchan = l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'][0]
    outchan = l2.rpc.listpeers(l3.info['id'])['peers'][0]['channels'][0]

    # Check that we correctly account channel changes
    assert inchan['in_payments_offered'] == 3
    assert inchan['in_payments_fulfilled'] == 1
    assert inchan['in_msatoshi_offered'] >= 3 * amount
    assert inchan['in_msatoshi_fulfilled'] >= amount

    assert outchan['out_payments_offered'] == 1
    assert outchan['out_payments_fulfilled'] == 1
    assert outchan['out_msatoshi_offered'] >= amount
    assert outchan['out_msatoshi_offered'] == outchan['out_msatoshi_fulfilled']

    assert outchan['out_msatoshi_fulfilled'] < inchan['in_msatoshi_fulfilled']

    stats = l2.rpc.listforwards()

    assert [f['status'] for f in stats['forwards']] == ['settled', 'failed', 'offered']
    assert l2.rpc.getinfo()['msatoshi_fees_collected'] == 1 + amount // 100000
    assert l1.rpc.getinfo()['msatoshi_fees_collected'] == 0
    assert l3.rpc.getinfo()['msatoshi_fees_collected'] == 0
    assert stats['forwards'][0]['received_time'] <= stats['forwards'][0]['resolved_time']
    assert stats['forwards'][1]['received_time'] <= stats['forwards'][1]['resolved_time']
    assert 'received_time' in stats['forwards'][2] and 'resolved_time' not in stats['forwards'][2]


@pytest.mark.developer("too slow without --dev-fast-gossip")
@pytest.mark.slow_test
def test_forward_local_failed_stats(node_factory, bitcoind, executor):
    """Check that we track forwarded payments correctly.

    We wire up the network to have l1 and l6 as payment initiator, l2 as
    forwarded (the one we check) and l3-l5 as payment recipients.

    There 5 cases for FORWARD_LOCAL_FAILED status:
    1. When Msater resolves the reply about the next peer infor(sent
       by Gossipd), and need handle unknown next peer failure in
       channel_resolve_reply(). For this case, we ask l1 pay to l3
       through l2 but close the channel between l2 and l3 after
       getroute(), the payment will fail in l2 because of
       WIRE_UNKNOWN_NEXT_PEER;
    2. When Master handle the forward process with the htlc_in and
       the id of next hop, it tries to drive a new htlc_out but fails
       in forward_htlc(). For this case, we ask l1 pay to 14 through
       with no fee, so the payment will fail in l2 becase of
       WIRE_FEE_INSUFFICIENT;
    3. When we send htlc_out, Master asks Channeld to add a new htlc
       into the outgoing channel but Channeld fails. Master need
       handle and store this failure in rcvd_htlc_reply(). For this
       case, we ask l1 pay to l5 with 10**8 sat though the channel
       (l2-->l5) with the max capacity of 10**4 msat , the payment
       will fail in l2 because of CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
    4. When Channeld receives a new revoke message, if the state of
       corresponding htlc is RCVD_ADD_ACK_REVOCATION, Master will tries
       to resolve onionpacket and handle the failure before resolving
       the next hop in peer_got_revoke(). For this case, we ask l6 pay
       to l4 though l1 and l2, but we replace the second node_id in route
       with the wrong one, so the payment will fail in l2 because of
       WIRE_INVALID_ONION_KEY;
    5. When Onchaind finds the htlc time out or missing htlc, Master
       need handle these failure as FORWARD_LOCAL_FAILED in if it's forward
       payment case. For this case, we ask l1 pay to l4 though l2 with the
       amount less than the invoice(the payment must fail in l4), and we
       also ask l5 disconnected before sending update_fail_htlc, so the
       htlc will be holding until l2 meets timeout and handle it as local_fail.
    """

    amount = 10**8

    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']

    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=[{},
                                                             {},
                                                             {},
                                                             {'disconnect': disconnects},
                                                             {},
                                                             {}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
    l2.rpc.connect(l5.info['id'], 'localhost', l5.port)
    l6.rpc.connect(l1.info['id'], 'localhost', l1.port)
    c12, _ = l1.fundchannel(l2, 10**6)
    c23, _ = l2.fundchannel(l3, 10**6)
    c24, _ = l2.fundchannel(l4, 10**6)
    c25, _ = l2.fundchannel(l5, 10**4 * 3)
    l6.fundchannel(l1, 10**6)

    # Make sure routes finalized.
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5, l6])
    l1.wait_channel_active(c23)
    l1.wait_channel_active(c24)
    l1.wait_channel_active(c25)
    l6.wait_channel_active(c24)

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 10)

    """1. When Msater resolves the reply about the next peer infor(sent
       by Gossipd), and need handle unknown next peer failure in
       channel_resolve_reply();

       For this case, we ask l1 pay to l3 through l2 but close the channel
       between l2 and l3 after getroute(), the payment will fail in l2
       because of WIRE_UNKNOWN_NEXT_PEER;
    """

    inv = l3.rpc.invoice(amount, "first", "desc")
    payment_hash = inv['payment_hash']
    route = l1.rpc.getroute(l3.info['id'], amount, 1)['route']

    l2.rpc.close(c23, 1)

    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(payment_hash)

    """2. When Master handle the forward process with the htlc_in and
       the id of next hop, it tries to drive a new htlc_out but fails
       in forward_htlc();

       For this case, we ask l1 pay to 14 through with no fee, so the
       payment will fail in l2 becase of WIRE_FEE_INSUFFICIENT;
    """

    inv = l4.rpc.invoice(amount, "third", "desc")
    payment_hash = inv['payment_hash']
    fee = amount * 10 // 1000000 + 1

    route = [{'msatoshi': amount,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'msatoshi': amount,
              'id': l4.info['id'],
              'delay': 6,
              'channel': c24}]

    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(payment_hash)

    """3. When we send htlc_out, Master asks Channeld to add a new htlc
       into the outgoing channel but Channeld fails. Master need
       handle and store this failure in rcvd_htlc_reply();

       For this case, we ask l1 pay to l5 with 10**8 sat though the channel
       (l2-->l5) with the max capacity of 10**4 msat , the payment will
       fail in l2 because of CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
    """

    inv = l5.rpc.invoice(amount, "second", "desc")
    payment_hash = inv['payment_hash']
    fee = amount * 10 // 1000000 + 1

    route = [{'msatoshi': amount + fee,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'msatoshi': amount,
              'id': l5.info['id'],
              'delay': 6,
              'channel': c25}]

    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(payment_hash)

    """4. When Channeld receives a new revoke message, if the state of
       corresponding htlc is RCVD_ADD_ACK_REVOCATION, Master will tries
       to resolve onionpacket and handle the failure before resolving
       the next hop in peer_got_revoke();

       For this case, we ask l6 pay to l4 though l1 and l2, but we replace
       the second node_id in route with the wrong one, so the payment will
       fail in l2 because of WIRE_INVALID_ONION_KEY;
    """

    inv = l4.rpc.invoice(amount, 'fourth', 'desc')
    payment_hash = inv['payment_hash']
    route = l6.rpc.getroute(l4.info['id'], amount, 1)['route']

    mangled_nodeid = '0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6510'

    # Replace id with a different pubkey, so onion encoded badly at l2 hop.
    route[1]['id'] = mangled_nodeid

    with pytest.raises(RpcError):
        l6.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
        l6.rpc.waitsendpay(payment_hash)

    """5. When Onchaind finds the htlc time out or missing htlc, Master
       need handle these failure as FORWARD_LOCAL_FAILED in if it's forward
       payment case.

       For this case, we ask l1 pay to l4 though l2 with the amount less than
       the invoice(the payment must fail in l4), and we also ask l5 disconnected
       before sending update_fail_htlc, so the htlc will be holding until l2
       meets timeout and handle it as local_fail.
    """
    inv = l4.rpc.invoice(amount, 'onchain_timeout', 'desc')
    payment_hash = inv['payment_hash']
    fee = amount * 10 // 1000000 + 1

    # We underpay, so it fails.
    route = [{'msatoshi': amount + fee - 1,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'msatoshi': amount - 1,
              'id': l4.info['id'],
              'delay': 5,
              'channel': c24}]

    executor.submit(l1.rpc.sendpay, route, payment_hash, payment_secret=inv['payment_secret'])

    l4.daemon.wait_for_log('permfail')
    l4.wait_for_channel_onchain(l2.info['id'])
    l2.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l4.daemon.wait_for_log(' to ONCHAIN')

    # Wait for timeout.
    l2.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US .* after 6 blocks')
    bitcoind.generate_block(6)

    l2.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                   'THEIR_UNILATERAL/OUR_HTLC')

    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
    l4.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l2])

    # give time to let l2 store the local_failed stats
    time.sleep(5)

    # Select all forwardings, and check the status
    stats = l2.rpc.listforwards()

    assert [f['status'] for f in stats['forwards']] == ['local_failed', 'local_failed', 'local_failed', 'local_failed', 'local_failed']
    assert l2.rpc.getinfo()['msatoshi_fees_collected'] == 0

    assert 'received_time' in stats['forwards'][0] and 'resolved_time' not in stats['forwards'][0]
    assert 'received_time' in stats['forwards'][1] and 'resolved_time' not in stats['forwards'][1]
    assert 'received_time' in stats['forwards'][2] and 'resolved_time' not in stats['forwards'][2]
    assert 'received_time' in stats['forwards'][3] and 'resolved_time' not in stats['forwards'][3]
    assert 'received_time' in stats['forwards'][3] and 'resolved_time' not in stats['forwards'][4]


@pytest.mark.developer("too slow without --dev-fast-gossip")
@pytest.mark.slow_test
def test_htlcs_cltv_only_difference(node_factory, bitcoind):
    # l1 -> l2 -> l3 -> l4
    # l4 ignores htlcs, so they stay.
    # l3 will see a reconnect from l4 when l4 restarts.
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True, opts=[{}] * 2 + [{'dev-no-reconnect': None, 'may_reconnect': True}] * 2)

    inv = l4.rpc.invoice(msatoshi=10**8, label='x', description='desc')
    h = inv['payment_hash']
    l4.rpc.dev_ignore_htlcs(id=l3.info['id'], ignore=True)

    # L2 tries to pay
    r = l2.rpc.getroute(l4.info['id'], 10**8, 1)["route"]
    l2.rpc.sendpay(r, h, payment_secret=inv['payment_secret'])

    # Now increment CLTV
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3, l4])

    # L1 tries to pay
    r = l1.rpc.getroute(l4.info['id'], 10**8, 1)["route"]
    l1.rpc.sendpay(r, h, payment_secret=inv['payment_secret'])

    # Now increment CLTV
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3, l4])

    # L3 tries to pay
    r = l3.rpc.getroute(l4.info['id'], 10**8, 1)["route"]
    l3.rpc.sendpay(r, h, payment_secret=inv['payment_secret'])

    # Give them time to go through.
    time.sleep(5)

    # Will all be connected OK.
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']
    assert only_one(l2.rpc.listpeers(l3.info['id'])['peers'])['connected']
    assert only_one(l3.rpc.listpeers(l4.info['id'])['peers'])['connected']

    # TODO Remove our reliance on HTLCs failing on startup and the need for
    #      this plugin
    l4.daemon.opts['plugin'] = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')

    # Restarting tail node will stop it ignoring HTLCs (it will actually
    # fail them immediately).
    l4.restart()
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    wait_for(lambda: only_one(l1.rpc.listsendpays()['payments'])['status'] == 'failed')
    wait_for(lambda: only_one(l2.rpc.listsendpays()['payments'])['status'] == 'failed')
    wait_for(lambda: only_one(l3.rpc.listsendpays()['payments'])['status'] == 'failed')

    # Should all still be connected.
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']
    assert only_one(l2.rpc.listpeers(l3.info['id'])['peers'])['connected']
    assert only_one(l3.rpc.listpeers(l4.info['id'])['peers'])['connected']


def test_pay_variants(node_factory):
    l1, l2 = node_factory.line_graph(2)

    # Upper case is allowed
    b11 = l2.rpc.invoice(123000, 'test_pay_variants upper', 'description')['bolt11'].upper()
    l1.rpc.decodepay(b11)
    l1.rpc.pay(b11)

    # lightning: prefix is allowed
    b11 = 'lightning:' + l2.rpc.invoice(123000, 'test_pay_variants with prefix', 'description')['bolt11']
    l1.rpc.decodepay(b11)
    l1.rpc.pay(b11)

    # BOTH is allowed.
    b11 = 'LIGHTNING:' + l2.rpc.invoice(123000, 'test_pay_variants upper with prefix', 'description')['bolt11'].upper()
    l1.rpc.decodepay(b11)
    l1.rpc.pay(b11)


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
@pytest.mark.slow_test
def test_pay_retry(node_factory, bitcoind, executor, chainparams):
    """Make sure pay command retries properly. """

    def exhaust_channel(opener, peer, scid, already_spent=0):
        """Spend all available capacity (10^6 - 1%) of channel
        """
        peer_node = opener.rpc.listpeers(peer.info['id'])['peers'][0]
        chan = peer_node['channels'][0]
        maxpay = chan['spendable_msatoshi']
        lbl = ''.join(random.choice(string.ascii_letters) for _ in range(20))
        inv = peer.rpc.invoice(maxpay, lbl, "exhaust_channel")
        routestep = {
            'msatoshi': maxpay,
            'id': peer.info['id'],
            'delay': 10,
            'channel': scid
        }
        opener.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])
        opener.rpc.waitsendpay(inv['payment_hash'])

    # We connect every node to l5; in a line and individually.
    # Keep fixed fees so we can easily calculate exhaustion
    l1, l2, l3, l4, l5 = node_factory.line_graph(5, fundchannel=False,
                                                 opts={'feerates': (7500, 7500, 7500, 7500), 'disable-mpp': None})

    # scid12
    l1.fundchannel(l2, 10**6, wait_for_active=False)
    # scid23
    l2.fundchannel(l3, 10**6, wait_for_active=False)
    # scid34
    l3.fundchannel(l4, 10**6, wait_for_active=False)
    scid45, _ = l4.fundchannel(l5, 10**6, wait_for_active=False)

    l1.rpc.connect(l5.info['id'], 'localhost', l5.port)
    scid15, _ = l1.fundchannel(l5, 10**6, wait_for_active=False)
    l2.rpc.connect(l5.info['id'], 'localhost', l5.port)
    scid25, _ = l2.fundchannel(l5, 10**6, wait_for_active=False)
    l3.rpc.connect(l5.info['id'], 'localhost', l5.port)
    scid35, _ = l3.fundchannel(l5, 10**6, wait_for_active=False)

    # Make sure l1 sees all 7 channels
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5])
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 14)

    # Exhaust shortcut channels one at a time, to force retries.
    exhaust_channel(l1, l5, scid15)
    exhaust_channel(l2, l5, scid25)
    exhaust_channel(l3, l5, scid35)

    def listpays_nofail(b11):
        while True:
            pays = l1.rpc.listpays(b11)['pays']
            if len(pays) != 0:
                if only_one(pays)['status'] == 'complete':
                    return
                assert only_one(pays)['status'] != 'failed'

    inv = l5.rpc.invoice(10**8, 'test_retry', 'test_retry')

    # Make sure listpays doesn't transiently show failure while pay
    # is retrying.
    fut = executor.submit(listpays_nofail, inv['bolt11'])

    # Pay l1->l5 should succeed via straight line (eventually)
    l1.rpc.dev_pay(inv['bolt11'], use_shadow=False)

    # This should be OK.
    fut.result()

    # This should make it fail.
    exhaust_channel(l4, l5, scid45, 10**8)

    # It won't try l1->l5, since it knows that's under capacity.
    # It will try l1->l2->l5, which fails.
    # It will try l1->l2->l3->l5, which fails.
    # It will try l1->l2->l3->l4->l5, which fails.
    # Finally, fails to find a route.
    inv = l5.rpc.invoice(10**8, 'test_retry2', 'test_retry2')['bolt11']
    with pytest.raises(RpcError, match=r'4 attempts'):
        l1.rpc.dev_pay(inv, use_shadow=False)


@pytest.mark.developer("needs DEVELOPER=1 otherwise gossip takes 5 minutes!")
@pytest.mark.slow_test
def test_pay_routeboost(node_factory, bitcoind, compat):
    """Make sure we can use routeboost information. """
    # l1->l2->l3--private-->l4
    l1, l2 = node_factory.line_graph(2, announce_channels=True, wait_for_announce=True)
    l3, l4, l5 = node_factory.line_graph(3, announce_channels=False, wait_for_announce=False)

    # This should a "could not find a route" because that's true.
    error = r'Destination [a-f0-9]{66} is not reachable directly and all routehints were unusable'

    with pytest.raises(RpcError, match=error):
        l1.rpc.pay(l5.rpc.invoice(10**8, 'test_retry', 'test_retry')['bolt11'])

    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    scidl2l3, _ = l2.fundchannel(l3, 10**6)

    # Make sure l1 knows about the 2->3 channel.
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5])
    l1.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scidl2l3),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scidl2l3)])
    # Make sure l4 knows about 2->3 channel too so it's not a dead-end.
    l4.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scidl2l3),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scidl2l3)])

    # Get an l4 invoice; it should put the private channel in routeboost.
    inv = l4.rpc.invoice(10**5, 'test_pay_routeboost', 'test_pay_routeboost',
                         exposeprivatechannels=True)
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))

    # Now we should be able to pay it.
    l1.rpc.dev_pay(inv['bolt11'], use_shadow=False)

    # Status should show all the gory details.
    status = l1.rpc.call('paystatus', [inv['bolt11']])
    assert only_one(status['pay'])['bolt11'] == inv['bolt11']
    assert only_one(status['pay'])['amount_msat'] == Millisatoshi(10**5)
    assert only_one(status['pay'])['destination'] == l4.info['id']
    assert 'label' not in only_one(status['pay'])
    assert 'routehint_modifications' not in only_one(status['pay'])
    assert 'local_exclusions' not in only_one(status['pay'])
    attempts = only_one(status['pay'])['attempts']
    scid34 = only_one(l3.rpc.listpeers(l4.info['id'])['peers'])['channels'][0]['short_channel_id']
    assert(len(attempts) == 1)
    a = attempts[0]
    assert(a['strategy'] == "Initial attempt")
    assert('success' in a)
    assert('payment_preimage' in a['success'])

    # With dev-route option we can test longer routehints.
    if DEVELOPER:
        scid45 = only_one(l4.rpc.listpeers(l5.info['id'])['peers'])['channels'][0]['short_channel_id']
        routel3l4l5 = [{'id': l3.info['id'],
                        'short_channel_id': scid34,
                        'fee_base_msat': 1000,
                        'fee_proportional_millionths': 10,
                        'cltv_expiry_delta': 6},
                       {'id': l4.info['id'],
                        'short_channel_id': scid45,
                        'fee_base_msat': 1000,
                        'fee_proportional_millionths': 10,
                        'cltv_expiry_delta': 6}]
        inv = l5.rpc.call('invoice', {'msatoshi': 10**5,
                                      'label': 'test_pay_routeboost2',
                                      'description': 'test_pay_routeboost2',
                                      'dev-routes': [routel3l4l5]})
        l1.rpc.dev_pay(inv['bolt11'], use_shadow=False)
        status = l1.rpc.call('paystatus', [inv['bolt11']])
        pay = only_one(status['pay'])
        attempts = pay['attempts']
        assert(len(attempts) == 1)
        assert 'failure' not in attempts[0]
        assert 'success' in attempts[0]

        # Finally, it should fall back to second routehint if first fails.
        # (Note, this is not public because it's not 6 deep)
        l3.rpc.connect(l5.info['id'], 'localhost', l5.port)
        scid35, _ = l3.fundchannel(l5, 10**6)
        l4.stop()
        routel3l5 = [{'id': l3.info['id'],
                      'short_channel_id': scid35,
                      'fee_base_msat': 1000,
                      'fee_proportional_millionths': 10,
                      'cltv_expiry_delta': 6}]
        inv = l5.rpc.call('invoice', {'msatoshi': 10**5,
                                      'label': 'test_pay_routeboost5',
                                      'description': 'test_pay_routeboost5',
                                      'dev-routes': [routel3l4l5, routel3l5]})
        l1.rpc.dev_pay(inv['bolt11'], label="paying test_pay_routeboost5",
                       use_shadow=False)

        status = l1.rpc.call('paystatus', [inv['bolt11']])
        assert only_one(status['pay'])['bolt11'] == inv['bolt11']
        assert only_one(status['pay'])['destination'] == l5.info['id']
        assert only_one(status['pay'])['label'] == "paying test_pay_routeboost5"
        assert 'routehint_modifications' not in only_one(status['pay'])
        assert 'local_exclusions' not in only_one(status['pay'])
        attempts = only_one(status['pay'])['attempts']

        # First one fails, second one succeeds, no routehint would come last.
        assert len(attempts) == 2
        assert 'success' not in attempts[0]
        assert 'success' in attempts[1]
        # TODO Add assertion on the routehint once we add them to the pay
        # output


@pytest.mark.developer("updates are delayed without --dev-fast-gossip")
def test_setchannelfee_usage(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] ---> [l2]  (channel funded)
    #   |
    #   o - - > [l3]  (only connected)
    #
    # - check initial SQL values
    # - check setchannelfee can be used
    # - checks command's return object format
    # - check custom SQL fee values
    # - check values in local nodes listchannels output
    # - json throws exception on negative values
    # - checks if peer id can be used instead of scid
    # - checks fee_base_msat and fee_proportional_millionths in `listpeers` out
    DEF_BASE = 10
    DEF_BASE_MSAT = Millisatoshi(DEF_BASE)
    DEF_PPM = 100

    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM})
    node_factory.join_nodes([l1, l2])
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

    def channel_get_fees(scid):
        return l1.db.query(
            'SELECT feerate_base, feerate_ppm FROM channels '
            'WHERE short_channel_id=\'{}\';'.format(scid))

    # get short channel id
    scid = l1.get_channel_scid(l2)

    # feerates should be init with global config
    db_fees = l1.db_query('SELECT feerate_base, feerate_ppm FROM channels;')
    assert(db_fees[0]['feerate_base'] == DEF_BASE)
    assert(db_fees[0]['feerate_ppm'] == DEF_PPM)
    # this is also what listpeers should return
    peers = l1.rpc.listpeers()['peers']
    assert peers[0]['channels'][0]['fee_base_msat'] == DEF_BASE_MSAT
    assert peers[0]['channels'][0]['fee_proportional_millionths'] == DEF_PPM

    # custom setchannelfee scid <base> <ppm>
    result = l1.rpc.setchannelfee(scid, 1337, 137)

    # check result format
    assert(result['base'] == 1337)
    assert(result['ppm'] == 137)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['peer_id'] == l2.info['id'])
    assert(result['channels'][0]['short_channel_id'] == scid)

    # check if custom values made it into the database
    db_fees = channel_get_fees(scid)
    assert(db_fees[0]['feerate_base'] == 1337)
    assert(db_fees[0]['feerate_ppm'] == 137)
    # also check for updated values in `listpeers`
    peers = l1.rpc.listpeers()['peers']
    assert peers[0]['channels'][0]['fee_base_msat'] == Millisatoshi(1337)
    assert peers[0]['channels'][0]['fee_proportional_millionths'] == 137

    # wait for gossip and check if l1 sees new fees in listchannels
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [DEF_BASE, 1337])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [DEF_PPM, 137])

    # also test with named and missing parameters
    result = l1.rpc.setchannelfee(ppm=42, id=scid)
    assert(result['base'] == DEF_BASE)
    assert(result['ppm'] == 42)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['short_channel_id'] == scid)
    result = l1.rpc.setchannelfee(base=42, id=scid)
    assert(result['base'] == 42)
    assert(result['ppm'] == DEF_PPM)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['short_channel_id'] == scid)

    # check if negative fees raise error and DB keeps values
    # JSONRPC2_INVALID_PARAMS := -32602
    with pytest.raises(RpcError, match=r'-32602'):
        l1.rpc.setchannelfee(scid, -1, -1)

    # test if zero fees is possible
    result = l1.rpc.setchannelfee(scid, 0, 0)
    assert(result['base'] == 0)
    assert(result['ppm'] == 0)
    db_fees = channel_get_fees(scid)
    assert(db_fees[0]['feerate_base'] == 0)
    assert(db_fees[0]['feerate_ppm'] == 0)
    # also check for updated values in `listpeers`
    peers = l1.rpc.listpeers()['peers']
    assert peers[0]['channels'][0]['fee_base_msat'] == Millisatoshi(0)
    assert peers[0]['channels'][0]['fee_proportional_millionths'] == 0

    # disable and check for global values to be returned
    result = l1.rpc.setchannelfee(scid)
    assert(result['base'] == DEF_BASE)
    assert(result['ppm'] == DEF_PPM)
    # check default values in DB
    db_fees = channel_get_fees(scid)
    assert(db_fees[0]['feerate_base'] == DEF_BASE)
    assert(db_fees[0]['feerate_ppm'] == DEF_PPM)
    # also check for updated values in `listpeers`
    peers = l1.rpc.listpeers()['peers']
    assert peers[0]['channels'][0]['fee_base_msat'] == DEF_BASE_MSAT
    assert peers[0]['channels'][0]['fee_proportional_millionths'] == DEF_PPM

    # check also peer id can be used
    result = l1.rpc.setchannelfee(l2.info['id'], 42, 43)
    assert(result['base'] == 42)
    assert(result['ppm'] == 43)
    assert(len(result['channels']) == 1)
    assert(result['channels'][0]['peer_id'] == l2.info['id'])
    assert(result['channels'][0]['short_channel_id'] == scid)
    db_fees = channel_get_fees(scid)
    assert(db_fees[0]['feerate_base'] == 42)
    assert(db_fees[0]['feerate_ppm'] == 43)

    # check if invalid scid raises proper error
    with pytest.raises(RpcError, match=r'-1.*Could not find active channel of peer with that id'):
        result = l1.rpc.setchannelfee(l3.info['id'], 42, 43)
    with pytest.raises(RpcError, match=r'-32602.*id: should be a channel ID or short channel ID: invalid token'):
        result = l1.rpc.setchannelfee('f42' + scid[3:], 42, 43)

    # check if 'base' unit can be modified to satoshi
    result = l1.rpc.setchannelfee(scid, '1sat')
    assert(result['base'] == 1000)
    db_fees = channel_get_fees(scid)
    assert(db_fees[0]['feerate_base'] == 1000)

    # check if 'ppm' values greater than u32_max fail
    with pytest.raises(RpcError, match=r'-32602.*ppm: should be an integer: invalid token'):
        l1.rpc.setchannelfee(scid, 0, 2**32)

    # check if 'base' values greater than u32_max fail
    with pytest.raises(RpcError, match=r'-32602.*base: exceeds u32 max: invalid token'):
        l1.rpc.setchannelfee(scid, 2**32)


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_setchannelfee_state(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l0] --> [l1] --> [l2]
    #
    # Initiate channel [l1,l2] and try to set feerates other states than
    # CHANNELD_NORMAL or CHANNELD_AWAITING_LOCKIN. Should raise error.
    # Use l0 to make a forward through l1/l2 for testing.
    DEF_BASE = 0
    DEF_PPM = 0

    l0, l1, l2 = node_factory.get_nodes(3, opts={
        'fee-base': DEF_BASE,
        'fee-per-satoshi': DEF_PPM
    })

    # connection and funding
    l0.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l0.fundchannel(l1, 1000000, wait_for_active=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 1000000, wait_for_active=False)

    # try setting the fee in state AWAITING_LOCKIN should be possible
    # assert(l1.channel_state(l2) == "CHANNELD_AWAITING_LOCKIN")
    result = l1.rpc.setchannelfee(l2.info['id'], 42, 0)
    assert(result['channels'][0]['peer_id'] == l2.info['id'])
    # cid = result['channels'][0]['channel_id']

    # test routing correct new fees once routing is established
    mine_funding_to_announce(bitcoind, [l0, l1, l2])

    l0.wait_for_route(l2)
    inv = l2.rpc.invoice(100000, 'test_setchannelfee_state', 'desc')['bolt11']
    result = l0.rpc.dev_pay(inv, use_shadow=False)
    assert result['status'] == 'complete'
    assert result['msatoshi_sent'] == 100042

    # Disconnect and unilaterally close from l2 to l1
    l2.rpc.disconnect(l1.info['id'], force=True)
    l1.rpc.disconnect(l2.info['id'], force=True)
    result = l2.rpc.close(scid, 1)
    assert result['type'] == 'unilateral'

    # wait for l1 to see unilateral close via bitcoin network
    while l1.channel_state(l2) == "CHANNELD_NORMAL":
        bitcoind.generate_block(1)
    # assert l1.channel_state(l2) == "FUNDING_SPEND_SEEN"

    # Try to setchannelfee in order to raise expected error.
    # To reduce false positive flakes, only test if state is not NORMAL anymore.
    with pytest.raises(RpcError, match=r'-1.*'):
        # l1.rpc.setchannelfee(l2.info['id'], 10, 1)
        l1.rpc.setchannelfee(l2.info['id'], 10, 1)


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_setchannelfee_routing(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] <--default_fees--> [l2] <--specific_fees--> [l3]
    #
    # - json listchannels is able to see the new values in foreign node
    # - routing calculates fees correctly
    # - payment can be done using specific fees
    # - channel specific fees can be disabled again
    # - payment can be done using global fees
    DEF_BASE = 1
    DEF_PPM = 10

    l1, l2, l3 = node_factory.line_graph(
        3, announce_channels=True, wait_for_announce=True,
        opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM})

    # get short channel id for 2->3
    scid = l2.get_channel_scid(l3)

    # TEST CUSTOM VALUES
    l2.rpc.setchannelfee(scid, 1337, 137)

    # wait for l1 to see updated channel via gossip
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [1337, DEF_BASE])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [137, DEF_PPM])

    # test fees are applied to HTLC forwards
    #
    # BOLT #7:
    # If l1 were to send 4,999,999 millisatoshi to l3 via l2, it needs to
    # pay l2 the fee it specified in the l2->l3 `channel_update`, calculated as
    # per [HTLC Fees](#htlc_fees):  base + amt * pm / 10**6
    #
    # 1337 + 4999999 * 137 / 1000000 = 2021.999 (2021)
    route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 2
    assert route[0]['msatoshi'] == 5002020
    assert route[1]['msatoshi'] == 4999999

    # In case l3 includes a routehint, we need to make sure they also know
    # about the new fees, otherwise we may end up with the old feerate
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['active']) for c in l3.rpc.listchannels(scid)['channels']] == [(1337, 137, True), (DEF_BASE, DEF_PPM, True)])

    # do and check actual payment
    inv = l3.rpc.invoice(4999999, 'test_setchannelfee_1', 'desc')['bolt11']
    result = l1.rpc.dev_pay(inv, use_shadow=False)
    assert result['status'] == 'complete'
    assert result['msatoshi_sent'] == 5002020

    # TEST DISABLE and check global fee routing
    l2.rpc.setchannelfee(scid)

    # wait for l1 to see default values again via gossip
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [DEF_BASE, DEF_BASE])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [DEF_PPM, DEF_PPM])

    # test if global fees are applied again (base 1 ppm 10)
    # 1 + 4999999 * 10 / 1000000 = 50.999 (50)
    route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 2
    assert route[0]['msatoshi'] == 5000049
    assert route[1]['msatoshi'] == 4999999

    # In case l3 includes a routehint, we need to make sure they also know
    # about the new fees, otherwise we may end up with the old feerate
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['active']) for c in l3.rpc.listchannels(scid)['channels']] == [(DEF_BASE, DEF_PPM, True), (DEF_BASE, DEF_PPM, True)])

    # do and check actual payment
    inv = l3.rpc.invoice(4999999, 'test_setchannelfee_2', 'desc')['bolt11']
    result = l1.rpc.dev_pay(inv, use_shadow=False)
    assert result['status'] == 'complete'
    assert result['msatoshi_sent'] == 5000049


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_setchannelfee_zero(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] <--default_fees--> [l2] <--specific_fees--> [l3]
    #
    # - json listchannels is able to see the new values in foreign node
    # - routing calculates fees correctly
    # - payment can be done using zero fees
    DEF_BASE = 1
    DEF_PPM = 10

    l1, l2, l3 = node_factory.line_graph(
        3, announce_channels=True, wait_for_announce=True,
        opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM})

    # get short channel id for 2->3
    scid = l2.get_channel_scid(l3)

    # TEST ZERO fees possible
    l2.rpc.setchannelfee(scid, 0, 0)
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [0, DEF_BASE])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [0, DEF_PPM])

    # test if zero fees are applied
    route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 2
    assert route[0]['msatoshi'] == 4999999
    assert route[1]['msatoshi'] == 4999999

    # Wait for l3 to know about our low-balling, otherwise they'll add a wrong
    # routehint to the invoice.
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['active']) for c in l3.rpc.listchannels(scid)['channels']] == [(0, 0, True), (DEF_BASE, DEF_PPM, True)])

    # do and check actual payment
    inv = l3.rpc.invoice(4999999, 'test_setchannelfee_3', 'desc')['bolt11']
    result = l1.rpc.dev_pay(inv, use_shadow=False)
    assert result['status'] == 'complete'
    assert result['msatoshi_sent'] == 4999999


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_setchannelfee_restart(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] <--default_fees--> [l2] <--specific_fees--> [l3]
    #
    # - l2 sets fees to custom values and restarts
    # - l1 routing can be made with the custom fees
    # - l2 sets fees to UIN32_MAX (db update default) and restarts
    # - l1 routing can be made to l3 and global (1 10) fees are applied
    DEF_BASE = 1
    DEF_PPM = 10
    OPTS = {'may_reconnect': True, 'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM}

    l1, l2, l3 = node_factory.line_graph(3, announce_channels=True, wait_for_announce=True, opts=OPTS)

    # get short channel idS
    scid12 = l1.get_channel_scid(l2)
    scid23 = l2.get_channel_scid(l3)

    # l2 set custom fees
    l2.rpc.setchannelfee(scid23, 1337, 137)

    # restart l2 and reconnect
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Make sure l1's gossipd registered channeld activating channel.
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(scid12)['channels']] == [True, True])

    # l1 wait for channel update from l2
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['active']) for c in l1.rpc.listchannels(scid23)['channels']] == [(1337, 137, True), (DEF_BASE, DEF_PPM, True)])

    # In case l3 includes a routehint, we need to make sure they also know
    # about the new fees, otherwise we may end up with the old feerate
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['active']) for c in l3.rpc.listchannels(scid23)['channels']] == [(1337, 137, True), (DEF_BASE, DEF_PPM, True)])

    # l1 can make payment to l3 with custom fees being applied
    # Note: BOLT #7 math works out to 2021 msat fees
    inv = l3.rpc.invoice(4999999, 'test_setchannelfee_1', 'desc')['bolt11']
    result = l1.rpc.dev_pay(inv, use_shadow=False)
    assert result['status'] == 'complete'
    assert result['msatoshi_sent'] == 5002020


@pytest.mark.developer("updates are delayed without --dev-fast-gossip")
def test_setchannelfee_all(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1]----> [l2]
    #   |
    #   o-----> [l3]
    DEF_BASE = 10
    DEF_PPM = 100

    l1, l2, l3 = node_factory.get_nodes(3, opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.fundchannel(l2, 1000000)
    l1.fundchannel(l3, 1000000)

    # get short channel id
    scid2 = l1.get_channel_scid(l2)
    scid3 = l1.get_channel_scid(l3)

    # now try to set all (two) channels using wildcard syntax
    result = l1.rpc.setchannelfee("all", 0xDEAD, 0xBEEF)

    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid2)['channels']] == [DEF_BASE, 0xDEAD])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid2)['channels']] == [DEF_PPM, 0xBEEF])
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid3)['channels']] == [0xDEAD, DEF_BASE])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid3)['channels']] == [0xBEEF, DEF_PPM])

    assert len(result['channels']) == 2
    assert result['base'] == 0xDEAD
    assert result['ppm'] == 0xBEEF
    assert result['channels'][0]['peer_id'] == l2.info['id']
    assert result['channels'][0]['short_channel_id'] == scid2
    assert result['channels'][1]['peer_id'] == l3.info['id']
    assert result['channels'][1]['short_channel_id'] == scid3


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_channel_spendable(node_factory, bitcoind):
    """Test that spendable_msat is accurate"""
    sats = 10**6
    l1, l2 = node_factory.line_graph(2, fundamount=sats, wait_for_announce=True,
                                     opts={'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'), 'holdtime': '30'})

    inv = l2.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']

    # We should be able to spend this much, and not one msat more!
    amount = l1.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat']
    route = l1.rpc.getroute(l2.info['id'], amount + 1, riskfactor=1, fuzzpercent=0)['route']
    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # This should fail locally with "capacity exceeded"
    with pytest.raises(RpcError, match=r"Capacity exceeded.*'erring_index': 0"):
        l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Exact amount should succeed.
    route = l1.rpc.getroute(l2.info['id'], amount, riskfactor=1, fuzzpercent=0)['route']
    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # Amount should drop to 0 once HTLC is sent; we have time, thanks to
    # hold_invoice.py plugin.
    wait_for(lambda: len(l1.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 1)
    assert l1.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat'] == Millisatoshi(0)
    l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Make sure l2 thinks it's all over.
    wait_for(lambda: len(l2.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 0)
    # Now, reverse should work similarly.
    inv = l1.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']
    amount = l2.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat']

    # Turns out we won't route this, as it's over max - reserve:
    route = l2.rpc.getroute(l1.info['id'], amount + 1, riskfactor=1, fuzzpercent=0)['route']
    l2.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # This should fail locally with "capacity exceeded"
    with pytest.raises(RpcError, match=r"Capacity exceeded.*'erring_index': 0"):
        l2.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Exact amount should succeed.
    route = l2.rpc.getroute(l1.info['id'], amount, riskfactor=1, fuzzpercent=0)['route']
    l2.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # Amount should drop to 0 once HTLC is sent; we have time, thanks to
    # hold_invoice.py plugin.
    wait_for(lambda: len(l2.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 1)
    assert l2.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat'] == Millisatoshi(0)
    l2.rpc.waitsendpay(payment_hash, TIMEOUT)


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_channel_receivable(node_factory, bitcoind):
    """Test that receivable_msat is accurate"""
    sats = 10**6
    l1, l2 = node_factory.line_graph(2, fundamount=sats, wait_for_announce=True,
                                     opts={'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'), 'holdtime': '30'})

    inv = l2.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']

    # We should be able to receive this much, and not one msat more!
    amount = l2.rpc.listpeers()['peers'][0]['channels'][0]['receivable_msat']
    route = l1.rpc.getroute(l2.info['id'], amount + 1, riskfactor=1, fuzzpercent=0)['route']
    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # This should fail locally with "capacity exceeded"
    with pytest.raises(RpcError, match=r"Capacity exceeded.*'erring_index': 0"):
        l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Exact amount should succeed.
    route = l1.rpc.getroute(l2.info['id'], amount, riskfactor=1, fuzzpercent=0)['route']
    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # Amount should drop to 0 once HTLC is sent; we have time, thanks to
    # hold_invoice.py plugin.
    wait_for(lambda: len(l2.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 1)
    assert l2.rpc.listpeers()['peers'][0]['channels'][0]['receivable_msat'] == Millisatoshi(0)
    l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Make sure both think it's all over.
    wait_for(lambda: len(l1.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 0)
    wait_for(lambda: len(l2.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 0)
    # Now, reverse should work similarly.
    inv = l1.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']
    amount = l1.rpc.listpeers()['peers'][0]['channels'][0]['receivable_msat']

    # Turns out we won't route this, as it's over max - reserve:
    route = l2.rpc.getroute(l1.info['id'], amount + 1, riskfactor=1, fuzzpercent=0)['route']
    l2.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # This should fail locally with "capacity exceeded"
    with pytest.raises(RpcError, match=r"Capacity exceeded.*'erring_index': 0"):
        l2.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Exact amount should succeed.
    route = l2.rpc.getroute(l1.info['id'], amount, riskfactor=1, fuzzpercent=0)['route']
    l2.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])

    # Amount should drop to 0 once HTLC is sent; we have time, thanks to
    # hold_invoice.py plugin.
    wait_for(lambda: len(l1.rpc.listpeers()['peers'][0]['channels'][0]['htlcs']) == 1)
    assert l1.rpc.listpeers()['peers'][0]['channels'][0]['receivable_msat'] == Millisatoshi(0)
    l2.rpc.waitsendpay(payment_hash, TIMEOUT)


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_channel_spendable_large(node_factory, bitcoind):
    """Test that spendable_msat is accurate for large channels"""
    # This is almost the max allowable spend.
    sats = 4294967
    l1, l2 = node_factory.line_graph(
        2,
        fundamount=sats,
        wait_for_announce=True,
        opts={
            'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'),
            'holdtime': '30'
        }
    )

    inv = l2.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']

    # We should be able to spend this much, and not one msat more!
    spendable = l1.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat']

    # receivable from the other side should calculate to the exact same amount
    receivable = l2.rpc.listpeers()['peers'][0]['channels'][0]['receivable_msat']
    assert spendable == receivable

    # route or waitsendpay fill fail.
    with pytest.raises(RpcError):
        route = l1.rpc.getroute(l2.info['id'], spendable + 1, riskfactor=1, fuzzpercent=0)['route']
        l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Exact amount should succeed.
    route = l1.rpc.getroute(l2.info['id'], spendable, riskfactor=1, fuzzpercent=0)['route']
    l1.rpc.sendpay(route, payment_hash, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(payment_hash, TIMEOUT)


def test_channel_spendable_receivable_capped(node_factory, bitcoind):
    """Test that spendable_msat and receivable_msat is capped at 2^32-1"""
    sats = 16777215
    l1, l2 = node_factory.line_graph(2, fundamount=sats, wait_for_announce=False)
    assert l1.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat'] == Millisatoshi(0xFFFFFFFF)
    assert l2.rpc.listpeers()['peers'][0]['channels'][0]['receivable_msat'] == Millisatoshi(0xFFFFFFFF)


@unittest.skipIf(True, "Test is extremely flaky")
@unittest.skipIf(not DEVELOPER and VALGRIND, "Doesn't raise exception, needs better sync")
def test_lockup_drain(node_factory, bitcoind):
    """Try to get channel into a state where opener can't afford fees on additional HTLC, so peer can't add HTLC"""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})

    # l1 sends all the money to l2 until even 1 msat can't get through.
    total = l1.drain(l2)

    # Even if feerate now increases 2x (30000), l2 should be able to send
    # non-dust HTLC to l1.
    l1.force_feerates(30000)
    l2.pay(l1, total // 2)

    # reset fees and send all back again
    l1.force_feerates(15000)
    l1.drain(l2)

    # But if feerate increase just a little more, l2 should not be able to send
    # non-fust HTLC to l1
    l1.force_feerates(30002)  # TODO: Why does 30001 fail? off by one in C code?
    wait_for(lambda: l1.rpc.listpeers()['peers'][0]['connected'])
    with pytest.raises(RpcError, match=r".*Capacity exceeded.*"):
        l2.pay(l1, total // 2)


@pytest.mark.developer("needs DEVELOPER=1 for dev_ignore_htlcs")
def test_htlc_too_dusty_outgoing(node_factory, bitcoind, chainparams):
    """ Try to hit the 'too much dust' limit, should fail the HTLC """
    feerate = 10000

    # elements txs are bigger so they become dusty faster
    max_dust_limit_sat = 100000 if chainparams['elements'] else 50000
    non_dust_htlc_val_sat = 20000 if chainparams['elements'] else 10000
    htlc_val_sat = 10000 if chainparams['elements'] else 5000

    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
                                              'feerates': (feerate, feerate, feerate, feerate),
                                              'max-dust-htlc-exposure-msat': '{}sat'.format(max_dust_limit_sat),
                                              'allow_warning': True})

    # l2 holds all of l1's htlcs hostage
    l2.rpc.dev_ignore_htlcs(id=l1.info['id'], ignore=True)

    # l2's max dust limit is set to 100k
    htlc_val_msat = htlc_val_sat * 1000
    num_dusty_htlcs = max_dust_limit_sat // htlc_val_sat

    # add a some non-dusty htlcs, these will fail when we raise the dust limit
    route = l1.rpc.getroute(l2.info['id'], non_dust_htlc_val_sat * 1000, 1)['route']
    for i in range(0, 3):
        inv = l2.rpc.invoice((non_dust_htlc_val_sat * 1000), str(i + 100), str(i + 100))
        l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
        l2.daemon.wait_for_log(r'their htlc .* dev_ignore_htlcs')
        res = only_one(l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])
        assert res['status'] == 'pending'

    # add some dusty-htlcs
    route = l1.rpc.getroute(l2.info['id'], htlc_val_msat, 1)['route']
    for i in range(0, num_dusty_htlcs):
        inv = l2.rpc.invoice(htlc_val_msat, str(i), str(i))
        l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
        l2.daemon.wait_for_log(r'their htlc .* dev_ignore_htlcs')
        res = only_one(l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])
        assert res['status'] == 'pending'

    # one more should tip it over, and return a payment failure
    inv = l2.rpc.invoice(htlc_val_msat, str(num_dusty_htlcs), str(num_dusty_htlcs))
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    l1.daemon.wait_for_log('CHANNEL_ERR_DUST_FAILURE')
    wait_for(lambda: only_one(l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])['status'] == 'failed')

    # but we can still add a non dust htlc
    route = l1.rpc.getroute(l2.info['id'], non_dust_htlc_val_sat * 1000, 1)['route']
    inv = l2.rpc.invoice((10000 * 1000), str(120), str(120))
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    l2.daemon.wait_for_log(r'their htlc .* dev_ignore_htlcs')
    res = only_one(l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])
    assert res['status'] == 'pending'

    # Ok, adjust our feerate upward, so the non-dust htlcs are now dust
    # note that this is above the buffer we've been keeping, so the channel
    # should automatically fail
    l1.set_feerates([feerate * 2] * 4, False)
    l1.restart()

    # the channel should start warning -- too much dust
    inv = l2.rpc.invoice(htlc_val_msat, str(num_dusty_htlcs + 1), str(num_dusty_htlcs + 1))
    with pytest.raises(RpcError, match=r'WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])


@pytest.mark.developer("needs DEVELOPER=1 for dev_ignore_htlcs")
def test_htlc_too_dusty_incoming(node_factory, bitcoind):
    """ Try to hit the 'too much dust' limit, should fail the HTLC """
    feerate = 30000
    l1, l2, l3 = node_factory.line_graph(3, opts=[{'may_reconnect': True,
                                                   'feerates': (feerate, feerate, feerate, feerate),
                                                   'max-dust-htlc-exposure-msat': '200000sat'},
                                                  {'may_reconnect': True,
                                                   'feerates': (feerate, feerate, feerate, feerate),
                                                   'max-dust-htlc-exposure-msat': '100000sat',
                                                   'fee-base': 0,
                                                   'fee-per-satoshi': 0},
                                                  {'max-dust-htlc-exposure-msat': '500000sat'}],
                                         wait_for_announce=True)

    # on the l2->l3, and l3 holds all the htlcs hostage
    # have l3 hold onto all the htlcs and not fulfill them
    l3.rpc.dev_ignore_htlcs(id=l2.info['id'], ignore=True)

    # l2's max dust limit is set to 100k
    max_dust_limit_sat = 100000
    htlc_val_sat = 10000
    htlc_val_msat = htlc_val_sat * 1000
    num_dusty_htlcs = max_dust_limit_sat // htlc_val_sat
    route = l1.rpc.getroute(l3.info['id'], htlc_val_msat, 1)['route']

    # l1 sends as much money as it can
    for i in range(0, num_dusty_htlcs):
        inv = l3.rpc.invoice(htlc_val_msat, str(i), str(i))
        l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
        l3.daemon.wait_for_log(r'their htlc .* dev_ignore_htlcs')
        res = only_one(l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])
        assert res['status'] == 'pending'

    # one more should tip it over, and return a payment failure
    inv = l3.rpc.invoice(htlc_val_msat, str(num_dusty_htlcs), str(num_dusty_htlcs))
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    l2.daemon.wait_for_log('failing immediately, as requested')
    wait_for(lambda: only_one(l1.rpc.listsendpays(payment_hash=inv['payment_hash'])['payments'])['status'] == 'failed')


def test_error_returns_blockheight(node_factory, bitcoind):
    """Test that incorrect_or_unknown_payment_details returns block height"""
    l1, l2 = node_factory.line_graph(2)

    l1.rpc.sendpay([{'msatoshi': 100,
                     'id': l2.info['id'],
                     'delay': 10,
                     'channel': l1.get_channel_scid(l2)}],
                   '00' * 32, payment_secret='00' * 32)

    with pytest.raises(RpcError, match=r"INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS.*'erring_index': 1") as err:
        l1.rpc.waitsendpay('00' * 32, TIMEOUT)

    # BOLT #4:
    # 1. type: PERM|15 (`incorrect_or_unknown_payment_details`)
    # 2. data:
    #    * [`u64`:`htlc_msat`]
    #    * [`u32`:`height`]
    assert (err.value.error['data']['raw_message']
            == '400f{:016x}{:08x}'.format(100, bitcoind.rpc.getblockcount()))


@pytest.mark.developer('Needs dev-routes')
def test_tlv_or_legacy(node_factory, bitcoind):
    # Ideally we'd test with l2 NOT var-onion, but then it can no longer connect
    # to us!
    l1, l2, l3 = node_factory.line_graph(3,
                                         opts={'plugin': os.path.join(os.getcwd(), 'tests/plugins/print_htlc_onion.py')})

    scid12 = l1.get_channel_scid(l2)
    scid23 = l2.get_channel_scid(l3)

    # We need to force l3 to provide route hint from l2 (it won't normally,
    # since it sees l2 as a dead end).
    inv = l3.rpc.call('invoice', {"msatoshi": 10000,
                                  "label": "test_tlv1",
                                  "description": "test_tlv1",
                                  "dev-routes": [[{'id': l2.info['id'],
                                                   'short_channel_id': scid23,
                                                   'fee_base_msat': 1,
                                                   'fee_proportional_millionths': 10,
                                                   'cltv_expiry_delta': 6}]]})['bolt11']
    l1.rpc.pay(inv)

    # Since L1 hasn't seen broadcast, it doesn't know L2 isn't TLV, but invoice tells it about L3
    l2.daemon.wait_for_log("Got onion.*'type': 'tlv'")
    l3.daemon.wait_for_log("Got onion.*'type': 'tlv'")

    # We need 5 more blocks to announce l1->l2 channel.
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Make sure l1 knows about l2
    wait_for(lambda: 'alias' in l1.rpc.listnodes(l2.info['id'])['nodes'][0])

    # Make sure l3 knows about l1->l2, so it will add route hint now.
    wait_for(lambda: len(l3.rpc.listchannels(scid12)['channels']) > 0)

    # Now it should send TLV to l2.
    inv = l3.rpc.invoice(10000, "test_tlv2", "test_tlv2")['bolt11']

    l1.rpc.pay(inv)
    l2.daemon.wait_for_log("Got onion.*'type': 'tlv'")
    l3.daemon.wait_for_log("Got onion.*'type': 'tlv'")


@pytest.mark.developer('Needs dev-routes')
@unittest.skipIf(TEST_NETWORK != 'regtest', "Invoice is network specific")
def test_pay_no_secret(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    l2.rpc.invoice(100000, "test_pay_no_secret", "test_pay_no_secret",
                   preimage='00' * 32, expiry=2000000000)

    # Produced from modified version (different secret!).
    inv_badsecret = 'lnbcrt1u1pwuedm6pp5ve584t0cv27hwmy0cx9ca8uwyqyfw9y9dm3r8vus9fv36r2l9yjsdqaw3jhxazlwpshjhmwda0hxetrwfjhgxq8pmnt9qqcqp9sp52au0npwmw4xxv2rfrat04kh9p3jlmklgavhfxqukx0l05pw5tccs9qypqsqa286dmt2xh3jy8cd8ndeyr845q8a7nhgjkerdqjns76jraux6j25ddx9f5k5r2ey0kk942x3uhaff66794kyjxxcd48uevf7p6ja53gqjj5ur7'
    with pytest.raises(RpcError, match=r"INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS.*'erring_index': 1"):
        l1.rpc.pay(inv_badsecret)

    # Produced from old version (no secret!)
    inv_nosecret = 'lnbcrt1u1pwue4vapp5ve584t0cv27hwmy0cx9ca8uwyqyfw9y9dm3r8vus9fv36r2l9yjsdqaw3jhxazlwpshjhmwda0hxetrwfjhgxq8pmnt9qqcqp9570xsjyykvssa6ty8fjth6f2y8h09myngad9utesttwjwclv95fz3lgd402f9e5yzpnxmkypg55rkvpg522gcz4ymsjl2w3m4jhw4jsp55m7tl'
    with pytest.raises(RpcError, match=r"INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS.*'erring_index': 1"):
        l1.rpc.pay(inv_nosecret)


@flaky
def test_shadow_routing(node_factory):
    """
    Test the value randomization through shadow routing

    Since there is a very low (0.5**10) probability that it fails we mark it
    as flaky.
    """
    # We need l3 for random walk
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    amount = 10000
    total_amount = 0
    n_payments = 10
    for i in range(n_payments):
        inv = l3.rpc.invoice(amount, "{}".format(i), "test")["bolt11"]
        total_amount += l1.rpc.pay(inv)["amount_sent_msat"]

    assert total_amount.millisatoshis > n_payments * amount
    # Test that the added amount isn't absurd
    assert total_amount.millisatoshis < (n_payments * amount) * (1 + 0.01)

    # FIXME: Test cltv delta too ?


def test_createonion_rpc(node_factory):
    l1 = node_factory.get_node()

    hops = [{
        "pubkey": "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        # legacy
        "payload": "000000000000000000000000000000000000000000000000000000000000000000"
    }, {
        "pubkey": "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        # tlv (20 bytes)
        "payload": "140101010101010101000000000000000100000001"
    }, {
        "pubkey": "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        # TLV (256 bytes)
        "payload": "fd0100000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    }, {
        "pubkey": "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        # tlv (20 bytes)
        "payload": "140303030303030303000000000000000300000003"
    }, {
        "pubkey": "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
        # legacy
        "payload": "000404040404040404000000000000000400000004000000000000000000000000"
    }]

    res = l1.rpc.createonion(hops=hops, assocdata="BB" * 32)
    assert(len(res['onion']) == 2 * 1366)
    assert(len(res['shared_secrets']) == len(hops))

    res = l1.rpc.createonion(hops=hops, assocdata="42" * 32,
                             session_key="41" * 32)
    # The trailer is generated using the filler and can be ued as a
    # checksum. This trailer is from the test-vector in the specs.
    print(res)
    assert(res['onion'].endswith('9400f45a48e6dc8ddbaeb3'))


@pytest.mark.developer("gossip propagation is slow without DEVELOPER=1")
def test_sendonion_rpc(node_factory):
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True)
    amt = 10**3
    route = l1.rpc.getroute(l4.info['id'], 10**3, 10)['route']
    inv = l4.rpc.invoice(amt, "lbl", "desc")

    first_hop = route[0]
    blockheight = l1.rpc.getinfo()['blockheight']

    def serialize_payload(n):
        block, tx, out = n['channel'].split('x')
        payload = hexlify(struct.pack(
            "!BQQL",
            0,
            int(block) << 40 | int(tx) << 16 | int(out),
            int(n['amount_msat']),
            blockheight + n['delay'])).decode('ASCII')
        payload += "00" * 12
        return payload

    def serialize_payload_final_tlv(n, payment_secret: str):
        def truncate_encode(i: int):
            """Encode a tu64 (or tu32 etc) value"""
            ret = struct.pack("!Q", i)
            while ret.startswith(b'\0'):
                ret = ret[1:]
            return ret

        payload = TlvPayload()
        # BOLT #4:
        #     1. type: 2 (`amt_to_forward`)
        #     2. data:
        #         * [`tu64`:`amt_to_forward`]
        b = BytesIO()
        b.write(truncate_encode(int(n['amount_msat'])))
        payload.add_field(2, b.getvalue())
        # BOLT #4:
        #    1. type: 4 (`outgoing_cltv_value`)
        #    2. data:
        #        * [`tu32`:`outgoing_cltv_value`]
        b = BytesIO()
        b.write(truncate_encode(n['delay']))
        payload.add_field(4, b.getvalue())
        # BOLT #4:
        #    1. type: 8 (`payment_data`)
        #    2. data:
        #        * [`32*byte`:`payment_secret`]
        #        * [`tu64`:`total_msat`]
        b = BytesIO()
        b.write(bytes.fromhex(payment_secret))
        b.write(truncate_encode(int(n['amount_msat'])))
        payload.add_field(8, b.getvalue())
        return payload.to_bytes().hex()

    # Need to shift the parameters by one hop
    hops = []
    for h, n in zip(route[:-1], route[1:]):
        # We tell the node h about the parameters to use for n (a.k.a. h + 1)
        hops.append({
            "pubkey": h['id'],
            "payload": serialize_payload(n)
        })

    # The last hop has a special payload:
    hops.append({
        "pubkey": route[-1]['id'],
        "payload": serialize_payload_final_tlv(route[-1], inv['payment_secret'])
    })

    onion = l1.rpc.createonion(hops=hops, assocdata=inv['payment_hash'])

    l1.rpc.sendonion(onion=onion['onion'], first_hop=first_hop,
                     payment_hash=inv['payment_hash'])

    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'])
    invs = l4.rpc.listinvoices(label="lbl")['invoices']
    assert(len(invs) == 1 and invs[0]['status'] == 'paid')

    pays = l1.rpc.listsendpays()['payments']
    assert(len(pays) == 1 and pays[0]['status'] == 'complete'
           and pays[0]['payment_hash'] == inv['payment_hash'])

    # And now for a failing payment, using a payment_hash that doesn't match an
    # invoice
    payment_hash = "00" * 32
    onion = l1.rpc.createonion(hops=hops, assocdata=payment_hash)
    l1.rpc.sendonion(onion=onion['onion'], first_hop=first_hop,
                     payment_hash=payment_hash)

    try:
        l1.rpc.waitsendpay(payment_hash=payment_hash)
        raise ValueError()
    except RpcError as e:
        assert(e.error['code'] == 202)
        assert(e.error['message'] == "Malformed error reply")

    pays = l1.rpc.listsendpays(payment_hash=payment_hash)['payments']
    assert(len(pays) == 1 and pays[0]['status'] == 'failed'
           and pays[0]['payment_hash'] == payment_hash)
    assert('erroronion' in pays[0])

    # Fail onion is msg + padding = 256 + 2*2 byte lengths + 32 byte HMAC
    assert(len(pays[0]['erroronion']) == (256 + 32 + 2 + 2) * 2)

    # Let's try that again, this time we give it the shared_secrets so it
    # should be able to decode the error.
    payment_hash = "01" * 32
    onion = l1.rpc.createonion(hops=hops, assocdata=payment_hash)
    l1.rpc.sendonion(onion=onion['onion'], first_hop=first_hop,
                     payment_hash=payment_hash,
                     shared_secrets=onion['shared_secrets'])

    try:
        l1.rpc.waitsendpay(payment_hash=payment_hash)
    except RpcError as e:
        assert(e.error['code'] == 204)
        assert(e.error['data']['raw_message'] == "400f00000000000003e80000006c")


@pytest.mark.developer("needs dev-disable-commit-after, dev-no-htlc-timeout")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_partial_payment(node_factory, bitcoind, executor):
    # We want to test two payments at the same time, before we send commit
    l1, l2, l3, l4 = node_factory.get_nodes(4, [{}] + [{'dev-disable-commit-after': 0, 'dev-no-htlc-timeout': None}] * 2 + [{'plugin': os.path.join(os.getcwd(), 'tests/plugins/print_htlc_onion.py')}])

    # Two routes to l4: one via l2, and one via l3.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 100000)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.fundchannel(l3, 100000)
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid24, _ = l2.fundchannel(l4, 100000)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid34, _ = l3.fundchannel(l4, 100000)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])

    # Wait until l1 knows about all channels.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 8)

    inv = l4.rpc.invoice(1000, 'inv', 'inv')
    paysecret = l4.rpc.decodepay(inv['bolt11'])['payment_secret']

    # Separate routes for each part of the payment.
    r134 = l1.rpc.getroute(l4.info['id'], 501, 1, exclude=[scid24 + '/0', scid24 + '/1'])['route']
    r124 = l1.rpc.getroute(l4.info['id'], 499, 1, exclude=[scid34 + '/0', scid34 + '/1'])['route']

    # These can happen in parallel.
    l1.rpc.sendpay(
        route=r134,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=1
    )

    # Can't mix non-parallel payment!
    with pytest.raises(RpcError, match=r'Already have parallel payment in progress'):
        l1.rpc.sendpay(
            route=r124,
            payment_hash=inv['payment_hash'],
            msatoshi=499,
            payment_secret=paysecret,
            groupid=1,
        )

    # It will not allow a parallel with different msatoshi!
    with pytest.raises(RpcError, match=r'msatoshi was previously 1000msat, now 999msat'):
        l1.rpc.sendpay(
            route=r124,
            payment_hash=inv['payment_hash'],
            msatoshi=999,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=2,
            groupid=1,
        )

    # This will work fine.
    l1.rpc.sendpay(
        route=r124,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=2,
        groupid=1,
    )

    # Any more would exceed total payment
    with pytest.raises(RpcError, match=r'Already have 1000msat of 1000msat payments in progress'):
        l1.rpc.sendpay(
            route=r124,
            payment_hash=inv['payment_hash'],
            msatoshi=1000,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=3,
            groupid=1,
        )

    # But repeat is a NOOP, as long as they're exactly the same!
    with pytest.raises(RpcError, match=r'Already pending with amount 501msat \(not 499msat\)'):
        l1.rpc.sendpay(
            route=r124,
            payment_hash=inv['payment_hash'],
            msatoshi=1000,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=1,
            groupid=1,
        )

    l1.rpc.sendpay(
        route=r134,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=1,
    )

    l1.rpc.sendpay(
        route=r124,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=2,
        groupid=1,
    )

    # Make sure they've got the HTLCs before we unsuppress
    l2.daemon.wait_for_logs('peer_in WIRE_UPDATE_ADD_HTLC')
    l3.daemon.wait_for_log('peer_in WIRE_UPDATE_ADD_HTLC')

    # Now continue, payments will succeed due to MPP.
    l2.rpc.dev_reenable_commit(l4.info['id'])
    l3.rpc.dev_reenable_commit(l4.info['id'])
    l2.rpc.dev_reenable_commit(l1.info['id'])
    l3.rpc.dev_reenable_commit(l1.info['id'])

    res = l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], partid=1)
    assert res['partid'] == 1
    res = l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], partid=2)
    assert res['partid'] == 2

    for i in range(2):
        line = l4.daemon.wait_for_log('print_htlc_onion.py: Got onion')
        assert "'type': 'tlv'" in line
        assert "'forward_amount': '499msat'" in line or "'forward_amount': '501msat'" in line
        assert "'total_msat': '1000msat'" in line
        assert "'payment_secret': '{}'".format(paysecret) in line

    pay = only_one(l1.rpc.listpays()['pays'])
    assert pay['bolt11'] == inv['bolt11']
    assert pay['status'] == 'complete'
    assert pay['number_of_parts'] == 2
    assert pay['amount_sent_msat'] == Millisatoshi(1002)

    # It will immediately succeed if we pay again.
    pay = l1.rpc.sendpay(
        route=r124,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=2,
        groupid=1,
    )
    assert pay['status'] == 'complete'

    # If we try with an unknown partid, it will refuse.
    with pytest.raises(RpcError, match=r'Already succeeded'):
        l1.rpc.sendpay(
            route=r124,
            payment_hash=inv['payment_hash'],
            msatoshi=1000,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=3,
            groupid=1)


def test_partial_payment_timeout(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(1000, 'inv', 'inv')
    paysecret = l2.rpc.decodepay(inv['bolt11'])['payment_secret']

    route = l1.rpc.getroute(l2.info['id'], 500, 1)['route']
    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=1,
    )

    with pytest.raises(RpcError, match=r'WIRE_MPP_TIMEOUT'):
        l1.rpc.waitsendpay(
            payment_hash=inv['payment_hash'],
            timeout=70 + TIMEOUT // 4,
            partid=1,
            groupid=1,
        )
    l2.daemon.wait_for_log(r'HTLC set contains 1 HTLCs, for a total of 500msat out of 1000msat \(payment_secret\)')

    # We can still pay it normally.
    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=2
    )
    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=2,
        groupid=2
    )
    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=1, groupid=2)
    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=2, groupid=2)
    l2.daemon.wait_for_log(r'HTLC set contains 1 HTLCs, for a total of 500msat out of 1000msat \(payment_secret\)')
    l2.daemon.wait_for_log(r'HTLC set contains 2 HTLCs, for a total of 1000msat out of 1000msat \(payment_secret\)')


def test_partial_payment_restart(node_factory, bitcoind):
    """Test that we recover a set when we restart"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{}]
                                         + [{'may_reconnect': True}] * 2)

    inv = l3.rpc.invoice(1000, 'inv', 'inv')
    paysecret = l3.rpc.decodepay(inv['bolt11'])['payment_secret']

    route = l1.rpc.getroute(l3.info['id'], 500, 1)['route']

    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=1,
    )

    wait_for(lambda: [f['status'] for f in l2.rpc.listforwards()['forwards']] == ['offered'])

    # Restart, and make sure it's reconnected to l2.
    l3.restart()
    print(l2.rpc.listpeers())
    wait_for(lambda: [p['connected'] for p in l2.rpc.listpeers()['peers']] == [True, True])

    # Pay second part.
    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        msatoshi=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=2,
        groupid=1,
    )

    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=1)
    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=2)


@pytest.mark.developer("needs dev-disconnect")
def test_partial_payment_htlc_loss(node_factory, bitcoind):
    """Test that we discard a set when the HTLC is lost"""
    # We want l2 to fail once it has completed first htlc.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{},
                                               {'disconnect': ['=WIRE_UPDATE_ADD_HTLC', '+WIRE_REVOKE_AND_ACK']},
                                               {}])

    inv = l3.rpc.invoice(1000, 'inv', 'inv')
    paysecret = l3.rpc.decodepay(inv['bolt11'])['payment_secret']

    route = l1.rpc.getroute(l3.info['id'], 500, 1)['route']

    l1.rpc.sendpay(route=route, payment_hash=inv['payment_hash'], msatoshi=1000, bolt11=inv['bolt11'], payment_secret=paysecret, partid=1)

    wait_for(lambda: not only_one(l2.rpc.listpeers(l3.info['id'])['peers'])['connected'])
    l2.rpc.dev_fail(l3.info['id'])

    # Since HTLC is missing from commit (dust), it's closed as soon as l2 sees
    # it onchain.  l3 shouldn't crash though.
    bitcoind.generate_block(1, wait_for_mempool=1)

    with pytest.raises(RpcError,
                       match=r'WIRE_PERMANENT_CHANNEL_FAILURE \(reply from remote\)'):
        l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=1)


def test_createonion_limits(node_factory):
    l1, = node_factory.get_nodes(1)
    hops = [{
        # privkey: 41bfd2660762506c9933ade59f1debf7e6495b10c14a92dbcd2d623da2507d3d
        "pubkey": "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
        "payload": "00" * 228
    }, {
        "pubkey": "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "payload": "00" * 228
    }, {
        "pubkey": "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        "payload": "00" * 228
    }, {
        "pubkey": "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        "payload": "00" * 228
    }, {
        "pubkey": "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
        "payload": "00" * 228
    }]

    # This should success since it's right at the edge
    l1.rpc.createonion(hops=hops, assocdata="BB" * 32)

    # This one should fail however
    with pytest.raises(RpcError, match=r'Payloads exceed maximum onion packet size.'):
        hops[0]['payload'] += '01'
        l1.rpc.createonion(hops=hops, assocdata="BB" * 32)

    # But with a larger onion, it will work!
    oniontool = os.path.join(os.path.dirname(__file__), "..", "devtools", "onion")
    onion = l1.rpc.createonion(hops=hops, assocdata="BB" * 32, onion_size=1301)['onion']

    # Oniontool wants a filename :(
    onionfile = os.path.join(l1.daemon.lightning_dir, 'onion')
    with open(onionfile, "w") as f:
        f.write(onion)

    subprocess.check_output(
        [oniontool, '--assoc-data', "BB" * 32,
         'decode', onionfile, "41bfd2660762506c9933ade59f1debf7e6495b10c14a92dbcd2d623da2507d3d"]
    )


@pytest.mark.developer("needs use_shadow")
def test_blockheight_disagreement(node_factory, bitcoind, executor):
    """
    While a payment is in-transit from payer to payee, a block
    might be mined, so that the blockheight the payer used to
    initiate the payment is no longer the blockheight when the
    payee receives it.
    This leads to a failure which *used* to be
    `final_expiry_too_soon`, a non-permanent failure, but
    which is *now* `incorrect_or_unknown_payment_details`,
    a permanent failure.
    `pay` treats permanent failures as, well, permanent, and
    gives up on receiving such failure from the payee, but
    this particular subcase of blockheight disagreement is
    actually a non-permanent failure (the payer only needs
    to synchronize to the same blockheight as the payee).
    """
    l1, l2 = node_factory.line_graph(2)

    sync_blockheight(bitcoind, [l1, l2])

    # Arrange l1 to stop getting new blocks.
    def no_more_blocks(req):
        return {"result": None,
                "error": {"code": -8, "message": "Block height out of range"}, "id": req['id']}
    l1.daemon.rpcproxy.mock_rpc('getblockhash', no_more_blocks)

    # Increase blockheight and make sure l2 knows it.
    # Why 2? Because `pay` uses min_final_cltv_expiry + 1.
    # But 2 blocks coming in close succession, plus slow
    # forwarding nodes and block propagation, are still
    # possible on the mainnet, thus this test.
    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l2])

    # Have l2 make an invoice.
    inv = l2.rpc.invoice(1000, 'l', 'd')['bolt11']

    # Have l1 pay l2
    def pay(l1, inv):
        l1.rpc.dev_pay(inv, use_shadow=False)
    fut = executor.submit(pay, l1, inv)

    # Make sure l1 sends out the HTLC.
    l1.daemon.wait_for_logs([r'NEW:: HTLC LOCAL'])

    height = bitcoind.rpc.getblockchaininfo()['blocks']
    l1.daemon.wait_for_log('Remote node appears to be on a longer chain.*catch up to block {}'.format(height))

    # Unblock l1 from new blocks.
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)

    # pay command should complete without error
    fut.result()


def test_sendpay_msatoshi_arg(node_factory):
    """sendpay msatoshi arg was used for non-MPP to indicate the amount
they asked for.  But using it with anything other than the final amount
caused a crash in 0.8.0, so we then disallowed it.
    """
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(1000, 'inv', 'inv')

    # Can't send non-MPP payment which specifies msatoshi != final.
    with pytest.raises(RpcError, match=r'Do not specify msatoshi \(1001msat\) without'
                       ' partid: if you do, it must be exactly'
                       r' the final amount \(1000msat\)'):
        l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1000, 1)['route'], payment_hash=inv['payment_hash'], msatoshi=1001, bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'Do not specify msatoshi \(999msat\) without'
                       ' partid: if you do, it must be exactly'
                       r' the final amount \(1000msat\)'):
        l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1000, 1)['route'], payment_hash=inv['payment_hash'], msatoshi=999, bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])

    # Can't send MPP payment which pays any more than amount.
    with pytest.raises(RpcError, match=r'Final amount 1001msat is greater than 1000msat, despite MPP'):
        l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1001, 1)['route'], payment_hash=inv['payment_hash'], msatoshi=1000, bolt11=inv['bolt11'], partid=1, payment_secret=inv['payment_secret'])

    # But this works
    l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1001, 1)['route'], payment_hash=inv['payment_hash'], msatoshi=1001, bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    inv = only_one(l2.rpc.listinvoices('inv')['invoices'])
    assert inv['status'] == 'paid'
    assert inv['amount_received_msat'] == Millisatoshi(1001)


def test_reject_invalid_payload(node_factory):
    """Send an onion payload with an unknown even type.

    Recipient l2 should reject it the incoming HTLC with an invalid onion
    payload error.

    """

    l1, l2 = node_factory.line_graph(2)
    amt = 10**3
    route = l1.rpc.getroute(l2.info['id'], amt, 10)['route']
    inv = l2.rpc.invoice(amt, "lbl", "desc")

    first_hop = route[0]

    # A TLV payload with an unknown even type:
    payload = TlvPayload()
    payload.add_field(0xB000, b'Hi there')
    hops = [{"pubkey": l2.info['id'], "payload": payload.to_hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=inv['payment_hash'])
    l1.rpc.sendonion(onion=onion['onion'],
                     first_hop=first_hop,
                     payment_hash=inv['payment_hash'],
                     shared_secrets=onion['shared_secrets'])

    l2.daemon.wait_for_log(r'Failing HTLC because of an invalid payload')

    with pytest.raises(RpcError, match=r'WIRE_INVALID_ONION_PAYLOAD'):
        l1.rpc.waitsendpay(inv['payment_hash'])


@pytest.mark.skip("Needs to be updated for modern onion")
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "Needs blinding args to sendpay")
def test_sendpay_blinding(node_factory):
    l1, l2, l3, l4 = node_factory.line_graph(4)

    blindedpathtool = os.path.join(os.path.dirname(__file__), "..", "devtools", "blindedpath")

    # Create blinded path l2->l4
    output = subprocess.check_output(
        [blindedpathtool, '--simple-output', 'create',
         l2.info['id'] + "/" + l2.get_channel_scid(l3),
         l3.info['id'] + "/" + l3.get_channel_scid(l4),
         l4.info['id']]
    ).decode('ASCII').strip()

    # First line is blinding, then <peerid> then <encblob>.
    blinding, p1, p1enc, p2, p2enc, p3 = output.split('\n')
    # First hop can't be blinded!
    assert p1 == l2.info['id']

    amt = 10**3
    inv = l4.rpc.invoice(amt, "lbl", "desc")

    route = [{'id': l2.info['id'],
              'channel': l1.get_channel_scid(l2),
              'amount_msat': Millisatoshi(1002),
              'delay': 21,
              'blinding': blinding,
              'enctlv': p1enc},
             {'id': p2,
              'amount_msat': Millisatoshi(1001),
              'delay': 15,
              # FIXME: this is a dummy!
              'channel': '0x0x0',
              'enctlv': p2enc},
             {'id': p3,
              # FIXME: this is a dummy!
              'channel': '0x0x0',
              'amount_msat': Millisatoshi(1000),
              'delay': 9,
              'style': 'tlv'}]
    l1.rpc.sendpay(route=route,
                   payment_hash=inv['payment_hash'],
                   bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])


def test_excluded_adjacent_routehint(node_factory, bitcoind, compat):
    """Test case where we try have a routehint which leads to an adjacent
    node, but the result exceeds our maxfee; we crashed trying to find
    what part of the path was most expensive in that case

    """
    l1, l2, l3 = node_factory.line_graph(3)

    # We'll be forced to use routehint, since we don't know about l3.
    wait_for(lambda: len(l3.rpc.listchannels(source=l2.info['id'])['channels']) == 1)
    inv = l3.rpc.invoice(10**3, "lbl", "desc", exposeprivatechannels=l2.get_channel_scid(l3))

    # This will make it reject the routehint.
    err = r'Fee exceeds our fee budget: 1msat > 0msat, discarding route'
    with pytest.raises(RpcError, match=err):
        l1.rpc.pay(bolt11=inv['bolt11'], maxfeepercent=0, exemptfee=0)


def test_keysend(node_factory):
    amt = 10000
    l1, l2, l3, l4 = node_factory.line_graph(
        4,
        wait_for_announce=True,
        opts=[{}, {}, {}, {'disable-plugin': 'keysend'}]
    )

    # The keysend featurebit must be set in the announcement, i.e., l1 should
    # learn that l3 supports keysends.
    features = l1.rpc.listnodes(l3.info['id'])['nodes'][0]['features']
    assert(int(features, 16) >> 55 & 0x01 == 1)

    # If we disable keysend, then the featurebit must not be set,
    # i.e., l4 doesn't support it.
    features = l1.rpc.listnodes(l4.info['id'])['nodes'][0]['features']
    assert(int(features, 16) >> 55 & 0x01 == 0)

    # Self-sends are not allowed (see #4438)
    with pytest.raises(RpcError, match=r'We are the destination.'):
        l1.rpc.keysend(l1.info['id'], amt)

    # Send an indirect one from l1 to l3
    l1.rpc.keysend(l3.info['id'], amt)
    invs = l3.rpc.listinvoices()['invoices']
    assert(len(invs) == 1)

    inv = invs[0]
    print(inv)
    assert(inv['msatoshi_received'] >= amt)

    # Now send a direct one instead from l1 to l2
    l1.rpc.keysend(l2.info['id'], amt)
    invs = l2.rpc.listinvoices()['invoices']
    assert(len(invs) == 1)

    inv = invs[0]
    assert(inv['msatoshi_received'] >= amt)

    # And finally try to send a keysend payment to l4, which doesn't
    # support it. It MUST fail.
    with pytest.raises(RpcError, match=r"Recipient [0-9a-f]{66} reported an invalid payload"):
        l3.rpc.keysend(l4.info['id'], amt)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "Requires extratlvs option")
def test_keysend_extra_tlvs(node_factory):
    """Use the extratlvs option to deliver a message with sphinx' TLV type.
    """
    amt = 10000
    l1, l2 = node_factory.line_graph(
        2,
        wait_for_announce=True,
        opts=[
            {},
            {
                'experimental-accept-extra-tlv-types': '133773310',
                "plugin": os.path.join(os.path.dirname(__file__), "plugins/sphinx-receiver.py"),
            },
        ]
    )

    # Send an indirect one from l1 to l3
    l1.rpc.keysend(l2.info['id'], amt, extratlvs={133773310: 'FEEDC0DE'})
    invs = l2.rpc.listinvoices()['invoices']
    assert(len(invs) == 1)
    assert(l2.daemon.is_in_log(r'plugin-sphinx-receiver.py.*extratlvs.*133773310.*feedc0de'))

    inv = invs[0]
    assert(inv['msatoshi_received'] >= amt)

    # Now try again with the TLV type in extra_tlvs as string:
    l1.rpc.keysend(l2.info['id'], amt, extratlvs={133773310: 'FEEDC0DE'})


def test_keysend_routehint(node_factory):
    """Test whether we can deliver a keysend by adding a routehint on the cli
    """
    amt = 10000
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)
    l3 = node_factory.get_node()
    l2.connect(l3)
    l2.fundchannel(l3, announce_channel=False)

    dest = l3.info['id']
    routehints = [
        [
            {
                'scid': l3.rpc.listpeers()['peers'][0]['channels'][0]['short_channel_id'],
                'id': l2.info['id'],
                'feebase': '1msat',
                'feeprop': 10,
                'expirydelta': 9,
            }
        ],
        [  # Dummy
            {
                'scid': '1x2x3',
                'id': '02' * 33,
                'feebase': 1,
                'feeprop': 1,
                'expirydelta': 9,
            },
        ],
    ]

    # Without any hints we should fail:
    with pytest.raises(RpcError):
        l1.rpc.call("keysend", payload={'destination': dest, 'msatoshi': amt})

    # We should also fail with only non-working hints:
    with pytest.raises(RpcError):
        l1.rpc.call("keysend", payload={'destination': dest, 'msatoshi': amt, 'routehints': routehints[1:]})

    l1.rpc.call("keysend", payload={'destination': dest, 'msatoshi': amt, 'routehints': routehints})
    invs = l3.rpc.listinvoices()['invoices']
    assert(len(invs) == 1)

    inv = invs[0]
    assert(inv['msatoshi_received'] >= amt)


def test_invalid_onion_channel_update(node_factory):
    '''
    Some onion failures "should" send a `channel_update`.

    This test checks to see if we handle things correctly
    even if some remote node does not send the required
    `channel_update`.
    '''
    plugin = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs_invalid.py')
    l1, l2, l3 = node_factory.line_graph(3,
                                         opts=[{},
                                               {'plugin': plugin},
                                               {}],
                                         wait_for_announce=True)

    l1id = l1.info['id']

    inv = l3.rpc.invoice(12345, 'inv', 'inv')['bolt11']
    # Should fail, since l2 will always fail to forward.
    with pytest.raises(RpcError):
        l1.rpc.pay(inv)

    # l1 should still be alive afterwards.
    assert l1.rpc.getinfo()['id'] == l1id


@pytest.mark.developer("Requires use_shadow")
def test_pay_exemptfee(node_factory, compat):
    """Tiny payment, huge fee

    l1 -> l2 -> l3

    Create a tiny invoice for 1 msat, it'll be dominated by the base_fee on
    the l2->l3 channel. So it'll get rejected on the first attempt if we set
    the exemptfee way too low. The default fee exemption threshold is
    5000msat, so 5001msat is not exempted by default and a 5001msat fee on
    l2->l3 should trigger this.

    """
    l1, l2, l3 = node_factory.line_graph(
        3,
        opts=[{}, {'fee-base': 5001, 'fee-per-satoshi': 0}, {}],
        wait_for_announce=True
    )

    err = r'Ran out of routes to try'

    with pytest.raises(RpcError, match=err):
        l1.rpc.dev_pay(l3.rpc.invoice(1, "lbl1", "desc")['bolt11'], use_shadow=False)

    # If we tell our node that 5001msat is ok this should work
    l1.rpc.dev_pay(l3.rpc.invoice(1, "lbl2", "desc")['bolt11'], use_shadow=False, exemptfee=5001)

    # Given the above network this is the smallest amount that passes without
    # the fee-exemption (notice that we let it through on equality).
    threshold = int(5001 / 0.05)

    # This should be just below the fee-exemption and is the first value that is allowed through
    with pytest.raises(RpcError, match=err):
        l1.rpc.dev_pay(l3.rpc.invoice(threshold - 1, "lbl3", "desc")['bolt11'], use_shadow=False)

    # While this'll work just fine
    l1.rpc.dev_pay(l3.rpc.invoice(int(5001 * 200), "lbl4", "desc")['bolt11'], use_shadow=False)


@pytest.mark.developer("Requires use_shadow flag")
def test_pay_peer(node_factory, bitcoind):
    """If we have a direct channel to the destination we should use that.

    This is complicated a bit by not having sufficient capacity, but the
    channel_hints can help us there.

    l1 -> l2
     |   ^
     v  /
     l3
    """
    # Set the dust exposure higher, this gets triggered on liquid
    l1, l2, l3 = node_factory.get_nodes(3, opts={'max-dust-htlc-exposure-msat': '100000sat'})
    node_factory.join_nodes([l1, l2])
    node_factory.join_nodes([l1, l3])
    node_factory.join_nodes([l3, l2], wait_for_announce=True)

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 6)

    def spendable(n1, n2):
        peer = n1.rpc.listpeers(n2.info['id'])['peers'][0]
        chan = peer['channels'][0]
        avail = chan['spendable_msat']
        return avail

    amt = Millisatoshi(10**8)
    # How many payments do we expect to go through directly?
    direct = spendable(l1, l2).millisatoshis // amt.millisatoshis

    # Remember the l1 -> l3 capacity, it should not change until we run out of
    # direct capacity.
    l1l3cap = spendable(l1, l3)

    for i in range(0, direct):
        inv = l2.rpc.invoice(amt.millisatoshis, "lbl{}".format(i),
                             "desc{}".format(i))['bolt11']
        l1.rpc.dev_pay(inv, use_shadow=False)

    # We should not have more than amt in the direct channel anymore
    assert(spendable(l1, l2) < amt)
    assert(spendable(l1, l3) == l1l3cap)

    # Next one should take the alternative, but it should still work
    inv = l2.rpc.invoice(amt.millisatoshis, "final", "final")['bolt11']
    l1.rpc.dev_pay(inv, use_shadow=False)


def test_mpp_presplit(node_factory):
    """Make a rather large payment of 5*10ksat and see it being split.
    """
    MPP_TARGET_SIZE = 10**7  # Taken from libpluin-pay.c
    amt = 5 * MPP_TARGET_SIZE

    # Assert that the amount we're going to send is indeed larger than our
    # split size.
    assert(MPP_TARGET_SIZE < amt)

    l1, l2, l3 = node_factory.line_graph(
        3, fundamount=10**8, wait_for_announce=True,
        opts={'wumbo': None,
              'max-dust-htlc-exposure-msat': '500000sat'}
    )

    inv = l3.rpc.invoice(amt, 'lbl', 'desc')['bolt11']
    p = l1.rpc.pay(inv)

    assert(p['parts'] >= 5)
    inv = l3.rpc.listinvoices()['invoices'][0]

    assert(inv['msatoshi'] == inv['msatoshi_received'])


def test_mpp_adaptive(node_factory, bitcoind):
    """We have two paths, both too small on their own, let's combine them.

    ```dot
    digraph {
      l1 -> l2 [label="scid=103x1x1, cap=amt-1"];
      l2 -> l4 [label="scid=105x1x1, cap=max"];
      l1 -> l3 [label="scid=107x1x1, cap=max"];
      l3 -> l4 [label="scid=109x1x1, cap=amt-1"];
    }
    """
    amt = 10**7 - 1
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    l1.connect(l2)
    l2.connect(l4)
    l1.connect(l3)
    l3.connect(l4)

    # First roadblock right away on an outgoing channel
    l2.fundchannel(l1, amt)
    l2.fundchannel(l4, amt, wait_for_active=True)
    l2.rpc.pay(l1.rpc.invoice(
        amt + 99999000 - 1,  # Slightly less than amt + reserve
        label="reb l1->l2",
        description="Rebalance l1 -> l2"
    )['bolt11'])

    # Second path fails only after the first hop
    l1.fundchannel(l3, amt)
    l4.fundchannel(l3, amt, wait_for_active=True)
    l4.rpc.pay(l3.rpc.invoice(
        amt + 99999000 - 1,  # Slightly less than amt + reserve
        label="reb l3->l4",
        description="Rebalance l3 -> l4"
    )['bolt11'])
    l1.rpc.listpeers()

    # Make sure neither channel can fit the payment by itself.
    c12 = l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'][0]
    c34 = l3.rpc.listpeers(l4.info['id'])['peers'][0]['channels'][0]
    assert(c12['spendable_msat'].millisatoshis < amt)
    assert(c34['spendable_msat'].millisatoshis < amt)

    # Make sure all HTLCs entirely resolved before we mine more blocks!
    def all_htlcs(n):
        htlcs = []
        for p in n.rpc.listpeers()['peers']:
            for c in p['channels']:
                htlcs += c['htlcs']
        return htlcs

    wait_for(lambda: all([all_htlcs(n) == [] for n in [l1, l2, l3, l4]]))

    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 8)

    inv = l4.rpc.invoice(
        amt,
        label="splittest",
        description="Needs to be split into at least 2"
    )['bolt11']

    p = l1.rpc.pay(inv)
    from pprint import pprint
    pprint(p)
    pprint(l1.rpc.paystatus(inv))


def test_pay_fail_unconfirmed_channel(node_factory, bitcoind):
    '''
    Replicate #3855.
    `pay` crash when any direct channel is still
    unconfirmed.
    '''
    l1, l2 = node_factory.get_nodes(2)

    amount_sat = 10 ** 6

    # create l2->l1 channel.
    l2.fundwallet(amount_sat * 5)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.fundchannel(l1.info['id'], amount_sat * 3)
    # channel is still unconfirmed.

    # Attempt to pay from l1 to l2.
    # This should fail since the channel capacities are wrong.
    invl2 = l2.rpc.invoice(Millisatoshi(amount_sat * 1000), 'i', 'i')['bolt11']
    with pytest.raises(RpcError):
        l1.rpc.pay(invl2)

    # Let the channel confirm.
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1, l2])

    # Now give enough capacity so l1 can pay.
    invl1 = l1.rpc.invoice(Millisatoshi(amount_sat * 2 * 1000), 'j', 'j')['bolt11']
    l2.rpc.pay(invl1)

    # Wait for us to recognize that the channel is available
    wait_for(lambda: l1.rpc.listpeers()['peers'][0]['channels'][0]['spendable_msat'].millisatoshis > amount_sat * 1000)

    # Now l1 can pay to l2.
    l1.rpc.pay(invl2)


def test_bolt11_null_after_pay(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2)

    amount_sat = 10 ** 6
    # pay a generic bolt11 and test if the label bol11 is null
    # inside the command listpays

    # create l2->l1 channel.
    l2.fundwallet(amount_sat * 5)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.fundchannel(l1.info['id'], amount_sat * 3)

    # Let the channel confirm.
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1, l2])
    wait_for(lambda: only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_NORMAL')

    amt = Millisatoshi(amount_sat * 2 * 1000)
    invl1 = l1.rpc.invoice(amt, 'j', 'j')['bolt11']
    l2.rpc.pay(invl1)

    pays = l2.rpc.listpays()["pays"]
    assert(pays[0]["bolt11"] == invl1)
    assert('amount_msat' in pays[0] and pays[0]['amount_msat'] == amt)
    assert('created_at' in pays[0])


def test_mpp_presplit_routehint_conflict(node_factory, bitcoind):
    '''
    We had a bug where pre-splitting the payment prevents *any*
    routehints from being taken.
    We tickle that bug here by building l1->l2->l3, but with
    l2->l3 as an unpublished channel.
    If the payment is large enough to trigger pre-splitting, the
    routehints are not applied in any of the splits.
    '''
    l1, l2, l3 = node_factory.get_nodes(3)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1l2, _ = l1.fundchannel(l2, 10**7, announce_channel=True)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.fundchannel(l3, 10**7, announce_channel=False)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Wait for l3 to learn about l1->l2, otherwise it will think
    # l2 is a deadend and not add it to the routehint.
    wait_for(lambda: len(l3.rpc.listchannels(l1l2)['channels']) >= 2)

    inv = l3.rpc.invoice(Millisatoshi(2 * 10000 * 1000), 'i', 'i', exposeprivatechannels=True)['bolt11']

    l1.rpc.pay(inv)


def test_delpay_argument_invalid(node_factory, bitcoind):
    """
    This test includes all possible combinations of input error inside the
    delpay command.
    """

    # Create the line graph l2 -> l1 with a channel of 10 ** 5 sat!
    l2, l1 = node_factory.line_graph(2, fundamount=10**5, wait_for_announce=True)

    with pytest.raises(RpcError):
        l2.rpc.delpay()

    # sanity check
    inv = l1.rpc.invoice(10 ** 5, 'inv', 'inv')
    payment_hash = "AA" * 32
    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'complete')

    l2.rpc.pay(inv['bolt11'])

    wait_for(lambda: l2.rpc.listpays(inv['bolt11'])['pays'][0]['status'] == 'complete')

    payment_hash = inv['payment_hash']

    # payment paid with wrong status (pending status is a illegal input)
    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'pending')

    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'invalid_status')

    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'failed')

    # test if the node is still ready
    payments = l2.rpc.delpay(payment_hash, 'complete')

    assert payments['payments'][0]['bolt11'] == inv['bolt11']
    assert len(payments['payments']) == 1
    assert len(l2.rpc.listpays()['pays']) == 0


def test_delpay_payment_split(node_factory, bitcoind):
    """
    Test behavior of delpay with an MPP
    """
    MPP_TARGET_SIZE = 10**7  # Taken from libpluin-pay.c
    amt = 4 * MPP_TARGET_SIZE

    l1, l2, l3 = node_factory.line_graph(3, fundamount=10**5,
                                         wait_for_announce=True)
    inv = l3.rpc.invoice(amt, 'lbl', 'desc')
    l1.rpc.pay(inv['bolt11'])

    assert len(l1.rpc.listpays()['pays']) == 1
    delpay_result = l1.rpc.delpay(inv['payment_hash'], 'complete')['payments']
    assert len(delpay_result) >= 4
    assert len(l1.rpc.listpays()['pays']) == 0


def test_listpay_result_with_paymod(node_factory, bitcoind):
    """
    The object of this test is to verify the correct behavior
    of the RPC command listpay e with two different type of
    payment, such as: keysend (without invoice) and pay (with invoice).
    l1 -> keysend -> l2
    l2 -> pay invoice -> l3
    """

    amount_sat = 10 ** 6

    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    invl2 = l2.rpc.invoice(amount_sat * 2, "inv_l2", "inv_l2")
    l1.rpc.pay(invl2['bolt11'])

    l2.rpc.keysend(l3.info['id'], amount_sat * 2, "keysend_l3")

    assert 'bolt11' in l1.rpc.listpays()['pays'][0]
    assert 'bolt11' not in l2.rpc.listpays()['pays'][0]
    assert 'payment_hash' in l2.rpc.listpays()['pays'][0]
    assert 'payment_hash' in l1.rpc.listpays()['pays'][0]
    assert 'destination' in l1.rpc.listpays()['pays'][0]
    assert 'destination' in l2.rpc.listpays()['pays'][0]


@unittest.skipIf(env('COMPAT') != 1, "legacypay requires COMPAT=1")
def test_listpays_ongoing_attempt(node_factory, bitcoind, executor):
    """Test to reproduce issue #3915.

    The issue is that the bolt11 string is not initialized if the root payment
    was split (no attempt with the bolt11 annotation ever hit `lightningd`,
    hence we cannot filter by that. In addition keysends never have a bolt11
    string, so we need to switch to payment_hash comparisons anyway.
    """
    plugin = os.path.join(os.path.dirname(__file__), 'plugins', 'hold_htlcs.py')
    l1, l2, l3 = node_factory.line_graph(3, opts=[{}, {}, {'plugin': plugin}],
                                         wait_for_announce=True)

    f = executor.submit(l1.rpc.keysend, l3.info['id'], 100)
    l3.daemon.wait_for_log(r'Holding onto an incoming htlc')
    l1.rpc.listpays()
    f.result()

    inv = l2.rpc.invoice(10**6, 'legacy', 'desc')['bolt11']
    l1.rpc.legacypay(inv)
    l1.rpc.listpays()

    # Produce loads of parts to increase probability of hitting the issue,
    # should result in 100 splits at least
    inv = l3.rpc.invoice(10**9, 'mpp invoice', 'desc')['bolt11']

    # Start the payment, it'll get stuck for 10 seconds at l3
    executor.submit(l1.rpc.pay, inv)
    l1.daemon.wait_for_log(r'Split into [0-9]+ sub-payments due to initial size')
    l3.daemon.wait_for_log(r'Holding onto an incoming htlc')

    # While that is going on, check in with `listpays` to see if aggregation
    # is working.
    l1.rpc.listpays()

    # Now restart and see if we still can aggregate things correctly.
    l1.restart()
    l1.rpc.listpays()


def test_listsendpays_and_listpays_order(node_factory):
    """listsendpays should be in increasing id order, listpays in created_at"""
    l1, l2 = node_factory.line_graph(2)
    for i in range(5):
        inv = l2.rpc.invoice(1000 - i, "test {}".format(i), "test")['bolt11']
        l1.rpc.pay(inv)

    ids = [p['id'] for p in l1.rpc.listsendpays()['payments']]
    assert ids == sorted(ids)

    created_at = [p['created_at'] for p in l1.rpc.listpays()['pays']]
    assert created_at == sorted(created_at)


@pytest.mark.developer("needs use_shadow")
def test_mpp_waitblockheight_routehint_conflict(node_factory, bitcoind, executor):
    '''
    We have a bug where a blockheight disagreement between us and
    the receiver causes us to advance through the routehints a bit
    too aggressively.
    '''
    l1, l2, l3 = node_factory.get_nodes(3)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1l2, _ = l1.fundchannel(l2, 10**7, announce_channel=True)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.fundchannel(l3, 10**7, announce_channel=False)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Wait for l3 to learn about l1->l2, otherwise it will think
    # l2 is a deadend and not add it to the routehint.
    wait_for(lambda: len(l3.rpc.listchannels(l1l2)['channels']) >= 2)

    # Now make the l1 payer stop receiving blocks.
    def no_more_blocks(req):
        return {"result": None,
                "error": {"code": -8, "message": "Block height out of range"}, "id": req['id']}
    l1.daemon.rpcproxy.mock_rpc('getblockhash', no_more_blocks)

    # Increase blockheight by 2, like in test_blockheight_disagreement.
    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l3])

    inv = l3.rpc.invoice(Millisatoshi(2 * 10000 * 1000), 'i', 'i', exposeprivatechannels=True)['bolt11']

    # Have l1 pay l3
    def pay(l1, inv):
        l1.rpc.dev_pay(inv, use_shadow=False)
    fut = executor.submit(pay, l1, inv)

    # Make sure l1 sends out the HTLC.
    l1.daemon.wait_for_logs([r'NEW:: HTLC LOCAL'])

    # Unblock l1 from new blocks.
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)

    # pay command should complete without error
    fut.result(TIMEOUT)


@pytest.mark.developer("channel setup very slow (~10 minutes) if not DEVELOPER")
@pytest.mark.slow_test
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(True, "Temporarily disabled while flake diagnosed: blame Rusty!")
def test_mpp_interference_2(node_factory, bitcoind, executor):
    '''
    We create a "public network" that looks like so.
    Each channel is perfectly balanced, with 7 * unit
    funds on each side.

        4 -- 5
        |   /|
        |  / |
        | /  |
        |/   |
        6 -- 7

    l1 is the payee, who will later issue some invoices.
    It arranges unpublished channels from the above public
    network:

        l5->l1: 7 * unit
        l6->l1: 5 * unit
        l4->l1: 3 * unit
        l7->l1: 2 * unit

    l2 and l3 are payers.
    They create some unpublished channels to the public network:

        l2->l4, l2->l6: 6 * unit each
        l3->l7, l3->l6: 6 * unit each

    Finally, l1 issues 6 * unit invoices, simultaneously, to l2 and l3.
    Both of them perform `pay` simultaneously, in order to test if
    they interfere with each other.

    This test then tries to check if both of them can pay, given
    that there is sufficient incoming capacity, and then some,
    to the payee, and the public network is perfectly balanced
    with more than sufficient capacity, as well.
    '''
    opts = {'feerates': (1000, 1000, 1000, 1000)}

    l1, l2, l3, l4, l5, l6, l7 = node_factory.get_nodes(7, opts=opts)

    # Unit
    unit = Millisatoshi(11000 * 1000)

    # Build the public network.
    public_network = [l4.fundbalancedchannel(l5, unit * 14),
                      l4.fundbalancedchannel(l6, unit * 14),
                      l5.fundbalancedchannel(l6, unit * 14),
                      l5.fundbalancedchannel(l7, unit * 14),
                      l6.fundbalancedchannel(l7, unit * 14)]

    # Build unpublished channels to the merchant l1.
    l4.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l5.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l6.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l7.rpc.connect(l1.info['id'], 'localhost', l1.port)

    # If we're 'dual-funding', turn off the reciprocal funding
    # so that we can fund channels without making them balanced
    if EXPERIMENTAL_DUAL_FUND:
        for n in [l1, l2, l3, l4, l5, l6, l7]:
            n.rpc.call('funderupdate', {'fund_probability': 0})

    # The order in which the routes are built should not matter so
    # shuffle them.
    incoming_builders = [lambda: l5.fundchannel(l1, int((unit * 7).to_satoshi()), announce_channel=False),
                         lambda: l6.fundchannel(l1, int((unit * 5).to_satoshi()), announce_channel=False),
                         lambda: l4.fundchannel(l1, int((unit * 3).to_satoshi()), announce_channel=False),
                         lambda: l7.fundchannel(l1, int((unit * 2).to_satoshi()), announce_channel=False)]
    random.shuffle(incoming_builders)
    for b in incoming_builders:
        b()

    # Build unpublished channels from the buyers l2 and l3.
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
    l2.rpc.connect(l6.info['id'], 'localhost', l6.port)
    l3.rpc.connect(l7.info['id'], 'localhost', l7.port)
    l3.rpc.connect(l6.info['id'], 'localhost', l6.port)
    l2.fundchannel(l4, int((unit * 6).to_satoshi()), announce_channel=False)
    l2.fundchannel(l6, int((unit * 6).to_satoshi()), announce_channel=False)
    l3.fundchannel(l7, int((unit * 6).to_satoshi()), announce_channel=False)
    l3.fundchannel(l6, int((unit * 6).to_satoshi()), announce_channel=False)

    # Now wait for the buyers to learn the entire public network.
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5, l6, l7])
    for channel in public_network:
        wait_for(lambda: len(l2.rpc.listchannels(channel)['channels']) == 2)
        wait_for(lambda: len(l3.rpc.listchannels(channel)['channels']) == 2)

    # At this point, we have the following incoming channel capacities:
    # 74094000, 52314000, 30318000, 19318000

    # We *always* rotate through, since we have no published channels,
    # but we can select badly and get an overlap. e.g. first invoice
    # takes 30318000, 19318000 and 74094000.  Second will then take
    # 52314000, and have to reuse 30318000, which gets exhausted by the
    # first payer, thus leaving them unable to pay 66000000.

    # So we re-do this until we only have 4 or fewer routehints.
    while True:
        # Buyers check out some purchaseable stuff from the merchant.
        i2 = l1.rpc.invoice(unit * 6, ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20)), 'i2')['bolt11']
        i3 = l1.rpc.invoice(unit * 6, ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20)), 'i3')['bolt11']
        if len(l1.rpc.decodepay(i2)['routes'] + l1.rpc.decodepay(i3)['routes']) <= 4:
            break

    # Pay simultaneously!
    p2 = executor.submit(l2.rpc.pay, i2)
    p3 = executor.submit(l3.rpc.pay, i3)

    # Both payments should succeed.
    p2.result(TIMEOUT)
    p3.result(TIMEOUT)


def test_large_mpp_presplit(node_factory):
    """Make sure that ludicrous amounts don't saturate channels

    We aim to have at most PRESPLIT_MAX_SPLITS HTLCs created directly from the
    `presplit` modifier. The modifier will scale up its target size to
    guarantee this, while still bucketizing payments that are in the following
    range:

    ```
    target_size = PRESPLIT_MAX_SPLITS^{n} + MPP_TARGET_SIZE
    target_size < amount <= target_size * PRESPLIT_MAX_SPLITS
    ```

    """
    PRESPLIT_MAX_SPLITS = 16
    MPP_TARGET_SIZE = 10 ** 7
    amt = 400 * MPP_TARGET_SIZE

    l1, l2, l3 = node_factory.line_graph(
        3, fundamount=10**8, wait_for_announce=True,
        opts={'wumbo': None}
    )

    inv = l3.rpc.invoice(amt, 'lbl', 'desc')['bolt11']
    p = l1.rpc.pay(inv)

    assert(p['parts'] <= PRESPLIT_MAX_SPLITS)
    inv = l3.rpc.listinvoices()['invoices'][0]

    assert(inv['msatoshi'] == inv['msatoshi_received'])


@pytest.mark.developer("builds large network, which is slow if not DEVELOPER")
@pytest.mark.slow_test
def test_mpp_overload_payee(node_factory, bitcoind):
    """
    We had a bug where if the payer is unusually well-connected compared
    to the payee, the payee is unable to accept a large payment since the
    payer will split it into lots of tiny payments, which would choke the
    max-concurrent-htlcs limit of the payee.
    """
    # Default value as of this writing.
    # However, with anchor commitments we might be able to safely lift this
    # default limit in the future, so explicitly put this value here, since
    # that is what our test assumes.
    opts = {'max-concurrent-htlcs': 30}

    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(6, opts=opts)

    # Respect wumbo.
    # Using max-sized channels shows that the issue is not capacity
    # but rather max-concurrent-htlcs.
    # This is grade-school level.
    amt = 2**24 - 1

    # Build the public network.
    # l1 is the very well-connected payer.
    # l2 is the poorly-connected payee.
    # l3->l6 are well-connected hop nodes.
    public_network = [l1.fundbalancedchannel(l3, amt),
                      l1.fundbalancedchannel(l4, amt),
                      l1.fundbalancedchannel(l5, amt),
                      l1.fundbalancedchannel(l6, amt),
                      l2.fundbalancedchannel(l6, amt),
                      l3.fundbalancedchannel(l4, amt),
                      l3.fundbalancedchannel(l5, amt),
                      l3.fundbalancedchannel(l6, amt),
                      l4.fundbalancedchannel(l5, amt),
                      l5.fundbalancedchannel(l6, amt)]

    # Ensure l1 knows the entire public network.
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5, l6])
    for c in public_network:
        wait_for(lambda: len(l1.rpc.listchannels(c)['channels']) >= 2)

    # Now create a 400,000-sat invoice.
    # This assumes the MPP presplitter strongly prefers to
    # create lot sizes of 10,000 sats each.
    # This leads the presplitter to prefer to split into
    # around 40 HTLCs of 10,000 sats each, but since
    # max-concurrent-htlcs is set to 30, l2 would be unable
    # to receive.
    inv = l2.rpc.invoice(Millisatoshi(400000 * 1000), 'i', 'i')['bolt11']

    # pay.
    l1.rpc.pay(inv)


@unittest.skipIf(EXPERIMENTAL_FEATURES, "this is always on with EXPERIMENTAL_FEATURES")
def test_offer_needs_option(node_factory):
    """Make sure we don't make offers without offer command"""
    l1 = node_factory.get_node()
    with pytest.raises(RpcError, match='experimental-offers not enabled'):
        l1.rpc.call('offer', {'amount': '1msat', 'description': 'test'})
    with pytest.raises(RpcError, match='experimental-offers not enabled'):
        l1.rpc.call('offerout', {'amount': '2msat',
                                 'description': 'simple test'})
    with pytest.raises(RpcError, match='Unknown command'):
        l1.rpc.call('fetchinvoice', {'offer': 'aaaa'})

    # Decode still works though
    assert l1.rpc.decode('lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqyys5qq7ypnwgkvdr57yzh6h92zg3qctvrm7w38djg67kzcm4yeg8vc4cq633uzqaxlsxzxergsrav494jjrpuy9hcldjeglha57lxvz20fhha6hjwhv69nnzwzjsajntyf0c4z8h9e70dfdlfq8jdvc9rdht8vr955udtg')['valid']


def test_offer(node_factory, bitcoind):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/currencyUSDAUD5000.py')
    l1 = node_factory.get_node(options={'plugin': plugin, 'experimental-offers': None})

    # Try empty description
    ret = l1.rpc.call('offer', [9, ''])
    l1.rpc.decode(ret['bolt12'])

    bolt12tool = os.path.join(os.path.dirname(__file__), "..", "devtools", "bolt12-cli")
    # Try different amount strings
    for amount in ['1msat', '0.1btc', 'any', '1USD', '1.10AUD']:
        ret = l1.rpc.call('offer', {'amount': amount,
                                    'description': 'test for ' + amount})
        offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])

        assert offer['bolt12'] == ret['bolt12']
        assert offer['bolt12_unsigned'] == ret['bolt12_unsigned']
        assert offer['offer_id'] == ret['offer_id']

        output = subprocess.check_output([bolt12tool, 'decode',
                                          offer['bolt12']]).decode('ASCII')
        if amount == 'any':
            assert 'amount' not in output
        else:
            assert 'amount' in output
        output = subprocess.check_output([bolt12tool, 'decode',
                                          offer['bolt12_unsigned']]).decode('ASCII')
        if amount == 'any':
            assert 'amount' not in output
        else:
            assert 'amount' in output

    # Try wrong amount precision:
    with pytest.raises(RpcError, match='Currency AUD requires 2 minor units'):
        l1.rpc.call('offer', {'amount': '1.100AUD',
                              'description': 'test for invalid amount'})

    with pytest.raises(RpcError, match='Currency AUD requires 2 minor units'):
        l1.rpc.call('offer', {'amount': '1.1AUD',
                              'description': 'test for invalid amount'})

    # Make sure it fails on unknown currencies.
    with pytest.raises(RpcError, match='No values available for currency EUR'):
        l1.rpc.call('offer', {'amount': '1.00EUR',
                              'description': 'test for unknown currency'})

    # Test label and description
    weird_label = 'label \\ " \t \n'
    weird_desc = 'description \\ " \t \n ナンセンス 1杯'
    ret = l1.rpc.call('offer', {'amount': '0.1btc',
                                'description': weird_desc,
                                'label': weird_label})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    assert offer['label'] == weird_label

    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'description: ' + weird_desc in output

    # Test issuer
    weird_issuer = 'description \\ " \t \n ナンセンス 1杯'
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'issuer test',
                                'issuer': weird_issuer})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])

    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'issuer: ' + weird_issuer in output

    # Test quantity min/max
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_min test',
                                'quantity_min': 1})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'quantity_min: 1' in output

    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'quantity_max': 2})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'quantity_max: 2' in output

    # BOLT-offers #12:
    # 	 * - MUST NOT set `quantity_min` or `quantity_max` less than 1.
    with pytest.raises(RpcError, match='quantity_min: must be >= 1'):
        ret = l1.rpc.call('offer', {'amount': '100000sat',
                                    'description': 'quantity_min test',
                                    'quantity_min': 0})

    with pytest.raises(RpcError, match='quantity_max: must be >= 1'):
        ret = l1.rpc.call('offer', {'amount': '100000sat',
                                    'description': 'quantity_max test',
                                    'quantity_max': 0})
    # BOLT-offers #12:
    # - if both:
    #    - MUST set `quantity_min` greater or equal to `quantity_max`.
    with pytest.raises(RpcError, match='quantity_min: must be <= quantity_max'):
        ret = l1.rpc.call('offer', {'amount': '100000sat',
                                    'description': 'quantity_max test',
                                    'quantity_min': 10,
                                    'quantity_max': 9})

    # Test absolute_expiry
    exp = int(time.time() + 2)
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'absolute_expiry': exp})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'absolute_expiry: {}'.format(exp) in output

    # Recurrence tests!
    for r in [['1second', 'seconds', 1],
              ['10seconds', 'seconds', 10],
              ['1minute', 'seconds', 60],
              ['10minutes', 'seconds', 600],
              ['1hour', 'seconds', 3600],
              ['10hours', 'seconds', 36000],
              ['1day', 'days', 1],
              ['10days', 'days', 10],
              ['1week', 'days', 7],
              ['10weeks', 'days', 70],
              ['1month', 'months', 1],
              ['10months', 'months', 10],
              ['1year', 'years', 1],
              ['10years', 'years', 10]]:
        ret = l1.rpc.call('offer', {'amount': '100000sat',
                                    'description': 'quantity_max test',
                                    'recurrence': r[0]})
        offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
        output = subprocess.check_output([bolt12tool, 'decode',
                                          offer['bolt12']]).decode('UTF-8')
        assert 'recurrence: every {} {}\n'.format(r[2], r[1]) in output

    # Test limit
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'recurrence': '10minutes',
                                'recurrence_limit': 5})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'recurrence: every 600 seconds limit 5\n' in output

    # Test base
    # (1456740000 == 10:00:00 (am) UTC on 29 February, 2016)
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'recurrence': '10minutes',
                                'recurrence_base': '@1456740000'})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'recurrence: every 600 seconds start 1456740000' in output
    assert '(can start any period)' not in output

    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'recurrence': '10minutes',
                                'recurrence_base': 1456740000})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'recurrence: every 600 seconds start 1456740000' in output
    assert '(can start any period)' in output

    # Test paywindow
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'recurrence': '10minutes',
                                'recurrence_paywindow': '-10+20'})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'recurrence: every 600 seconds paywindow -10 to +20\n' in output

    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'recurrence': '10minutes',
                                'recurrence_paywindow': '-10+600%'})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'recurrence: every 600 seconds paywindow -10 to +600 (pay proportional)\n' in output


@pytest.mark.developer("dev-no-modern-onion is DEVELOPER-only")
def test_fetchinvoice_3hop(node_factory, bitcoind):
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True,
                                             opts={'experimental-offers': None,
                                                   'may_reconnect': True,
                                                   'dev-no-reconnect': None})
    offer1 = l4.rpc.call('offer', {'amount': '2msat',
                                   'description': 'simple test'})
    assert offer1['created'] is True

    l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})

    # Make sure l4 handled both onions before shutting down
    l1.daemon.wait_for_log(r'plugin-fetchinvoice: Received modern onion .*obs2\\":false')
    l1.daemon.wait_for_log(r'plugin-fetchinvoice: No match for modern onion.*obs2\\":true')

    # Test with obsolete onion.
    l4.stop()
    l4.daemon.opts['dev-no-modern-onion'] = None
    l4.start()
    l4.rpc.connect(l3.info['id'], 'localhost', l3.port)

    l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})

    # Test with modern onion.
    l4.stop()
    del l4.daemon.opts['dev-no-modern-onion']
    l4.daemon.opts['dev-no-obsolete-onion'] = None
    l4.start()
    l4.rpc.connect(l3.info['id'], 'localhost', l3.port)

    l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})


def test_fetchinvoice(node_factory, bitcoind):
    # We remove the conversion plugin on l3, causing it to get upset.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{'experimental-offers': None},
                                               {'experimental-offers': None},
                                               {'experimental-offers': None,
                                                'allow_broken_log': True}])

    # Simple offer first.
    offer1 = l3.rpc.call('offer', {'amount': '2msat',
                                   'description': 'simple test'})
    assert offer1['created'] is True

    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})
    inv2 = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12_unsigned'],
                                        'payer_note': 'Thanks for the fish!'})
    assert inv1 != inv2
    assert 'next_period' not in inv1
    assert 'next_period' not in inv2
    assert only_one(l3.rpc.call('listoffers', [offer1['offer_id']])['offers'])['used'] is False
    l1.rpc.pay(inv1['invoice'])
    assert only_one(l3.rpc.call('listoffers', [offer1['offer_id']])['offers'])['used'] is True
    l1.rpc.pay(inv2['invoice'])
    assert only_one(l3.rpc.call('listoffers', [offer1['offer_id']])['offers'])['used'] is True

    # listinvoices will show these on l3
    assert [x['local_offer_id'] for x in l3.rpc.listinvoices()['invoices']] == [offer1['offer_id'], offer1['offer_id']]

    assert 'payer_note' not in only_one(l3.rpc.call('listinvoices', {'invstring': inv1['invoice']})['invoices'])
    assert only_one(l3.rpc.call('listinvoices', {'invstring': inv2['invoice']})['invoices'])['payer_note'] == 'Thanks for the fish!'

    # BTW, test listinvoices-by-offer_id:
    assert len(l3.rpc.listinvoices(offer_id=offer1['offer_id'])['invoices']) == 2

    # We can also set the amount explicitly, to tip.
    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'msatoshi': 3})
    assert l1.rpc.call('decode', [inv1['invoice']])['amount_msat'] == 3
    l1.rpc.pay(inv1['invoice'])

    # More than ~5x expected is rejected as absurd (it's actually a divide test,
    # which means we need 15 here, not 11).
    with pytest.raises(RpcError, match="Remote node sent failure message.*Amount vastly exceeds 2msat"):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'msatoshi': 15})

    # Underpay is rejected.
    with pytest.raises(RpcError, match="Remote node sent failure message.*Amount must be at least 2msat"):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'msatoshi': 1})

    # If no amount is specified in offer, one must be in invoice.
    offer_noamount = l3.rpc.call('offer', {'amount': 'any',
                                           'description': 'any amount test'})
    with pytest.raises(RpcError, match="msatoshi parameter required"):
        l1.rpc.call('fetchinvoice', {'offer': offer_noamount['bolt12']})
    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer_noamount['bolt12'], 'msatoshi': 100})
    # But amount won't appear in changes
    assert 'msat' not in inv1['changes']

    # Single-use invoice can be fetched multiple times, only paid once.
    offer2 = l3.rpc.call('offer', {'amount': '1msat',
                                   'description': 'single-use test',
                                   'single_use': True})['bolt12']

    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer2})
    inv2 = l1.rpc.call('fetchinvoice', {'offer': offer2})
    assert inv1 != inv2
    assert 'next_period' not in inv1
    assert 'next_period' not in inv2

    l1.rpc.pay(inv1['invoice'])

    # We can't pay the other one now.
    with pytest.raises(RpcError, match="INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS.*'erring_node': '{}'".format(l3.info['id'])):
        l1.rpc.pay(inv2['invoice'])

    # We can't reuse the offer, either.
    with pytest.raises(RpcError, match='Offer no longer available'):
        l1.rpc.call('fetchinvoice', {'offer': offer2})

    # Recurring offer.
    offer3 = l2.rpc.call('offer', {'amount': '1msat',
                                   'description': 'recurring test',
                                   'recurrence': '1minutes'})
    assert only_one(l2.rpc.call('listoffers', [offer3['offer_id']])['offers'])['used'] is False

    ret = l1.rpc.call('fetchinvoice', {'offer': offer3['bolt12'],
                                       'recurrence_counter': 0,
                                       'recurrence_label': 'test recurrence'})
    period1 = ret['next_period']
    assert period1['counter'] == 1
    assert period1['endtime'] == period1['starttime'] + 59
    assert period1['paywindow_start'] == period1['starttime'] - 60
    assert period1['paywindow_end'] == period1['endtime']
    assert only_one(l2.rpc.call('listoffers', [offer3['offer_id']])['offers'])['used'] is False

    l1.rpc.pay(ret['invoice'], label='test recurrence')
    assert only_one(l2.rpc.call('listoffers', [offer3['offer_id']])['offers'])['used'] is True

    ret = l1.rpc.call('fetchinvoice', {'offer': offer3['bolt12'],
                                       'recurrence_counter': 1,
                                       'recurrence_label': 'test recurrence'})
    period2 = ret['next_period']
    assert period2['counter'] == 2
    assert period2['starttime'] == period1['endtime'] + 1
    assert period2['endtime'] == period2['starttime'] + 59
    assert period2['paywindow_start'] == period2['starttime'] - 60
    assert period2['paywindow_end'] == period2['endtime']

    # Can't request 2 before paying 1.
    with pytest.raises(RpcError, match='previous invoice has not been paid'):
        l1.rpc.call('fetchinvoice', {'offer': offer3['bolt12'],
                                     'recurrence_counter': 2,
                                     'recurrence_label': 'test recurrence'})

    l1.rpc.pay(ret['invoice'], label='test recurrence')

    # Now we can, but it's too early:
    with pytest.raises(RpcError, match="Too early: can't send until time {}".format(period1['starttime'])):
        l1.rpc.call('fetchinvoice', {'offer': offer3['bolt12'],
                                     'recurrence_counter': 2,
                                     'recurrence_label': 'test recurrence'})

    # Wait until the correct moment.
    while time.time() < period1['starttime']:
        time.sleep(1)

    l1.rpc.call('fetchinvoice', {'offer': offer3['bolt12'],
                                 'recurrence_counter': 2,
                                 'recurrence_label': 'test recurrence'})

    # Check we can request invoice without a channel.
    l4 = node_factory.get_node(options={'experimental-offers': None})
    l4.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # ... even if we can't find ourselves.
    l4.rpc.call('fetchinvoice', {'offer': offer3['bolt12'],
                                 'recurrence_counter': 0,
                                 'recurrence_label': 'test nochannel'})
    # ... even if we know it from gossmap
    wait_for(lambda: l4.rpc.listnodes(l3.info['id'])['nodes'] != [])
    l4.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l4.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})

    # Now, test amount in different currency!
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/currencyUSDAUD5000.py')
    l3.rpc.plugin_start(plugin)

    offerusd = l3.rpc.call('offer', {'amount': '10.05USD',
                                     'description': 'USD test'})['bolt12']

    inv = l1.rpc.call('fetchinvoice', {'offer': offerusd})
    assert inv['changes']['msat'] == Millisatoshi(int(10.05 * 5000))

    # If we remove plugin, it can no longer give us an invoice.
    l3.rpc.plugin_stop(plugin)

    with pytest.raises(RpcError, match="Internal error"):
        l1.rpc.call('fetchinvoice', {'offer': offerusd})
    l3.daemon.wait_for_log("Unknown command 'currencyconvert'")
    # But we can still pay the (already-converted) invoice.
    l1.rpc.pay(inv['invoice'])

    # Identical creation gives it again, just with created false.
    offer1 = l3.rpc.call('offer', {'amount': '2msat',
                                   'description': 'simple test'})
    assert offer1['created'] is False
    l3.rpc.call('disableoffer', {'offer_id': offer1['offer_id']})
    with pytest.raises(RpcError, match="1000.*Offer already exists, but isn't active"):
        l3.rpc.call('offer', {'amount': '2msat',
                              'description': 'simple test'})

    # Test timeout.
    l3.stop()
    with pytest.raises(RpcError, match='Timeout waiting for response'):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'timeout': 10})

    # Now try an offer with a more complex paywindow (only 10 seconds before)
    offer = l2.rpc.call('offer', {'amount': '1msat',
                                  'description': 'paywindow test',
                                  'recurrence': '20seconds',
                                  'recurrence_paywindow': '-10+0'})['bolt12']

    ret = l1.rpc.call('fetchinvoice', {'offer': offer,
                                       'recurrence_counter': 0,
                                       'recurrence_label': 'test paywindow'})
    period3 = ret['next_period']
    assert period3['counter'] == 1
    assert period3['endtime'] == period3['starttime'] + 19
    assert period3['paywindow_start'] == period3['starttime'] - 10
    assert period3['paywindow_end'] == period3['starttime']
    l1.rpc.pay(ret['invoice'], label='test paywindow')

    # We can get another invoice, as many times as we want.
    # (It may return the same one!).
    while int(time.time()) <= period3['paywindow_start']:
        time.sleep(1)

    l1.rpc.call('fetchinvoice', {'offer': offer,
                                 'recurrence_counter': 1,
                                 'recurrence_label': 'test paywindow'})
    l1.rpc.call('fetchinvoice', {'offer': offer,
                                 'recurrence_counter': 1,
                                 'recurrence_label': 'test paywindow'})

    # Wait until too late!
    while int(time.time()) <= period3['paywindow_end']:
        time.sleep(1)

    with pytest.raises(RpcError, match="Too late: expired time {}".format(period3['paywindow_end'])):
        l1.rpc.call('fetchinvoice', {'offer': offer,
                                     'recurrence_counter': 1,
                                     'recurrence_label': 'test paywindow'})


@pytest.mark.developer("Needs dev-allow-localhost for autoconnect, dev-force-features to avoid routing onionmsgs")
def test_fetchinvoice_autoconnect(node_factory, bitcoind):
    """We should autoconnect if we need to, to route."""

    if EXPERIMENTAL_FEATURES:
        # We have to force option_onion_messages off!
        opts1 = {'dev-force-features': '-39'}
    else:
        opts1 = {}
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts=[opts1,
                                           {'experimental-offers': None,
                                            'dev-allow-localhost': None}])

    l3 = node_factory.get_node(options={'experimental-offers': None})
    l3.rpc.connect(l1.info['id'], 'localhost', l1.port)
    wait_for(lambda: l3.rpc.listnodes(l2.info['id'])['nodes'] != [])

    offer = l2.rpc.call('offer', {'amount': '2msat',
                                  'description': 'simple test'})
    l3.rpc.call('fetchinvoice', {'offer': offer['bolt12']})
    assert l3.rpc.listpeers(l2.info['id'])['peers'] != []

    # Similarly for send-invoice offer.
    l3.rpc.disconnect(l2.info['id'])
    offer = l2.rpc.call('offerout', {'amount': '2msat',
                                     'description': 'simple test'})
    # Ofc l2 can't actually pay it!
    with pytest.raises(RpcError, match='pay attempt failed: "Ran out of routes to try'):
        l3.rpc.call('sendinvoice', {'offer': offer['bolt12'], 'label': 'payme!'})

    assert l3.rpc.listpeers(l2.info['id'])['peers'] != []

    # But if we create a channel l3->l1->l2 (and balance!), l2 can!
    node_factory.join_nodes([l3, l1], wait_for_announce=True)
    # Make sure l2 knows about it
    wait_for(lambda: l2.rpc.listnodes(l3.info['id'])['nodes'] != [])

    l3.rpc.pay(l2.rpc.invoice(FUNDAMOUNT * 500, 'balancer', 'balancer')['bolt11'])
    # Make sure l2 has capacity (can be still resolving!).
    wait_for(lambda: only_one(only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['channels'])['spendable_msat'] != Millisatoshi(0))

    l3.rpc.disconnect(l2.info['id'])
    l3.rpc.call('sendinvoice', {'offer': offer['bolt12'], 'label': 'payme for real!'})
    # It will have autoconnected, to send invoice (since l1 says it doesn't do onion messages!)
    assert l3.rpc.listpeers(l2.info['id'])['peers'] != []


def test_pay_waitblockheight_timeout(node_factory, bitcoind):
    plugin = os.path.join(os.path.dirname(__file__), 'plugins', 'endlesswaitblockheight.py')
    l1, l2 = node_factory.line_graph(2, opts=[{}, {'plugin': plugin}])

    sync_blockheight(bitcoind, [l1, l2])
    inv = l2.rpc.invoice(42, 'lbl', 'desc')['bolt11']

    with pytest.raises(RpcError, match=r'WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        l1.rpc.pay(inv)

    # Post mortem checks that we tried only once.
    status = l1.rpc.paystatus(inv)

    # Should have only one attempt that triggered the wait, which then failed.
    assert len(status['pay']) == 1
    assert len(status['pay'][0]['attempts']) == 1


@pytest.mark.developer("dev-rawrequest is DEVELOPER-only")
def test_dev_rawrequest(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False,
                                     opts={'experimental-offers': None})

    offer = l2.rpc.call('offer', {'amount': '2msat',
                                  'description': 'simple test'})
    # Get fetchinvoice to make us an invoice_request
    l1.rpc.call('fetchinvoice', {'offer': offer['bolt12']})

    m = re.search(r'invoice_request: \\"([a-z0-9]*)\\"', l1.daemon.is_in_log('invoice_request:'))
    ret = l1.rpc.call('dev-rawrequest', {'invreq': m.group(1),
                                         'nodeid': l2.info['id'],
                                         'timeout': 10})
    assert 'invoice' in ret


def do_test_sendinvoice(node_factory, bitcoind, disable):
    l2opts = {'experimental-offers': None}
    if disable:
        l2opts[disable] = None
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts=[{'experimental-offers': None},
                                           l2opts])

    # Simple offer to send money (balances channel a little)
    offer = l1.rpc.call('offerout', {'amount': '100000sat',
                                     'description': 'simple test'})

    # Fetchinvoice will refuse, since you're supposed to send an invoice.
    with pytest.raises(RpcError, match='Offer wants an invoice, not invoice_request'):
        l2.rpc.call('fetchinvoice', {'offer': offer['bolt12']})

    # used will be false
    assert only_one(l1.rpc.call('listoffers', [offer['offer_id']])['offers'])['used'] is False

    # sendinvoice should work.
    out = l2.rpc.call('sendinvoice', {'offer': offer['bolt12_unsigned'],
                                      'label': 'test sendinvoice 1'})
    assert out['label'] == 'test sendinvoice 1'
    assert out['description'] == 'simple test'
    assert 'bolt12' in out
    assert 'payment_hash' in out
    assert out['status'] == 'paid'
    assert 'payment_preimage' in out
    assert 'expires_at' in out
    assert out['msatoshi'] == 100000000
    assert out['amount_msat'] == Millisatoshi(100000000)
    assert 'pay_index' in out
    assert out['msatoshi_received'] == 100000000
    assert out['amount_received_msat'] == Millisatoshi(100000000)

    # Note, if we're slow, this fails with "Offer no longer available",
    # *but* if it hasn't heard about payment success yet, l2 will fail
    # simply because payments are already pending.
    with pytest.raises(RpcError, match='Offer no longer available|pay attempt failed'):
        l2.rpc.call('sendinvoice', {'offer': offer['bolt12'],
                                    'label': 'test sendinvoice 2'})

    # Technically, l1 may not have gotten payment success, so we need to wait.
    wait_for(lambda: only_one(l1.rpc.call('listoffers', [offer['offer_id']])['offers'])['used'] is True)

    # Now try a refund.
    offer = l2.rpc.call('offer', {'amount': '100msat',
                                  'description': 'simple test'})
    assert only_one(l2.rpc.call('listoffers', [offer['offer_id']])['offers'])['used'] is False

    inv = l1.rpc.call('fetchinvoice', {'offer': offer['bolt12']})
    l1.rpc.pay(inv['invoice'])
    assert only_one(l2.rpc.call('listoffers', [offer['offer_id']])['offers'])['used'] is True

    refund = l2.rpc.call('offerout', {'amount': '100msat',
                                      'description': 'refund test',
                                      'refund_for': inv['invoice']})
    assert only_one(l2.rpc.call('listoffers', [refund['offer_id']])['offers'])['used'] is False

    l1.rpc.call('sendinvoice', {'offer': refund['bolt12'],
                                'label': 'test sendinvoice refund'})
    wait_for(lambda: only_one(l2.rpc.call('listoffers', [refund['offer_id']])['offers'])['used'] is True)

    # Offer with issuer: we must not copy issuer into our invoice!
    offer = l1.rpc.call('offerout', {'amount': '10000sat',
                                     'description': 'simple test',
                                     'issuer': "clightning test suite"})

    out = l2.rpc.call('sendinvoice', {'offer': offer['bolt12'],
                                      'label': 'test sendinvoice 3'})
    assert out['label'] == 'test sendinvoice 3'
    assert out['description'] == 'simple test'
    assert 'issuer' not in out
    assert 'bolt12' in out
    assert 'payment_hash' in out
    assert out['status'] == 'paid'
    assert 'payment_preimage' in out
    assert 'expires_at' in out
    assert out['msatoshi'] == 10000000
    assert out['amount_msat'] == Millisatoshi(10000000)
    assert 'pay_index' in out
    assert out['msatoshi_received'] == 10000000
    assert out['amount_received_msat'] == Millisatoshi(10000000)


def test_sendinvoice(node_factory, bitcoind):
    do_test_sendinvoice(node_factory, bitcoind, None)


@pytest.mark.developer("needs to --dev-no-obsolete-onion")
def test_sendinvoice_modern(node_factory, bitcoind):
    do_test_sendinvoice(node_factory, bitcoind, 'dev-no-obsolete-onion')


@pytest.mark.developer("needs to --dev-no-modern-onion")
def test_sendinvoice_obsolete(node_factory, bitcoind):
    do_test_sendinvoice(node_factory, bitcoind, 'dev-no-modern-onion')


def test_self_pay(node_factory):
    """Repro test for issue 4345: pay ourselves via the pay plugin.

    """
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    inv = l1.rpc.invoice(10000, 'test', 'test')['bolt11']

    with pytest.raises(RpcError):
        l1.rpc.pay(inv)


@unittest.skipIf(TEST_NETWORK != 'regtest', "Canned invoice is network specific")
def test_unreachable_routehint(node_factory, bitcoind):
    """Test that we discard routehints that we can't reach.

    Reachability is tested by checking whether we can reach the
    entrypoint of the routehint, i.e., the first node in the
    routehint. The network we create is partitioned on purpose for
    this: first we attempt with an unknown destination and an unknown
    routehint entrypoint, later we make them known, but still
    unreachable, by connecting them without a channel.

    """

    # Create a partitioned network, first without connecting it, then
    # connecting it without a channel so they can sync gossip. Notice
    # that l4 is there only to trick the deadend heuristic.
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)
    l3, l4, l5 = node_factory.line_graph(3, wait_for_announce=True)
    entrypoint = '0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199'

    # Generate an invoice with exactly one routehint.
    for i in range(100):
        invoice = l5.rpc.invoice(10, 'attempt{}'.format(i), 'description')['bolt11']
        decoded = l1.rpc.decodepay(invoice)
        if 'routes' in decoded and len(decoded['routes']) == 1:
            break

    assert('routes' in decoded and len(decoded['routes']) == 1)

    with pytest.raises(RpcError, match=r'Destination [a-f0-9]{66} is not reachable'):
        l1.rpc.pay(invoice)

    l1.daemon.wait_for_log(
        r"Removed routehint 0 because entrypoint {entrypoint} is unknown.".format(
            entrypoint=entrypoint
        )
    )

    # Now connect l2 to l3 to create a bridge, but without a
    # channel. The entrypoint will become known, but still
    # unreachable, resulting in a slightly different error message,
    # but the routehint will still be removed.
    l2.connect(l3)
    wait_for(lambda: len(l1.rpc.listnodes(entrypoint)['nodes']) == 1)

    with pytest.raises(RpcError, match=r'Destination [a-f0-9]{66} is not reachable') as excinfo:
        l1.rpc.pay(invoice)

    # Verify that we failed for the correct reason.
    l1.daemon.wait_for_log(
        r"Removed routehint 0 because entrypoint {entrypoint} is unreachable.".format(
            entrypoint=entrypoint
        )
    )

    # Since we aborted once we realized the destination is unreachable
    # both directly, and via the routehints we should now just have a
    # single attempt.
    assert(len(excinfo.value.error['attempts']) == 1)


def test_routehint_tous(node_factory, bitcoind):
    """
Test bug where trying to pay an invoice from an *offline* node which
gives a routehint straight to us causes an issue
"""

    # Existence of l1 makes l3 use l2 for routehint (otherwise it sees deadend)
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)
    l3 = node_factory.get_node()
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid23, _ = l2.fundchannel(l3, 1000000, announce_channel=False)
    # Make sure l3 sees l1->l2 channel.
    wait_for(lambda: l3.rpc.listnodes(l1.info['id'])['nodes'] != [])

    inv = l3.rpc.invoice(10, "test", "test")['bolt11']
    decoded = l3.rpc.decodepay(inv)
    assert(only_one(only_one(decoded['routes']))['short_channel_id'] == scid23)

    l3.stop()
    with pytest.raises(RpcError, match=r'Destination .* is not reachable directly and all routehints were unusable'):
        l2.rpc.pay(inv)


def test_pay_low_max_htlcs(node_factory):
    """Test we can pay if *any* HTLC slots are available"""

    l1, l2, l3 = node_factory.line_graph(3,
                                         opts={'max-concurrent-htlcs': 1},
                                         wait_for_announce=True)
    l1.rpc.pay(l3.rpc.invoice(FUNDAMOUNT * 50, "test", "test")['bolt11'])
    l1.daemon.wait_for_log(
        r'Number of pre-split HTLCs \([0-9]+\) exceeds our HTLC budget \([0-9]+\), skipping pre-splitter'
    )


def test_setchannelfee_enforcement_delay(node_factory, bitcoind):
    # Fees start at 1msat + 1%
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts={'fee-base': 1,
                                               'fee-per-satoshi': 10000})

    chanid1 = only_one(l1.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id']
    chanid2 = only_one(l2.rpc.getpeer(l3.info['id'])['channels'])['short_channel_id']

    route = [{'msatoshi': 1011,
              'id': l2.info['id'],
              'delay': 20,
              'channel': chanid1},
             {'msatoshi': 1000,
              'id': l3.info['id'],
              'delay': 10,
              'channel': chanid2}]

    # This works.
    inv = l3.rpc.invoice(1000, "test1", "test1")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    # Increase fee immediately; l1 payment rejected.
    l2.rpc.setchannelfee("all", 2, 10000, 0)

    inv = l3.rpc.invoice(1000, "test2", "test2")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'WIRE_FEE_INSUFFICIENT'):
        l1.rpc.waitsendpay(inv['payment_hash'])

    # Test increased amount.
    route[0]['msatoshi'] += 1
    inv = l3.rpc.invoice(1000, "test3", "test3")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    # Now, give us 30 seconds please.
    l2.rpc.setchannelfee("all", 3, 10000, 30)
    inv = l3.rpc.invoice(1000, "test4", "test4")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])
    l2.daemon.wait_for_log("Allowing payment using older feerate")

    time.sleep(30)
    inv = l3.rpc.invoice(1000, "test5", "test5")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'WIRE_FEE_INSUFFICIENT'):
        l1.rpc.waitsendpay(inv['payment_hash'])


def test_listpays_with_filter_by_status(node_factory, bitcoind):
    """
    This test check if the filtering by status of the command listpays
    has some mistakes.
    """

    # Create the line graph l2 -> l1 with a channel of 10 ** 5 sat!
    l2, l1 = node_factory.line_graph(2, fundamount=10**5, wait_for_announce=True)

    inv = l1.rpc.invoice(10 ** 5, 'inv', 'inv')
    l2.rpc.pay(inv['bolt11'])

    wait_for(lambda: l2.rpc.listpays(inv['bolt11'])['pays'][0]['status'] == 'complete')

    # test if the node is still ready
    payments = l2.rpc.listpays(status='failed')

    assert len(payments['pays']) == 0

    payments = l2.rpc.listpays()
    assert len(l2.rpc.listpays()['pays']) == 1


def test_sendpay_grouping(node_factory, bitcoind):
    """Paying an invoice multiple times, listpays should list them individually
    """
    l1, l2, l3 = node_factory.line_graph(
        3,
        wait_for_announce=True,
        opts=[
            {},
            {'may_reconnect': True},
            {'may_reconnect': True},
        ],
    )
    wait_for(lambda: len(l1.rpc.listnodes()['nodes']) == 3)

    inv = l3.rpc.invoice(msatoshi='any', label='lbl1', description='desc')['bolt11']
    l3.stop()  # Stop recipient so the first attempt fails

    assert(len(l1.db.query("SELECT * FROM payments")) == 0)
    assert(len(l1.rpc.listpays()['pays']) == 0)

    with pytest.raises(RpcError, match=r'Ran out of routes to try after [0-9]+ attempts'):
        l1.rpc.pay(inv, msatoshi='100000msat')

    # After this one invocation we have one entry in `listpays`
    assert(len(l1.rpc.listpays()['pays']) == 1)

    with pytest.raises(RpcError, match=r'Ran out of routes to try after [0-9]+ attempts'):
        l1.rpc.pay(inv, msatoshi='200000msat')

    # Surprise: we should have 2 entries after 2 invocations
    assert(len(l1.rpc.listpays()['pays']) == 2)

    l3.start()
    invoices = l3.rpc.listinvoices()['invoices']
    assert(len(invoices) == 1)
    assert(invoices[0]['status'] == 'unpaid')
    # Will reconnect automatically
    wait_for(lambda: only_one(l3.rpc.listpeers()['peers'])['connected'] is True)
    scid = l3.rpc.listpeers()['peers'][0]['channels'][0]['short_channel_id']
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(scid)['channels']] == [True, True])
    l1.rpc.pay(inv, msatoshi='420000msat')

    # And finally we should have all 3 attempts to pay the invoice
    pays = l1.rpc.listpays()['pays']
    assert(len(pays) == 3)
    assert([p['status'] for p in pays] == ['failed', 'failed', 'complete'])


def test_pay_manual_exclude(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)
    l1_id = l1.rpc.getinfo()['id']
    l2_id = l2.rpc.getinfo()['id']
    l3_id = l3.rpc.getinfo()['id']
    chan12 = l1.rpc.listpeers(l2_id)['peers'][0]['channels'][0]
    chan23 = l2.rpc.listpeers(l3_id)['peers'][0]['channels'][0]
    scid12 = chan12['short_channel_id'] + '/' + str(chan12['direction'])
    scid23 = chan23['short_channel_id'] + '/' + str(chan23['direction'])
    inv = l3.rpc.invoice(msatoshi='123000', label='label1', description='desc')['bolt11']
    # Exclude the payer node id
    with pytest.raises(RpcError, match=r'Payer is manually excluded'):
        l1.rpc.pay(inv, exclude=[l1_id])
    # Exclude the direct payee node id
    with pytest.raises(RpcError, match=r'Payee is manually excluded'):
        l2.rpc.pay(inv, exclude=[l3_id])
    # Exclude intermediate node id
    with pytest.raises(RpcError, match=r'is not reachable directly and all routehints were unusable.'):
        l1.rpc.pay(inv, exclude=[l2_id])
    # Exclude intermediate channel id
    with pytest.raises(RpcError, match=r'is not reachable directly and all routehints were unusable.'):
        l1.rpc.pay(inv, exclude=[scid12])
    # Exclude direct channel id
    with pytest.raises(RpcError, match=r'is not reachable directly and all routehints were unusable.'):
        l2.rpc.pay(inv, exclude=[scid23])
