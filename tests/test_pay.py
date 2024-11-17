from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from hashlib import sha256
from pathlib import Path
from pyln.client import RpcError, Millisatoshi
from pyln.proto.onion import TlvPayload
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND, FUNDAMOUNT, scid_to_int
from utils import (
    wait_for, only_one, sync_blockheight, TIMEOUT,
    mine_funding_to_announce, first_scid, serialize_payload_tlv, serialize_payload_final_tlv,
    tu64_encode
)
import copy
import os
import pytest
import random
import re
import string
import subprocess
import time
import unittest


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_pay(node_factory):
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(123000, 'test_pay', 'description')['bolt11']
    before = int(time.time())
    details = l1.dev_pay(inv, dev_use_shadow=False)
    after = time.time()
    preimage = details['payment_preimage']
    assert details['status'] == 'complete'
    assert details['amount_msat'] == Millisatoshi(123000)
    assert details['destination'] == l2.info['id']
    assert details['created_at'] >= before
    assert details['created_at'] <= after

    invoices = l2.rpc.listinvoices('test_pay')['invoices']
    assert len(invoices) == 1
    invoice = invoices[0]
    assert invoice['status'] == 'paid' and invoice['paid_at'] >= before and invoice['paid_at'] <= after

    # Repeat payments are NOPs (if valid): we can hand null.
    l1.dev_pay(inv, dev_use_shadow=False)
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
        l1.dev_pay(inv2, random.randint(1000, 999999), dev_use_shadow=False)

    # Should see 6 completed payments
    assert len(l1.rpc.listsendpays()['payments']) == 6

    # Test listsendpays indexed by bolt11.
    payments = l1.rpc.listsendpays(inv)['payments']
    assert len(payments) == 1 and payments[0]['payment_preimage'] == preimage

    # Make sure they're completely settled, so accounting correct.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    # Check channels apy summary view of channel activity
    apys_1 = l1.rpc.bkpr_channelsapy()['channels_apy']
    apys_2 = l2.rpc.bkpr_channelsapy()['channels_apy']

    assert apys_1[0]['channel_start_balance_msat'] == apys_2[0]['channel_start_balance_msat']
    assert apys_1[0]['channel_start_balance_msat'] == apys_1[0]['our_start_balance_msat']
    assert apys_2[0]['our_start_balance_msat'] == Millisatoshi(0)
    assert apys_1[0]['routed_out_msat'] == apys_2[0]['routed_in_msat']
    assert apys_1[0]['routed_in_msat'] == apys_2[0]['routed_out_msat']


def test_pay_amounts(node_factory):
    l1, l2 = node_factory.line_graph(2)
    inv = l2.rpc.invoice(Millisatoshi("123sat"), 'test_pay_amounts', 'description')['bolt11']

    invoice = only_one(l2.rpc.listinvoices('test_pay_amounts')['invoices'])

    assert invoice['amount_msat'] == Millisatoshi(123000)

    l1.dev_pay(inv, dev_use_shadow=False)

    invoice = only_one(l2.rpc.listinvoices('test_pay_amounts')['invoices'])
    assert invoice['amount_received_msat'] >= Millisatoshi(123000)


def test_pay_limits(node_factory):
    """Test that we enforce fee max percentage and max delay"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    # FIXME: pylightning should define these!
    PAY_STOPPED_RETRYING = 210

    inv = l3.rpc.invoice("any", "any", 'description')

    # Fee too high.
    err = r'Fee exceeds our fee budget: [1-9]msat > 0msat, discarding route'
    with pytest.raises(RpcError, match=err) as err:
        l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'amount_msat': 100000, 'maxfeepercent': 0.0001, 'exemptfee': 0})

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
        l1.rpc.call('pay', {'bolt11': inv['bolt11'], 'amount_msat': 100000, 'maxdelay': 0})

    assert err.value.error['code'] == PAY_STOPPED_RETRYING
    # Should also have retried two more times.
    status = l1.rpc.call('paystatus', {'bolt11': inv['bolt11']})['pay'][1]['attempts']

    assert(len(status) == 2)
    assert(status[0]['failure']['code'] == 205)

    # This fails!
    err = r'Fee exceeds our fee budget: 2msat > 1msat, discarding route'
    with pytest.raises(RpcError, match=err) as err:
        l1.rpc.pay(bolt11=inv['bolt11'], amount_msat=100000, maxfee=1)

    # This works, because fee is less than exemptfee.
    l1.dev_pay(inv['bolt11'], amount_msat=100000, maxfeepercent=0.0001,
               exemptfee=2000, dev_use_shadow=False)
    status = l1.rpc.call('paystatus', {'bolt11': inv['bolt11']})['pay'][3]['attempts']
    assert len(status) == 1
    assert status[0]['strategy'] == "Initial attempt"


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
    assert only_one(l1.rpc.decode(inv)['routes'])[0]['pubkey'] == l2.info['id']

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
        'amount_msat': 0,
        'id': l2.info['id'],
        'delay': 10,
        'channel': chanid
    }

    # Amount must be nonzero!
    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'WIRE_AMOUNT_BELOW_MINIMUM'):
        l1.rpc.waitsendpay(rhash)


def test_pay_disconnect(node_factory, bitcoind):
    """If the remote node has disconnected, we fail payment, but can try again when it reconnects"""
    l1, l2 = node_factory.line_graph(2, opts={'dev-max-fee-multiplier': 5,
                                              'may_reconnect': True,
                                              'allow_warning': True})

    # Dummy payment to kick off update_fee messages
    l1.pay(l2, 1000)

    inv = l2.rpc.invoice(123000, 'test_pay_disconnect', 'description')
    rhash = inv['payment_hash']

    # Can't use `pay` since that'd notice that we can't route, due to disabling channel_update
    route = l1.rpc.getroute(l2.info['id'], 123000, 1)["route"]

    l2.stop()
    # Make sure channeld has exited!
    wait_for(lambda: 'owner' not in only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels']))

    # Can't pay while its offline.
    with pytest.raises(RpcError, match=r'failed: WIRE_TEMPORARY_CHANNEL_FAILURE \(First peer not ready\)'):
        l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])

    l2.start()
    l1.daemon.wait_for_log('peer_out WIRE_CHANNEL_REESTABLISH')

    # Make l2 upset by asking for crazy fee.
    l1.set_feerates((10**6, 10**6, 10**6, 10**6), False)

    # Wait for l1 notice
    if 'anchors/even' in only_one(l1.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        l1.daemon.wait_for_log(r'WARNING .*: update_fee \d+ outside range 253-75000')
    else:
        l1.daemon.wait_for_log(r'WARNING .*: update_fee \d+ outside range 1875-75000')
    # They hang up on us
    l1.daemon.wait_for_log(r'Peer transient failure in CHANNELD_NORMAL')

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


def test_pay_get_error_with_update(node_factory):
    """We should process an update inside a temporary_channel_failure"""
    l1, l2, l3 = node_factory.line_graph(3, opts={'log-level': 'io'}, fundchannel=True, wait_for_announce=True)
    chanid2 = l2.get_channel_scid(l3)

    inv = l3.rpc.invoice(123000, 'test_pay_get_error_with_update', 'description')

    # Make sure l2 doesn't tell l1 directly that channel is disabled.
    l2.rpc.dev_suppress_gossip()
    l3.stop()

    # Make sure that l2 has seen disconnect, considers channel disabled.
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['peer_connected'] is False)

    assert(l1.is_channel_active(chanid2))

    # Make sure it's not doing startup any more (where it doesn't disable channels!)
    l1.daemon.wait_for_log("channel_gossip: no longer in startup mode", timeout=70)

    with pytest.raises(RpcError, match=r'WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.pay(inv['bolt11'])

    # Make sure we get an onionreply, without the type prefix of the nested
    # channel_update, and it should patch it to include a type prefix. The
    # prefix 0x0102 should be in the channel_update, but not in the
    # onionreply (negation of 0x0102 in the RE)
    l1.daemon.wait_for_log(r'Extracted channel_update 0102.*from onionreply 1007008a[0-9a-fA-F]{276}$')

    # And now monitor for l1 to apply the channel_update we just extracted
    wait_for(lambda: not l1.is_channel_active(chanid2))


def test_pay_error_update_fees(node_factory):
    """We should process an update inside a temporary_channel_failure"""
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=True, wait_for_announce=True)

    # Don't include any routehints in first invoice.
    inv1 = l3.dev_invoice(amount_msat=123000,
                          label='test_pay_error_update_fees',
                          description='description',
                          dev_routes=[])

    inv2 = l3.rpc.invoice(123000, 'test_pay_error_update_fees2', 'desc')  # noqa: F841

    # Make sure l2 doesn't tell l1 directly that channel fee is changed.
    l2.rpc.dev_suppress_gossip()
    l2.rpc.setchannel(l3.info['id'], 1337, 137, enforcedelay=0)

    # Should bounce off and retry...
    l1.rpc.pay(inv1['bolt11'])
    attempts = only_one(l1.rpc.paystatus(inv1['bolt11'])['pay'])['attempts']
    assert len(attempts) == 2
    # WIRE_FEE_INSUFFICIENT = UPDATE|12
    assert attempts[0]['failure']['data']['failcode'] == 4108

    # FIXME: We *DO NOT* handle misleading routehints!
    # # Should ignore old routehint and do the same...
    # l1.rpc.pay(inv2['bolt11'])
    # attempts = only_one(l1.rpc.paystatus(inv2['bolt11'])['pay'])['attempts']
    # assert len(attempts) == 2
    # # WIRE_FEE_INSUFFICIENT = UPDATE|12
    # assert attempts[0]['failure']['data']['failcode'] == 4108


def test_pay_optional_args(node_factory):
    l1, l2 = node_factory.line_graph(2)

    inv1 = l2.rpc.invoice(123000, 'test_pay', 'desc')['bolt11']
    l1.dev_pay(inv1, label='desc', dev_use_shadow=False)
    payment1 = l1.rpc.listsendpays(inv1)['payments']
    assert len(payment1) and payment1[0]['amount_sent_msat'] == 123000
    assert payment1[0]['label'] == 'desc'

    inv2 = l2.rpc.invoice(321000, 'test_pay2', 'description')['bolt11']
    l1.dev_pay(inv2, riskfactor=5.0, dev_use_shadow=False)
    payment2 = l1.rpc.listsendpays(inv2)['payments']
    assert(len(payment2) == 1)
    # The pay plugin uses `sendonion` since 0.9.0 and `lightningd` doesn't
    # learn about the amount we intended to send (that's why we annotate the
    # root of a payment tree with the bolt11 invoice).

    anyinv = l2.rpc.invoice('any', 'any_pay', 'desc')['bolt11']
    l1.dev_pay(anyinv, label='desc', amount_msat=500, dev_use_shadow=False)
    payment3 = l1.rpc.listsendpays(anyinv)['payments']
    assert len(payment3) == 1
    assert payment3[0]['label'] == 'desc'

    # Should see 3 completed transactions
    assert len(l1.rpc.listsendpays()['payments']) == 3


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
    executor.submit(l1.dev_pay, inv1['bolt11'], dev_use_shadow=False)

    l1.daemon.wait_for_log(r'dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    print("Killing l1 in mid HTLC")
    l1.daemon.kill()

    # Restart l1, without disconnect stuff.
    del l1.daemon.opts['dev-no-reconnect']
    l1.daemon.disconnect = None

    # Should reconnect, and sort the payment out.
    l1.start()

    wait_for(lambda: l1.rpc.listsendpays()['payments'][0]['status'] != 'pending')

    payments = l1.rpc.listsendpays()['payments']
    invoices = l2.rpc.listinvoices('inv1')['invoices']
    assert len(payments) == 1 and payments[0]['status'] == 'complete'
    assert len(invoices) == 1 and invoices[0]['status'] == 'paid'

    l1.wait_local_channel_active(chanid)

    # A duplicate should succeed immediately (nop) and return correct preimage.
    preimage = l1.dev_pay(
        inv1['bolt11'],
        dev_use_shadow=False
    )['payment_preimage']
    assert l1.rpc.dev_rhash(preimage)['rhash'] == inv1['payment_hash']


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
    l1.daemon.disconnect = None

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
        pay_status = l1.rpc.pay(bolt11, maxfeepercent=0.001)
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
        'amount_msat': amt,
        'id': l2.info['id'],
        'delay': 5,
        'channel': first_scid(l1, l2)
    }

    # Insufficient funds.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['amount_msat'] = rs['amount_msat'] - 1
        l1.rpc.sendpay([rs], rhash, payment_secret=inv['payment_secret'])
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Gross overpayment (more than factor of 2)
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['amount_msat'] = rs['amount_msat'] * 2 + 1
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
    l1.rpc.check_request_schemas = False
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['id'] = '00000000000000000000000000000000'
        l1.rpc.sendpay([rs], rhash, payment_secret=inv['payment_secret'])
    assert invoice_unpaid(l2, 'testpayment2')
    l1.rpc.check_request_schemas = True

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
    c1 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])
    c2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert c1['to_us_msat'] == 10**6 * 1000
    assert c1['total_msat'] == 10**6 * 1000
    assert c2['to_us_msat'] == 0
    assert c2['total_msat'] == 10**6 * 1000

    # This works.
    before = int(time.time())
    details = l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    after = int(time.time())
    preimage = l1.rpc.waitsendpay(rhash)['payment_preimage']
    # Check details
    assert details['payment_hash'] == rhash
    assert details['destination'] == l2.info['id']
    assert details['amount_msat'] == amt
    assert details['created_at'] >= before
    assert details['created_at'] <= after
    # Check receiver
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['pay_index'] == 1
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['amount_received_msat'] == rs['amount_msat']
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['payment_preimage'] == preimage

    # Balances should reflect it.
    def check_balances():
        c1 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])
        c2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
        return (
            c1['to_us_msat'] == 10**6 * 1000 - amt
            and c1['total_msat'] == 10**6 * 1000
            and c2['to_us_msat'] == amt
            and c2['total_msat'] == 10**6 * 1000
        )
    wait_for(check_balances)

    # Repeat will "succeed", but won't actually send anything (duplicate)
    assert not l1.daemon.is_in_log('Payment: .* COMPLETE')
    details = l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    assert details['status'] == "complete"
    preimage2 = details['payment_preimage']
    assert preimage == preimage2
    l1.daemon.wait_for_log('Payment: .* COMPLETE')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['amount_received_msat'] == rs['amount_msat']

    # Overpaying by "only" a factor of 2 succeeds.
    inv = l2.rpc.invoice(amt, 'testpayment3', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['status'] == 'unpaid'
    routestep = {'amount_msat': amt * 2, 'id': l2.info['id'], 'delay': 5, 'channel': first_scid(l1, l2)}
    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    preimage3 = l1.rpc.waitsendpay(rhash)['payment_preimage']
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['amount_received_msat'] == amt * 2

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


def test_repay(node_factory):
    l1, l2 = node_factory.line_graph(2, fundamount=10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'testpayment2', 'desc')
    routestep = {
        'amount_msat': amt,
        'id': l2.info['id'],
        'delay': 5,
        'channel': first_scid(l1, l2)
    }
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])
    l1.daemon.wait_for_log("Sending 200000000msat over 1 hops to deliver 200000000msat")
    l1.rpc.waitsendpay(inv['payment_hash'])['payment_preimage']

    # Re-attempt is instant
    assert l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])['status'] == 'complete'

    # Don't re-log that we are sending!
    assert l1.daemon.is_in_log("Sending 200000000msat over 1 hops to deliver 200000000msat", start=l1.daemon.logsearch_start) is None


def test_wait_sendpay(node_factory, executor):
    l1, l2 = node_factory.line_graph(2, fundamount=10**6)

    assert l1.rpc.wait(subsystem='sendpays', indexname='created', nextvalue=0) == {'subsystem': 'sendpays', 'created': 0}

    wait_created = executor.submit(l1.rpc.call, 'wait', {'subsystem': 'sendpays', 'indexname': 'created', 'nextvalue': 1})
    wait_updated = executor.submit(l1.rpc.call, 'wait', {'subsystem': 'sendpays', 'indexname': 'updated', 'nextvalue': 1})

    time.sleep(1)
    amt = 200000000
    inv = l2.rpc.invoice(amt, 'testpayment2', 'desc')
    routestep = {
        'amount_msat': amt,
        'id': l2.info['id'],
        'delay': 5,
        'channel': first_scid(l1, l2)
    }
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])
    assert wait_created.result(TIMEOUT) == {'subsystem': 'sendpays',
                                            'created': 1,
                                            'details': {'groupid': 1,
                                                        'partid': 0,
                                                        'payment_hash': inv['payment_hash'],
                                                        'status': 'pending'}}
    assert wait_updated.result(TIMEOUT) == {'subsystem': 'sendpays',
                                            'updated': 1,
                                            'details': {'groupid': 1,
                                                        'partid': 0,
                                                        'payment_hash': inv['payment_hash'],
                                                        'status': 'complete'}}

    l1.rpc.waitsendpay(inv['payment_hash'])['payment_preimage']


@unittest.skipIf(TEST_NETWORK != 'regtest', "The reserve computation is bitcoin specific")
@pytest.mark.parametrize("anchors", [False, True])
def test_sendpay_cant_afford(node_factory, anchors):
    # Set feerates the same so we don't have to wait for update.
    opts = {'feerates': (15000, 15000, 15000, 15000),
            'commit-feerate-offset': 0}
    if anchors is False:
        opts['dev-force-features'] = "-23"

    l1, l2 = node_factory.line_graph(2, fundamount=10**6, opts=opts)

    # Can't pay more than channel capacity.
    with pytest.raises(RpcError):
        l1.pay(l2, 10**9 + 1)

    # Reserve is 1%.
    reserve = 10**7

    # This is how we recalc constants (v. v. slow!)
    # minimum = 1
    # maximum = 10**9
    # while maximum - minimum > 1:
    #     l1, l2 = node_factory.line_graph(2, fundamount=10**6, opts=opts)
    #     try:
    #         l1.pay(l2, (minimum + maximum) // 2)
    #         print("XXX Pay {} WORKED!".format((minimum + maximum) // 2))
    #         minimum = (minimum + maximum) // 2
    #     except RpcError:
    #         print("XXX Pay {} FAILED!".format((minimum + maximum) // 2))
    #         maximum = (minimum + maximum) // 2
    #     print("{} - {}".format(minimum, maximum))

    # assert False, "Max we can pay == {}".format(minimum)
    # # Currently this gives: 962713000 for non-anchors, 951833000 for anchors
    # # Add reserve to this result to derive `available`

    # This is the fee, which needs to be taken into account for l1.
    if anchors:
        available = 951833000 + reserve
    else:
        available = 962713000 + reserve

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


def test_decode(node_factory):
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
    b11 = l1.rpc.decode(
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
    b11 = l1.rpc.decode(
        'lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqf'
        'qypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cq'
        'v3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rsp'
        'fj9srp'
    )
    assert b11['currency'] == 'bc'
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
    b11 = l1.rpc.decode(
        'lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqy'
        'pqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jr'
        'c5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf'
        '4sefvf9sygkshp5zfem29trqq2yxxz7'
    )
    assert b11['currency'] == 'bc'
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
    b11 = l1.rpc.decode(
        'lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t'
    )
    assert b11['currency'] == 'tb'
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
    b11 = l1.rpc.decode('lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj')
    assert b11['currency'] == 'bc'
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
    b11 = l1.rpc.decode('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y')
    assert b11['currency'] == 'bc'
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
    b11 = l1.rpc.decode('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8')
    assert b11['currency'] == 'bc'
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
    b11 = l1.rpc.decode('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava')
    assert b11['currency'] == 'bc'
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
    b11 = l1.rpc.decode('lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzsze992adudgku8p05pstl6zh7av6rx2f297pv89gu5q93a0hf3g7lynl3xq56t23dpvah6u7y9qey9lccrdml3gaqwc6nxsl5ktzm464sq73t7cl')
    assert b11['currency'] == 'bc'
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
        l1.rpc.decode('lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9q4pqqqqqqqqqqqqqqqqqqszk3ed62snp73037h4py4gry05eltlp0uezm2w9ajnerhmxzhzhsu40g9mgyx5v3ad4aqwkmvyftzk4k9zenz90mhjcy9hcevc7r3lx2sphzfxz7')

    # Example of an invoice without a multiplier suffix to the amount. This
    # should then be interpreted as 7 BTC according to the spec:
    #
    #   `amount`: optional number in that currency, followed by an optional
    #   `multiplier` letter. The unit encoded here is the 'social' convention of
    #   a payment unit -- in the case of Bitcoin the unit is 'bitcoin' NOT
    #   satoshis.
    b11 = "lnbcrt71p0g4u8upp5xn4k45tsp05akmn65s5k2063d5fyadhjse9770xz5sk7u4x6vcmqdqqcqzynxqrrssx94cf4p727jamncsvcd8m99n88k423ruzq4dxwevfatpp5gx2mksj2swshjlx4pe3j5w9yed5xjktrktzd3nc2a04kq8yu84l7twhwgpxjn3pw"
    b11 = l1.rpc.decode(b11)
    sat_per_btc = 10**8
    assert(b11['amount_msat'] == 7 * sat_per_btc * 1000)

    with pytest.raises(RpcError):
        l1.rpc.decode('1111111')


def test_forward(node_factory, bitcoind):
    # Connect 1 -> 2 -> 3.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    # If they're at different block heights we can get spurious errors.
    sync_blockheight(bitcoind, [l1, l2, l3])

    chanid1 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    chanid2 = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['short_channel_id']
    assert only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['short_channel_id'] == chanid1
    assert only_one(l3.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id'] == chanid2

    inv = l3.rpc.invoice(100000000, 'testpayment1', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l3.rpc.listinvoices('testpayment1')['invoices'])['status'] == 'unpaid'

    # Fee for node2 is 10 millionths, plus 1.
    amt = 100000000
    fee = amt * 10 // 1000000 + 1

    baseroute = [{'amount_msat': amt + fee,
                  'id': l2.info['id'],
                  'delay': 12,
                  'channel': chanid1},
                 {'amount_msat': amt,
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

    # Check that invoice payment and fee are tracked appropriately
    l1.daemon.wait_for_log('coin_move .* [(]invoice[)]')
    l1.rpc.bkpr_dumpincomecsv('koinly', 'koinly.csv')

    koinly_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'koinly.csv')
    koinly_csv = open(koinly_path, 'rb').read()
    expected_line = r'0.00100000000,.*,,,0.00000001001,.*,invoice'
    assert only_one(re.findall(expected_line, str(koinly_csv)))


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
    assert route[0]['amount_msat'] == 4999999
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

    assert route[0]['amount_msat'] == 5010198
    assert route[0]['delay'] == 20 + 9 + shadow_route
    assert route[1]['amount_msat'] == 4999999
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

    assert route[0]['amount_msat'] == 5010198
    assert route[0]['delay'] == 20 + 9
    assert route[1]['amount_msat'] == 4999999
    assert route[1]['delay'] == 9

    # Modify so we overpay, overdo the cltv.
    route[0]['amount_msat'] += 2000
    route[0]['delay'] += 20
    route[1]['amount_msat'] += 1000
    route[1]['delay'] += 10

    # This should work.
    inv = l3.rpc.invoice(4999999, 'test_forward_pad_fees_and_cltv', 'desc')
    rhash = inv['payment_hash']
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(rhash)
    assert only_one(l3.rpc.listinvoices('test_forward_pad_fees_and_cltv')['invoices'])['status'] == 'paid'

    # Do some checks of the bookkeeper's records
    def _income_tagset(node, tagset):
        incomes = node.rpc.bkpr_listincome()['income_events']
        return [e for e in incomes if e['tag'] in tagset]

    tags = ['invoice', 'invoice_fee']
    wait_for(lambda: len(_income_tagset(l1, tags)) == 2)
    incomes = _income_tagset(l1, tags)
    # the balance on l3 should equal the invoice
    accts = l3.rpc.bkpr_listbalances()['accounts']
    assert len(accts) == 2
    wallet = accts[0]
    chan_acct = accts[1]
    assert wallet['account'] == 'wallet'
    # We no longer make a zero balance entry for the wallet at start
    assert wallet['balances'] == []
    assert incomes[0]['tag'] == 'invoice'
    assert only_one(chan_acct['balances'])['balance_msat'] == incomes[0]['debit_msat']
    inve = only_one([e for e in l1.rpc.bkpr_listaccountevents()['events'] if e['tag'] == 'invoice'])
    assert inve['debit_msat'] == incomes[0]['debit_msat'] + incomes[1]['debit_msat']


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
                              "FROM forwards "
                              "ORDER BY in_htlc_id;")
    assert(len(forwardings) == 3)
    states = [f['state'] for f in forwardings]
    assert(states == [1, 2, 0])  # settled, failed, offered

    inchan = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]
    outchan = l2.rpc.listpeerchannels(l3.info['id'])['channels'][0]

    # Check that we correctly account channel changes
    assert inchan['in_payments_offered'] == 3
    assert inchan['in_payments_fulfilled'] == 1
    assert inchan['in_offered_msat'] >= Millisatoshi(3 * amount)
    assert inchan['in_fulfilled_msat'] >= Millisatoshi(amount)

    assert outchan['out_payments_offered'] == 1
    assert outchan['out_payments_fulfilled'] == 1
    assert outchan['out_offered_msat'] >= Millisatoshi(amount)
    assert outchan['out_offered_msat'] == outchan['out_fulfilled_msat']

    assert outchan['out_fulfilled_msat'] < inchan['in_fulfilled_msat']

    stats = l2.rpc.listforwards()

    assert [f['status'] for f in stats['forwards']] == ['settled', 'failed', 'offered']
    assert l2.rpc.getinfo()['fees_collected_msat'] == 1 + amount // 100000
    assert l1.rpc.getinfo()['fees_collected_msat'] == 0
    assert l3.rpc.getinfo()['fees_collected_msat'] == 0
    assert stats['forwards'][0]['received_time'] <= stats['forwards'][0]['resolved_time']
    assert stats['forwards'][1]['received_time'] <= stats['forwards'][1]['resolved_time']
    assert 'received_time' in stats['forwards'][2] and 'resolved_time' not in stats['forwards'][2]


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

    route = [{'amount_msat': amount,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'amount_msat': amount,
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

    route = [{'amount_msat': amount + fee,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'amount_msat': amount,
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
    route = [{'amount_msat': amount + fee - 1,
              'id': l2.info['id'],
              'delay': 12,
              'channel': c12},
             {'amount_msat': amount - 1,
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
    _, txid, blocks = l2.wait_for_onchaind_tx('OUR_HTLC_TIMEOUT_TO_US',
                                              'THEIR_UNILATERAL/OUR_HTLC')
    assert blocks == 5
    bitcoind.generate_block(5)

    # Could be RBF!
    l2.mine_txid_or_rbf(txid)
    l2.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
    l4.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l2])

    # give time to let l2 store the local_failed stats
    time.sleep(5)

    # Select all forwardings, and check the status
    stats = l2.rpc.listforwards()

    assert [f['status'] for f in stats['forwards']] == ['local_failed', 'local_failed', 'local_failed', 'local_failed', 'local_failed']
    assert l2.rpc.getinfo()['fees_collected_msat'] == 0

    assert 'received_time' in stats['forwards'][0] and 'resolved_time' not in stats['forwards'][0]
    assert 'received_time' in stats['forwards'][1] and 'resolved_time' not in stats['forwards'][1]
    assert 'received_time' in stats['forwards'][2] and 'resolved_time' not in stats['forwards'][2]
    assert 'received_time' in stats['forwards'][3] and 'resolved_time' not in stats['forwards'][3]
    assert 'received_time' in stats['forwards'][3] and 'resolved_time' not in stats['forwards'][4]

    # Correct in and out channels
    assert [s['in_channel'] for s in stats['forwards']] == [c12] * 5
    assert [s.get('out_channel') for s in stats['forwards']] == [c23, c24, c25, None, c24]


@pytest.mark.slow_test
def test_htlcs_cltv_only_difference(node_factory, bitcoind):
    # l1 -> l2 -> l3 -> l4
    # l4 ignores htlcs, so they stay.
    # l3 will see a reconnect from l4 when l4 restarts.
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True, opts=[{}] * 2 + [{'dev-no-reconnect': None, 'may_reconnect': True}] * 2)

    inv = l4.rpc.invoice(amount_msat=10**8, label='x', description='desc')
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
    l1.rpc.decode(b11)
    l1.rpc.pay(b11)

    # lightning: prefix is allowed
    b11 = 'lightning:' + l2.rpc.invoice(123000, 'test_pay_variants with prefix', 'description')['bolt11']
    l1.rpc.decode(b11)
    l1.rpc.pay(b11)

    # BOTH is allowed.
    b11 = 'LIGHTNING:' + l2.rpc.invoice(123000, 'test_pay_variants upper with prefix', 'description')['bolt11'].upper()
    l1.rpc.decode(b11)
    l1.rpc.pay(b11)


@pytest.mark.slow_test
def test_pay_retry(node_factory, bitcoind, executor, chainparams):
    """Make sure pay command retries properly. """

    def exhaust_channel(opener, peer, scid, already_spent=0):
        """Spend all available capacity (10^6 - 1%) of channel
        """
        chan = only_one(opener.rpc.listpeerchannels(peer.info['id'])["channels"])
        maxpay = chan['spendable_msat']
        lbl = ''.join(random.choice(string.ascii_letters) for _ in range(20))
        inv = peer.rpc.invoice(maxpay, lbl, "exhaust_channel")
        routestep = {
            'amount_msat': maxpay,
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
    l1.dev_pay(inv['bolt11'], dev_use_shadow=False)

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
        l1.dev_pay(inv, dev_use_shadow=False)


@pytest.mark.slow_test
def test_pay_avoid_low_fee_chan(node_factory, bitcoind, executor, chainparams):
    """Make sure we're able to route around a low fee depleted channel """

    # NOTE: This test did not consistently fail. If this test is flaky, that
    # probably means it needs to be fixed!

    # Setup:
    # sender - router --------- dest
    #             \              /
    #              - randomnode -
    # router is connected to the destination
    # randomnode is also connected to router and the destination, with a low fee
    # path. The channel however, is depleted.
    sender, router, randomnode, dest = node_factory.get_nodes(4)
    sender.rpc.connect(router.info['id'], 'localhost', router.port)
    sender.fundchannel(router, 200000, wait_for_active=True)
    router.rpc.connect(dest.info['id'], 'localhost', dest.port)
    router_dest_scid, _ = router.fundchannel(dest, 10**6, wait_for_active=True)
    randomnode.rpc.connect(dest.info['id'], 'localhost', dest.port)
    randomnode_dest_scid, _ = randomnode.fundchannel(dest, 10**6, wait_for_active=True)

    # Router has a depleted channel to randomnode. Mimic this by opening the
    # channel the other way around.
    randomnode.rpc.connect(router.info['id'], 'localhost', router.port)
    scid_router_random, _ = randomnode.fundchannel(router, 10**6, wait_for_active=True)

    # Set relevant fees:
    # - High fee from router to dest
    # - Low fee from router to randomnode and randomnode to dest
    router.rpc.setchannel(router_dest_scid, feebase=0, feeppm=2000, htlcmin=1)
    router.rpc.setchannel(scid_router_random, feebase=0, feeppm=1, htlcmin=1)
    randomnode.rpc.setchannel(randomnode_dest_scid, feebase=0, feeppm=1, htlcmin=1)

    def has_gossip():
        channels = sender.rpc.listchannels()['channels']
        if sum(1 for c in channels if c['fee_per_millionth'] == 1) != 2:
            return False

        if sum(1 for c in channels if c['fee_per_millionth'] == 2000) != 1:
            return False

        return True

    # Make sure all relevant gossip reached the sender.
    mine_funding_to_announce(bitcoind, [sender, router, randomnode, dest])
    wait_for(has_gossip)

    def listpays_nofail(b11):
        while True:
            pays = sender.rpc.listpays(b11)['pays']
            if len(pays) != 0:
                if only_one(pays)['status'] == 'complete':
                    return
                assert only_one(pays)['status'] != 'failed'

    inv = dest.rpc.invoice(100000000, 'test_low_fee', 'test_low_fee')

    # Make sure listpays doesn't transiently show failure while pay
    # is retrying.
    fut = executor.submit(listpays_nofail, inv['bolt11'])

    # Pay sender->dest should succeed via non-depleted channel
    sender.dev_pay(inv['bolt11'], dev_use_shadow=False)

    fut.result()


@pytest.mark.slow_test
def test_pay_routeboost(node_factory, bitcoind):
    """Make sure we can use routeboost information.

    ```dot
    graph {
      l1 -- l2 -- l3
      l3 -- l4 [style="dotted"]
      l4 -- l5 [style="dotted"]
    }
    ```
    """
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
    assert only_one(only_one(l1.rpc.decode(inv['bolt11'])['routes']))

    # Now we should be able to pay it.
    l1.dev_pay(inv['bolt11'], dev_use_shadow=False)

    # Status should show all the gory details.
    status = l1.rpc.call('paystatus', [inv['bolt11']])
    assert only_one(status['pay'])['bolt11'] == inv['bolt11']
    assert only_one(status['pay'])['amount_msat'] == Millisatoshi(10**5)
    assert only_one(status['pay'])['destination'] == l4.info['id']
    assert 'label' not in only_one(status['pay'])
    assert 'routehint_modifications' not in only_one(status['pay'])
    assert 'local_exclusions' not in only_one(status['pay'])
    attempts = only_one(status['pay'])['attempts']
    scid34 = l3.rpc.listpeerchannels(l4.info['id'])['channels'][0]['alias']['local']
    assert(len(attempts) == 1)
    a = attempts[0]
    assert(a['strategy'] == "Initial attempt")
    assert('success' in a)
    assert('payment_preimage' in a['success'])

    # With dev-route option we can test longer routehints.
    scid45 = l4.rpc.listpeerchannels(l5.info['id'])['channels'][0]['alias']['local']
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
    inv = l5.dev_invoice(amount_msat=10**5,
                         label='test_pay_routeboost2',
                         description='test_pay_routeboost2',
                         dev_routes=[routel3l4l5])
    l1.dev_pay(inv['bolt11'], dev_use_shadow=False)
    status = l1.rpc.call('paystatus', [inv['bolt11']])
    pay = only_one(status['pay'])
    attempts = pay['attempts']
    assert(len(attempts) == 1)
    assert 'failure' not in attempts[0]
    assert 'success' in attempts[0]

    # Finally, it should fall back to second routehint if first fails.
    # (Note, this is not public because it's not 6 deep). To test this
    # we add another edge to the graph, resulting in:
    #
    # ```dot
    # graph {
    #   rankdir=LR
    #   l1 -- l2 -- l3
    #   l4 [label="l4 (offline)",style="dashed"]
    #   l3 -- l4 [style="dotted"]
    #   l4 -- l5 [style="dotted"]
    #   l3 -- l5 [style="dotted"]
    # }
    # ```
    l3.rpc.connect(l5.info['id'], 'localhost', l5.port)
    scid35, _ = l3.fundchannel(l5, 10**6)
    l4.stop()

    # Now that we have the channels ready, let's build the routehints through l3l5
    routel3l5 = [{'id': l3.info['id'],
                  'short_channel_id': scid35,
                  'fee_base_msat': 1000,
                  'fee_proportional_millionths': 10,
                  'cltv_expiry_delta': 6}]
    inv = l5.dev_invoice(amount_msat=10**5,
                         label='test_pay_routeboost5',
                         description='test_pay_routeboost5',
                         dev_routes=[routel3l4l5, routel3l5])
    l1.dev_pay(inv['bolt11'], label="paying test_pay_routeboost5",
               dev_use_shadow=False)

    status = l1.rpc.call('paystatus', [inv['bolt11']])
    assert only_one(status['pay'])['bolt11'] == inv['bolt11']
    assert only_one(status['pay'])['destination'] == l5.info['id']
    assert only_one(status['pay'])['label'] == "paying test_pay_routeboost5"
    assert 'routehint_modifications' not in only_one(status['pay'])
    assert 'local_exclusions' not in only_one(status['pay'])
    attempts = only_one(status['pay'])['attempts']

    # First routehint in the invoice fails, we may retry that one
    # unsuccessfully before switching, hence the >2 instead of =2
    assert len(attempts) >= 2
    assert 'success' not in attempts[0]
    assert 'success' in attempts[-1]
    # TODO Add assertion on the routehint once we add them to the pay
    # output


def test_setchannel_usage(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] ---> [l2]  (channel funded)
    #   |
    #   o - - > [l3]  (only connected)
    #
    # - check initial SQL values
    # - check setchannel can be used
    # - checks command's return object format
    # - check custom SQL fee values
    # - check values in local nodes listchannels output
    # - json throws exception on negative values
    # - checks if peer id can be used instead of scid
    # - checks fee_base_msat and fee_proportional_millionths in `listpeers` out
    DEF_BASE = 10
    DEF_BASE_MSAT = Millisatoshi(DEF_BASE)
    DEF_PPM = 100
    # Minus reserve
    MAX_HTLC = Millisatoshi(int(FUNDAMOUNT * 1000 * 0.99))

    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM})
    node_factory.join_nodes([l1, l2])
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

    def channel_get_config(scid):
        return l1.db.query(
            'SELECT feerate_base, feerate_ppm, htlc_minimum_msat, htlc_maximum_msat FROM channels '
            'WHERE scid={};'.format(scid_to_int(scid)))

    # get short channel id
    scid = l1.get_channel_scid(l2)

    # feerates should be init with global config
    db_fees = l1.db_query('SELECT feerate_base, feerate_ppm, htlc_maximum_msat FROM channels;')
    assert(db_fees[0]['feerate_base'] == DEF_BASE)
    assert(db_fees[0]['feerate_ppm'] == DEF_PPM)
    # This will be the capacity - reserves:
    assert(db_fees[0]['htlc_maximum_msat'] == MAX_HTLC)
    # this is also what listpeers should return
    channel = only_one(l1.rpc.listpeerchannels()['channels'])
    assert channel['fee_base_msat'] == DEF_BASE_MSAT
    assert channel['fee_proportional_millionths'] == DEF_PPM
    assert channel['maximum_htlc_out_msat'] == MAX_HTLC

    # custom setchannel scid <feebase> <feeppm> <htlcmin> <htlcmax>
    result = l1.rpc.setchannel(scid, 1337, 137, 17, 133337)

    # check result format
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['peer_id'] == l2.info['id'])
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 1337)
    assert(result['channels'][0]['fee_proportional_millionths'] == 137)
    assert(result['channels'][0]['minimum_htlc_out_msat'] == 17)
    assert(result['channels'][0]['maximum_htlc_out_msat'] == 133337)
    assert(result['channels'][0]['ignore_fee_limits'] is False)

    # check if custom values made it into the database
    db_fees = channel_get_config(scid)
    assert(db_fees[0]['feerate_base'] == 1337)
    assert(db_fees[0]['feerate_ppm'] == 137)
    assert(db_fees[0]['htlc_minimum_msat'] == 17)
    assert(db_fees[0]['htlc_maximum_msat'] == 133337)
    # also check for updated values in `listpeers`
    channel = only_one(l1.rpc.listpeerchannels()['channels'])
    assert channel['fee_base_msat'] == Millisatoshi(1337)
    assert channel['fee_proportional_millionths'] == 137
    assert channel['minimum_htlc_out_msat'] == 17
    assert channel['maximum_htlc_out_msat'] == 133337

    # wait for gossip and check if l1 sees new fees in listchannels after mining
    bitcoind.generate_block(5)
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [DEF_BASE, 1337])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [DEF_PPM, 137])
    wait_for(lambda: [c['htlc_minimum_msat'] for c in l1.rpc.listchannels(scid)['channels']] == [0, 17])
    wait_for(lambda: [c['htlc_maximum_msat'] for c in l1.rpc.listchannels(scid)['channels']] == [MAX_HTLC, 133337])

    # also test with named and missing parameters
    result = l1.rpc.setchannel(feeppm=42, id=scid)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 1337)
    assert(result['channels'][0]['fee_proportional_millionths'] == 42)
    assert result['channels'][0]['minimum_htlc_out_msat'] == 17
    assert(result['channels'][0]['maximum_htlc_out_msat'] == 133337)

    result = l1.rpc.setchannel(feebase=43, id=scid)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 43)
    assert(result['channels'][0]['fee_proportional_millionths'] == 42)
    assert result['channels'][0]['minimum_htlc_out_msat'] == 17
    assert(result['channels'][0]['maximum_htlc_out_msat'] == 133337)

    result = l1.rpc.setchannel(htlcmin=45, id=scid)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 43)
    assert(result['channels'][0]['fee_proportional_millionths'] == 42)
    assert result['channels'][0]['minimum_htlc_out_msat'] == 45
    assert(result['channels'][0]['maximum_htlc_out_msat'] == 133337)

    result = l1.rpc.setchannel(htlcmax=43333, id=scid)
    assert(len(result['channels']) == 1)
    assert(re.match('^[0-9a-f]{64}$', result['channels'][0]['channel_id']))
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 43)
    assert(result['channels'][0]['fee_proportional_millionths'] == 42)
    assert result['channels'][0]['minimum_htlc_out_msat'] == 45
    assert(result['channels'][0]['maximum_htlc_out_msat'] == 43333)

    # check if negative fees raise error and DB keeps values
    # JSONRPC2_INVALID_PARAMS := -32602
    from pyln.client import LightningRpc
    with pytest.raises(RpcError, match=r'-32602'):
        # Need to bypass pyln since it'd check args locally. We also
        # have to sidestep the schema validation, it attempts to
        # instantiate Millisatoshis and fails due to the non-negative
        # constraint.
        LightningRpc.call(l1.rpc, 'setchannel', {
            "id": scid,
            "feebase": -1,
            "feeppm": -1
        })

    # test if zero fees is possible
    result = l1.rpc.setchannel(scid, 0, 0)
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 0)
    assert(result['channels'][0]['fee_proportional_millionths'] == 0)

    db_fees = channel_get_config(scid)
    assert(db_fees[0]['feerate_base'] == 0)
    assert(db_fees[0]['feerate_ppm'] == 0)
    # also check for updated values in `listpeers`
    channel = only_one(l1.rpc.listpeerchannels()['channels'])
    assert channel['fee_base_msat'] == Millisatoshi(0)
    assert channel['fee_proportional_millionths'] == 0

    # check also peer id can be used
    result = l1.rpc.setchannel(l2.info['id'], 142, 143)
    assert(len(result['channels']) == 1)
    assert(result['channels'][0]['peer_id'] == l2.info['id'])
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 142)
    assert(result['channels'][0]['fee_proportional_millionths'] == 143)

    db_fees = channel_get_config(scid)
    assert(db_fees[0]['feerate_base'] == 142)
    assert(db_fees[0]['feerate_ppm'] == 143)

    # check if invalid scid raises proper error
    with pytest.raises(RpcError, match=r'-1.*Could not find any active channels of peer with that id'):
        result = l1.rpc.setchannel(l3.info['id'], 42, 43)
    with pytest.raises(RpcError, match=r'-32602.*id: should be a channel ID or short channel ID: invalid token'):
        result = l1.rpc.setchannel('f42' + scid[3:], 42, 43)

    # check if 'base' unit can be modified to satoshi
    result = l1.rpc.setchannel(scid, '1sat')
    assert(len(result['channels']) == 1)
    assert(result['channels'][0]['peer_id'] == l2.info['id'])
    assert(result['channels'][0]['short_channel_id'] == scid)
    assert(result['channels'][0]['fee_base_msat'] == 1000)
    db_fees = channel_get_config(scid)
    assert(db_fees[0]['feerate_base'] == 1000)

    # check if 'ppm' values greater than u32_max fail
    with pytest.raises(RpcError, match=r'-32602.*ppm: should be an integer: invalid token'):
        LightningRpc.call(l1.rpc, 'setchannel', payload={
            "id": scid,
            'feebase': 0,
            'feeppm': 2**32,
        })

    # check if 'base' values greater than u32_max fail
    with pytest.raises(RpcError, match=r'-32602.*base: exceeds u32 max: invalid token'):
        LightningRpc.call(l1.rpc, 'setchannel', payload={
            "id": scid,
            "feebase": 2**32,
        })


def test_setchannel_state(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] --> [l2] --> [l3]
    #
    # Initiate channel [l2,l3] and try to set feerates other states than
    # CHANNELD_NORMAL or CHANNELD_AWAITING_LOCKIN. Should raise error.
    # Use l1 to make a forward through l2/l3 for testing.
    DEF_BASE = 0
    DEF_PPM = 0

    l1, l2, l3 = node_factory.get_nodes(3, opts={
        'fee-base': DEF_BASE,
        'fee-per-satoshi': DEF_PPM
    })

    # connection and funding
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 1000000, wait_for_active=True)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    scid, _ = l2.fundchannel(l3, 1000000, wait_for_active=False)

    # try setting the fee in state AWAITING_LOCKIN should be possible
    # assert(l2.channel_state(l3) == "CHANNELD_AWAITING_LOCKIN")
    result = l2.rpc.setchannel(l3.info['id'], 42, 0)
    assert(result['channels'][0]['peer_id'] == l3.info['id'])
    # cid = result['channels'][0]['channel_id']

    # test routing correct new fees once routing is established
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    l1.wait_for_route(l3)
    inv = l3.rpc.invoice(100000, 'test_setchannel_state', 'desc')['bolt11']
    result = l1.dev_pay(inv, dev_use_shadow=False)
    assert result['status'] == 'complete'
    assert result['amount_sent_msat'] == 100042

    # Disconnect and unilaterally close from l3 to l2
    l3.rpc.disconnect(l2.info['id'], force=True)
    result = l3.rpc.close(scid, 1)
    assert result['type'] == 'unilateral'

    # wait for l2 to see unilateral close via bitcoin network
    while l2.channel_state(l3) == "CHANNELD_NORMAL":
        bitcoind.generate_block(1)
    # assert l2.channel_state(l3) == "FUNDING_SPEND_SEEN"

    # Try to setchannel in order to raise expected error.
    # To reduce false positive flakes, only test if state is not NORMAL anymore.
    with pytest.raises(RpcError, match=r'-1.*'):
        # l2.rpc.setchannel(l3.info['id'], 10, 1)
        l2.rpc.setchannel(l3.info['id'], 10, 1)


def test_setchannel_routing(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] <--default_fees--> [l2] <--specific_fees--> [l3]
    #
    # - json listchannels is able to see the new values in foreign node
    # - routing calculates fees correctly
    # - payment can be done using specific fees
    # - channel specific fees can be disabled again
    # - payment can be done using global fees
    # - htlc max is honored
    DEF_BASE = 1
    DEF_PPM = 10
    MAX_HTLC = Millisatoshi(int(FUNDAMOUNT * 1000 * 0.99))
    MIN_HTLC = Millisatoshi(0)

    l1, l2, l3 = node_factory.line_graph(
        3, announce_channels=True, wait_for_announce=True,
        opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM,
              'disable-mpp': None})

    # get short channel id for 2->3
    scid = l2.get_channel_scid(l3)

    # TEST CUSTOM VALUES
    l2.rpc.setchannel(scid, 1337, 137, 17, 4000000, enforcedelay=0)

    # wait for l1 to see updated channel via gossip
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [1337, DEF_BASE])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [137, DEF_PPM])
    wait_for(lambda: [c['htlc_minimum_msat'] for c in l1.rpc.listchannels(scid)['channels']] == [17, MIN_HTLC])
    wait_for(lambda: [c['htlc_maximum_msat'] for c in l1.rpc.listchannels(scid)['channels']] == [4000000, MAX_HTLC])

    # test fees are applied to HTLC forwards
    #
    # BOLT #7:
    # If l1 were to send 4,999,999 millisatoshi to l3 via l2, it needs to
    # pay l2 the fee it specified in the l2->l3 `channel_update`, calculated as
    # per [HTLC Fees](#htlc_fees):  base + amt * pm / 10**6

    # Note: we use fp16 internally for channel max, so we overestimate:
    # from devtools/fp16 4000000: fp16:5fa1 min 3999744 max 4001791
    # Since it rounds up, it will use 4001792 as max capacity.

    # Should refuse to route this!
    with pytest.raises(RpcError, match=r'Could not find a route'):
        l1.rpc.getroute(l3.info['id'], 4001793, 1, fuzzpercent=0)["route"]

    # We should consider this unroutable!  (MPP is disabled!)
    inv = l3.dev_invoice(amount_msat=4001793,
                         label='test_setchannel_1',
                         description='desc',
                         dev_routes=[])
    with pytest.raises(RpcError) as routefail:
        l1.dev_pay(inv['bolt11'], dev_use_shadow=False)
    assert routefail.value.error['attempts'][0]['failreason'] == 'No path found'

    # 1337 + 4000000 * 137 / 1000000 = 1885
    route_ok = l1.rpc.getroute(l3.info['id'], 4000000, 1)["route"]
    assert len(route_ok) == 2
    assert route_ok[0]['amount_msat'] == 4001885
    assert route_ok[1]['amount_msat'] == 4000000

    # Make variant that tries to pay more than allowed htlc!
    route_bad = copy.deepcopy(route_ok)
    route_bad[0]['amount_msat'] = Millisatoshi(4001887)
    route_bad[1]['amount_msat'] = Millisatoshi(4000001)
    assert route_bad != route_ok

    # In case l3 includes a routehint, we need to make sure they also know
    # about the new fees, otherwise we may end up with the old feerate
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['htlc_minimum_msat'], c['htlc_maximum_msat'], c['active']) for c in l3.rpc.listchannels(scid)['channels']] == [(1337, 137, 17, 4000000, True), (DEF_BASE, DEF_PPM, MIN_HTLC, MAX_HTLC, True)])

    # do and check actual payment
    inv = l3.rpc.invoice(4000000, 'test_setchannel_2', 'desc')
    # Check that routehint from l3 incorporated new feerate!
    decoded = l1.rpc.decode(inv['bolt11'])
    assert decoded['routes'] == [[{'pubkey': l2.info['id'], 'short_channel_id': scid, 'fee_base_msat': 1337, 'fee_proportional_millionths': 137, 'cltv_expiry_delta': 6}]]

    # This will fail.
    l1.rpc.sendpay(route_bad, inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match='WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.waitsendpay(inv['payment_hash'])

    # This will succeed
    l1.rpc.sendpay(route_ok, inv['payment_hash'], payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    # Now try below minimum
    route_ok = l1.rpc.getroute(l3.info['id'], 17, 1)["route"]
    assert len(route_ok) == 2
    assert route_ok[0]['amount_msat'] == 1337 + 17
    assert route_ok[1]['amount_msat'] == 17

    route_bad = copy.deepcopy(route_ok)
    route_bad[0]['amount_msat'] = Millisatoshi(1337 + 16)
    route_bad[1]['amount_msat'] = Millisatoshi(16)
    assert route_bad != route_ok

    inv = l3.rpc.invoice(17, 'test_setchannel_3', 'desc')

    # This will fail.
    l1.rpc.sendpay(route_bad, inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match='WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.waitsendpay(inv['payment_hash'])

    # This will succeed
    l1.rpc.sendpay(route_ok, inv['payment_hash'], payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    # Check that this one warns about capacity!
    inv = l3.rpc.call('invoice', {'amount_msat': 4001793,
                                  'label': 'test_setchannel_4',
                                  'description': 'desc'})
    assert 'warning_capacity' in inv


def test_setchannel_zero(node_factory, bitcoind):
    # TEST SETUP
    #
    # [l1] <--default_fees--> [l2] <--specific_fees--> [l3]
    #
    # - json listchannels is able to see the new values in foreign node
    # - routing calculates fees correctly
    # - payment can be done using zero fees
    DEF_BASE = 1
    DEF_PPM = 10
    MAX_HTLC = Millisatoshi(int(FUNDAMOUNT * 1000 * 0.99))

    l1, l2, l3 = node_factory.line_graph(
        3, announce_channels=True, wait_for_announce=True,
        opts={'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM})

    # get short channel id for 2->3
    scid = l2.get_channel_scid(l3)

    # TEST ZERO fees possible
    l2.rpc.setchannel(scid, 0, 0)
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l1.rpc.listchannels(scid)['channels']] == [0, DEF_BASE])
    wait_for(lambda: [c['fee_per_millionth'] for c in l1.rpc.listchannels(scid)['channels']] == [0, DEF_PPM])

    # test if zero fees are applied
    route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
    assert len(route) == 2
    assert route[0]['amount_msat'] == 4999999
    assert route[1]['amount_msat'] == 4999999

    # Wait for l3 to know about our low-balling, otherwise they'll add a wrong
    # routehint to the invoice.
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['active']) for c in l3.rpc.listchannels(scid)['channels']] == [(0, 0, True), (DEF_BASE, DEF_PPM, True)])

    # do and check actual payment
    inv = l3.rpc.invoice(4999999, 'test_setchannel_3', 'desc')['bolt11']
    result = l1.dev_pay(inv, dev_use_shadow=False)
    assert result['status'] == 'complete'
    assert result['amount_sent_msat'] == 4999999

    # FIXME: hack something up to advertize min_htlc > 0, then test mintoolow.
    with pytest.raises(RpcError, match="htlcmax cannot be less than htlcmin"):
        l2.rpc.setchannel(scid, htlcmin=100000, htlcmax=99999)

    ret = l2.rpc.setchannel(scid, htlcmax=FUNDAMOUNT * 1000)
    assert 'warning_htlcmax_too_high' in only_one(ret['channels'])
    assert only_one(ret['channels'])['maximum_htlc_out_msat'] == MAX_HTLC


def test_setchannel_restart(node_factory, bitcoind):
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
    MIN_HTLC = Millisatoshi(0)
    MAX_HTLC = Millisatoshi(int(FUNDAMOUNT * 1000 * 0.99))
    OPTS = {'may_reconnect': True, 'fee-base': DEF_BASE, 'fee-per-satoshi': DEF_PPM}

    l1, l2, l3 = node_factory.line_graph(3, announce_channels=True, wait_for_announce=True, opts=OPTS)

    # get short channel idS
    scid12 = l1.get_channel_scid(l2)
    scid23 = l2.get_channel_scid(l3)

    # l2 set custom fees
    l2.rpc.setchannel(scid23, 1337, 137, 17, 500001)

    # restart l2 and reconnect
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Make sure l1's gossipd registered channeld activating channel.
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(scid12)['channels']] == [True, True])

    # l1 wait for channel update from l2
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['htlc_minimum_msat'], c['htlc_maximum_msat'], c['active']) for c in l1.rpc.listchannels(scid23)['channels']] == [(1337, 137, 17, 500001, True), (DEF_BASE, DEF_PPM, MIN_HTLC, MAX_HTLC, True)])

    # In case l3 includes a routehint, we need to make sure they also know
    # about the new fees, otherwise we may end up with the old feerate
    wait_for(lambda: [(c['base_fee_millisatoshi'], c['fee_per_millionth'], c['htlc_minimum_msat'], c['htlc_maximum_msat'], c['active']) for c in l3.rpc.listchannels(scid23)['channels']] == [(1337, 137, 17, 500001, True), (DEF_BASE, DEF_PPM, MIN_HTLC, MAX_HTLC, True)])

    # l1 can make payment to l3 with custom fees being applied
    # Note: BOLT #7 math works out to 1405 msat fees
    inv = l3.rpc.invoice(499999, 'test_setchannel_1', 'desc')['bolt11']
    result = l1.dev_pay(inv, dev_use_shadow=False)
    assert result['status'] == 'complete'
    assert result['amount_sent_msat'] == 501404


def test_setchannel_all(node_factory, bitcoind):
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
    result = l1.rpc.setchannel("all", 0xDEAD, 0xBEEF, 0xBAD, 0xCAFE)

    channel_after = {"htlc_minimum_msat": Millisatoshi(0xBAD),
                     "htlc_maximum_msat": Millisatoshi(0xCAFE),
                     "cltv_expiry_delta": 6,
                     "fee_base_msat": Millisatoshi(0xDEAD),
                     "fee_proportional_millionths": 0xBEEF}

    # We should see these updates immediately.
    assert only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['updates']['local'] == channel_after
    assert only_one(l1.rpc.listpeerchannels(l3.info['id'])['channels'])['updates']['local'] == channel_after

    # Peer should see them soon (once we sent)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['updates']['remote'] == channel_after)
    wait_for(lambda: only_one(l3.rpc.listpeerchannels()['channels'])['updates']['remote'] == channel_after)

    # Don't assume order!
    assert len(result['channels']) == 2
    if result['channels'][0]['peer_id'] == l3.info['id']:
        result['channels'] = [result['channels'][1], result['channels'][0]]
    assert result['channels'][0]['peer_id'] == l2.info['id']
    assert result['channels'][0]['short_channel_id'] == scid2
    assert result['channels'][0]['fee_base_msat'] == 0xDEAD
    assert result['channels'][0]['fee_proportional_millionths'] == 0xBEEF
    assert result['channels'][0]['minimum_htlc_out_msat'] == 0xBAD
    assert result['channels'][0]['maximum_htlc_out_msat'] == 0xCAFE
    assert result['channels'][1]['peer_id'] == l3.info['id']
    assert result['channels'][1]['short_channel_id'] == scid3
    assert result['channels'][1]['fee_base_msat'] == 0xDEAD
    assert result['channels'][1]['fee_proportional_millionths'] == 0xBEEF
    assert result['channels'][1]['minimum_htlc_out_msat'] == 0xBAD
    assert result['channels'][1]['maximum_htlc_out_msat'] == 0xCAFE


def test_setchannel_startup_opts(node_factory, bitcoind):
    """Tests that custom config/cmdline options are applied correctly when set
    """
    opts = {
        'fee-base': 2,
        'fee-per-satoshi': 3,
        'htlc-minimum-msat': '4msat',
        'htlc-maximum-msat': '5msat'
    }
    l1, l2 = node_factory.line_graph(2, opts=opts, wait_for_announce=True)

    result = l2.rpc.listchannels()['channels']
    assert result[0]['base_fee_millisatoshi'] == 2
    assert result[0]['fee_per_millionth'] == 3
    assert result[0]['htlc_minimum_msat'] == Millisatoshi(4)
    assert result[0]['htlc_maximum_msat'] == Millisatoshi(5)
    assert result[1]['base_fee_millisatoshi'] == 2
    assert result[1]['fee_per_millionth'] == 3
    assert result[1]['htlc_minimum_msat'] == Millisatoshi(4)
    assert result[1]['htlc_maximum_msat'] == Millisatoshi(5)


@pytest.mark.parametrize("anchors", [False, True])
def test_channel_spendable(node_factory, bitcoind, anchors):
    """Test that spendable_msat is accurate"""
    sats = 10**6
    opts = {'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'), 'holdtime': '30'}
    if anchors is False:
        opts['dev-force-features'] = "-23"
    l1, l2 = node_factory.line_graph(2, fundamount=sats, wait_for_announce=True,
                                     opts=opts)

    inv = l2.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']

    # We should be able to spend this much, and not one msat more!
    amount = l1.rpc.listpeerchannels()['channels'][0]['spendable_msat']
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
    wait_for(lambda: len(l1.rpc.listpeerchannels()['channels'][0]['htlcs']) == 1)
    assert l1.rpc.listpeerchannels()['channels'][0]['spendable_msat'] == Millisatoshi(0)
    l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Make sure l2 thinks it's all over.
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels'][0]['htlcs']) == 0)
    # Now, reverse should work similarly.
    inv = l1.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']
    amount = l2.rpc.listpeerchannels()['channels'][0]['spendable_msat']

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
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels'][0]['htlcs']) == 1)
    assert l2.rpc.listpeerchannels()['channels'][0]['spendable_msat'] == Millisatoshi(0)
    l2.rpc.waitsendpay(payment_hash, TIMEOUT)


def test_channel_receivable(node_factory, bitcoind):
    """Test that receivable_msat is accurate"""
    sats = 10**6
    l1, l2 = node_factory.line_graph(2, fundamount=sats, wait_for_announce=True,
                                     opts={'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_invoice.py'), 'holdtime': '30'})

    inv = l2.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']

    # We should be able to receive this much, and not one msat more!
    amount = l2.rpc.listpeerchannels()['channels'][0]['receivable_msat']
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
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels'][0]['htlcs']) == 1)
    assert l2.rpc.listpeerchannels()['channels'][0]['receivable_msat'] == Millisatoshi(0)
    l1.rpc.waitsendpay(payment_hash, TIMEOUT)

    # Make sure both think it's all over.
    wait_for(lambda: len(l1.rpc.listpeerchannels()['channels'][0]['htlcs']) == 0)
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels'][0]['htlcs']) == 0)
    # Now, reverse should work similarly.
    inv = l1.rpc.invoice('any', 'inv', 'for testing')
    payment_hash = inv['payment_hash']
    amount = l1.rpc.listpeerchannels()['channels'][0]['receivable_msat']

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
    wait_for(lambda: len(l1.rpc.listpeerchannels()['channels'][0]['htlcs']) == 1)
    assert l1.rpc.listpeerchannels()['channels'][0]['receivable_msat'] == Millisatoshi(0)
    l2.rpc.waitsendpay(payment_hash, TIMEOUT)


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
    spendable = l1.rpc.listpeerchannels()['channels'][0]['spendable_msat']

    # receivable from the other side should calculate to the exact same amount
    receivable = l2.rpc.listpeerchannels()['channels'][0]['receivable_msat']
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
    l1, l2 = node_factory.line_graph(2, fundamount=sats, wait_for_announce=False,
                                     opts={'dev-force-features': '-19'})
    assert l1.rpc.listpeerchannels()['channels'][0]['spendable_msat'] == Millisatoshi(0xFFFFFFFF)
    assert l2.rpc.listpeerchannels()['channels'][0]['receivable_msat'] == Millisatoshi(0xFFFFFFFF)


@unittest.skipIf(True, "Test is extremely flaky")
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


@unittest.skipIf(TEST_NETWORK != 'regtest', 'Assumes anchors')
def test_htlc_too_dusty_outgoing(node_factory, bitcoind, chainparams):
    """ Try to hit the 'too much dust' limit, should fail the HTLC """

    # elements txs are bigger so they become dusty faster
    max_dust_limit_sat = 1000 if chainparams['elements'] else 500
    non_dust_htlc_val_sat = 2000 if chainparams['elements'] else 1000
    htlc_val_sat = 250

    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
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


def test_htlc_too_dusty_incoming(node_factory, bitcoind):
    """ Try to hit the 'too much dust' limit, should fail the HTLC """
    l1, l2, l3 = node_factory.line_graph(3, opts=[{'may_reconnect': True,
                                                   'max-dust-htlc-exposure-msat': '200000sat'},
                                                  {'may_reconnect': True,
                                                   'max-dust-htlc-exposure-msat': '1000sat',
                                                   'fee-base': 0,
                                                   'fee-per-satoshi': 0},
                                                  {'max-dust-htlc-exposure-msat': '1000sat'}],
                                         wait_for_announce=True)

    # on the l2->l3, and l3 holds all the htlcs hostage
    # have l3 hold onto all the htlcs and not fulfill them
    l3.rpc.dev_ignore_htlcs(id=l2.info['id'], ignore=True)

    # l2's max dust limit is set to 1k
    max_dust_limit_sat = 1000
    htlc_val_sat = 250
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

    l1.rpc.sendpay([{'amount_msat': 100,
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


def test_shadow_routing(node_factory):
    """
    Test the value randomization through shadow routing

    Note there is a very low (0.5**10) probability that it fails.
    """
    # We need l3 for random walk
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    amount = 10000
    total_amount = 0
    n_payments = 10
    for i in range(n_payments):
        inv = l3.rpc.invoice(amount, "{}".format(i), "test")["bolt11"]
        total_amount += l1.rpc.pay(inv)["amount_sent_msat"]

    assert total_amount > n_payments * amount
    # Test that the added amount isn't absurd
    assert total_amount < int((n_payments * amount) * (1 + 0.01))

    # FIXME: Test cltv delta too ?


def test_createonion_rpc(node_factory):
    l1 = node_factory.get_node()

    # From bolt04/onion-test.json:
    hops = [{
        "pubkey": "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619",
        "payload": "1202023a98040205dc06080000000000000001"
    }, {
        "pubkey": "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "payload": "52020236b00402057806080000000000000002fd02013c0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f"
    }, {
        "pubkey": "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        "payload": "12020230d4040204e206080000000000000003"
    }, {
        "pubkey": "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        "payload": "1202022710040203e806080000000000000004"
    }, {
        "pubkey": "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
        "payload": "fd011002022710040203e8082224a33562c54507a9334e79f0dc4f17d407e6d7c61f0e2f3d0d38599502f617042710fd012de02a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
    }]

    res = l1.rpc.createonion(hops=hops, assocdata="BB" * 32)
    assert(len(res['onion']) == 2 * 1366)
    assert(len(res['shared_secrets']) == len(hops))

    res = l1.rpc.createonion(hops=hops, assocdata="42" * 32,
                             session_key="41" * 32)
    # The trailer is generated using the filler and can be ued as a
    # checksum. This trailer is from the test-vector in the specs.
    assert(res['onion'].endswith('9126aaefb627719f421e20'))


def test_sendonion_rpc(node_factory):
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True)
    amt = 10**3
    route = l1.rpc.getroute(l4.info['id'], 10**3, 10)['route']
    inv = l4.rpc.invoice(amt, "lbl", "desc")

    first_hop = route[0]
    blockheight = l1.rpc.getinfo()['blockheight']

    # Need to shift the parameters by one hop
    hops = []
    for h, n in zip(route[:-1], route[1:]):
        # We tell the node h about the parameters to use for n (a.k.a. h + 1)
        hops.append({
            "pubkey": h['id'],
            "payload": serialize_payload_tlv(n['amount_msat'], n['delay'], n['channel'], blockheight).hex()
        })

    # The last hop has a special payload:
    hops.append({
        "pubkey": route[-1]['id'],
        "payload": serialize_payload_final_tlv(route[-1]['amount_msat'], route[-1]['delay'], route[-1]['amount_msat'], blockheight, inv['payment_secret']).hex()
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
    paysecret = l4.rpc.decode(inv['bolt11'])['payment_secret']

    # Separate routes for each part of the payment.
    r134 = l1.rpc.getroute(l4.info['id'], 501, 1, exclude=[scid24 + '/0', scid24 + '/1'])['route']
    r124 = l1.rpc.getroute(l4.info['id'], 499, 1, exclude=[scid34 + '/0', scid34 + '/1'])['route']

    # These can happen in parallel.
    l1.rpc.sendpay(
        route=r134,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
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
            amount_msat=499,
            payment_secret=paysecret,
            groupid=1,
        )

    # It will not allow a parallel with different msatoshi!
    with pytest.raises(RpcError, match=r'msatoshi was previously 1000msat, now 999msat'):
        l1.rpc.sendpay(
            route=r124,
            payment_hash=inv['payment_hash'],
            amount_msat=999,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=2,
            groupid=1,
        )

    # This will work fine.
    l1.rpc.sendpay(
        route=r124,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
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
            amount_msat=1000,
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
            amount_msat=1000,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=1,
            groupid=1,
        )

    l1.rpc.sendpay(
        route=r134,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=1,
    )

    l1.rpc.sendpay(
        route=r124,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
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

    res = l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], partid=1, timeout=TIMEOUT)
    assert res['partid'] == 1
    res = l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], partid=2, timeout=TIMEOUT)
    assert res['partid'] == 2

    for i in range(2):
        line = l4.daemon.wait_for_log('print_htlc_onion.py: Got onion')
        assert "'type': 'tlv'" in line
        assert "'forward_msat': 499" in line or "'forward_msat': 501" in line
        assert "'total_msat': 1000" in line
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
        amount_msat=1000,
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
            amount_msat=1000,
            bolt11=inv['bolt11'],
            payment_secret=paysecret,
            partid=3,
            groupid=1)


def test_partial_payment_timeout(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(1000, 'inv', 'inv')
    paysecret = l2.rpc.decode(inv['bolt11'])['payment_secret']

    route = l1.rpc.getroute(l2.info['id'], 500, 1)['route']
    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
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
        amount_msat=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=1,
        groupid=2
    )
    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
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
    paysecret = l3.rpc.decode(inv['bolt11'])['payment_secret']

    route = l1.rpc.getroute(l3.info['id'], 500, 1)['route']

    l1.rpc.sendpay(
        route=route,
        payment_hash=inv['payment_hash'],
        amount_msat=1000,
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
        amount_msat=1000,
        bolt11=inv['bolt11'],
        payment_secret=paysecret,
        partid=2,
        groupid=1,
    )

    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=1)
    l1.rpc.waitsendpay(payment_hash=inv['payment_hash'], timeout=TIMEOUT, partid=2)


def test_partial_payment_htlc_loss(node_factory, bitcoind):
    """Test that we discard a set when the HTLC is lost"""
    # We want l2 to fail once it has completed first htlc.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{},
                                               {'disconnect': ['=WIRE_UPDATE_ADD_HTLC', '+WIRE_REVOKE_AND_ACK']},
                                               {}])

    inv = l3.rpc.invoice(1000, 'inv', 'inv')
    paysecret = l3.rpc.decode(inv['bolt11'])['payment_secret']

    route = l1.rpc.getroute(l3.info['id'], 500, 1)['route']

    l1.rpc.sendpay(route=route, payment_hash=inv['payment_hash'], amount_msat=1000, bolt11=inv['bolt11'], payment_secret=paysecret, partid=1)

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
        "payload": bytes([227] + [0] * 227).hex(),
    }, {
        "pubkey": "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
        "payload": bytes([227] + [0] * 227).hex(),
    }, {
        "pubkey": "027f31ebc5462c1fdce1b737ecff52d37d75dea43ce11c74d25aa297165faa2007",
        "payload": bytes([227] + [0] * 227).hex(),
    }, {
        "pubkey": "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
        "payload": bytes([227] + [0] * 227).hex(),
    }, {
        "pubkey": "02edabbd16b41c8371b92ef2f04c1185b4f03b6dcd52ba9b78d9d7c89c8f221145",
        "payload": bytes([227] + [0] * 227).hex(),
    }]

    # This should success since it's right at the edge
    l1.rpc.createonion(hops=hops, assocdata="BB" * 32)

    # This one should fail however
    with pytest.raises(RpcError, match=r'Payloads exceed maximum onion packet size.'):
        hops[0]['payload'] = bytes([228] + [0] * 228).hex()
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
        l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1000, 1)['route'], payment_hash=inv['payment_hash'], amount_msat=1001, bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'Do not specify msatoshi \(999msat\) without'
                       ' partid: if you do, it must be exactly'
                       r' the final amount \(1000msat\)'):
        l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1000, 1)['route'], payment_hash=inv['payment_hash'], amount_msat=999, bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])

    # Can't send MPP payment which pays any more than amount.
    with pytest.raises(RpcError, match=r'Final amount 1001msat is greater than 1000msat, despite MPP'):
        l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1001, 1)['route'], payment_hash=inv['payment_hash'], amount_msat=1000, bolt11=inv['bolt11'], partid=1, payment_secret=inv['payment_secret'])

    # But this works
    l1.rpc.sendpay(route=l1.rpc.getroute(l2.info['id'], 1001, 1)['route'], payment_hash=inv['payment_hash'], amount_msat=1001, bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])
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


@unittest.skip("Test is flaky causing CI to be unusable.")
def test_excluded_adjacent_routehint(node_factory, bitcoind):
    """Test case where we try have a routehint which leads to an adjacent
    node, but the result exceeds our maxfee; we crashed trying to find
    what part of the path was most expensive in that case

    """
    l1, l2, l3 = node_factory.line_graph(3)

    # We'll be forced to use routehint, since we don't know about l3.
    inv = l3.rpc.invoice(10**3, "lbl", "desc", exposeprivatechannels=l2.get_channel_scid(l3))

    l1.wait_channel_active(l1.get_channel_scid(l2))
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
    assert(inv['amount_received_msat'] >= Millisatoshi(amt))

    # Now send a direct one instead from l1 to l2
    l1.rpc.keysend(l2.info['id'], amt)
    invs = l2.rpc.listinvoices()['invoices']
    assert(len(invs) == 1)

    inv = invs[0]
    assert(inv['amount_received_msat'] >= Millisatoshi(amt))

    # And finally try to send a keysend payment to l4, which doesn't
    # support it. It MUST fail.
    with pytest.raises(RpcError, match=r"Recipient [0-9a-f]{66} reported an invalid payload"):
        l3.rpc.keysend(l4.info['id'], amt)


def test_keysend_strip_tlvs(node_factory):
    """Use the extratlvs option to deliver a message with sphinx' TLV type, which keysend strips.
    """
    amt = 10**7
    l1, l2 = node_factory.line_graph(
        2,
        wait_for_announce=True,
        opts=[
            {
                # Not needed, just for listconfigs test.
                'accept-htlc-tlv-type': [133773310, 99990],
                "plugin": os.path.join(os.path.dirname(__file__), "plugins/sphinx-receiver.py"),
            },
            {
                "plugin": os.path.join(os.path.dirname(__file__), "plugins/sphinx-receiver.py"),
            },
        ]
    )

    # Make sure listconfigs works here
    assert l1.rpc.listconfigs('accept-htlc-tlv-type')['configs']['accept-htlc-tlv-type']['values_int'] == [133773310, 99990]

    # l1 is configured to accept, so l2 should still filter them out
    l1.rpc.keysend(l2.info['id'], amt, extratlvs={133773310: 'FEEDC0DE'})
    inv = only_one(l2.rpc.listinvoices()['invoices'])
    assert not l2.daemon.is_in_log(r'plugin-sphinx-receiver.py.*extratlvs.*133773310.*feedc0de')

    assert(inv['amount_received_msat'] >= Millisatoshi(amt))
    assert inv['description'] == 'keysend'
    l2.rpc.delinvoice(inv['label'], 'paid')

    # Now try again with the TLV type in extra_tlvs as string:
    l1.rpc.keysend(l2.info['id'], amt, extratlvs={133773310: b'hello there'.hex()})
    inv = only_one(l2.rpc.listinvoices()['invoices'])
    assert inv['description'] == 'keysend: hello there'
    l2.daemon.wait_for_log('Keysend payment uses illegal even field 133773310: stripping')
    l2.rpc.delinvoice(inv['label'], 'paid')

    # We can (just!) fit a giant description in.
    l1.rpc.keysend(l2.info['id'], amt, extratlvs={133773310: (b'a' * 1100).hex()})
    inv = only_one(l2.rpc.listinvoices()['invoices'])
    assert inv['description'] == 'keysend: ' + 'a' * 1100
    l2.rpc.delinvoice(inv['label'], 'paid')
    l2.daemon.wait_for_log('Keysend payment uses illegal even field 133773310: stripping')

    # Now try with some special characters
    ksinfo = """💕 ₿"'
More info
"""
    # Since we're at it, use this to test string-keyed TLVs
    l1.rpc.keysend(l2.info['id'], amt, extratlvs={"133773310": bytes(ksinfo, encoding='utf8').hex()})
    inv = only_one(l2.rpc.listinvoices()['invoices'])
    assert inv['description'] == 'keysend: ' + ksinfo
    l2.daemon.wait_for_log('Keysend payment uses illegal even field 133773310: stripping')

    # Now reverse the direction. l1 accepts 133773310, but filters out
    # other even unknown types (like 133773312).
    l2.rpc.keysend(l1.info['id'], amt, extratlvs={
        "133773310": b"helloworld".hex(),  # This one is allowlisted
        "133773312": b"filterme".hex(),  # This one will get stripped
    })

    # The invoice_payment hook must contain the allowlisted TLV type,
    # but not the stripped one.
    assert l1.daemon.wait_for_log(r'plugin-sphinx-receiver.py: invoice_payment.*extratlvs.*133773310')
    assert not l1.daemon.is_in_log(r'plugin-sphinx-receiver.py: invoice_payment.*extratlvs.*133773312')


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
                'scid': only_one(l3.rpc.listpeerchannels()['channels'])['alias']['remote'],
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
        l1.rpc.call("keysend", payload={'destination': dest, 'amount_msat': amt})

    # We should also fail with only non-working hints:
    with pytest.raises(RpcError):
        l1.rpc.call("keysend", payload={'destination': dest, 'amount_msat': amt, 'routehints': routehints[1:]})

    l1.rpc.call("keysend", payload={'destination': dest, 'amount_msat': amt, 'routehints': routehints})
    invs = l3.rpc.listinvoices()['invoices']
    assert(len(invs) == 1)

    inv = invs[0]
    assert(inv['amount_received_msat'] >= Millisatoshi(amt))


def test_keysend_maxfee(node_factory):
    l1, l2, l3 = node_factory.line_graph(
        3,
        wait_for_announce=True,
        opts=[{}, {'fee-base': 50, 'fee-per-satoshi': 0}, {}]
    )

    # We should fail because maxfee and exemptfee cannot be set simultaneously.
    with pytest.raises(RpcError):
        l1.rpc.call("keysend", payload={'destination': l3.info['id'], 'amount_msat': 1, 'maxfee': 1, 'exemptfee': 5000})

    # We should fail because maxfee and maxfeepercent cannot be set simultaneously.
    with pytest.raises(RpcError):
        l1.rpc.call("keysend", payload={'destination': l3.info['id'], 'amount_msat': 1, 'maxfee': 1, 'maxfeepercent': 0.0001})

    # We should fail because 50msat base fee on l2 exceeds maxfee of 1msat.
    with pytest.raises(RpcError):
        l1.rpc.call("keysend", payload={'destination': l3.info['id'], 'amount_msat': 1, 'maxfee': 1})
    assert len(l3.rpc.listinvoices()['invoices']) == 0

    # Perform a normal keysend with maxfee.
    l1.rpc.call("keysend", payload={'destination': l3.info['id'], 'amount_msat': 1, 'maxfee': 50})
    assert len(l3.rpc.listinvoices()['invoices']) == 1


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


def test_pay_exemptfee(node_factory):
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
        l1.dev_pay(l3.rpc.invoice(1, "lbl1", "desc")['bolt11'], dev_use_shadow=False)

    # If we tell our node that 5001msat is ok this should work
    l1.dev_pay(l3.rpc.invoice(1, "lbl2", "desc")['bolt11'], dev_use_shadow=False, exemptfee=5001)

    # Given the above network this is the smallest amount that passes without
    # the fee-exemption (notice that we let it through on equality).
    threshold = int(5001 / 0.05)

    # This should be just below the fee-exemption and is the first value that is allowed through
    with pytest.raises(RpcError, match=err):
        l1.dev_pay(l3.rpc.invoice(threshold - 1, "lbl3", "desc")['bolt11'], dev_use_shadow=False)

    # While this'll work just fine
    l1.dev_pay(l3.rpc.invoice(int(5001 * 200), "lbl4", "desc")['bolt11'], dev_use_shadow=False)


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
        chan = n1.rpc.listpeerchannels(n2.info['id'])['channels'][0]
        avail = chan['spendable_msat']
        return Millisatoshi(avail)

    amt = Millisatoshi(10**8)
    # How many payments do we expect to go through directly?
    direct = spendable(l1, l2) // amt

    # Remember the l1 -> l3 capacity, it should not change until we run out of
    # direct capacity.
    l1l3cap = spendable(l1, l3)

    for i in range(0, direct):
        inv = l2.rpc.invoice(amt.millisatoshis, "lbl{}".format(i),
                             "desc{}".format(i))['bolt11']
        l1.dev_pay(inv, dev_use_shadow=False)

    # We should not have more than amt in the direct channel anymore
    assert(spendable(l1, l2) < amt)
    assert(spendable(l1, l3) == l1l3cap)

    # Next one should take the alternative, but it should still work
    inv = l2.rpc.invoice(amt.millisatoshis, "final", "final")['bolt11']
    l1.dev_pay(inv, dev_use_shadow=False)


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
    c12 = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    c34 = l3.rpc.listpeerchannels(l4.info['id'])['channels'][0]
    assert(c12['spendable_msat'] < amt)
    assert(c34['spendable_msat'] < amt)

    # Make sure all HTLCs entirely resolved before we mine more blocks!
    def all_htlcs(n):
        htlcs = []
        for p in n.rpc.listpeers()['peers']:
            for c in n.rpc.listpeerchannels(p['id'])['channels']:
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

    # Make sure that bolt11 isn't duplicated for every part
    bolt11s = 0
    count = 0
    for p in l1.rpc.listsendpays()['payments']:
        if 'bolt11' in p:
            bolt11s += 1
        count += 1

    # You were supposed to mpp!
    assert count > 1
    # Not every one should have the bolt11 string
    assert bolt11s < count

    # listpays() shows bolt11 string
    assert 'bolt11' in only_one(l1.rpc.listpays()['pays'])


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
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'][0]['spendable_msat'] > amount_sat * 1000)

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
    # Make sure l2 considers it fully connected too!
    wait_for(lambda: l2.rpc.listpeers(l1.info['id']) != {'peers': []})
    l2.rpc.fundchannel(l1.info['id'], amount_sat * 3)

    # Let the channel confirm.
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1, l2])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    amt = Millisatoshi(amount_sat * 2 * 1000)
    invl1 = l1.rpc.invoice(amt, 'j', 'j')['bolt11']
    l2.rpc.pay(invl1)

    pays = l2.rpc.listpays()["pays"]
    assert(pays[0]["bolt11"] == invl1)
    assert('amount_msat' in pays[0] and pays[0]['amount_msat'] == amt)
    assert('created_at' in pays[0])
    assert('completed_at' in pays[0])


def test_delpay_argument_invalid(node_factory, bitcoind):
    """
    This test includes all possible combinations of input error inside the
    delpay command.
    """

    # Create the line graph l2 -> l1 with a channel of 10 ** 5 sat!
    l2, l1 = node_factory.line_graph(2, fundamount=10**5, wait_for_announce=True)

    l2.rpc.check_request_schemas = False
    with pytest.raises(RpcError):
        l2.rpc.delpay()
    l2.rpc.check_request_schemas = True

    # sanity check
    inv = l1.rpc.invoice(10 ** 5, 'inv', 'inv')
    payment_hash = "AA" * 32
    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'complete')

    l2.rpc.pay(inv['bolt11'])

    wait_for(lambda: l2.rpc.listpays(inv['bolt11'])['pays'][0]['status'] == 'complete')

    payment_hash = inv['payment_hash']

    # payment paid with wrong status (pending status is a illegal input)
    l2.rpc.check_request_schemas = False
    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'pending')

    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'invalid_status')
    l2.rpc.check_request_schemas = True

    with pytest.raises(RpcError):
        l2.rpc.delpay(payment_hash, 'failed')

    # test if the node is still ready
    payments = l2.rpc.delpay(payment_hash, 'complete')

    assert payments['payments'][0]['bolt11'] == inv['bolt11']
    assert len(payments['payments']) == 1
    assert len(l2.rpc.listpays()['pays']) == 0


def test_delpay_mixed_status(node_factory, bitcoind):
    """
    One failure, one success; we only want to delete the failed one!
    """
    l1, l2, l3 = node_factory.line_graph(3, fundamount=10**5,
                                         wait_for_announce=True)
    # Expensive route!
    l4 = node_factory.get_node(options={'fee-per-satoshi': 1000,
                                        'fee-base': 2000})
    node_factory.join_nodes([l1, l4, l3], wait_for_announce=True)

    # Don't give a hint, so l1 chooses cheapest.
    inv = l3.dev_invoice(10**5, 'lbl', 'desc', dev_routes=[])
    l3.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.pay(inv['bolt11'])

    assert len(l1.rpc.listsendpays()['payments']) == 2
    delpay_result = l1.rpc.delpay(inv['payment_hash'], 'failed')['payments']
    assert len(delpay_result) == 1
    assert len(l1.rpc.listsendpays()['payments']) == 1


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
    l2l3, _ = l2.fundchannel(l3, 10**7, announce_channel=False)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Wait for l3 to learn about l1->l2, otherwise it will think
    # l2 is a deadend and not add it to the routehint.
    l3.wait_channel_active(l1l2)

    # Now make the l1 payer stop receiving blocks.
    def no_more_blocks(req):
        return {"result": None,
                "error": {"code": -8, "message": "Block height out of range"}, "id": req['id']}
    l1.daemon.rpcproxy.mock_rpc('getblockhash', no_more_blocks)

    # Increase blockheight by 2, like in test_blockheight_disagreement.
    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l3])

    inv = l3.rpc.invoice(Millisatoshi(2 * 10000 * 1000), 'i', 'i', exposeprivatechannels=True)['bolt11']
    assert 'routes' in l3.rpc.decode(inv)

    # Have l1 pay l3
    def pay(l1, inv):
        l1.dev_pay(inv, dev_use_shadow=False)
    fut = executor.submit(pay, l1, inv)

    # Make sure l1 sends out the HTLC.
    l1.daemon.wait_for_logs([r'NEW:: HTLC LOCAL'])

    # Unblock l1 from new blocks.
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)

    # pay command should complete without error
    fut.result(TIMEOUT)


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
        if len(l1.rpc.decode(i2)['routes'] + l1.rpc.decode(i3)['routes']) <= 4:
            break

    # Pay simultaneously!
    p2 = executor.submit(l2.rpc.pay, i2)
    p3 = executor.submit(l3.rpc.pay, i3)

    # Both payments should succeed.
    p2.result(TIMEOUT)
    p3.result(TIMEOUT)


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


@unittest.skipIf(TEST_NETWORK != 'regtest', "Canned offer is network specific")
def test_offer_needs_option(node_factory):
    """Make sure we don't make offers without offer command"""
    l1 = node_factory.get_node()
    with pytest.raises(RpcError, match='experimental-offers not enabled'):
        l1.rpc.call('offer', {'amount': '1msat', 'description': 'test'})
    with pytest.raises(RpcError, match='experimental-offers not enabled'):
        l1.rpc.call('invoicerequest', {'amount': '2msat',
                                       'description': 'simple test'})
    with pytest.raises(RpcError, match='experimental-offers not enabled'):
        l1.rpc.call('fetchinvoice', {'offer': 'lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqyqs5pr5v4ehg93pqfnwgkvdr57yzh6h92zg3qctvrm7w38djg67kzcm4yeg8vc4cq63s'})

    # Decode still works though
    assert l1.rpc.decode('lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcgqyqs5pr5v4ehg93pqfnwgkvdr57yzh6h92zg3qctvrm7w38djg67kzcm4yeg8vc4cq63s')['valid']


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
        assert offer['offer_id'] == ret['offer_id']

        output = subprocess.check_output([bolt12tool, 'decode',
                                          offer['bolt12']]).decode('ASCII')
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

    # Test quantity
    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max existence test',
                                'quantity_max': 0})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'quantity_max: 0' in output

    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'quantity_max': 2})
    offer = only_one(l1.rpc.call('listoffers', [ret['offer_id']])['offers'])
    output = subprocess.check_output([bolt12tool, 'decode',
                                      offer['bolt12']]).decode('UTF-8')
    assert 'quantity_max: 2' in output

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
        ret = l1.rpc.call('offer', {
            'amount': '100000sat',
            'description': 'quantity_max test',
            'recurrence': r[0],
        })

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

    # Cannot use recurrence_start_any_period without recurrence_base
    with pytest.raises(RpcError, match='Cannot set to false without specifying recurrence_base'):
        l1.rpc.call('offer', {'amount': '100000sat',
                              'description': 'quantity_max test',
                              'recurrence': '10minutes',
                              'recurrence_start_any_period': False})

    ret = l1.rpc.call('offer', {'amount': '100000sat',
                                'description': 'quantity_max test',
                                'recurrence': '10minutes',
                                'recurrence_base': 1456740000,
                                'recurrence_start_any_period': False})
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

    # This is deprecated:
    l1.rpc.jsonschemas = {}
    with pytest.raises(RpcError, match='invalid token'):
        l1.rpc.call('offer', {'amount': '100000sat',
                              'description': 'test deprecated recurrence_base',
                              'recurrence': '10minutes',
                              'recurrence_base': '@1456740000'})


def test_offer_deprecated_api(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None,
                                              'allow-deprecated-apis': True})

    offer = l2.rpc.call('offer', {'amount': '2msat',
                                  'description': 'test_offer_deprecated_api'})
    inv = l1.rpc.call('fetchinvoice', {'offer': offer['bolt12']})

    # Deprecated fields make schema checker upset.
    l1.rpc.jsonschemas = {}
    l1.rpc.pay(inv['invoice'])


def test_fetchinvoice_3hop(node_factory, bitcoind):
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True,
                                             opts={'experimental-offers': None,
                                                   'may_reconnect': True,
                                                   'dev-no-reconnect': None})
    offer1 = l4.rpc.call('offer', {'amount': '2msat',
                                   'description': 'simple test'})
    assert offer1['created'] is True

    l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})


def test_fetchinvoice(node_factory, bitcoind):
    # We remove the conversion plugin on l3, causing it to get upset.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{'experimental-offers': None},
                                               {'experimental-offers': None},
                                               {'experimental-offers': None,
                                                'broken_log': "plugin-offers: Failed invreq.*Unknown command 'currencyconvert'"}])

    # Simple offer first.
    offer1 = l3.rpc.call('offer', {'amount': '2msat',
                                   'description': 'simple test'})
    assert offer1['created'] is True

    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})
    inv2 = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'],
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

    assert 'invreq_payer_note' not in only_one(l3.rpc.call('listinvoices', {'invstring': inv1['invoice']})['invoices'])
    assert only_one(l3.rpc.call('listinvoices', {'invstring': inv2['invoice']})['invoices'])['invreq_payer_note'] == 'Thanks for the fish!'

    # BTW, test listinvoices-by-offer_id:
    assert len(l3.rpc.listinvoices(offer_id=offer1['offer_id'])['invoices']) == 2

    # We can also set the amount explicitly, to tip.
    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'amount_msat': 3})
    assert l1.rpc.call('decode', [inv1['invoice']])['invoice_amount_msat'] == 3
    l1.rpc.pay(inv1['invoice'])

    # We've done 4 onion calls: sleep now to avoid hitting ratelimit!
    time.sleep(1)

    # More than ~5x expected is rejected as absurd (it's actually a divide test,
    # which means we need 15 here, not 11).
    with pytest.raises(RpcError, match="Remote node sent failure message.*Amount vastly exceeds 2msat"):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'amount_msat': 15})

    # Underpay is rejected.
    with pytest.raises(RpcError, match="Remote node sent failure message.*Amount must be at least 2msat"):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'amount_msat': 1})

    # If no amount is specified in offer, one must be in invoice.
    offer_noamount = l3.rpc.call('offer', {'amount': 'any',
                                           'description': 'any amount test'})
    with pytest.raises(RpcError, match="amount_msat parameter required"):
        l1.rpc.call('fetchinvoice', {'offer': offer_noamount['bolt12']})
    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer_noamount['bolt12'], 'amount_msat': 100})
    # But amount won't appear in changes
    assert 'msat' not in inv1['changes']

    # Single-use invoice can be fetched multiple times, only paid once.
    offer2 = l3.rpc.call('offer', {'amount': '1msat',
                                   'description': 'single-use test',
                                   'single_use': True})['bolt12']

    # We've done 3 onion calls: sleep now to avoid hitting ratelimit!
    time.sleep(1)

    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer2})
    inv2 = l1.rpc.call('fetchinvoice', {'offer': offer2})
    assert inv1 != inv2
    assert 'next_period' not in inv1
    assert 'next_period' not in inv2

    l1.rpc.pay(inv1['invoice'])

    # We can't pay the other one now.
    # FIXME: Even dummy blinded paths always return WIRE_INVALID_ONION_BLINDING!
    with pytest.raises(RpcError, match="INVALID_ONION_BLINDING.*'erring_node': '{}'".format(l3.info['id'])):
        l1.rpc.pay(inv2['invoice'])

    # We can't reuse the offer, either.
    with pytest.raises(RpcError, match='Offer no longer available'):
        l1.rpc.call('fetchinvoice', {'offer': offer2})

    # Now, test amount in different currency!
    plugin = os.path.join(os.path.dirname(__file__), 'plugins/currencyUSDAUD5000.py')
    l3.rpc.plugin_start(plugin)

    offerusd = l3.rpc.call('offer', {'amount': '10.05USD',
                                     'description': 'USD test'})['bolt12']

    # We've done 3 onion calls: sleep now to avoid hitting ratelimit!
    time.sleep(1)

    inv = l1.rpc.call('fetchinvoice', {'offer': offerusd})
    assert inv['changes']['amount_msat'] == Millisatoshi(int(10.05 * 5000))

    # Check we can request invoice without a channel.
    offer3 = l2.rpc.call('offer', {'amount': '1msat',
                                   'description': 'offer3'})
    l4 = node_factory.get_node(options={'experimental-offers': None})
    l4.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # ... even if we can't find ourselves.
    l4.rpc.call('fetchinvoice', {'offer': offer3['bolt12']})
    # ... even if we know it from gossmap
    wait_for(lambda: l4.rpc.listnodes(l3.info['id'])['nodes'] != [])
    l4.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l4.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})

    # We've done 3 onion calls: sleep now to avoid hitting ratelimit!
    time.sleep(1)

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
    with pytest.raises(RpcError, match="1000.*Already exists, but isn't active"):
        l3.rpc.call('offer', {'amount': '2msat',
                              'description': 'simple test'})

    # Test timeout.
    l3.stop()
    with pytest.raises(RpcError, match='Timeout waiting for response'):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'timeout': 10})


def test_fetchinvoice_recurrence(node_factory, bitcoind):
    """Test for our recurrence extension"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts={'experimental-offers': None})

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


def test_fetchinvoice_autoconnect(node_factory, bitcoind):
    """We should autoconnect if we need to, to route."""

    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     # No onion_message support in l1
                                     opts=[{'dev-force-features': -39},
                                           {'experimental-offers': None,
                                            'dev-allow-localhost': None}])

    l3 = node_factory.get_node(options={'experimental-offers': None})
    l3.rpc.connect(l1.info['id'], 'localhost', l1.port)
    wait_for(lambda: l3.rpc.listnodes(l2.info['id'])['nodes'] != [])

    offer = l2.rpc.call('offer', {'amount': '2msat',
                                  'description': 'simple test'})
    l3.rpc.call('fetchinvoice', {'offer': offer['bolt12']})
    assert l3.rpc.listpeers(l2.info['id'])['peers'] != []

    # Similarly for an invoice_request.
    l3.rpc.disconnect(l2.info['id'])
    invreq = l2.rpc.call('invoicerequest', {'amount': '2msat',
                                            'description': 'simple test'})
    # Ofc l2 can't actually pay it!
    with pytest.raises(RpcError, match='pay attempt failed: "Ran out of routes to try'):
        l3.rpc.call('sendinvoice', {'invreq': invreq['bolt12'], 'label': 'payme!'})

    assert l3.rpc.listpeers(l2.info['id'])['peers'] != []

    # But if we create a channel l3->l1->l2 (and balance!), l2 can!
    node_factory.join_nodes([l3, l1], wait_for_announce=True)
    # Make sure l2 knows about it
    wait_for(lambda: l2.rpc.listnodes(l3.info['id'])['nodes'] != [])

    l3.rpc.pay(l2.rpc.invoice(FUNDAMOUNT * 500, 'balancer', 'balancer')['bolt11'])
    # Make sure l2 has capacity (can be still resolving!).
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['spendable_msat'] != Millisatoshi(0))

    l3.rpc.disconnect(l2.info['id'])
    l3.rpc.call('sendinvoice', {'invreq': invreq['bolt12'], 'label': 'payme for real!'})
    # It will have autoconnected, to send invoice (since l1 says it doesn't do onion messages!)
    assert l3.rpc.listpeers(l2.info['id'])['peers'] != []


def test_fetchinvoice_disconnected_reply(node_factory, bitcoind):
    """We ask for invoice, but reply path doesn't lead directly from recipient"""
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts={'experimental-offers': None,
                                              'may_reconnect': True,
                                              'dev-no-reconnect': None,
                                              'dev-allow-localhost': None})
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Make l1, l2 public (so l3 can auto connect).
    node_factory.join_nodes([l1, l2], wait_for_announce=True)
    # Make sure l3 knows about l1's public address
    wait_for(lambda: ['addresses' in n for n in l3.rpc.listnodes()['nodes']] == [True] * 2)

    offer = l3.rpc.offer(amount='5msat', description='test_fetchinvoice_disconnected_reply')

    # l2 is already connected to l3, so it can fetch.  It specifies a reply
    # path of l1->l2.  l3 knows it can simply route reply to l1 via l2.
    l2.rpc.fetchinvoice(offer=offer['bolt12'], dev_reply_path=[l1.info['id'], l2.info['id']])
    assert l3.rpc.listpeers(l1.info['id']) == {'peers': []}


def test_pay_blockheight_mismatch(node_factory, bitcoind):
    """Test that we can send a payment even if not caught up with the chain.

    We removed the requirement for the node to be fully synced up with
    the blockchain in v24.05, allowing us to send a payment while still
    processing blocks. This test pins the sender at a lower height,
    but `getnetworkinfo` still reports the correct height. Since CLTV
    computations are based on headers and not our own sync height, the
    recipient should still be happy with the parameters we chose.

    """

    send, direct, recv = node_factory.line_graph(3, wait_for_announce=True)
    sync_blockheight(bitcoind, [send, recv])

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

    send.daemon.rpcproxy.mock_rpc('getblockhash', mock_getblockhash)
    bitcoind.generate_block(100)

    sync_blockheight(bitcoind, [recv])

    inv = recv.rpc.invoice(42, 'lbl', 'desc')['bolt11']
    send.rpc.pay(inv)

    # The direct_override payment modifier does some trickery on the
    # route calculation, so we better ensure direct payments still
    # work correctly.
    inv = direct.rpc.invoice(13, 'lbl', 'desc')['bolt11']
    send.rpc.pay(inv)


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


def test_sendinvoice(node_factory, bitcoind):
    l2opts = {'experimental-offers': None}
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts=[{'experimental-offers': None},
                                           l2opts])

    # Simple offer to send money (balances channel a little)
    invreq = l1.rpc.call('invoicerequest', {'amount': '100000sat',
                                            'description': 'simple test'})

    # Fetchinvoice will refuse, since it's not an offer.
    with pytest.raises(RpcError, match='unexpected prefix lnr'):
        l2.rpc.call('fetchinvoice', {'offer': invreq['bolt12']})

    # Pay will refuse, since it's not an invoice.
    with pytest.raises(RpcError, match='unexpected prefix lnr'):
        l2.rpc.call('fetchinvoice', {'offer': invreq['bolt12']})

    # used will be false
    assert only_one(l1.rpc.call('listinvoicerequests', [invreq['invreq_id']])['invoicerequests'])['used'] is False

    # sendinvoice should work.
    out = l2.rpc.call('sendinvoice', {'invreq': invreq['bolt12'],
                                      'label': 'test sendinvoice 1'})
    assert out['label'] == 'test sendinvoice 1'
    assert out['description'] == 'simple test'
    assert 'bolt12' in out
    assert 'payment_hash' in out
    assert out['status'] == 'paid'
    assert 'payment_preimage' in out
    assert 'expires_at' in out
    assert out['amount_msat'] == Millisatoshi(100000000)
    assert 'pay_index' in out
    assert out['amount_received_msat'] == Millisatoshi(100000000)

    # Note, if we're slow, this fails with "Offer no longer available",
    # *but* if it hasn't heard about payment success yet, l2 will fail
    # simply because payments are already pending.
    with pytest.raises(RpcError, match='no longer available|pay attempt failed'):
        l2.rpc.call('sendinvoice', {'invreq': invreq['bolt12'],
                                    'label': 'test sendinvoice 2'})

    # Technically, l1 may not have gotten payment success, so we need to wait.
    wait_for(lambda: only_one(l1.rpc.call('listinvoicerequests', [invreq['invreq_id']])['invoicerequests'])['used'] is True)

    # Offer with issuer: we must copy issuer into our invoice!
    invreq = l1.rpc.call('invoicerequest', {'amount': '10000sat',
                                            'description': 'simple test',
                                            'issuer': "clightning test suite"})

    out = l2.rpc.call('sendinvoice', {'invreq': invreq['bolt12'],
                                      'label': 'test sendinvoice 3'})
    assert out['label'] == 'test sendinvoice 3'
    assert out['description'] == 'simple test'
    assert 'issuer' not in out
    assert 'bolt12' in out
    assert 'payment_hash' in out
    assert out['status'] == 'paid'
    assert 'payment_preimage' in out
    assert 'expires_at' in out
    assert out['amount_msat'] == Millisatoshi(10000000)
    assert 'pay_index' in out
    assert out['amount_received_msat'] == Millisatoshi(10000000)


def test_sendinvoice_blindedpath(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts=[{},
                                           {'experimental-offers': None}])
    # We join l3->l1->l2 so l3 can pay invoice sent by l2.
    l3 = node_factory.get_node(options={'experimental-offers': None})
    node_factory.join_nodes([l3, l1], announce_channels=False)

    # Make sure l3 knows l1, l2 is public, so it will create blinded path to it.
    wait_for(lambda: ['alias' in n for n in l3.rpc.listnodes()['nodes']] == [True, True])

    invreq1 = l3.rpc.invoicerequest(amount='100000sat',
                                    description='test_sendinvoice_blindedpath')
    decode = l1.rpc.decode(invreq1['bolt12'])
    assert len(decode['invreq_paths']) == 1
    assert decode['invreq_paths'][0]['first_node_id'] == l1.info['id']

    l2.rpc.sendinvoice(invreq=invreq1['bolt12'], label='test_sendinvoice_blindedpath 1')


def test_self_pay(node_factory):
    """Repro test for issue 4345: pay ourselves via the pay plugin.

    """
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    inv = l1.rpc.invoice(10000, 'test', 'test')['bolt11']
    l1.rpc.pay(inv)

    # We can pay twice, no problem!
    l1.rpc.pay(inv)

    inv2 = l1.rpc.invoice(10000, 'test2', 'test2')['bolt11']
    l1.rpc.delinvoice('test2', 'unpaid')

    with pytest.raises(RpcError, match=r'Unknown invoice') as excinfo:
        l1.rpc.pay(inv2)
    assert excinfo.value.error['code'] == 203


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
        decoded = l1.rpc.decode(invoice)
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
    scid12 = first_scid(l1, l2)
    l3 = node_factory.get_node()
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid23, _ = l2.fundchannel(l3, 1000000, announce_channel=False)
    # Make sure l3 sees l1->l2 channel.
    l3.wait_channel_active(scid12)

    inv = l3.rpc.invoice(10, "test", "test")['bolt11']
    decoded = l3.rpc.decode(inv)
    assert(only_one(only_one(decoded['routes']))['short_channel_id']
           == only_one(l3.rpc.listpeerchannels()['channels'])['alias']['remote'])

    l3.stop()
    with pytest.raises(RpcError, match=r'Destination .* is not reachable directly and all routehints were unusable'):
        l2.rpc.pay(inv)


def test_setchannel_enforcement_delay(node_factory, bitcoind):
    # Fees start at 1msat + 1%
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts={'fee-base': 1,
                                               'fee-per-satoshi': 10000})

    chanid1 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    chanid2 = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['short_channel_id']

    route = [{'amount_msat': 1011,
              'id': l2.info['id'],
              'delay': 20,
              'channel': chanid1},
             {'amount_msat': 1000,
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
    l2.rpc.setchannel("all", 2, 10000, enforcedelay=0)

    inv = l3.rpc.invoice(1000, "test2", "test2")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'WIRE_FEE_INSUFFICIENT'):
        l1.rpc.waitsendpay(inv['payment_hash'])

    # Test increased amount.
    route[0]['amount_msat'] += 1
    inv = l3.rpc.invoice(1000, "test3", "test3")
    l1.rpc.sendpay(route,
                   payment_hash=inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    # Now, give us 30 seconds please.
    l2.rpc.setchannel("all", 3, 10000, enforcedelay=30)
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
    """`listpays` should be smart enough to group repeated `pay` calls.

    We always use slightly decreasing values for the payment, in order
    to avoid having to adjust the channel_hints that are being
    remembered across attempts. In case of a failure the
    `channel_hint` will be `attempted amount - 1msat` so use that as
    the next payment's amount.

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

    inv = l3.rpc.invoice(amount_msat='any', label='lbl1', description='desc')['bolt11']
    l3.stop()  # Stop recipient so the first attempt fails

    assert(len(l1.db.query("SELECT * FROM payments")) == 0)
    assert(len(l1.rpc.listpays()['pays']) == 0)

    with pytest.raises(RpcError, match=r'Ran out of routes to try after [1-9]+ attempts'):
        l1.rpc.pay(inv, amount_msat='100002msat')

    # After this one invocation we have one entry in `listpays`
    assert(len(l1.rpc.listpays()['pays']) == 1)

    # Pay learns, and sometimes now refuses to even attempt.  Give it a new channel.
    l3.start()
    node_factory.join_nodes([l2, l3], wait_for_announce=True)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 6)
    l3.stop()

    with pytest.raises(RpcError, match=r'Ran out of routes to try after [1-9]+ attempts'):
        l1.rpc.pay(inv, amount_msat='100001msat')

    # Surprise: we should have 2 entries after 2 invocations
    assert(len(l1.rpc.listpays()['pays']) == 2)

    l3.start()
    invoices = l3.rpc.listinvoices()['invoices']
    assert(len(invoices) == 1)
    assert(invoices[0]['status'] == 'unpaid')
    # Will reconnect automatically
    wait_for(lambda: only_one(l3.rpc.listpeers()['peers'])['connected'] is True)
    scid = l3.rpc.listpeerchannels()['channels'][0]['short_channel_id']
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(scid)['channels']] == [True, True])
    l1.rpc.pay(inv, amount_msat='10000msat')

    # And finally we should have all 3 attempts to pay the invoice
    pays = l1.rpc.listpays()['pays']
    assert(len(pays) == 3)
    assert([p['status'] for p in pays] == ['failed', 'failed', 'complete'])


def test_pay_manual_exclude(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)
    l1_id = l1.rpc.getinfo()['id']
    l2_id = l2.rpc.getinfo()['id']
    l3_id = l3.rpc.getinfo()['id']
    chan12 = l1.rpc.listpeerchannels(l2_id)['channels'][0]
    chan23 = l2.rpc.listpeerchannels(l3_id)['channels'][0]
    scid12 = chan12['short_channel_id'] + '/' + str(chan12['direction'])
    scid23 = chan23['short_channel_id'] + '/' + str(chan23['direction'])
    inv = l3.rpc.invoice(amount_msat=123000, label='label1', description='desc')['bolt11']
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


@unittest.skipIf(TEST_NETWORK != 'regtest', "Invoice is network specific")
def test_pay_bolt11_metadata(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2)

    # BOLT #11:
    # > ### Please send 0.01 BTC with payment metadata 0x01fafaf0
    # > lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc

    b11 = l1.rpc.decode('lnbc10m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdp9wpshjmt9de6zqmt9w3skgct5vysxjmnnd9jx2mq8q8a04uqsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9q2gqqqqqqsgq7hf8he7ecf7n4ffphs6awl9t6676rrclv9ckg3d3ncn7fct63p6s365duk5wrk202cfy3aj5xnnp5gs3vrdvruverwwq7yzhkf5a3xqpd05wjc')
    assert b11['payment_metadata'] == '01fafaf0'

    # I previously hacked lightningd to add "this is metadata" to metadata.
    # After CI started failing, I *also* hacked it to set expiry to BIGNUM.
    inv = "lnbcrt1230n1p3yzgcxsp5q8g040f9rl9mu2unkjuj0vn262s6nyrhz5hythk3ueu2lfzahmzspp5ve584t0cv27hwmy0cx9ca8uwyqyfw9y9dm3r8vus9fv36r2l9yjsdq8v3jhxccmq6w35xjueqd9ejqmt9w3skgct5vyxqxra2q2qcqp99q2sqqqqqysgqfw6efxpzk5x5vfj8se46yg667x5cvhyttnmuqyk0q7rmhx3gs249qhtdggnek8c5adm2pztkjddlwyn2art2zg9xap2ckczzl3fzz4qqsej6mf"
    # Make l2 "know" about this invoice.
    l2.rpc.invoice(amount_msat=123000, label='label1', description='desc', preimage='00' * 32)

    with pytest.raises(RpcError, match=r'WIRE_INVALID_ONION_PAYLOAD'):
        l1.rpc.pay(inv)

    l2.daemon.wait_for_log("Unexpected payment_metadata {}".format(b'this is metadata'.hex()))


def test_pay_middle_fail(node_factory, bitcoind, executor):
    """Test the case where a HTLC is failed, but not on peer's side, then
    we go onchain"""
    # Set feerates the same so we don't have update_fee interfering.
    # We want to disconnect on revoke-and-ack we send for failing htlc.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{'feerates': (1500,) * 4},
                                               {'feerates': (1500,) * 4},
                                               {'feerates': (1500,) * 4,
                                                'disconnect': ['-WIRE_REVOKE_AND_ACK*2']}])

    chanid12 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    chanid23 = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['short_channel_id']

    # Make a failing payment.
    route = [{'amount_msat': 1011,
              'id': l2.info['id'],
              'delay': 20,
              'channel': chanid12},
             {'amount_msat': 1000,
              'id': l3.info['id'],
              'delay': 10,
              'channel': chanid23}]

    # Start payment, it will fail.
    l1.rpc.sendpay(route, payment_hash='00' * 32)

    wait_for(lambda: only_one(l3.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)

    # After this (cltv is actually +11, and we give it 1 block grace)
    # l2 will go onchain since HTLC is not resolved.
    bitcoind.generate_block(12)
    sync_blockheight(bitcoind, [l1, l2, l3])
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['state'] == 'AWAITING_UNILATERAL')

    # Three blocks and it will resolve the parent.
    bitcoind.generate_block(3, wait_for_mempool=1)

    # And that will fail upstream
    with pytest.raises(RpcError, match=r'WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        l1.rpc.waitsendpay('00' * 32)


@unittest.skipIf(TEST_NETWORK != 'regtest', "Invoice is network specific")
@pytest.mark.slow_test
def test_payerkey(node_factory):
    """payerkey calculation should not change across releases!"""
    nodes = node_factory.get_nodes(7)

    expected_keys = ["035e43e4ec029ee6cc0e320ebefdf863bc0f284ec0208275f780837d17e21bba32",
                     "02411811b24f4940de49ad460ee14ecb96810e29ca49cdd3600a985da2eda06b87",
                     "036a19f00424ff244af1841715e89f3716c08f1f62a8e5d9bd0f69a21aa96a7b8d",
                     "026d8b82fe6039fe16f8ef376174b630247e821331b90620315a1e9c3db8384056",
                     "0393fb950e04916c063a585aa644df3d72642c16de4eb44ccf5dbede194836140f",
                     "030b68257230f7057e694222bbd54d9d108decced6b647a90da6f578360af53f7d",
                     "02f402bd7374a1304b07c7236d9c683b83f81072517195ddede8ab328026d53157"]

    bolt12tool = os.path.join(os.path.dirname(__file__), "..", "devtools", "bolt12-cli")

    # Returns "lnr <hexstring>" on first line
    hexprefix = subprocess.check_output([bolt12tool, 'decodehex',
                                         'lnr1qqgz2d7u2smys9dc5q2447e8thjlgq3qqc3xu3s3rg94nj40zfsy866mhu5vxne6tcej5878k2mneuvgjy8ssqvepgz5zsjrg3z3vggzvkm2khkgvrxj27r96c00pwl4kveecdktm29jdd6w0uwu5jgtv5v9qgqxyfhyvyg6pdvu4tcjvpp7kkal9rp57wj7xv4pl3ajku70rzy3pu']).decode('UTF-8').split('\n')[0].split()

    # Now we are supposed to put invreq_payer_id inside invreq, and lightningd
    # checks the derivation as a courtesy.  Fortunately, invreq_payer_id is last
    for n, k in zip(nodes, expected_keys):
        # BOLT-offers #12:
        #     1. type: 88 (`invreq_payer_id`)
        #     2. data:
        #        * [`point`:`key`]
        encoded = subprocess.check_output([bolt12tool, 'encodehex'] + hexprefix + ['5821', k]).decode('UTF-8').strip()
        n.rpc.createinvoicerequest(encoded, False)['bolt12']


def test_pay_multichannel_use_zeroconf(bitcoind, node_factory):
    """Check that we use the zeroconf direct channel to pay when we need to"""
    # 0. Setup normal channel, 200k sats.
    zeroconf_plugin = Path(__file__).parent / "plugins" / "zeroconf-selective.py"
    l1, l2 = node_factory.line_graph(2, wait_for_announce=False,
                                     fundamount=200_000,
                                     opts=[{},
                                           {'plugin': zeroconf_plugin,
                                            'zeroconf-allow': 'any'}])

    # 1. Open a zeoconf channel l1 -> l2
    zeroconf_sats = 1_000_000

    # 1.1 Add funds to l1's wallet for the channel open
    l1.fundwallet(zeroconf_sats * 2)  # This will mine a block!
    sync_blockheight(bitcoind, [l1, l2])

    # 1.2 Open the zeroconf channel
    l1.rpc.fundchannel(l2.info['id'], zeroconf_sats, announce=False, mindepth=0)

    # 1.3 Wait until all channels active.
    wait_for(lambda: all([c['state'] == 'CHANNELD_NORMAL' for c in l1.rpc.listpeerchannels()['channels'] + l2.rpc.listpeerchannels()['channels']]))

    # 2. Have l2 generate an invoice to be paid
    invoice_sats = "500000sat"
    inv = l2.rpc.invoice(invoice_sats, "test", "test")

    # 3. Send a payment over the zeroconf channel
    riskfactor = 0
    l1.rpc.pay(inv['bolt11'], riskfactor=riskfactor)


def test_delpay_works(node_factory, bitcoind):
    """
    One failure, one success; deleting the success works (groupid=1, partid=2)
    """
    l1, l2, l3 = node_factory.line_graph(3, fundamount=10**5,
                                         wait_for_announce=True)
    # Expensive route!
    l4 = node_factory.get_node(options={'fee-per-satoshi': 1000,
                                        'fee-base': 2000})
    node_factory.join_nodes([l1, l4, l3], wait_for_announce=True)

    # Don't give a hint, so l1 chooses cheapest.
    inv = l3.dev_invoice(10**5, 'lbl', 'desc', dev_routes=[])
    l3.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.pay(inv['bolt11'])

    assert len(l1.rpc.listsendpays()['payments']) == 2
    failed = [p for p in l1.rpc.listsendpays()['payments'] if p['status'] == 'complete'][0]
    l1.rpc.delpay(payment_hash=failed['payment_hash'],
                  status=failed['status'],
                  groupid=failed['groupid'],
                  partid=failed['partid'])

    with pytest.raises(RpcError, match=r'No payment for that payment_hash'):
        l1.rpc.delpay(payment_hash=failed['payment_hash'],
                      status=failed['status'],
                      groupid=failed['groupid'],
                      partid=failed['partid'])


def test_fetchinvoice_with_no_quantity(node_factory):
    """
    Reproducer for https://github.com/ElementsProject/lightning/issues/6089

    The issue is when the offer has the quantity_max and the parameter.

    In particular, in the fetchinvoice we forget to map the
    quantity parameter with the invoice request quantity field.
    """
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts={'experimental-offers': None})
    offer1 = l2.rpc.call('offer', {'amount': '2msat',
                                   'description': 'simple test',
                                   'quantity_max': 10})

    assert offer1['created'] is True, f"offer created is {offer1['created']}"

    with pytest.raises(RpcError, match="quantity parameter required"):
        l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12']})

    inv = l1.rpc.call('fetchinvoice', {'offer': offer1['bolt12'], 'quantity': 2})
    inv = inv['invoice']
    decode_inv = l2.rpc.decode(inv)
    assert decode_inv['invreq_quantity'] == 2, f'`invreq_quantity` in the invoice did not match, received {decode_inv["quantity"]}, expected 2'


def test_invoice_pay_desc_with_quotes(node_factory):
    """Test that we can decode and pay invoice where hashed description contains double quotes"""
    l1, l2 = node_factory.line_graph(2, opts={'allow-deprecated-apis': True})
    description = '[["text/plain","Funding @odell on stacker.news"],["text/identifier","odell@stacker.news"]]'

    invoice = l2.rpc.invoice(label="test12345", amount_msat=1000,
                             description=description, deschashonly=True)["bolt11"]

    l1.rpc.decodepay(invoice, description)

    # pay an invoice
    l1.rpc.pay(invoice, description=description)


def test_self_sendpay(node_factory):
    """We get much more descriptive errors from a self-payment than a remote payment, since we're not relying on a single WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS but can share more useful information"""
    l1 = node_factory.get_node()

    inv = l1.rpc.invoice('100000sat', 'test_selfpay', "Test of payment to self")
    assert only_one(l1.rpc.listinvoices()['invoices'])['status'] == 'unpaid'
    inv_expires = l1.rpc.invoice('1btc', 'test_selfpay-expires', "Test of payment to self", expiry=1)

    # Requires amount.
    with pytest.raises(RpcError, match="Self-payment requires amount_msat"):
        l1.rpc.sendpay([], inv['payment_hash'], label='selfpay', bolt11=inv['bolt11'], payment_secret=inv['payment_secret'])

    # Requires non-zero partid.
    with pytest.raises(RpcError, match=r"Self-payment does not allow \(non-zero\) partid"):
        l1.rpc.sendpay([], inv['payment_hash'], label='selfpay', bolt11=inv['bolt11'], payment_secret=inv['payment_secret'], amount_msat='100000sat', partid=1)

    # Bad payment_hash.
    with pytest.raises(RpcError, match="Unknown invoice"):
        l1.rpc.sendpay([], '00' * 32, label='selfpay-badimage', bolt11=inv['bolt11'], payment_secret=inv['payment_secret'], amount_msat='100000sat')

    # Missing payment_secret
    with pytest.raises(RpcError, match="Attempt to pay .* without secret"):
        l1.rpc.sendpay([], inv['payment_hash'], label='selfpay-badimage', bolt11=inv['bolt11'], amount_msat='100000sat')

    # Bad payment_secret
    with pytest.raises(RpcError, match="Attempt to pay .* with wrong payment_secret"):
        l1.rpc.sendpay([], inv['payment_hash'], label='selfpay-badimage', bolt11=inv['bolt11'], payment_secret='00' * 32, amount_msat='100000sat')

    # Expired
    time.sleep(2)
    with pytest.raises(RpcError, match="Already paid or expired invoice"):
        l1.rpc.sendpay([], inv_expires['payment_hash'], label='selfpay-badimage', bolt11=inv_expires['bolt11'], payment_secret=inv['payment_secret'], amount_msat='1btc')

    # This one works!
    l1.rpc.sendpay([], inv['payment_hash'], label='selfpay', bolt11=inv['bolt11'], payment_secret=inv['payment_secret'], amount_msat='100000sat')

    assert only_one(l1.rpc.listinvoices(payment_hash=inv['payment_hash'])['invoices'])['status'] == 'paid'
    # Only one is complete.
    assert [p['status'] for p in l1.rpc.listsendpays()['payments'] if p['status'] != 'failed'] == ['complete']

    # Can't pay paid one already paid!
    with pytest.raises(RpcError, match="Already paid or expired invoice"):
        l1.rpc.sendpay([], inv['payment_hash'], label='selfpay', bolt11=inv['bolt11'], payment_secret=inv['payment_secret'], amount_msat='100000sat')


def test_strip_lightning_suffix_from_inv(node_factory):
    """
    Reproducer for [1] that pay an invoice with the `lightning:<bolt11|bolt12>`
    prefix and then, will check if core lightning is able to strip it during
    list `listpays` command.

    [1] https://github.com/ElementsProject/lightning/issues/6207
    """
    l1, l2 = node_factory.line_graph(2)
    inv = l2.rpc.invoice(40, "strip-lightning-prefix", "test to be able to strip the `lightning:` prefix.")["bolt11"]
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    # Testing the prefix stripping case
    l1.rpc.pay(f"lightning:{inv}")
    listpays = l1.rpc.listpays()["pays"]
    assert len(listpays) == 1, f"the list pays is bigger than what we expected {listpays}"
    # we can access by index here because the payment are sorted by db idx
    assert listpays[0]['bolt11'] == inv, f"list pays contains a different invoice, expected is {inv} but we get {listpays[0]['bolt11']}"

    # Testing the case of the invoice is upper case
    inv = l2.rpc.invoice(40, "strip-lightning-prefix-upper-case", "test to be able to strip the `lightning:` prefix with an upper case invoice.")["bolt11"]
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    # Testing the prefix stripping with an invoice in upper case case
    l1.rpc.pay(f"lightning:{inv.upper()}")
    listpays = l1.rpc.listpays()["pays"]
    assert len(listpays) == 2, f"the list pays is bigger than what we expected {listpays}"
    assert listpays[1]['bolt11'] == inv, f"list pays contains a different invoice, expected is {inv} but we get {listpays[0]['bolt11']}"

    # Testing the string lowering of an invoice in upper case
    # Testing the case of the invoice is upper case
    inv = l2.rpc.invoice(40, "strip-lightning-upper-case", "test to be able to lower the invoice string.")["bolt11"]
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    l1.rpc.pay(inv.upper())
    listpays = l1.rpc.listpays()["pays"]
    assert len(listpays) == 3, f"the list pays is bigger than what we expected {listpays}"
    assert listpays[2]['bolt11'] == inv, f"list pays contains a different invoice, expected is {inv} but we get {listpays[0]['bolt11']}"


def test_listsendpays_crash(node_factory):
    l1 = node_factory.get_node()

    inv = l1.rpc.invoice(40, "inv", "inv")["bolt11"]
    l1.rpc.listsendpays('lightning:' + inv)


def test_sendpays_wait(node_factory, executor):
    l1, l2 = node_factory.line_graph(2)

    waitres = l1.rpc.wait(subsystem='sendpays', indexname='created', nextvalue=0)
    assert waitres == {'subsystem': 'sendpays',
                       'created': 0}

    # Now ask for 1.
    waitfut = executor.submit(l1.rpc.wait, subsystem='sendpays', indexname='created', nextvalue=1)
    time.sleep(1)

    inv1 = l2.rpc.invoice(42, 'invlabel', 'invdesc')
    l1.rpc.pay(inv1['bolt11'])

    waitres = waitfut.result(TIMEOUT)
    assert waitres == {'subsystem': 'sendpays',
                       'created': 1,
                       'details': {'status': 'pending',
                                   'partid': 0,
                                   'groupid': 1,
                                   'payment_hash': inv1['payment_hash']}}
    assert only_one(l1.rpc.listsendpays(bolt11=inv1['bolt11'])['payments'])['created_index'] == 1
    assert only_one(l1.rpc.listsendpays(bolt11=inv1['bolt11'])['payments'])['updated_index'] == 1

    # Second returns instantly, without any details.
    waitres = l1.rpc.wait(subsystem='sendpays', indexname='created', nextvalue=1)
    assert waitres == {'subsystem': 'sendpays',
                       'created': 1}

    # Now for updates
    waitres = l1.rpc.wait(subsystem='sendpays', indexname='updated', nextvalue=0)
    assert waitres == {'subsystem': 'sendpays',
                       'updated': 1}

    inv2 = l2.rpc.invoice(42, 'invlabel2', 'invdesc2')

    waitfut = executor.submit(l1.rpc.wait, subsystem='sendpays', indexname='updated', nextvalue=2)
    time.sleep(1)
    l1.rpc.pay(inv2['bolt11'])
    waitres = waitfut.result(TIMEOUT)
    assert waitres == {'subsystem': 'sendpays',
                       'updated': 2,
                       'details': {'status': 'complete',
                                   'partid': 0,
                                   'groupid': 1,
                                   'payment_hash': inv2['payment_hash']}}
    assert only_one(l1.rpc.listsendpays(bolt11=inv2['bolt11'])['payments'])['created_index'] == 2
    assert only_one(l1.rpc.listsendpays(bolt11=inv2['bolt11'])['payments'])['updated_index'] == 2

    # Second returns instantly, without any details.
    waitres = l1.rpc.wait(subsystem='sendpays', indexname='updated', nextvalue=2)
    assert waitres == {'subsystem': 'sendpays',
                       'updated': 2}

    # Now check failure.
    inv3 = l2.rpc.invoice(42, 'invlabel3', 'invdesc3')
    l2.rpc.delinvoice('invlabel3', 'unpaid')

    waitfut = executor.submit(l1.rpc.wait, subsystem='sendpays', indexname='updated', nextvalue=3)
    time.sleep(1)
    with pytest.raises(RpcError, match="WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"):
        l1.rpc.pay(inv3['bolt11'])

    waitres = waitfut.result(TIMEOUT)
    assert waitres == {'subsystem': 'sendpays',
                       'updated': 3,
                       'details': {'status': 'failed',
                                   'partid': 0,
                                   'groupid': 1,
                                   'payment_hash': inv3['payment_hash']}}

    # Order and pagination.
    assert [(p['created_index'], p['bolt11']) for p in l1.rpc.listsendpays(index='created')['payments']] == [(1, inv1['bolt11']), (2, inv2['bolt11']), (3, inv3['bolt11'])]
    assert [(p['created_index'], p['bolt11']) for p in l1.rpc.listsendpays(index='created', start=2)['payments']] == [(2, inv2['bolt11']), (3, inv3['bolt11'])]
    assert [(p['created_index'], p['bolt11']) for p in l1.rpc.listsendpays(index='created', limit=2)['payments']] == [(1, inv1['bolt11']), (2, inv2['bolt11'])]

    # We can also filter by status.
    assert [(p['created_index'], p['bolt11']) for p in l1.rpc.listsendpays(status='failed', index='created', limit=2)['payments']] == [(3, inv3['bolt11'])]

    assert [(p['updated_index'], p['bolt11']) for p in l1.rpc.listsendpays(index='updated')['payments']] == [(1, inv1['bolt11']), (2, inv2['bolt11']), (3, inv3['bolt11'])]

    # Finally, check deletion.
    waitres = l1.rpc.wait(subsystem='sendpays', indexname='deleted', nextvalue=0)
    assert waitres == {'subsystem': 'sendpays',
                       'deleted': 0}

    waitfut = executor.submit(l1.rpc.wait, subsystem='sendpays', indexname='deleted', nextvalue=1)
    time.sleep(1)

    l1.rpc.delpay(inv3['payment_hash'], 'failed', 0, 1)

    waitres = waitfut.result(TIMEOUT)
    assert waitres == {'subsystem': 'sendpays',
                       'deleted': 1,
                       'details': {'status': 'failed',
                                   'partid': 0,
                                   'groupid': 1,
                                   'payment_hash': inv3['payment_hash']}}


def test_pay_routehint_minhtlc(node_factory, bitcoind):
    # l1 -> l2 -> l3 private -> l4
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)
    l4 = node_factory.get_node()

    scid34, _ = l3.fundchannel(l4, announce_channel=False)

    # l2->l3 required htlc of at least 1sat
    scid = only_one(l2.rpc.setchannel(l3.info['id'], htlcmin=1000)['channels'])['short_channel_id']

    # Make sure l4 knows about l1
    wait_for(lambda: l4.rpc.listnodes(l1.info['id'])['nodes'] != [])

    # And make sure l1 knows that l2->l3 has htlcmin 1000
    wait_for(lambda: l1.rpc.listchannels(scid)['channels'][0]['htlc_minimum_msat'] == Millisatoshi(1000))

    inv = l4.rpc.invoice(100000, "inv", "inv")
    assert only_one(l1.rpc.decode(inv['bolt11'])['routes'])

    # You should be able to pay the invoice!
    l1.rpc.pay(inv['bolt11'])

    # And you should also be able to getroute (and have it ignore htlc_min/max constraints!)
    l1.rpc.getroute(l3.info['id'], amount_msat=0, riskfactor=1)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_pay_partial_msat(node_factory, executor):
    l1, l2, l3 = node_factory.line_graph(3)

    inv = l3.rpc.invoice(100000000, "inv", "inv")

    with pytest.raises(RpcError, match="partial_msat must be less or equal to total amount 10000000"):
        l2.rpc.pay(inv['bolt11'], partial_msat=100000001)

    # This will fail with an MPP timeout.
    with pytest.raises(RpcError, match="failed: WIRE_MPP_TIMEOUT"):
        l2.rpc.pay(inv['bolt11'], partial_msat=90000000)

    # This will work like normal.
    l2.rpc.pay(inv['bolt11'], partial_msat=100000000)

    # Make sure l3 can pay to l2 now.
    wait_for(lambda: only_one(l3.rpc.listpeerchannels()['channels'])['spendable_msat'] > 1001)

    # Now we can combine together to pay l2:
    inv = l2.rpc.invoice('any', "inv", "inv")

    # If we specify different totals, this *won't work*
    l1pay = executor.submit(l1.rpc.pay, inv['bolt11'], amount_msat=10000, partial_msat=9000)
    l3pay = executor.submit(l3.rpc.pay, inv['bolt11'], amount_msat=10001, partial_msat=1001)

    # BOLT #4:
    # - SHOULD fail the entire HTLC set if `total_msat` is not
    #   the same for all HTLCs in the set.
    with pytest.raises(RpcError, match="failed: WIRE_FINAL_INCORRECT_HTLC_AMOUNT"):
        l3pay.result(TIMEOUT)
    with pytest.raises(RpcError, match="failed: WIRE_FINAL_INCORRECT_HTLC_AMOUNT"):
        l1pay.result(TIMEOUT)

    # But same amount, will combine forces!
    l1pay = executor.submit(l1.rpc.pay, inv['bolt11'], amount_msat=10000, partial_msat=9000)
    l3pay = executor.submit(l3.rpc.pay, inv['bolt11'], amount_msat=10000, partial_msat=1000)

    l1pay.result(TIMEOUT)
    l3pay.result(TIMEOUT)


def test_blindedpath_privchan(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts={'experimental-offers': None,
                                           'may_reconnect': True})
    l3 = node_factory.get_node(options={'experimental-offers': None,
                                        'cltv-final': 120},
                               may_reconnect=True)

    # Private channel.
    node_factory.join_nodes([l2, l3], announce_channels=False)
    # Make sure l3 knows about l1-l2, so will add route hint.
    wait_for(lambda: l3.rpc.listnodes(l1.info['id']) != {'nodes': []})

    offer = l3.rpc.offer(1000, 'test_pay_blindedpath_privchan')
    l1.rpc.decode(offer['bolt12'])

    inv = l2.rpc.fetchinvoice(offer['bolt12'])
    decode = l1.rpc.decode(inv['invoice'])
    assert len(decode['invoice_paths']) == 1
    assert decode['invoice_paths'][0]['first_node_id'] == l2.info['id']

    # Carla points out that the path's cltv_expiry_delta *includes*
    # the final node's final value.
    assert decode['invoice_paths'][0]['payinfo']['cltv_expiry_delta'] == l3.config('cltv-final') + l2.config('cltv-delta')

    l1.rpc.pay(inv['invoice'])

    # Now try when l3 uses scid for entry point of blinded path.
    l3.stop()
    l3.daemon.opts['dev-invoice-bpath-scid'] = None
    l3.start()
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)

    chan = only_one(l1.rpc.listchannels(source=l2.info['id'])['channels'])

    inv = l2.rpc.fetchinvoice(offer['bolt12'])
    decode = l1.rpc.decode(inv['invoice'])
    assert len(decode['invoice_paths']) == 1
    assert 'first_node_id' not in decode['invoice_paths'][0]
    assert decode['invoice_paths'][0]['first_scid'] == chan['short_channel_id']
    assert decode['invoice_paths'][0]['first_scid_dir'] == chan['direction']

    l1.rpc.pay(inv['invoice'])


def test_blinded_reply_path_scid(node_factory):
    """Check that we handle a blinded path which begins with a scid instead of a nodeid"""
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts={'experimental-offers': None})
    offer = l2.rpc.offer(amount='2msat', description='test_blinded_reply_path_scid')

    chan = only_one(l1.rpc.listpeerchannels()['channels'])
    scidd = "{}/{}".format(chan['short_channel_id'], chan['direction'])
    inv = l1.rpc.fetchinvoice(offer=offer['bolt12'], dev_path_use_scidd=scidd)['invoice']

    l1.rpc.pay(inv)


def test_pay_while_opening_channel(node_factory, bitcoind, executor):
    delay_plugin = {'plugin': os.path.join(os.getcwd(),
                                           'tests/plugins/openchannel_hook_delay.py'),
                    'delaytime': '10'}
    l1, l2 = node_factory.line_graph(2, fundamount=10**6, wait_for_announce=True)
    l3 = node_factory.get_node(options=delay_plugin)
    l1.connect(l3)
    executor.submit(l1.rpc.fundchannel, l3.info['id'], 100000)
    wait_for(lambda: l1.rpc.listpeerchannels(l3.info['id'])['channels'] != [])

    # the uncommitted channel should now show up in listpeerchannels
    assert only_one(l1.rpc.listpeerchannels(l3.info['id'])['channels'])['state'] == 'OPENINGD'
    inv = l2.rpc.invoice(10000, "inv", "inv")
    l1.rpc.pay(inv['bolt11'])


def test_offer_paths(node_factory, bitcoind):
    opts = {'experimental-offers': None,
            'dev-allow-localhost': None}

    # Need to announce channels to use their scid in offers anyway!
    l1, l2, l3, l4 = node_factory.line_graph(4,
                                             opts=opts,
                                             wait_for_announce=True)

    chan = only_one(l1.rpc.listpeerchannels()['channels'])
    scidd = "{}/{}".format(chan['short_channel_id'], chan['direction'])
    offer = l2.rpc.offer(amount='100sat', description='test_offer_paths',
                         dev_paths=[[scidd, l2.info['id']],
                                    [l3.info['id'], l2.info['id']]])

    paths = l1.rpc.decode(offer['bolt12'])['offer_paths']
    assert len(paths) == 2
    assert paths[0]['first_scid'] == chan['short_channel_id']
    assert paths[0]['first_scid_dir'] == chan['direction']
    assert paths[1]['first_node_id'] == l3.info['id']

    l5 = node_factory.get_node(options=opts)

    # Get all the gossip, so we have addresses
    l5.rpc.connect(l1.info['id'], 'localhost', l1.port)
    wait_for(lambda: len(l5.rpc.listnodes()['nodes']) == 4 and all(['addresses' in n for n in l5.rpc.listnodes()['nodes']]))

    # We have a path ->l1 (head of blinded path), so we can use that without connecting.
    l5.rpc.fetchinvoice(offer=offer['bolt12'])
    assert not l5.daemon.is_in_log('connecting directly to')

    # Make scid path invalid by closing it
    close = l1.rpc.close(paths[0]['first_scid'])
    bitcoind.generate_block(13, wait_for_mempool=only_one(close['txids']))
    wait_for(lambda: l5.rpc.listchannels(paths[0]['first_scid']) == {'channels': []})

    # Now connect l5->l4, and it will be able to reach l3 via that, and join blinded path.
    l5.rpc.connect(l4.info['id'], 'localhost', l4.port)
    l5.rpc.fetchinvoice(offer=offer['bolt12'])
    assert not l5.daemon.is_in_log('connecting')

    # This will make us connect straight to l3 to use blinded path from there.
    l5.rpc.disconnect(l4.info['id'])
    l5.rpc.fetchinvoice(offer=offer['bolt12'])
    assert l5.daemon.is_in_log('connecting')

    # Restart l5 with fetchinvoice-noconnect and it will fail.
    l5.stop()
    l5.daemon.opts['fetchinvoice-noconnect'] = None
    l5.start()

    with pytest.raises(RpcError, match=f"Failed: could not route or connect directly to blinded path at {l3.info['id']}: fetchinvoice-noconnect set: not initiating a new connection"):
        l5.rpc.fetchinvoice(offer=offer['bolt12'])


def test_pay_legacy_forward(node_factory, bitcoind, executor):
    """We removed legacy in 22.11, and LND will still send them for
    route hints!  See
    https://github.com/lightningnetwork/lnd/issues/8785

    """
    l1, l2, l3 = node_factory.line_graph(3, fundamount=10**6, wait_for_announce=True)

    inv = l3.rpc.invoice(1000, "inv", "inv")

    chanid12 = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['short_channel_id']
    chanid23 = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['short_channel_id']
    route = [{'amount_msat': 1011,
              'id': l2.info['id'],
              'delay': 20,
              'channel': chanid12},
             {'amount_msat': 1000,
              'id': l3.info['id'],
              'delay': 10,
              'channel': chanid23}]

    l1.rpc.call("sendpay", payload={'route': route,
                                    'payment_hash': inv['payment_hash'],
                                    'payment_secret': inv['payment_secret'],
                                    'dev_legacy_hop': True})
    l1.rpc.waitsendpay(inv['payment_hash'])


# CI is so slow under valgrind that this does not reach the ratelimit!
@pytest.mark.slow_test
def test_onionmessage_ratelimit(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False,
                                     opts={'experimental-offers': None,
                                           'allow_warning': True})

    offer = l2.rpc.call('offer', {'amount': '2msat',
                                  'description': 'simple test'})

    # Hopefully we can do this fast enough to reach ratelimit!
    with pytest.raises(RpcError, match="Timeout waiting for response"):
        for _ in range(8):
            l1.rpc.fetchinvoice(offer['bolt12'])

    assert l1.daemon.is_in_log('WARNING: Ratelimited onion_message: exceeded one per 250msec')

    # It will recover though!
    time.sleep(0.250)
    l1.rpc.fetchinvoice(offer['bolt12'])


def test_offer_path_self(node_factory):
    """We can fetch an offer, and pay an invoice which uses a blinded path starting at us"""
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=False,
                                         opts={'experimental-offers': None,
                                               'may_reconnect': True})

    # Private channel from l2->l3, makes l3 add a hint.
    node_factory.join_nodes([l1, l2], wait_for_announce=True)
    node_factory.join_nodes([l2, l3], announce_channels=False)
    wait_for(lambda: ['alias' in n for n in l3.rpc.listnodes()['nodes']] == [True, True])

    # l3 uses l2 as entry point for offer.
    offer = l3.rpc.offer(amount='2msat', description='test_offer_path_self')
    paths = l1.rpc.decode(offer['bolt12'])['offer_paths']
    assert len(paths) == 1
    assert paths[0]['first_node_id'] == l2.info['id']

    # l1 can fetch invoice.
    l1.rpc.fetchinvoice(offer['bolt12'])['invoice']

    # l2 can fetch invoice
    inv = l2.rpc.fetchinvoice(offer['bolt12'])['invoice']

    # And can pay it!
    l2.rpc.pay(inv)

    # We can also handle it if invoice has next hop specified by real scid, or alias.
    scid = only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['alias']['local']

    l3.stop()
    l3.daemon.opts['dev-invoice-internal-scid'] = scid
    l3.start()
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    inv = l2.rpc.fetchinvoice(offer['bolt12'])['invoice']

    # And can pay it!
    l2.rpc.pay(inv)

    # It should have mapped the hop.
    l2.daemon.wait_for_log(f"Mapped decrypted next hop from {scid} -> {l3.info['id']}")


def test_offer_selfpay(node_factory):
    """We can fetch an pay our own offer"""
    l1 = node_factory.get_node(options={'experimental-offers': None})

    offer = l1.rpc.offer(amount='2msat', description='test_offer_path_self')['bolt12']
    inv = l1.rpc.fetchinvoice(offer)['invoice']
    l1.rpc.pay(inv)


def test_decryptencrypteddata(node_factory):
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=False,
                                         opts={'experimental-offers': None})

    # Private channel from l2->l3, makes l3 add a blinded path to invoice
    # (l1's existence makes sure l3 doesn't see l2 as a dead end!)
    node_factory.join_nodes([l1, l2], wait_for_announce=True)
    node_factory.join_nodes([l2, l3], announce_channels=False)
    wait_for(lambda: ['alias' in n for n in l3.rpc.listnodes()['nodes']] == [True, True])

    offer = l3.rpc.offer(amount='2msat', description='test_offer_path_self')
    inv = l2.rpc.fetchinvoice(offer['bolt12'])['invoice']

    decode = l2.rpc.decode(inv)
    path = decode['invoice_paths'][0]
    assert path['first_node_id'] == l2.info['id']
    first_path_key = path['first_path_key']

    encdata1 = path['path'][0]['encrypted_recipient_data']
    # BOLT #4:
    # 1. `tlv_stream`: `encrypted_data_tlv`
    # 2. types:
    # ...
    #     1. type: 4 (`next_node_id`)
    #     2. data:
    #         * [`point`:`node_id`]
    dec = l2.rpc.decryptencrypteddata(encrypted_data=encdata1, path_key=first_path_key)['decryptencrypteddata']
    assert dec['decrypted'].startswith('0421' + l3.info['id'])


def test_offer_experimental_fields(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None})

    # Append experimental type 1000000001, length 1
    offer = l1.rpc.offer(amount='2msat', description='test_offer_path_self')['bolt12']
    bolt12tool = os.path.join(os.path.dirname(__file__), "..", "devtools", "bolt12-cli")
    # Returns HRP and hex
    as_hex = subprocess.check_output([bolt12tool, 'decodehex', offer]).decode('UTF-8').split()
    mangled = subprocess.check_output([bolt12tool, 'encodehex', as_hex[0], as_hex[1] + 'FE3B9ACA01' '01' '00']).decode('UTF-8').strip()

    assert l1.rpc.decode(mangled)['unknown_offer_tlvs'] == [{'type': 1000000001, 'length': 1, 'value': '00'}]

    # This will fail (offer has added field!)
    with pytest.raises(RpcError, match="Unknown offer"):
        l2.rpc.fetchinvoice(mangled)

    # invice request contains the unknown field
    m = re.search(r'invoice_request: \\"([a-z0-9]*)\\"', l2.daemon.is_in_log('invoice_request:'))
    assert l1.rpc.decode(m.group(1))['unknown_invoice_request_tlvs'] == [{'type': 1000000001, 'length': 1, 'value': '00'}]


def test_fetch_no_description_offer(node_factory):
    """Reproducing the issue: https://github.com/ElementsProject/lightning/issues/7405"""
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None,
                                              'allow-deprecated-apis': True})

    # Deprecated fields make schema checker upset.
    offer = l2.rpc.call('offer', {'amount': 'any'})
    inv = l1.rpc.call('fetchinvoice', {'offer': offer['bolt12'], 'amount_msat': '2sat'})

    # Deprecated fields make schema checker upset.
    l1.rpc.jsonschemas = {}
    offer_decode = l1.rpc.decode(offer['bolt12'])
    assert offer_decode['type'] == 'bolt12 offer', f'No possible to decode the offer `{offer}`'

    l1.rpc.pay(inv['invoice'])


def test_fetch_no_description_with_amount(node_factory):
    """Reproducing the issue: https://github.com/ElementsProject/lightning/issues/7405"""
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None,
                                              'allow-deprecated-apis': True})

    # Deprecated fields make schema checker upset.
    # BOLT-offers #12:
    #
    # - if offer_amount is set and offer_description is not set:
    #   - MUST NOT respond to the offer.
    err = r'description is required for the user to know what it was they paid for'
    with pytest.raises(RpcError, match=err) as err:
        _ = l2.rpc.call('offer', {'amount': '2msat'})


def test_decodepay(node_factory, chainparams):
    """Test we don't break (deprecated) decodepay command"""
    l1 = node_factory.get_node(options={'allow-deprecated-apis': True})

    addr1 = l1.rpc.newaddr('bech32')['bech32']
    addr2 = '2MxqzNANJNAdMjHQq8ZLkwzooxAFiRzXvEz' if not chainparams['elements'] else 'XGx1E2JSTLZLmqYMAo3CGpsco85aS7so33'

    before = int(time.time())
    inv = l1.rpc.invoice(123000, 'label', 'description', 3700, [addr1, addr2])
    after = int(time.time())
    b11 = l1.rpc.decodepay(inv['bolt11'])

    # This can vary within a range.
    created = b11['created_at']
    assert created >= before
    assert created <= after

    # Don't bother checking these
    del b11['fallbacks'][0]['hex']
    del b11['fallbacks'][1]['hex']
    del b11['payment_secret']
    del b11['signature']

    assert b11 == {
        'amount_msat': 123000,
        'currency': chainparams['bip173_prefix'],
        'created_at': created,
        'payment_hash': inv['payment_hash'],
        'description': 'description',
        'expiry': 3700,
        'payee': l1.info['id'],
        'fallbacks': [{'addr': addr1,
                       'type': 'P2WPKH'},
                      {'addr': addr2,
                       'type': 'P2SH'}],
        'features': '02024100',
        'min_final_cltv_expiry': 5}


def test_enableoffer(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None})

    # Normal offer, works as expected
    offer1 = l2.rpc.call('offer', {'amount': '2msat',
                                   'description': 'test_disableoffer_reenable'})
    assert offer1['created'] is True
    l1.rpc.fetchinvoice(offer=offer1['bolt12'])

    l2.rpc.disableoffer(offer_id=offer1['offer_id'])

    with pytest.raises(RpcError, match="Offer no longer available"):
        l1.rpc.fetchinvoice(offer=offer1['bolt12'])

    with pytest.raises(RpcError, match="1000.*Already exists, but isn't active"):
        l2.rpc.call('offer', {'amount': '2msat',
                              'description': 'test_disableoffer_reenable'})

    l2.rpc.enableoffer(offer_id=offer1['offer_id'])
    l1.rpc.fetchinvoice(offer=offer1['bolt12'])

    # Can't enable twice.
    with pytest.raises(RpcError, match="1006.*offer already active"):
        l2.rpc.enableoffer(offer_id=offer1['offer_id'])

    # Can't enable unknown.
    with pytest.raises(RpcError, match="Unknown offer"):
        l1.rpc.enableoffer(offer_id=offer1['offer_id'])


def diamond_network(node_factory):
    """Build a diamond, with a cheap route, that is exhausted. The
    first payment should try that route first, learn it's exhausted,
    and then succeed over the other leg. The second, unrelated,
    payment should immediately skip the exhausted leg and go for the
    more expensive one.

    ```mermaid
    graph LR
      Sender -- "propfee=1" --> Forwarder1
      Forwarder1 -- "propfee="1\nexhausted --> Recipient
      Sender -- "propfee=1" --> Forwarder2
      Forwarder2 -- "propfee=5" --> Recipient
    ```
    """
    opts = [
        {'fee-per-satoshi': 0, 'fee-base': 0},     # Sender
        {'fee-per-satoshi': 0, 'fee-base': 0},     # Low fee, but exhausted channel
        {'fee-per-satoshi': 5000, 'fee-base': 0},  # Disincentivize using fw2
        {'fee-per-satoshi': 0, 'fee-base': 0},     # Recipient
    ]

    sender, fw1, fw2, recipient, = node_factory.get_nodes(4, opts=opts)

    # And now wire them all up: notice that all channels, except the
    # recipent <> fw1 are created in the direction of the planned
    # from, meaning we won't be able to forward through there, causing
    # a `channel_hint` to be created, disincentivizing usage of this
    # channel on the second payment.
    node_factory.join_nodes(
        [sender, fw2, recipient, fw1],
        wait_for_announce=True,
        announce_channels=True,
    )
    # And we complete the diamond by adding the edge from sender to fw1
    node_factory.join_nodes(
        [sender, fw1],
        wait_for_announce=True,
        announce_channels=True
    )
    return [sender, fw1, fw2, recipient]


def test_pay_remember_hint(node_factory):
    """Using a diamond graph, with inferred `channel_hint`s, see if we remember
    """
    sender, fw1, fw2, recipient, = diamond_network(node_factory)

    inv = recipient.rpc.invoice(
        4200000,
        "lbl1",
        "desc1",
        exposeprivatechannels=[],  # suppress routehints, so fees alone control route
    )['bolt11']

    p = sender.rpc.pay(inv)

    # Ensure we failed the first, cheap, path, and then tried the successful one.
    assert(p['parts'] == 2)

    # Now for the final trick: a new payment should remember the
    # previous failure, and go directly for the successful route
    # through fw2

    inv = recipient.rpc.invoice(
        4200000,
        "lbl2",
        "desc2",
        exposeprivatechannels=[],  # suppress routehints, so fees alone control route
    )['bolt11']

    # We should not have touched fw1, and should succeed after a single call
    p = sender.rpc.pay(inv)
    assert(p['parts'] == 1)


def test_injectpaymentonion_simple(node_factory, executor):
    l1, l2 = node_factory.line_graph(2)

    blockheight = l1.rpc.getinfo()['blockheight']
    inv1 = l2.rpc.invoice(1000, "test_injectpaymentonion1", "test_injectpaymentonion1")

    # First hop for injectpaymentonion is self.
    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, inv1['payment_secret']).hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=inv1['payment_hash'])

    ret = l1.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=inv1['payment_hash'],
                                    amount_msat=1000,
                                    cltv_expiry=blockheight + 18 + 6,
                                    partid=1,
                                    groupid=0)
    assert ret['completed_at'] >= ret['created_at']
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv1['payment_hash']
    assert ret == {'payment_preimage': ret['payment_preimage'],
                   'created_index': 1,
                   'completed_at': ret['completed_at'],
                   'created_at': ret['created_at']}
    assert only_one(l2.rpc.listinvoices("test_injectpaymentonion1")['invoices'])['status'] == 'paid'
    lsp = only_one(l1.rpc.listsendpays(inv1['bolt11'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == inv1['payment_hash']
    assert lsp['status'] == 'complete'

    # We FAIL on reattempt
    with pytest.raises(RpcError, match="Already paid this invoice") as err:
        l1.rpc.injectpaymentonion(onion=onion['onion'],
                                  payment_hash=inv1['payment_hash'],
                                  amount_msat=1000,
                                  cltv_expiry=blockheight + 18 + 6,
                                  partid=1,
                                  groupid=0)
    # PAY_INJECTPAYMENTONION_ALREADY_PAID
    assert err.value.error['code'] == 219
    assert 'onionreply' not in err.value.error['data']
    assert err.value.error['data'] == lsp


def test_injectpaymentonion_mpp(node_factory, executor):
    l1, l2 = node_factory.line_graph(2)

    blockheight = l1.rpc.getinfo()['blockheight']
    inv2 = l2.rpc.invoice(3000, "test_injectpaymentonion2", "test_injectpaymentonion2")

    # First hop for injectpaymentonion is self.
    hops1 = [{'pubkey': l1.info['id'],
              'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
             {'pubkey': l2.info['id'],
              'payload': serialize_payload_final_tlv(1000, 18, 3000, blockheight, inv2['payment_secret']).hex()}]
    onion1 = l1.rpc.createonion(hops=hops1, assocdata=inv2['payment_hash'])
    hops2 = [{'pubkey': l1.info['id'],
              'payload': serialize_payload_tlv(2000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
             {'pubkey': l2.info['id'],
              'payload': serialize_payload_final_tlv(2000, 18, 3000, blockheight, inv2['payment_secret']).hex()}]
    onion2 = l1.rpc.createonion(hops=hops2, assocdata=inv2['payment_hash'])

    fut1 = executor.submit(l1.rpc.injectpaymentonion,
                           onion1['onion'],
                           inv2['payment_hash'],
                           1000,
                           blockheight + 18 + 6,
                           1,
                           0)
    fut2 = executor.submit(l1.rpc.injectpaymentonion,
                           onion2['onion'],
                           inv2['payment_hash'],
                           2000,
                           blockheight + 18 + 6,
                           2,
                           0)

    # Now both should complete.
    ret = fut1.result(TIMEOUT)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv2['payment_hash']
    ret = fut2.result(TIMEOUT)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv2['payment_hash']

    assert only_one(l2.rpc.listinvoices("test_injectpaymentonion2")['invoices'])['status'] == 'paid'
    lsps = l1.rpc.listsendpays(inv2['bolt11'])['payments']
    for lsp in lsps:
        assert lsp['groupid'] == 0
        assert lsp['partid'] == 1 or lsp['partid'] == 2
        assert lsp['payment_hash'] == inv2['payment_hash']
        assert lsp['status'] == 'complete'
    assert len(lsps) == 2


def test_injectpaymentonion_3hop(node_factory, executor):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    blockheight = l1.rpc.getinfo()['blockheight']
    inv3 = l3.rpc.invoice(1000, "test_injectpaymentonion3", "test_injectpaymentonion3")

    # First hop for injectpaymentonion is self.
    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1001, 18 + 6 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l3, l2), blockheight).hex()},
            {'pubkey': l3.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, inv3['payment_secret']).hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=inv3['payment_hash'])

    ret = l1.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=inv3['payment_hash'],
                                    amount_msat=1001,
                                    cltv_expiry=blockheight + 18 + 6 + 6,
                                    partid=1,
                                    groupid=0)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv3['payment_hash']
    assert only_one(l3.rpc.listinvoices("test_injectpaymentonion3")['invoices'])['status'] == 'paid'
    lsp = only_one(l1.rpc.listsendpays(inv3['bolt11'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == inv3['payment_hash']
    assert lsp['status'] == 'complete'


def test_injectpaymentonion_selfpay(node_factory, executor):
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None})

    blockheight = l1.rpc.getinfo()['blockheight']

    # Test simple self-pay.
    inv4 = l1.rpc.invoice(1000, "test_injectpaymentonion4", "test_injectpaymentonion4")

    # First hop for injectpaymentonion is self.
    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, inv4['payment_secret']).hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=inv4['payment_hash'])

    ret = l1.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=inv4['payment_hash'],
                                    amount_msat=1000,
                                    cltv_expiry=blockheight + 18,
                                    partid=1,
                                    groupid=0)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv4['payment_hash']
    assert only_one(l1.rpc.listinvoices("test_injectpaymentonion4")['invoices'])['status'] == 'paid'
    lsp = only_one(l1.rpc.listsendpays(inv4['bolt11'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == inv4['payment_hash']
    assert lsp['status'] == 'complete'

    # Test self-pay with MPP.
    inv5 = l1.rpc.invoice(1000, "test_injectpaymentonion5", "test_injectpaymentonion5")

    # First hop for injectpaymentonion is self.
    hops1 = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_final_tlv(333, 18, 1000, blockheight, inv5['payment_secret']).hex()}]
    onion1 = l1.rpc.createonion(hops=hops1, assocdata=inv5['payment_hash'])
    hops2 = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_final_tlv(666, 18, 1000, blockheight, inv5['payment_secret']).hex()}]
    onion2 = l1.rpc.createonion(hops=hops2, assocdata=inv5['payment_hash'])

    fut1 = executor.submit(l1.rpc.injectpaymentonion,
                           onion1['onion'],
                           inv5['payment_hash'],
                           333,
                           blockheight + 18,
                           1,
                           0)
    fut2 = executor.submit(l1.rpc.injectpaymentonion,
                           onion2['onion'],
                           inv5['payment_hash'],
                           667,
                           blockheight + 18,
                           2,
                           0)
    # Now both should complete.
    ret = fut1.result(TIMEOUT)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv5['payment_hash']

    ret = fut2.result(TIMEOUT)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv5['payment_hash']

    assert only_one(l1.rpc.listinvoices("test_injectpaymentonion5")['invoices'])['status'] == 'paid'
    lsps = l1.rpc.listsendpays(inv5['bolt11'])['payments']
    for lsp in lsps:
        assert lsp['groupid'] == 0
        assert lsp['partid'] == 1 or lsp['partid'] == 2
        assert lsp['payment_hash'] == inv5['payment_hash']
        assert lsp['status'] == 'complete'
    assert len(lsps) == 2

    # Check listpays gives a reasonable result!
    pays = only_one(l1.rpc.listpays(inv5['bolt11'])['pays'])
    # Don't know these values
    del pays['created_at']
    del pays['completed_at']
    del pays['preimage']
    assert pays == {'bolt11': inv5['bolt11'],
                    'payment_hash': inv5['payment_hash'],
                    'status': "complete",
                    'amount_sent_msat': 1000,
                    'number_of_parts': 2,
                    'created_index': 2,
                    'updated_index': 3}

    # Test self-pay with MPP from non-selfpay.
    inv6 = l2.rpc.invoice(3000, "test_injectpaymentonion6", "test_injectpaymentonion6")

    # First hop for injectpaymentonion is self.
    hops1 = [{'pubkey': l1.info['id'],
              'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
             {'pubkey': l2.info['id'],
              'payload': serialize_payload_final_tlv(1000, 18, 3000, blockheight, inv6['payment_secret']).hex()}]
    onion1 = l1.rpc.createonion(hops=hops1, assocdata=inv6['payment_hash'])
    hops2 = [{'pubkey': l2.info['id'],
              'payload': serialize_payload_final_tlv(2000, 18, 3000, blockheight, inv6['payment_secret']).hex()}]
    onion2 = l1.rpc.createonion(hops=hops2, assocdata=inv6['payment_hash'])

    fut1 = executor.submit(l1.rpc.injectpaymentonion,
                           onion1['onion'],
                           inv6['payment_hash'],
                           1000,
                           blockheight + 18 + 6,
                           1,
                           0)
    fut2 = executor.submit(l2.rpc.injectpaymentonion,
                           onion2['onion'],
                           inv6['payment_hash'],
                           2000,
                           blockheight + 18,
                           2,
                           1)

    # Now both should complete.
    ret = fut1.result(TIMEOUT)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv6['payment_hash']

    ret = fut2.result(TIMEOUT)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == inv6['payment_hash']

    assert only_one(l2.rpc.listinvoices("test_injectpaymentonion6")['invoices'])['status'] == 'paid'
    lsp = only_one(l1.rpc.listsendpays(inv6['bolt11'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == inv6['payment_hash']
    assert lsp['status'] == 'complete'
    lsp = only_one(l2.rpc.listsendpays(inv6['bolt11'])['payments'])
    assert lsp['groupid'] == 1
    assert lsp['partid'] == 2
    assert lsp['payment_hash'] == inv6['payment_hash']
    assert lsp['status'] == 'complete'

    # Test bolt12 self-pay.
    offer = l1.rpc.offer('any')
    inv10 = l1.rpc.fetchinvoice(offer['bolt12'], '1000msat')
    decoded = l1.rpc.decode(inv10['invoice'])

    final_tlvs = TlvPayload()
    final_tlvs.add_field(2, tu64_encode(1000))
    final_tlvs.add_field(4, tu64_encode(blockheight + 18))
    final_tlvs.add_field(10, bytes.fromhex(decoded['invoice_paths'][0]['path'][0]['encrypted_recipient_data']))
    final_tlvs.add_field(12, bytes.fromhex(decoded['invoice_paths'][0]['first_path_key']))
    final_tlvs.add_field(18, tu64_encode(1000))

    hops = [{'pubkey': l1.info['id'],
             'payload': final_tlvs.to_bytes().hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=decoded['invoice_payment_hash'])

    ret = l1.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=decoded['invoice_payment_hash'],
                                    amount_msat=1000,
                                    cltv_expiry=blockheight + 18,
                                    partid=1,
                                    groupid=0)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == decoded['invoice_payment_hash']
    # The label for the invoice is deterministic.
    label = f"{decoded['offer_id']}-{decoded['invreq_payer_id']}-0"
    assert only_one(l1.rpc.listinvoices(label)['invoices'])['status'] == 'paid'
    lsp = only_one(l1.rpc.listsendpays(inv4['bolt11'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == inv4['payment_hash']
    assert lsp['status'] == 'complete'


def test_injectpaymentonion_blindedpath(node_factory, executor):
    l1, l2 = node_factory.line_graph(2,
                                     wait_for_announce=True,
                                     opts={'experimental-offers': None})
    blockheight = l1.rpc.getinfo()['blockheight']

    # Test bolt12, with stub blinded path.
    offer = l2.rpc.offer('any')
    inv7 = l1.rpc.fetchinvoice(offer['bolt12'], '1000msat')

    decoded = l1.rpc.decode(inv7['invoice'])
    assert len(decoded['invoice_paths']) == 1
    path_key = decoded['invoice_paths'][0]['first_path_key']
    assert decoded['invoice_paths'][0]['first_node_id'] == l2.info['id']
    path = decoded['invoice_paths'][0]['path']
    assert len(path) == 1

    # Manually encode the onion payload to include blinded info
    # BOLT #4:
    #   - For every node inside a blinded route:
    #     - MUST include the `encrypted_recipient_data` provided by the recipient
    #     - For the first node in the blinded route:
    #       - MUST include the `path_key` provided by the recipient in `current_path_key`
    #     - If it is the final node:
    #       - MUST include `amt_to_forward`, `outgoing_cltv_value` and `total_amount_msat`.
    #       - The value set for `outgoing_cltv_value`:
    #         - MUST use the current block height as a baseline value.
    #         - if a [random offset](07-routing-gossip.md#recommendations-for-routing) was added to improve privacy:
    #           - SHOULD add the offset to the baseline value.
    #     - MUST NOT include any other tlv field.
    final_tlvs = TlvPayload()

    # BOLT #4:
    #     1. type: 2 (`amt_to_forward`)
    #     2. data:
    #         * [`tu64`:`amt_to_forward`]
    #     1. type: 4 (`outgoing_cltv_value`)
    #     2. data:
    #         * [`tu32`:`outgoing_cltv_value`]
    # ...
    #     1. type: 10 (`encrypted_recipient_data`)
    #     2. data:
    #         * [`...*byte`:`encrypted_recipient_data`]
    #     1. type: 12 (`current_path_key`)
    #     2. data:
    #         * [`point`:`path_key`]
    # ...
    #    1. type: 18 (`total_amount_msat`)
    #    2. data:
    #        * [`tu64`:`total_msat`]
    final_tlvs.add_field(2, tu64_encode(1000))
    final_tlvs.add_field(4, tu64_encode(blockheight + 18))
    final_tlvs.add_field(10, bytes.fromhex(path[0]['encrypted_recipient_data']))
    final_tlvs.add_field(12, bytes.fromhex(path_key))
    final_tlvs.add_field(18, tu64_encode(1000))

    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': final_tlvs.to_bytes().hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=decoded['invoice_payment_hash'])

    ret = l1.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=decoded['invoice_payment_hash'],
                                    amount_msat=1000,
                                    cltv_expiry=blockheight + 18 + 6,
                                    partid=1,
                                    groupid=0)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == decoded['invoice_payment_hash']
    # The label for l2's invoice is deterministic.
    label = f"{decoded['offer_id']}-{decoded['invreq_payer_id']}-0"
    assert only_one(l2.rpc.listinvoices(label)['invoices'])['status'] == 'paid'

    lsp = only_one(l1.rpc.listsendpays(inv7['invoice'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == decoded['invoice_payment_hash']
    assert lsp['status'] == 'complete'

    # Now test bolt12 with real blinded path.
    l4 = node_factory.get_node(options={'experimental-offers': None})
    # Private channel.
    node_factory.join_nodes([l2, l4], announce_channels=False)

    # Make sure l4 knows about other nodes, so will add route hint.
    wait_for(lambda: len(l4.rpc.listnodes()['nodes']) == 2)
    offer = l4.rpc.offer('any')
    inv8 = l1.rpc.fetchinvoice(offer['bolt12'], '1000msat')

    decoded = l1.rpc.decode(inv8['invoice'])
    assert len(decoded['invoice_paths']) == 1
    path_key = decoded['invoice_paths'][0]['first_path_key']
    assert decoded['invoice_paths'][0]['first_node_id'] == l2.info['id']
    path = decoded['invoice_paths'][0]['path']
    assert len(path) == 2

    mid_tlvs = TlvPayload()
    mid_tlvs.add_field(10, bytes.fromhex(path[0]['encrypted_recipient_data']))
    mid_tlvs.add_field(12, bytes.fromhex(path_key))

    final_tlvs = TlvPayload()
    final_tlvs.add_field(2, tu64_encode(1000))
    final_tlvs.add_field(4, tu64_encode(blockheight + 18))
    final_tlvs.add_field(10, bytes.fromhex(path[1]['encrypted_recipient_data']))
    final_tlvs.add_field(18, tu64_encode(1000))

    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1001, 18 + 6 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': mid_tlvs.to_bytes().hex()},
            {'pubkey': path[1]['blinded_node_id'],
             'payload': final_tlvs.to_bytes().hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=decoded['invoice_payment_hash'])

    ret = l1.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=decoded['invoice_payment_hash'],
                                    amount_msat=1001,
                                    cltv_expiry=blockheight + 18 + 6,
                                    partid=1,
                                    groupid=0)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == decoded['invoice_payment_hash']
    # The label for l4's invoice is deterministic.
    label = f"{decoded['offer_id']}-{decoded['invreq_payer_id']}-0"
    assert only_one(l4.rpc.listinvoices(label)['invoices'])['status'] == 'paid'
    lsp = only_one(l1.rpc.listsendpays(inv8['invoice'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == decoded['invoice_payment_hash']
    assert lsp['status'] == 'complete'

    # Finally, with blinded path which starts with us.
    offer = l4.rpc.offer('any')
    inv9 = l1.rpc.fetchinvoice(offer['bolt12'], '1000msat')

    decoded = l1.rpc.decode(inv9['invoice'])
    assert len(decoded['invoice_paths']) == 1
    path_key = decoded['invoice_paths'][0]['first_path_key']
    assert decoded['invoice_paths'][0]['first_node_id'] == l2.info['id']
    path = decoded['invoice_paths'][0]['path']
    assert len(path) == 2

    mid_tlvs = TlvPayload()
    mid_tlvs.add_field(10, bytes.fromhex(path[0]['encrypted_recipient_data']))
    mid_tlvs.add_field(12, bytes.fromhex(path_key))

    final_tlvs = TlvPayload()
    final_tlvs.add_field(2, tu64_encode(1000))
    final_tlvs.add_field(4, tu64_encode(blockheight + 18))
    final_tlvs.add_field(10, bytes.fromhex(path[1]['encrypted_recipient_data']))
    final_tlvs.add_field(18, tu64_encode(1000))

    hops = [{'pubkey': l2.info['id'],
             'payload': mid_tlvs.to_bytes().hex()},
            {'pubkey': path[1]['blinded_node_id'],
             'payload': final_tlvs.to_bytes().hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=decoded['invoice_payment_hash'])

    ret = l2.rpc.injectpaymentonion(onion=onion['onion'],
                                    payment_hash=decoded['invoice_payment_hash'],
                                    amount_msat=1001,
                                    cltv_expiry=blockheight + 18 + 6,
                                    partid=1,
                                    groupid=0)
    assert sha256(bytes.fromhex(ret['payment_preimage'])).hexdigest() == decoded['invoice_payment_hash']
    # The label for the invoice is deterministic.
    label = f"{decoded['offer_id']}-{decoded['invreq_payer_id']}-0"
    assert only_one(l4.rpc.listinvoices(label)['invoices'])['status'] == 'paid'
    lsp = only_one(l2.rpc.listsendpays(inv9['invoice'])['payments'])
    assert lsp['groupid'] == 0
    assert lsp['partid'] == 1
    assert lsp['payment_hash'] == decoded['invoice_payment_hash']
    assert lsp['status'] == 'complete'


def test_injectpaymentonion_failures(node_factory, executor):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)
    blockheight = l1.rpc.getinfo()['blockheight']

    #
    # Failure cases should give an onion:
    #  Unknown invoice.
    #  Unknown invoice (selfpay)
    #  Cannot forward.

    # Unknown invoice
    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l2.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, '00' * 32).hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata='00' * 32)

    with pytest.raises(RpcError) as err:
        l1.rpc.injectpaymentonion(onion=onion['onion'],
                                  payment_hash='00' * 32,
                                  amount_msat=1000,
                                  cltv_expiry=blockheight + 18 + 6,
                                  partid=1,
                                  groupid=0)

    # PAY_INJECTPAYMENTONION_FAILED
    assert err.value.error['code'] == 218
    assert 'onionreply' in err.value.error['data']

    # Self-pay (unknown payment_hash)
    hops = [{'pubkey': l1.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, '00' * 32).hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata='00' * 32)

    with pytest.raises(RpcError) as err:
        l1.rpc.injectpaymentonion(onion=onion['onion'],
                                  payment_hash='00' * 32,
                                  amount_msat=1000,
                                  cltv_expiry=blockheight + 18 + 6,
                                  partid=1,
                                  groupid=1)

    # PAY_INJECTPAYMENTONION_FAILED
    assert err.value.error['code'] == 218
    assert 'onionreply' in err.value.error['data']

    # Insufficient funds (l2 can't pay to l1)
    inv11 = l1.rpc.invoice(3000, "test_injectpaymentonion11", "test_injectpaymentonion11")
    hops = [{'pubkey': l2.info['id'],
             'payload': serialize_payload_tlv(1000, 18 + 6, first_scid(l1, l2), blockheight).hex()},
            {'pubkey': l1.info['id'],
             'payload': serialize_payload_final_tlv(1000, 18, 1000, blockheight, inv11['payment_secret']).hex()}]
    onion = l1.rpc.createonion(hops=hops, assocdata=inv11['payment_hash'])

    with pytest.raises(RpcError) as err:
        l2.rpc.injectpaymentonion(onion=onion['onion'],
                                  payment_hash=inv11['payment_hash'],
                                  amount_msat=1000,
                                  cltv_expiry=blockheight + 18 + 6,
                                  partid=1,
                                  groupid=0)

    # PAY_INJECTPAYMENTONION_FAILED
    assert err.value.error['code'] == 218
    assert 'onionreply' in err.value.error['data']


def test_parallel_channels_reserve(node_factory, bitcoind):
    """Tests wether we are able to pay through parallel channels concurrently.
    To do that we need to enable strict-forwarding."""

    def direction(node1, node2):
        return 0 if node1.info["id"] < node2.info["id"] else 1

    def get_local_channel_by_id(node, chanid):
        peerchannels = node.rpc.listpeerchannels()["channels"]
        if not peerchannels:
            return None
        for c in peerchannels:
            if c["channel_id"] == chanid:
                return c
        return None

    opts = {
        "fee-base": 0,
        "fee-per-satoshi": 0,
        "cltv-delta": 6,
        "dev-strict-forwarding": None,
    }
    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)

    l1.fundwallet(10**7)
    l2.fundwallet(10**7)

    scids = []

    l1.rpc.connect(l2.info["id"], "localhost", l2.port)
    l2.rpc.connect(l3.info["id"], "localhost", l3.port)

    c12 = l1.rpc.fundchannel(l2.info["id"], 3000_000, minconf=0)["channel_id"]

    c23 = []
    c23.append(l2.rpc.fundchannel(l3.info["id"], 1000_000, minconf=0)["channel_id"])
    c23.append(l2.rpc.fundchannel(l3.info["id"], 2000_000, minconf=0)["channel_id"])

    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1, l2, l3])

    scids.append(get_local_channel_by_id(l1, c12)["short_channel_id"])
    scids.append(get_local_channel_by_id(l2, c23[0])["short_channel_id"])
    scids.append(get_local_channel_by_id(l2, c23[1])["short_channel_id"])

    for l in [l1, l2, l3]:
        for c in scids:
            l.wait_channel_active(c)

    # we should be able to send these two parts:
    nparts = 2
    route_amounts = ["750000sat", "1750000sat"]
    total_msat = sum([Millisatoshi(a) for a in route_amounts[:nparts]])

    # Test succeeds if we are able to pay this invoice
    inv = l3.rpc.call(
        "invoice",
        {"amount_msat": total_msat, "label": "inv", "description": "inv", "cltv": 10},
    )

    # Share data by every route we will construct: l1->l2->l3
    route = [
        {
            "id": l2.info["id"],
            "direction": direction(l1, l2),
            "delay": 16,
            "style": "tlv",
        },
        {
            "id": l3.info["id"],
            "direction": direction(l2, l3),
            "delay": 10,
            "style": "tlv",
        },
    ]

    # Send every part with sendpay
    for part in range(nparts):
        this_part_msat = Millisatoshi(route_amounts[part])
        chan1 = get_local_channel_by_id(l1, c12)
        chan2 = get_local_channel_by_id(l2, c23[part])

        route[0]["channel"] = chan1["short_channel_id"]
        route[1]["channel"] = chan2["short_channel_id"]
        route[0]["amount_msat"] = route[1]["amount_msat"] = this_part_msat

        assert chan1["spendable_msat"] >= this_part_msat
        assert chan2["spendable_msat"] >= this_part_msat

        l1.rpc.call(
            "sendpay",
            {
                "route": route,
                "payment_hash": inv["payment_hash"],
                "payment_secret": inv["payment_secret"],
                "amount_msat": total_msat,
                "groupid": 1,
                "partid": part + 1,
            },
        )
    l1.wait_for_htlcs()

    # Are we happy?
    receipt = only_one(l3.rpc.listinvoices("inv")["invoices"])
    assert receipt["status"] == "paid"
    assert receipt["amount_received_msat"] == total_msat
