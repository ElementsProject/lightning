from fixtures import *  # noqa: F401,F403
from lightning import RpcError
from utils import DEVELOPER, wait_for, only_one, sync_blockheight


import copy
import pytest
import random
import string
import time
import unittest


def test_pay(node_factory):
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(123000, 'test_pay', 'description')['bolt11']
    before = int(time.time())
    details = l1.rpc.pay(inv)
    after = int(time.time())
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
    l1.rpc.pay(inv)
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
        l1.rpc.pay(inv2, random.randint(1000, 999999))

    # Should see 6 completed payments
    assert len(l1.rpc.listpayments()['payments']) == 6

    # Test listpayments indexed by bolt11.
    payments = l1.rpc.listpayments(inv)['payments']
    assert len(payments) == 1 and payments[0]['payment_preimage'] == preimage


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
    l1.rpc.sendpay([routestep], rhash)
    with pytest.raises(RpcError, match=r'WIRE_AMOUNT_BELOW_MINIMUM'):
        l1.rpc.waitsendpay(rhash)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_pay_disconnect(node_factory, bitcoind):
    """If the remote node has disconnected, we fail payment, but can try again when it reconnects"""
    l1, l2 = node_factory.line_graph(2, opts={'dev-max-fee-multiplier': 5})

    inv = l2.rpc.invoice(123000, 'test_pay_disconnect', 'description')
    rhash = inv['payment_hash']

    # Can't use `pay` since that'd notice that we can't route, due to disabling channel_update
    route = l1.rpc.getroute(l2.info['id'], 123000, 1)["route"]

    # Make l2 upset by asking for crazy fee.
    l1.rpc.dev_setfees('150000')
    # Wait for l1 notice
    l1.daemon.wait_for_log(r'Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: received ERROR channel .*: update_fee 150000 outside range 1875-75000')

    # Can't pay while its offline.
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, rhash)
    l1.daemon.wait_for_log('failed: WIRE_TEMPORARY_CHANNEL_FAILURE \\(First peer not ready\\)')

    # Should fail due to temporary channel fail
    with pytest.raises(RpcError):
        l1.rpc.sendpay(route, rhash)

    l1.daemon.wait_for_log('failed: WIRE_TEMPORARY_CHANNEL_FAILURE \\(First peer not ready\\)')
    assert not l1.daemon.is_in_log('Payment is still in progress')

    # After it sees block, someone should close channel.
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('ONCHAIN')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for dev_suppress_gossip")
def test_pay_get_error_with_update(node_factory):
    """We should process an update inside a temporary_channel_failure"""
    l1, l2, l3 = node_factory.line_graph(3, opts={'log-level': 'io'}, fundchannel=True, announce=True)
    chanid2 = l2.get_channel_scid(l3)

    inv = l3.rpc.invoice(123000, 'test_pay_get_error_with_update', 'description')

    def try_route(src, dst):
        try:
            src.rpc.getroute(dst.info['id'], 1, 1)
            return True
        except Exception:
            return False

    wait_for(lambda: try_route(l1, l3))

    route = l1.rpc.getroute(l3.info['id'], 12300, 1)["route"]

    # Make sure l2 doesn't tell l1 directly that channel is disabled.
    l2.rpc.dev_suppress_gossip()
    l3.stop()

    # Make sure that l2 has processed the local update which disables.
    l2.daemon.wait_for_log('Received channel_update for channel {}\(.*\) now DISABLED was ACTIVE \(from apply_delayed_local_update\)'.format(chanid2))

    l1.rpc.sendpay(route, inv['payment_hash'])
    with pytest.raises(RpcError, match=r'WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.waitsendpay(inv['payment_hash'])

    # Make sure we get an onionreply, without the type prefix of the nested
    # channel_update, and it should patch it to include a type prefix. The
    # prefix 0x0102 should be in the channel_update, but not in the
    # onionreply (negation of 0x0102 in the RE)
    l1.daemon.wait_for_log(r'Extracted channel_update 0102.*from onionreply 10070080(?!.*0102)')

    # And now monitor for l1 to apply the channel_update we just extracted
    l1.daemon.wait_for_log('Received channel_update for channel {}\(.\) now DISABLED was ACTIVE \(from error\)'.format(chanid2))


def test_pay_optional_args(node_factory):
    l1, l2 = node_factory.line_graph(2)

    inv1 = l2.rpc.invoice(123000, 'test_pay', 'desc')['bolt11']
    l1.rpc.pay(inv1, description='desc')
    payment1 = l1.rpc.listpayments(inv1)['payments']
    assert len(payment1) and payment1[0]['msatoshi'] == 123000
    assert payment1[0]['description'] == 'desc'

    inv2 = l2.rpc.invoice(321000, 'test_pay2', 'description')['bolt11']
    l1.rpc.pay(inv2, riskfactor=5.0)
    payment2 = l1.rpc.listpayments(inv2)['payments']
    assert len(payment2) == 1 and payment2[0]['msatoshi'] == 321000

    anyinv = l2.rpc.invoice('any', 'any_pay', 'desc')['bolt11']
    l1.rpc.pay(anyinv, description='desc', msatoshi='500')
    payment3 = l1.rpc.listpayments(anyinv)['payments']
    assert len(payment3) == 1 and payment3[0]['msatoshi'] == 500
    assert payment3[0]['description'] == 'desc'

    # Should see 3 completed transactions
    assert len(l1.rpc.listpayments()['payments']) == 3


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_payment_success_persistence(node_factory, executor):
    # Start two nodes and open a channel.. die during payment.
    l1 = node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'],
                               options={'dev-no-reconnect': None},
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    chanid = l1.fund_channel(l2, 100000)

    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')

    # Fire off a pay request, it'll get interrupted by a restart
    executor.submit(l1.rpc.pay, inv1['bolt11'])

    l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    print("Killing l1 in mid HTLC")
    l1.daemon.kill()

    # Restart l1, without disconnect stuff.
    del l1.daemon.opts['dev-no-reconnect']
    del l1.daemon.opts['dev-disconnect']

    # Should reconnect, and sort the payment out.
    l1.start()

    wait_for(lambda: l1.rpc.listpayments()['payments'][0]['status'] != 'pending')

    payments = l1.rpc.listpayments()['payments']
    invoices = l2.rpc.listinvoices('inv1')['invoices']
    assert len(payments) == 1 and payments[0]['status'] == 'complete'
    assert len(invoices) == 1 and invoices[0]['status'] == 'paid'

    # FIXME: We should re-add pre-announced routes on startup!
    l1.bitcoin.rpc.generate(5)
    l1.wait_channel_active(chanid)

    # A duplicate should succeed immediately (nop) and return correct preimage.
    preimage = l1.rpc.pay(inv1['bolt11'])['payment_preimage']
    assert l1.rpc.dev_rhash(preimage)['rhash'] == inv1['payment_hash']


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_payment_failed_persistence(node_factory, executor):
    # Start two nodes and open a channel.. die during payment.
    l1 = node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'],
                               options={'dev-no-reconnect': None},
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 100000)

    # Expires almost immediately, so it will fail.
    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1', 5)

    # Fire off a pay request, it'll get interrupted by a restart
    executor.submit(l1.rpc.pay, inv1['bolt11'])

    l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    print("Killing l1 in mid HTLC")
    l1.daemon.kill()

    # Restart l1, without disconnect stuff.
    del l1.daemon.opts['dev-no-reconnect']
    del l1.daemon.opts['dev-disconnect']

    # Make sure invoice has expired.
    time.sleep(5 + 1)

    # Should reconnect, and fail the payment
    l1.start()

    wait_for(lambda: l1.rpc.listpayments()['payments'][0]['status'] != 'pending')

    payments = l1.rpc.listpayments()['payments']
    invoices = l2.rpc.listinvoices('inv1')['invoices']
    assert len(invoices) == 1 and invoices[0]['status'] == 'expired'
    assert len(payments) == 1 and payments[0]['status'] == 'failed'

    # Another attempt should also fail.
    with pytest.raises(RpcError):
        l1.rpc.pay(inv1['bolt11'])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_payment_duplicate_uncommitted(node_factory, executor):
    # We want to test two payments at the same time, before we send commit
    l1 = node_factory.get_node(disconnect=['=WIRE_UPDATE_ADD_HTLC-nocommit'])
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 100000)

    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')

    # Start first payment, but not yet in db.
    fut = executor.submit(l1.rpc.pay, inv1['bolt11'])

    # Make sure that's started...
    l1.daemon.wait_for_log('dev_disconnect: =WIRE_UPDATE_ADD_HTLC-nocommit')

    # We should see it in listpayments
    payments = l1.rpc.listpayments()['payments']
    assert len(payments) == 1
    assert payments[0]['status'] == 'pending' and payments[0]['payment_hash'] == inv1['payment_hash']

    # Second one will succeed eventually.
    fut2 = executor.submit(l1.rpc.pay, inv1['bolt11'])

    # Now, let it commit.
    l1.rpc.dev_reenable_commit(l2.info['id'])

    # These should succeed.
    fut.result(10)
    fut2.result(10)


def test_sendpay(node_factory):
    l1, l2 = node_factory.line_graph(2, fundamount=10**6)

    amt = 200000000
    rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']

    def invoice_unpaid(dst, label):
        invoices = dst.rpc.listinvoices(label)['invoices']
        return len(invoices) == 1 and invoices[0]['status'] == 'unpaid'

    def only_one(arr):
        assert len(arr) == 1
        return arr[0]

    routestep = {
        'msatoshi': amt,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1:1:1'
    }

    # Insufficient funds.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] - 1
        l1.rpc.sendpay([rs], rhash)
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Gross overpayment (more than factor of 2)
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] * 2 + 1
        l1.rpc.sendpay([rs], rhash)
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Insufficient delay.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['delay'] = rs['delay'] - 2
        l1.rpc.sendpay([rs], rhash)
        l1.rpc.waitsendpay(rhash)
    assert invoice_unpaid(l2, 'testpayment2')

    # Bad ID.
    with pytest.raises(RpcError):
        rs = copy.deepcopy(routestep)
        rs['id'] = '00000000000000000000000000000000'
        l1.rpc.sendpay([rs], rhash)
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
    details = l1.rpc.sendpay([routestep], rhash)
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

    # Balances should reflect it.
    def check_balances():
        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        return (
            only_one(p1['channels'])['msatoshi_to_us'] == 10**6 * 1000 - amt and
            only_one(p1['channels'])['msatoshi_total'] == 10**6 * 1000 and
            only_one(p2['channels'])['msatoshi_to_us'] == amt and
            only_one(p2['channels'])['msatoshi_total'] == 10**6 * 1000
        )
    wait_for(check_balances)

    # Repeat will "succeed", but won't actually send anything (duplicate)
    assert not l1.daemon.is_in_log('... succeeded')
    details = l1.rpc.sendpay([routestep], rhash)
    assert details['status'] == "complete"
    preimage2 = details['payment_preimage']
    assert preimage == preimage2
    l1.daemon.wait_for_log('... succeeded')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['msatoshi_received'] == rs['msatoshi']

    # Overpaying by "only" a factor of 2 succeeds.
    rhash = l2.rpc.invoice(amt, 'testpayment3', 'desc')['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['status'] == 'unpaid'
    routestep = {'msatoshi': amt * 2, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}
    l1.rpc.sendpay([routestep], rhash)
    preimage3 = l1.rpc.waitsendpay(rhash)['payment_preimage']
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['status'] == 'paid'
    assert only_one(l2.rpc.listinvoices('testpayment3')['invoices'])['msatoshi_received'] == amt * 2

    # Test listpayments
    payments = l1.rpc.listpayments()['payments']
    assert len(payments) == 2

    invoice2 = only_one(l2.rpc.listinvoices('testpayment2')['invoices'])
    payments = l1.rpc.listpayments(payment_hash=invoice2['payment_hash'])['payments']
    assert len(payments) == 1

    assert payments[0]['status'] == 'complete'
    assert payments[0]['payment_preimage'] == preimage2

    invoice3 = only_one(l2.rpc.listinvoices('testpayment3')['invoices'])
    payments = l1.rpc.listpayments(payment_hash=invoice3['payment_hash'])['payments']
    assert len(payments) == 1

    assert payments[0]['status'] == 'complete'
    assert payments[0]['payment_preimage'] == preimage3


def test_sendpay_cant_afford(node_factory):
    l1, l2 = node_factory.line_graph(2, fundamount=10**6)

    # Can't pay more than channel capacity.
    def pay(lsrc, ldst, amt, label=None):
        if not label:
            label = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))
        rhash = ldst.rpc.invoice(amt, label, label)['payment_hash']
        routestep = {'msatoshi': amt, 'id': ldst.info['id'], 'delay': 5, 'channel': '1:1:1'}
        lsrc.rpc.sendpay([routestep], rhash)
        lsrc.rpc.waitsendpay(rhash)

    with pytest.raises(RpcError):
        pay(l1, l2, 10**9 + 1)

    # This is the fee, which needs to be taken into account for l1.
    available = 10**9 - 6720
    # Reserve is 1%.
    reserve = 10**7

    # Can't pay past reserve.
    with pytest.raises(RpcError):
        pay(l1, l2, available)
    with pytest.raises(RpcError):
        pay(l1, l2, available - reserve + 1)

    # Can pay up to reserve (1%)
    pay(l1, l2, available - reserve)

    # And now it can't pay back, due to its own reserve.
    with pytest.raises(RpcError):
        pay(l2, l1, available - reserve)

    # But this should work.
    pay(l2, l1, available - reserve * 2)


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
    assert b11['routes'][0][0]['short_channel_id'] == '66051:263430:1800'
    assert b11['routes'][0][0]['fee_base_msat'] == 1
    assert b11['routes'][0][0]['fee_proportional_millionths'] == 20
    assert b11['routes'][0][0]['cltv_expiry_delta'] == 3

    assert b11['routes'][0][1]['pubkey'] == '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
    # 0x030405:0x060708:0x090a
    assert b11['routes'][0][1]['short_channel_id'] == '197637:395016:2314'
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
    assert b11['created_at'] == 1496314658
    assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
    assert b11['expiry'] == 3600
    assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
    assert len(b11['fallbacks']) == 1
    assert b11['fallbacks'][0]['type'] == 'P2WSH'
    assert b11['fallbacks'][0]['addr'] == 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'

    with pytest.raises(RpcError):
        l1.rpc.decodepay('1111111')


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
def test_forward(node_factory, bitcoind):
    # Connect 1 -> 2 -> 3.
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=True)

    # Allow announce messages.
    l1.bitcoin.generate_block(5)

    # If they're at different block heights we can get spurious errors.
    sync_blockheight(bitcoind, [l1, l2, l3])

    chanid1 = only_one(l1.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id']
    chanid2 = only_one(l2.rpc.getpeer(l3.info['id'])['channels'])['short_channel_id']
    assert only_one(l2.rpc.getpeer(l1.info['id'])['channels'])['short_channel_id'] == chanid1
    assert only_one(l3.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id'] == chanid2

    rhash = l3.rpc.invoice(100000000, 'testpayment1', 'desc')['payment_hash']
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
    l1.rpc.sendpay(route, rhash)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # Delay too short (we always add one internally anyway, so subtract 2 here).
    route = copy.deepcopy(baseroute)
    route[0]['delay'] = 8
    l1.rpc.sendpay(route, rhash)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # Final delay too short
    route = copy.deepcopy(baseroute)
    route[1]['delay'] = 3
    l1.rpc.sendpay(route, rhash)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # This one works
    route = copy.deepcopy(baseroute)
    l1.rpc.sendpay(route, rhash)
    l1.rpc.waitsendpay(rhash)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
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
    l1 = node_factory.get_node(options={'cltv-delta': 10, 'fee-base': 100, 'fee-per-satoshi': 1000})
    l2 = node_factory.get_node(options={'cltv-delta': 20, 'fee-base': 200, 'fee-per-satoshi': 2000})
    l3 = node_factory.get_node(options={'cltv-delta': 30, 'cltv-final': 9, 'fee-base': 300, 'fee-per-satoshi': 3000})

    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('Handing back peer .* to master')
    l2.daemon.wait_for_log('Handing back peer .* to master')

    ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    assert ret['id'] == l3.info['id']

    l2.daemon.wait_for_log('Handing back peer .* to master')
    l3.daemon.wait_for_log('Handing back peer .* to master')

    c1 = l1.fund_channel(l2, 10**6)
    c2 = l2.fund_channel(l3, 10**6)
    bitcoind.generate_block(5)

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

    rhash = l3.rpc.invoice(4999999, 'test_forward_different_fees_and_cltv', 'desc')['payment_hash']
    assert only_one(l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'])['status'] == 'unpaid'

    # This should work.
    l1.rpc.sendpay(route, rhash)
    l1.rpc.waitsendpay(rhash)

    # We add one to the blockcount for a bit of fuzz (FIXME: Shadowroute would fix this!)
    shadow_route = 1
    l1.daemon.wait_for_log("Adding HTLC 0 msat=5010198 cltv={} gave CHANNEL_ERR_ADD_OK"
                           .format(bitcoind.rpc.getblockcount() + 20 + 9 + shadow_route))
    l2.daemon.wait_for_log("Adding HTLC 0 msat=4999999 cltv={} gave CHANNEL_ERR_ADD_OK"
                           .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
    l3.daemon.wait_for_log("test_forward_different_fees_and_cltv: Actual amount 4999999msat, HTLC expiry {}"
                           .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
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


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
def test_forward_pad_fees_and_cltv(node_factory, bitcoind):
    """Test that we are allowed extra locktime delta, and fees"""

    l1 = node_factory.get_node(options={'cltv-delta': 10, 'fee-base': 100, 'fee-per-satoshi': 1000})
    l2 = node_factory.get_node(options={'cltv-delta': 20, 'fee-base': 200, 'fee-per-satoshi': 2000})
    l3 = node_factory.get_node(options={'cltv-delta': 30, 'cltv-final': 9, 'fee-base': 300, 'fee-per-satoshi': 3000})

    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('Handing back peer .* to master')
    l2.daemon.wait_for_log('Handing back peer .* to master')

    ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    assert ret['id'] == l3.info['id']

    l2.daemon.wait_for_log('Handing back peer .* to master')
    l3.daemon.wait_for_log('Handing back peer .* to master')

    c1 = l1.fund_channel(l2, 10**6)
    c2 = l2.fund_channel(l3, 10**6)
    bitcoind.generate_block(5)

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
    route[0]['delay'] += 20
    route[1]['msatoshi'] += 1000
    route[1]['delay'] += 10

    # This should work.
    rhash = l3.rpc.invoice(4999999, 'test_forward_pad_fees_and_cltv', 'desc')['payment_hash']
    l1.rpc.sendpay(route, rhash)
    l1.rpc.waitsendpay(rhash)
    assert only_one(l3.rpc.listinvoices('test_forward_pad_fees_and_cltv')['invoices'])['status'] == 'paid'
