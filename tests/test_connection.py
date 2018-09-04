from fixtures import *  # noqa: F401,F403
from lightning import RpcError
from utils import DEVELOPER, only_one, wait_for, sync_blockheight


import os
import pytest
import time
import random
import shutil
import unittest


def test_connect(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    # These should be in openingd.
    assert l1.rpc.getpeer(l2.info['id'])['connected']
    assert l2.rpc.getpeer(l1.info['id'])['connected']
    assert len(l1.rpc.getpeer(l2.info['id'])['channels']) == 0
    assert len(l2.rpc.getpeer(l1.info['id'])['channels']) == 0

    # Reconnect should be a noop
    ret = l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    assert ret['id'] == l2.info['id']

    ret = l2.rpc.connect(l1.info['id'], host='localhost', port=l1.port)
    assert ret['id'] == l1.info['id']

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1

    # Should get reasonable error if unknown addr for peer.
    with pytest.raises(RpcError, match=r'No address known'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e')

    # Should get reasonable error if connection refuse.
    with pytest.raises(RpcError, match=r'Connection establishment: Connection refused'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', 1)

    # Should get reasonable error if wrong key for peer.
    with pytest.raises(RpcError, match=r'Cryptographic handshake: '):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', l2.port)


def test_connect_standard_addr(node_factory):
    """Test standard node@host:port address
    """
    l1, l2, l3 = node_factory.get_nodes(3)

    # node@host
    ret = l1.rpc.connect("{}@{}".format(l2.info['id'], 'localhost'), port=l2.port)
    assert ret['id'] == l2.info['id']

    # node@host:port
    ret = l1.rpc.connect("{}@localhost:{}".format(l3.info['id'], l3.port))
    assert ret['id'] == l3.info['id']

    # node@[ipv6]:port --- not supported by our CI
    # ret = l1.rpc.connect("{}@[::1]:{}".format(l3.info['id'], l3.port))
    # assert ret['id'] == l3.info['id']


def test_reconnect_channel_peers(node_factory, executor):
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 10**6)
    l2.restart()

    # Should reconnect.
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    wait_for(lambda: only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])
    # Connect command should succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Stop l2 and wait for l1 to notice.
    l2.stop()
    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])

    # Now should fail.
    with pytest.raises(RpcError, match=r'Connection refused'):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Wait for exponential backoff to give us a 2 second window.
    l1.daemon.wait_for_log('Will try reconnect in 2 seconds')

    # It should now succeed when it restarts.
    l2.start()

    # Multiples should be fine!
    fut1 = executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
    fut2 = executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
    fut3 = executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
    fut1.result(10)
    fut2.result(10)
    fut3.result(10)


def test_balance(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=True)
    p1 = only_one(l1.rpc.getpeer(peer_id=l2.info['id'], level='info')['channels'])
    p2 = only_one(l2.rpc.getpeer(l1.info['id'], 'info')['channels'])
    assert p1['msatoshi_to_us'] == 10**6 * 1000
    assert p1['msatoshi_total'] == 10**6 * 1000
    assert p2['msatoshi_to_us'] == 0
    assert p2['msatoshi_total'] == 10**6 * 1000


def test_bad_opening(node_factory):
    # l1 asks for a too-long locktime
    l1 = node_factory.get_node(options={'watchtime-blocks': 100})
    l2 = node_factory.get_node(options={'max-locktime-blocks': 99})
    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('openingd-.*: Handed peer, entering loop')
    l2.daemon.wait_for_log('openingd-.*: Handed peer, entering loop')

    l1.fundwallet(10**6 + 1000000)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    l2.daemon.wait_for_log('to_self_delay 100 larger than 99')


def test_second_channel(node_factory):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()
    l3 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.fund_channel(l2, 10**6)
    l1.fund_channel(l3, 10**6)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_disconnect(node_factory):
    # These should all make us fail
    disconnects = ['-WIRE_INIT',
                   '@WIRE_INIT',
                   '+WIRE_INIT']
    l1 = node_factory.get_node(disconnect=disconnects)
    l2 = node_factory.get_node()

    with pytest.raises(RpcError):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Should have 3 connect fails.
    for d in disconnects:
        l1.daemon.wait_for_log('Failed connected out for {}'
                               .format(l2.info['id']))

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_disconnect_funder(node_factory):
    # Now error on funder side duringchannel open.
    disconnects = ['-WIRE_OPEN_CHANNEL',
                   '@WIRE_OPEN_CHANNEL',
                   '+WIRE_OPEN_CHANNEL',
                   '-WIRE_FUNDING_CREATED',
                   '@WIRE_FUNDING_CREATED']
    l1 = node_factory.get_node(disconnect=disconnects)
    l2 = node_factory.get_node()

    l1.fundwallet(2000000)

    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.fundchannel(l2.info['id'], 20000)
        assert l1.rpc.getpeer(l2.info['id']) is None

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 20000)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_disconnect_fundee(node_factory):
    # Now error on fundee side during channel open.
    disconnects = ['-WIRE_ACCEPT_CHANNEL',
                   '@WIRE_ACCEPT_CHANNEL',
                   '+WIRE_ACCEPT_CHANNEL']
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.fundwallet(2000000)

    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.fundchannel(l2.info['id'], 20000)
        assert l1.rpc.getpeer(l2.info['id']) is None

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 20000)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_disconnect_half_signed(node_factory):
    # Now, these are the corner cases.  Fundee sends funding_signed,
    # but funder doesn't receive it.
    disconnects = ['@WIRE_FUNDING_SIGNED']
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.fundwallet(2000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 20000)

    # Fundee remembers, funder doesn't.
    assert l1.rpc.getpeer(l2.info['id']) is None
    assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_signed(node_factory):
    # This will fail *after* both sides consider channel opening.
    disconnects = ['+WIRE_FUNDING_SIGNED']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)

    l1.fundwallet(2000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 20000)

    # They haven't forgotten each other.
    assert l1.rpc.getpeer(l2.info['id'])['id'] == l2.info['id']
    assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

    # Technically, this is async to fundchannel (and could reconnect first)
    l1.daemon.wait_for_logs(['sendrawtx exit 0',
                             'Peer has reconnected, state CHANNELD_AWAITING_LOCKIN'])

    l1.bitcoin.generate_block(6)

    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(' to CHANNELD_NORMAL')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_openingd(node_factory):
    # Openingd thinks we're still opening; funder reconnects..
    disconnects = ['0WIRE_ACCEPT_CHANNEL']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundwallet(2000000)

    # l2 closes on l1, l1 forgets.
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 20000)
    assert l1.rpc.getpeer(l2.info['id']) is None

    # Reconnect.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We should get a message about reconnecting.
    l2.daemon.wait_for_log('Killing openingd: Reconnected')
    l2.daemon.wait_for_log('lightning_openingd.*Handed peer, entering loop')

    # Should work fine.
    l1.rpc.fundchannel(l2.info['id'], 20000)
    l1.daemon.wait_for_log('sendrawtx exit 0')

    # Just to be sure, second openingd hand over to channeld.
    l2.daemon.wait_for_log('lightning_openingd.*UPDATE WIRE_OPENING_FUNDEE')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_gossiping(node_factory):
    # connectd thinks we're still gossiping; peer reconnects.
    disconnects = ['0WIRE_PING']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l2.rpc.ping(l1.info['id'], 1, 65532)
    l1.daemon.wait_for_log('Forgetting peer')

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('processing now old peer gone')


def test_connect_stresstest(node_factory, executor):
    # This test is unreliable, but it's better than nothing.
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l3 = node_factory.get_node(may_reconnect=True)

    # Hack l3 into a clone of l2, to stress reconnect code.
    l3.stop()
    shutil.copyfile(os.path.join(l2.daemon.lightning_dir, 'hsm_secret'),
                    os.path.join(l3.daemon.lightning_dir, 'hsm_secret'))
    l3.start()
    l3.info = l3.rpc.getinfo()

    assert l3.info['id'] == l2.info['id']

    # We fire off random connect/disconnect commands.
    actions = [
        (l2.rpc.connect, l1.info['id'], 'localhost', l1.port),
        (l3.rpc.connect, l1.info['id'], 'localhost', l3.port),
        (l1.rpc.connect, l2.info['id'], 'localhost', l2.port),
        (l1.rpc.connect, l3.info['id'], 'localhost', l3.port),
        (l1.rpc.disconnect, l2.info['id'])
    ]
    args = [random.choice(actions) for _ in range(1000)]

    # We get them all to connect to each other.
    futs = []
    for a in args:
        futs.append(executor.submit(*a))

    # We don't actually care if they fail, since some will.
    successes = 0
    failures = 0
    for f in futs:
        if f.exception():
            failures += 1
        else:
            f.result()
            successes += 1

    assert successes > failures


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_normal(node_factory):
    # Should reconnect fine even if locked message gets lost.
    disconnects = ['-WIRE_FUNDING_LOCKED',
                   '@WIRE_FUNDING_LOCKED',
                   '+WIRE_FUNDING_LOCKED']
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 10**6)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_sender_add1(node_factory):
    # Fail after add is OK, will cause payment failure though.
    disconnects = ['-WIRE_UPDATE_ADD_HTLC-nocommit',
                   '+WIRE_UPDATE_ADD_HTLC-nocommit',
                   '@WIRE_UPDATE_ADD_HTLC-nocommit']

    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True,
                               feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 10**6)

    amt = 200000000
    rhash = l2.rpc.invoice(amt, 'test_reconnect_sender_add1', 'desc')['payment_hash']
    assert only_one(l2.rpc.listinvoices('test_reconnect_sender_add1')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]

    for i in range(0, len(disconnects)):
        l1.rpc.sendpay(route, rhash)
        with pytest.raises(RpcError):
            l1.rpc.waitsendpay(rhash)

        # Wait for reconnection.
        l1.daemon.wait_for_log('Already have funding locked in')

    # This will send commit, so will reconnect as required.
    l1.rpc.sendpay(route, rhash)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_sender_add(node_factory):
    disconnects = ['-WIRE_COMMITMENT_SIGNED',
                   '@WIRE_COMMITMENT_SIGNED',
                   '+WIRE_COMMITMENT_SIGNED',
                   '-WIRE_REVOKE_AND_ACK',
                   '@WIRE_REVOKE_AND_ACK',
                   '+WIRE_REVOKE_AND_ACK']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True,
                               feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 10**6)

    amt = 200000000
    rhash = l2.rpc.invoice(amt, 'testpayment', 'desc')['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]

    # This will send commit, so will reconnect as required.
    l1.rpc.sendpay(route, rhash)
    # Should have printed this for every reconnect.
    for i in range(0, len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_receiver_add(node_factory):
    disconnects = ['-WIRE_COMMITMENT_SIGNED',
                   '@WIRE_COMMITMENT_SIGNED',
                   '+WIRE_COMMITMENT_SIGNED',
                   '-WIRE_REVOKE_AND_ACK',
                   '@WIRE_REVOKE_AND_ACK',
                   '+WIRE_REVOKE_AND_ACK']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(may_reconnect=True, feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 10**6)

    amt = 200000000
    rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]
    l1.rpc.sendpay(route, rhash)
    for i in range(len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_reconnect_receiver_fulfill(node_factory):
    # Ordering matters: after +WIRE_UPDATE_FULFILL_HTLC, channeld
    # will continue and try to send WIRE_COMMITMENT_SIGNED: if
    # that's the next failure, it will do two in one run.
    disconnects = ['@WIRE_UPDATE_FULFILL_HTLC',
                   '+WIRE_UPDATE_FULFILL_HTLC',
                   '-WIRE_UPDATE_FULFILL_HTLC',
                   '-WIRE_COMMITMENT_SIGNED',
                   '@WIRE_COMMITMENT_SIGNED',
                   '+WIRE_COMMITMENT_SIGNED',
                   '-WIRE_REVOKE_AND_ACK',
                   '@WIRE_REVOKE_AND_ACK',
                   '+WIRE_REVOKE_AND_ACK']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 10**6)

    amt = 200000000
    rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]
    l1.rpc.sendpay(route, rhash)
    for i in range(len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_shutdown_reconnect(node_factory):
    disconnects = ['-WIRE_SHUTDOWN',
                   '@WIRE_SHUTDOWN',
                   '+WIRE_SHUTDOWN']
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    chan = l1.fund_channel(l2, 10**6)
    l1.pay(l2, 200000000)

    assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

    # This should return with an error, then close.
    with pytest.raises(RpcError, match=r'Channel close negotiation not finished'):
        l1.rpc.close(chan, False, 0)

    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
    l2.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')

    l1.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')
    l2.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')

    # And should put closing into mempool (happens async, so
    # CLOSINGD_COMPLETE may come first).
    l1.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    l2.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1


def test_shutdown_awaiting_lockin(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'funding-confirms': 3})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundwallet(10**6 + 1000000)
    chanid = l1.rpc.fundchannel(l2.info['id'], 10**6)['channel_id']

    # Technically, this is async to fundchannel.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)

    # This should return with an error, then close.
    with pytest.raises(RpcError, match=r'Channel close negotiation not finished'):
        l1.rpc.close(chanid, False, 0)

    l1.daemon.wait_for_log('CHANNELD_AWAITING_LOCKIN to CHANNELD_SHUTTING_DOWN')
    l2.daemon.wait_for_log('CHANNELD_AWAITING_LOCKIN to CHANNELD_SHUTTING_DOWN')

    l1.daemon.wait_for_log('CHANNELD_SHUTTING_DOWN to CLOSINGD_SIGEXCHANGE')
    l2.daemon.wait_for_log('CHANNELD_SHUTTING_DOWN to CLOSINGD_SIGEXCHANGE')

    # And should put closing into mempool (happens async, so
    # CLOSINGD_COMPLETE may come first).
    l1.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    l2.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    assert bitcoind.rpc.getmempoolinfo()['size'] == 1

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(100)
    wait_for(lambda: l1.rpc.listpeers()['peers'] == [])
    wait_for(lambda: l2.rpc.listpeers()['peers'] == [])


def test_funding_change(node_factory, bitcoind):
    """Add some funds, fund a channel, and make sure we remember the change
    """
    l1, l2 = node_factory.line_graph(2, fundchannel=False)
    l1.fundwallet(10000000)
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 10000000

    l1.rpc.fundchannel(l2.info['id'], 1000000)
    outputs = {r['status']: r['value'] for r in l1.db_query(
        'SELECT status, SUM(value) AS value FROM outputs GROUP BY status;')}

    # The 10m out is spent and we have a change output of 9m-fee
    assert outputs[0] > 8990000
    assert outputs[2] == 10000000


def test_funding_all(node_factory, bitcoind):
    """Add some funds, fund a channel using all funds, make sure no funds remain
    """
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    l1.fundwallet(0.1 * 10**8)
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 10000000

    l1.rpc.fundchannel(l2.info['id'], "all")

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert len(outputs) == 0


def test_funding_all_too_much(node_factory):
    """Add more than max possible funds, fund a channel using all funds we can.
    """
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    l1.fundwallet(2**24 + 10000)
    l1.rpc.fundchannel(l2.info['id'], "all")

    assert only_one(l1.rpc.listfunds()['outputs'])['status'] == 'unconfirmed'
    assert only_one(l1.rpc.listfunds()['channels'])['channel_total_sat'] == 2**24 - 1


def test_funding_fail(node_factory, bitcoind):
    """Add some funds, fund a channel without enough funds"""
    # Previous runs with same bitcoind can leave funds!
    max_locktime = 5 * 6 * 24
    l1 = node_factory.get_node(random_hsm=True, options={'max-locktime-blocks': max_locktime})
    l2 = node_factory.get_node(options={'watchtime-blocks': max_locktime + 1})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    funds = 1000000

    addr = l1.rpc.newaddr()['address']
    l1.bitcoin.rpc.sendtoaddress(addr, funds / 10**8)
    bitcoind.generate_block(1)

    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fail because l1 dislikes l2's huge locktime.
    with pytest.raises(RpcError, match=r'to_self_delay \d+ larger than \d+'):
        l1.rpc.fundchannel(l2.info['id'], int(funds / 10))

    assert only_one(l1.rpc.listpeers()['peers'])['connected']
    assert only_one(l2.rpc.listpeers()['peers'])['connected']

    # Restart l2 without ridiculous locktime.
    del l2.daemon.opts['watchtime-blocks']
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We don't have enough left to cover fees if we try to spend it all.
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
        l1.rpc.fundchannel(l2.info['id'], funds)

    # Should still be connected.
    assert only_one(l1.rpc.listpeers()['peers'])['connected']
    l2.daemon.wait_for_log('lightning_openingd-.*: Handed peer, entering loop')
    assert only_one(l2.rpc.listpeers()['peers'])['connected']

    # This works.
    l1.rpc.fundchannel(l2.info['id'], int(funds / 10))


def test_funding_toolarge(node_factory, bitcoind):
    """Try to create a giant channel"""
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Send funds.
    amount = 2**24
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['address'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)

    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fail to open (too large)
    with pytest.raises(RpcError, match=r'Amount exceeded 16777215'):
        l1.rpc.fundchannel(l2.info['id'], amount)

    # This should work.
    amount = amount - 1
    l1.rpc.fundchannel(l2.info['id'], amount)


def test_lockin_between_restart(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(options={'funding-confirms': 3},
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundwallet(10**6 + 1000000)
    l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']

    # l1 goes down.
    l1.stop()

    # Now 120 blocks go by...
    bitcoind.generate_block(120)

    # Restart
    l1.start()

    # All should be good.
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(' to CHANNELD_NORMAL')


def test_funding_while_offline(node_factory, bitcoind):
    l1 = node_factory.get_node()
    addr = l1.rpc.newaddr()['address']
    sync_blockheight(bitcoind, [l1])

    # l1 goes down.
    l1.stop()

    # We send funds
    bitcoind.rpc.sendtoaddress(addr, (10**6 + 1000000) / 10**8)

    # Now 120 blocks go by...
    bitcoind.generate_block(120)

    # Restart
    l1.start()
    sync_blockheight(bitcoind, [l1])

    assert len(l1.rpc.listfunds()['outputs']) == 1


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_channel_persistence(node_factory, bitcoind, executor):
    # Start two nodes and open a channel (to remember). l2 will
    # mysteriously die while committing the first HTLC so we can
    # check that HTLCs reloaded from the DB work.
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(may_reconnect=True, feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'],
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Neither node should have a channel open, they are just connected
    for n in (l1, l2):
        assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 0)

    l1.fund_channel(l2, 100000)

    peers = l1.rpc.listpeers()['peers']
    assert(only_one(peers[0]['channels'])['state'] == 'CHANNELD_NORMAL')

    # Both nodes should now have exactly one channel in the database
    for n in (l1, l2):
        assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 1)

    # Fire off a sendpay request, it'll get interrupted by a restart
    executor.submit(l1.pay, l2, 10000)
    # Wait for it to be committed to, i.e., stored in the DB
    l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # Stop l2, l1 will reattempt to connect
    print("Killing l2 in mid HTLC")
    l2.daemon.kill()

    # Clear the disconnect and timer stop so we can proceed normally
    del l2.daemon.opts['dev-disconnect']

    # Wait for l1 to notice
    wait_for(lambda: 'connected' not in only_one(l1.rpc.listpeers()['peers'][0]['channels']))

    # Now restart l2 and it should reload peers/channels from the DB
    l2.start()
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 1)

    # Wait for the restored HTLC to finish
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99990000, interval=1)

    wait_for(lambda: len([p for p in l1.rpc.listpeers()['peers'] if p['connected']]), interval=1)
    wait_for(lambda: len([p for p in l2.rpc.listpeers()['peers'] if p['connected']]), interval=1)

    # Now make sure this is really functional by sending a payment
    l1.pay(l2, 10000)

    # L1 doesn't actually update msatoshi_to_us until it receives
    # revoke_and_ack from L2, which can take a little bit.
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99980000)
    assert only_one(l2.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 20000

    # Finally restart l1, and make sure it remembers
    l1.restart()
    assert only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99980000

    # Now make sure l1 is watching for unilateral closes
    l2.rpc.dev_fail(l1.info['id'])
    l2.daemon.wait_for_log('Failing due to dev-fail command')
    l2.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)

    # L1 must notice.
    l1.daemon.wait_for_log(' to ONCHAIN')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
def test_channel_reenable(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True}, fundchannel=True, announce=True)

    l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))
    l2.daemon.wait_for_log('Received node_announcement for node {}'.format(l1.info['id']))

    # Both directions should be active before the restart
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])

    # Restart l2, will cause l1 to reconnect
    l2.stop()
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [False, False])
    l2.start()

    # Updates may be suppressed if redundant; just test results.
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels()['channels']] == [True, True])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_update_fee(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=True)
    chanid = l1.get_channel_scid(l2)

    # Make l1 send out feechange.
    l1.set_feerates((14000, 7500, 3750))
    l2.daemon.wait_for_log('peer updated fee to 14000')

    # Now make sure an HTLC works.
    # (First wait for route propagation.)
    l1.wait_channel_active(chanid)
    sync_blockheight(bitcoind, [l1, l2])

    # Make payments.
    l1.pay(l2, 200000000)
    l2.pay(l1, 100000000)

    # Now shutdown cleanly.
    with pytest.raises(RpcError, match=r'Channel close negotiation not finished'):
        l1.rpc.close(chanid, False, 0)

    l1.daemon.wait_for_log(' to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log(' to CLOSINGD_COMPLETE')

    # And should put closing into mempool.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(99)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_fee_limits(node_factory):
    # FIXME: Test case where opening denied.
    l1, l2 = node_factory.line_graph(2, opts={'dev-max-fee-multiplier': 5, 'may_reconnect': True}, fundchannel=True)

    # L1 asks for stupid low fee (will actually hit the floor of 253)
    l1.stop()
    l1.set_feerates((15, 15, 15), False)
    l1.start()

    l1.daemon.wait_for_log('Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: received ERROR channel .*: update_fee 253 outside range 1875-75000')
    # Make sure the resolution of this one doesn't interfere with the next!
    # Note: may succeed, may fail with insufficient fee, depending on how
    # bitcoind feels!
    l1.daemon.wait_for_log('sendrawtx exit')

    # Restore to normal.
    l1.stop()
    l1.set_feerates((15000, 7500, 3750), False)
    l1.start()

    # Try with node which sets --ignore-fee-limits
    l3 = node_factory.get_node(options={'ignore-fee-limits': 'true'}, may_reconnect=True)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    chan = l1.fund_channel(l3, 10**6)

    # Try stupid high fees
    l1.stop()
    l1.set_feerates((15000 * 10, 7500, 3750), False)
    l1.start()

    l3.daemon.wait_for_log('peer_in WIRE_UPDATE_FEE')
    l3.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # We need to wait until both have committed and revoked the
    # old state, otherwise we'll still try to commit with the old
    # 15sat/byte fee
    l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

    # This should wait for close to complete
    l1.rpc.close(chan)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_update_fee_reconnect(node_factory, bitcoind):
    # Disconnect after first commitsig.
    disconnects = ['+WIRE_COMMITMENT_SIGNED']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects, may_reconnect=True,
                               feerates=(15000, 15000, 3750))
    # We match l2's later feerate, so we agree on same closing tx for simplicity.
    l2 = node_factory.get_node(may_reconnect=True,
                               feerates=(14000, 14000, 3750))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chan = l1.fund_channel(l2, 10**6)

    # Make l1 send out feechange; triggers disconnect/reconnect.
    # (Note: < 10% change, so no smoothing here!)
    l1.set_feerates((14000, 14000, 3750))
    l1.daemon.wait_for_log('Setting REMOTE feerate to 14000')
    l2.daemon.wait_for_log('Setting LOCAL feerate to 14000')
    l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    # Wait for reconnect....
    l1.daemon.wait_for_log('Applying feerate 14000 to LOCAL')

    l1.pay(l2, 200000000)
    l2.pay(l1, 100000000)

    # They should both have gotten commits with correct feerate.
    assert l1.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')
    assert l2.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')

    # Now shutdown cleanly.
    l1.rpc.close(chan)

    # And should put closing into mempool.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(99)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
def test_multiple_channels(node_factory):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    for i in range(3):
        # FIXME: we shouldn't disconnect on close?
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('openingd-.*: Handed peer, entering loop')
        l2.daemon.wait_for_log('openingd-.*: Handed peer, entering loop')
        chan = l1.fund_channel(l2, 10**6)

        l1.rpc.close(chan)

    channels = only_one(l1.rpc.listpeers()['peers'])['channels']
    assert len(channels) == 3
    # Most in state ONCHAIN, last is CLOSINGD_COMPLETE
    for i in range(len(channels) - 1):
        assert channels[i]['state'] == 'ONCHAIN'
    assert channels[-1]['state'] == 'CLOSINGD_COMPLETE'


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_forget_channel(node_factory):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()
    l1.fundwallet(10**6)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 10**5)

    assert len(l1.rpc.listpeers()['peers']) == 1

    # This should fail, the funding tx is in the mempool and may confirm
    with pytest.raises(RpcError, match=r'Cowardly refusing to forget channel'):
        l1.rpc.dev_forget_channel(l2.info['id'])

    assert len(l1.rpc.listpeers()['peers']) == 1

    # Forcing should work
    l1.rpc.dev_forget_channel(l2.info['id'], True)
    assert len(l1.rpc.listpeers()['peers']) == 0

    # And restarting should keep that peer forgotten
    l1.restart()
    assert len(l1.rpc.listpeers()['peers']) == 0


def test_peerinfo(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts={'may_reconnect': True})
    # Gossiping but no node announcement yet
    assert l1.rpc.getpeer(l2.info['id'])['connected']
    assert len(l1.rpc.getpeer(l2.info['id'])['channels']) == 0
    assert l1.rpc.getpeer(l2.info['id'])['local_features'] == '8a'
    assert l1.rpc.getpeer(l2.info['id'])['global_features'] == ''

    # Fund a channel to force a node announcement
    chan = l1.fund_channel(l2, 10**6)
    # Now proceed to funding-depth and do a full gossip round
    bitcoind.generate_block(5)
    l1.daemon.wait_for_logs(['Received node_announcement for node ' + l2.info['id']])
    l2.daemon.wait_for_logs(['Received node_announcement for node ' + l1.info['id']])

    # Should have announced the same global features as told to peer.
    nodes1 = l1.rpc.listnodes(l2.info['id'])['nodes']
    nodes2 = l2.rpc.listnodes(l2.info['id'])['nodes']
    peer1 = l1.rpc.getpeer(l2.info['id'])
    peer2 = l2.rpc.getpeer(l1.info['id'])
    assert only_one(nodes1)['global_features'] == peer1['global_features']
    assert only_one(nodes2)['global_features'] == peer2['global_features']

    assert l1.rpc.getpeer(l2.info['id'])['local_features'] == '8a'
    assert l2.rpc.getpeer(l1.info['id'])['local_features'] == '8a'

    # If it reconnects after db load, it should know features.
    l1.restart()
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'])
    wait_for(lambda: l2.rpc.getpeer(l1.info['id'])['connected'])
    assert l1.rpc.getpeer(l2.info['id'])['local_features'] == '8a'
    assert l2.rpc.getpeer(l1.info['id'])['local_features'] == '8a'

    # Close the channel to forget the peer
    with pytest.raises(RpcError, match=r'Channel close negotiation not finished'):
        l1.rpc.close(chan, False, 0)

    l1.daemon.wait_for_log('Forgetting peer')
    bitcoind.generate_block(100)
    l1.daemon.wait_for_log('WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED')
    l2.daemon.wait_for_log('WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED')

    # The only channel was closed, everybody should have forgotten the nodes
    assert l1.rpc.listnodes()['nodes'] == []
    assert l2.rpc.listnodes()['nodes'] == []


def test_disconnectpeer(node_factory, bitcoind):
    l1, l2, l3 = node_factory.get_nodes(3, opts={'may_reconnect': False})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Gossiping
    assert l1.rpc.getpeer(l2.info['id'])['connected']
    assert len(l1.rpc.getpeer(l2.info['id'])['channels']) == 0
    assert l1.rpc.getpeer(l3.info['id'])['connected']
    assert len(l1.rpc.getpeer(l3.info['id'])['channels']) == 0
    wait_for(lambda: l2.rpc.getpeer(l1.info['id']) is not None)

    # Disconnect l2 from l1
    l1.rpc.disconnect(l2.info['id'])

    # Make sure listpeers no longer returns the disconnected node
    assert l1.rpc.getpeer(l2.info['id']) is None
    wait_for(lambda: l2.rpc.getpeer(l1.info['id']) is None)

    # Make sure you cannot disconnect after disconnecting
    with pytest.raises(RpcError, match=r'Peer not connected'):
        l1.rpc.disconnect(l2.info['id'])
    with pytest.raises(RpcError, match=r'Peer not connected'):
        l2.rpc.disconnect(l1.info['id'])

    # Fund channel l1 -> l3
    l1.fund_channel(l3, 10**6)
    bitcoind.generate_block(5)

    # disconnecting a non gossiping peer results in error
    with pytest.raises(RpcError, match=r'Peer is in state CHANNELD_NORMAL'):
        l1.rpc.disconnect(l3.info['id'])


@unittest.skipIf(not DEVELOPER, "needs --dev-max-funding-unconfirmed-blocks")
def test_fundee_forget_funding_tx_unconfirmed(node_factory, bitcoind):
    """Test that fundee will forget the channel if
    the funding tx has been unconfirmed for too long.
    """
    # Keep this low (default is 2016), since everything
    # is much slower in VALGRIND mode and wait_for_log
    # could time out before lightningd processes all the
    # blocks.
    blocks = 200
    # funder
    l1 = node_factory.get_node()
    # fundee
    l2 = node_factory.get_node(options={"dev-max-funding-unconfirmed-blocks": blocks})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Give funder some funds.
    l1.fundwallet(10**7)
    # Let blocks settle.
    time.sleep(1)

    # Prevent funder from broadcasting funding tx.
    l1.bitcoind_cmd_override('exit 1')
    # Fund the channel.
    # The process will complete, but funder will be unable
    # to broadcast and confirm funding tx.
    l1.rpc.fundchannel(l2.info['id'], 10**6)
    # Prevent l1 from timing out bitcoin-cli.
    l1.bitcoind_cmd_remove_override()
    # Generate blocks until unconfirmed.
    bitcoind.generate_block(blocks)

    # fundee will forget channel!
    l2.daemon.wait_for_log('Forgetting channel: It has been {} blocks'.format(blocks))
    # fundee will also forget and disconnect from peer.
    assert len(l2.rpc.listpeers(l1.info['id'])['peers']) == 0


@unittest.skipIf(not DEVELOPER, "needs dev_fail")
def test_no_fee_estimate(node_factory, bitcoind, executor):
    l1 = node_factory.get_node(start=False)
    l1.bitcoind_cmd_override(cmd='estimatesmartfee',
                             failscript="""echo '{ "errors": [ "Insufficient data or no feerate found" ], "blocks": 0 }'; exit 0""")
    l1.start()

    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Can't fund a channel.
    l1.fundwallet(10**7)
    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    # Can't withdraw either.
    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.withdraw(l2.rpc.newaddr()['address'], 'all')

    # Can't use feerate names, either.
    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.withdraw(l2.rpc.newaddr()['address'], 'all', 'urgent')
        l1.rpc.withdraw(l2.rpc.newaddr()['address'], 'all', 'normal')
        l1.rpc.withdraw(l2.rpc.newaddr()['address'], 'all', 'slow')

    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.fundchannel(l2.info['id'], 10**6, 'urgent')
        l1.rpc.fundchannel(l2.info['id'], 10**6, 'normal')
        l1.rpc.fundchannel(l2.info['id'], 10**6, 'slow')

    # Can with manual feerate.
    l1.rpc.withdraw(l2.rpc.newaddr()['address'], 10000, '1500perkb')
    l1.rpc.fundchannel(l2.info['id'], 10**6, '2000perkw')

    # Make sure we clean up cahnnel for later attempt.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.rpc.dev_fail(l2.info['id'])
    l1.daemon.wait_for_log('Failing due to dev-fail command')
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(6)
    wait_for(lambda: only_one(l1.rpc.getpeer(l2.info['id'])['channels'])['state'] == 'ONCHAIN')
    wait_for(lambda: only_one(l2.rpc.getpeer(l1.info['id'])['channels'])['state'] == 'ONCHAIN')

    # But can accept incoming connections.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.fund_channel(l1, 10**6)

    # Can do HTLCs.
    l2.pay(l1, 10**5)

    # Can do mutual close.
    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(100)

    # Can do unilateral close.
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.fund_channel(l1, 10**6)
    l2.pay(l1, 10**9 // 2)
    l1.rpc.dev_fail(l2.info['id'])
    l1.daemon.wait_for_log('Failing due to dev-fail command')
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(5)
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(100)

    # Start estimatesmartfee.
    l1.set_feerates((15000, 7500, 3750), True)

    # Can now fund a channel (as a test, use slow feerate).
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 10**6, 'slow')

    # Can withdraw (use urgent feerate).
    l1.rpc.withdraw(l2.rpc.newaddr()['address'], 'all', 'urgent')


@unittest.skipIf(not DEVELOPER, "needs --dev-disconnect")
def test_funder_feerate_reconnect(node_factory, bitcoind):
    # l1 updates fees, then reconnect so l2 retransmits commitment_signed.
    disconnects = ['-WIRE_COMMITMENT_SIGNED']
    l1 = node_factory.get_node(may_reconnect=True,
                               feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects, may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    # create fee update, causing disconnect.
    l1.set_feerates((15000, 7500, 3750))
    l2.daemon.wait_for_log('dev_disconnect: \-WIRE_COMMITMENT_SIGNED')

    # Wait until they reconnect.
    l1.daemon.wait_for_log('Peer transient failure in CHANNELD_NORMAL')
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'])

    # Should work normally.
    l1.pay(l2, 200000000)


@unittest.skipIf(not DEVELOPER, "needs LIGHTNINGD_DEV_LOG_IO")
def test_dataloss_protection(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True, log_all_io=True)
    l2 = node_factory.get_node(may_reconnect=True, log_all_io=True)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l1 should send out WIRE_INIT (0010)
    l1.daemon.wait_for_log("\[OUT\] 0010"
                           # gflen == 0
                           "0000"
                           # lflen == 1
                           "0001"
                           # Local features 1, 3 and 7 (0x8a).
                           "8a")

    l1.fund_channel(l2, 10**6)
    l2.stop()

    # Save copy of the db.
    dbpath = os.path.join(l2.daemon.lightning_dir, "lightningd.sqlite3")
    orig_db = open(dbpath, "rb").read()
    l2.start()

    # l1 should have sent WIRE_CHANNEL_REESTABLISH with option_data_loss_protect.
    l1.daemon.wait_for_log("\[OUT\] 0088"
                           # channel_id
                           "[0-9a-f]{64}"
                           # next_local_commitment_number
                           "000000000000000[1-9]"
                           # next_remote_revocation_number
                           "000000000000000[0-9]"
                           # your_last_per_commitment_secret (funding_depth may
                           # trigger a fee-update and commit, hence this may not
                           # be zero)
                           "[0-9a-f]{64}"
                           # my_current_per_commitment_point
                           "0[23][0-9a-f]{64}")
    # After an htlc, we should get different results (two more commits)
    l1.pay(l2, 200000000)

    # Make sure both sides consider it completely settled (has received both
    # REVOKE_AND_ACK)
    l1.daemon.wait_for_logs(["\[IN\] 0085"] * 2)
    l2.daemon.wait_for_logs(["\[IN\] 0085"] * 2)

    l2.restart()

    # l1 should have sent WIRE_CHANNEL_REESTABLISH with option_data_loss_protect.
    l1.daemon.wait_for_log("\[OUT\] 0088"
                           # channel_id
                           "[0-9a-f]{64}"
                           # next_local_commitment_number
                           "000000000000000[1-9]"
                           # next_remote_revocation_number
                           "000000000000000[1-9]"
                           # your_last_per_commitment_secret
                           "[0-9a-f]{64}"
                           # my_current_per_commitment_point
                           "0[23][0-9a-f]{64}")

    # Now, move l2 back in time.
    l2.stop()
    # Overwrite with OLD db.
    open(dbpath, "wb").write(orig_db)
    l2.start()

    # l2 should freak out!
    l2.daemon.wait_for_log("Peer permanent failure in CHANNELD_NORMAL: Awaiting unilateral close")

    # l1 should drop to chain.
    l1.daemon.wait_for_log('sendrawtx exit 0')

    # l2 must NOT drop to chain.
    l2.daemon.wait_for_log("Cannot broadcast our commitment tx: they have a future one")
    assert not l2.daemon.is_in_log('sendrawtx exit 0')

    closetxid = only_one(bitcoind.rpc.getrawmempool(False))

    # l2 should still recover something!
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log("ERROR: Unknown commitment #[0-9], recovering our funds!")

    # Restarting l2, and it should remember from db.
    l2.restart()

    l2.daemon.wait_for_log("ERROR: Unknown commitment #[0-9], recovering our funds!")
    bitcoind.generate_block(100)
    l2.daemon.wait_for_log('WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED')

    # l2 should have it in wallet.
    assert (closetxid, "confirmed") in set([(o['txid'], o['status']) for o in l2.rpc.listfunds()['outputs']])


@unittest.skipIf(not DEVELOPER, "needs dev_disconnect")
def test_restart_multi_htlc_rexmit(node_factory, bitcoind, executor):
    # l1 disables commit timer once we send first htlc, dies on commit
    disconnects = ['=WIRE_UPDATE_ADD_HTLC-nocommit',
                   '-WIRE_COMMITMENT_SIGNED']
    l1, l2 = node_factory.line_graph(2, opts=[{'disconnect': disconnects,
                                               'may_reconnect': True},
                                              {'may_reconnect': True}])

    executor.submit(l1.pay, l2, 20000)
    executor.submit(l1.pay, l2, 30000)

    l1.daemon.wait_for_logs(['peer_out WIRE_UPDATE_ADD_HTLC'] * 2)
    l1.rpc.dev_reenable_commit(l2.info['id'])
    l1.daemon.wait_for_log('dev_disconnect: -WIRE_COMMITMENT_SIGNED')

    # This will make it reconnect
    l1.stop()
    # Clear the disconnect so we can proceed normally
    del l1.daemon.opts['dev-disconnect']
    l1.start()

    # Payments will fail due to restart, but we can see results in listpayments.
    print(l1.rpc.listpayments())
    wait_for(lambda: [p['status'] for p in l1.rpc.listpayments()['payments']] == ['complete', 'complete'])
