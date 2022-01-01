from collections import namedtuple
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from flaky import flaky  # noqa: F401
from ephemeral_port_reserve import reserve  # type: ignore
from pyln.client import RpcError, Millisatoshi
import pyln.proto.wire as wire
from utils import (
    only_one, wait_for, sync_blockheight, TIMEOUT,
    expected_peer_features, expected_node_features,
    expected_channel_features,
    check_coin_moves, first_channel_id, account_balance, basic_fee,
    scriptpubkey_addr,
    EXPERIMENTAL_FEATURES, mine_funding_to_announce
)
from pyln.testing.utils import SLOW_MACHINE, VALGRIND, EXPERIMENTAL_DUAL_FUND, FUNDAMOUNT

import os
import pytest
import random
import re
import shutil
import time
import unittest
import websocket


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
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l2.port}

    ret = l2.rpc.connect(l1.info['id'], host='localhost', port=l1.port)
    assert ret['id'] == l1.info['id']
    # FIXME: This gives a bogus address (since they connected to us): better to give none!
    assert 'address' in ret

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1

    if EXPERIMENTAL_FEATURES:
        l1.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")

    # Should get reasonable error if unknown addr for peer.
    with pytest.raises(RpcError, match=r'Unable to connect, no address known'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e')

    # Should get reasonable error if connection refuse.
    with pytest.raises(RpcError, match=r'Connection establishment: Connection refused'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', 1)

    # Should get reasonable error if wrong key for peer.
    with pytest.raises(RpcError, match=r'Cryptographic handshake: peer closed connection \(wrong key\?\)'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', l2.port)


def test_connect_standard_addr(node_factory):
    """Test standard node@host:port address
    """
    l1, l2, l3 = node_factory.get_nodes(3)

    # node@host
    ret = l1.rpc.connect("{}@{}".format(l2.info['id'], 'localhost'), port=l2.port)
    assert ret['id'] == l2.info['id']
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l2.port}

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

    l1.fundchannel(l2, 10**6)
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
    with pytest.raises(RpcError, match=r'(Connection refused|Bad file descriptor)'):
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


def test_connection_moved(node_factory, executor):
    slow_start = os.path.join(os.getcwd(), 'tests/plugins/slow_start.py')
    options = {'may_reconnect': True, 'plugin': slow_start}
    l1, l2 = node_factory.get_nodes(2, opts=options)

    # Set up the plugin to wait for a connection
    executor.submit(l1.rpc.waitconn)
    log = l1.daemon.wait_for_log('listening for connections')
    match = re.search(r'on port (\d*)', log)
    assert match and len(match.groups()) == 1
    hang_port = match.groups()[0]

    # Attempt connection
    fut_hang = executor.submit(l1.rpc.connect, l2.info['id'],
                               'localhost', hang_port)
    l1.daemon.wait_for_log('connection from')

    # Provide correct connection details
    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l2.port}

    # If we failed to update the connection, this call will error
    fut_hang.result(TIMEOUT)


def test_balance(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=True)
    p1 = only_one(l1.rpc.getpeer(peer_id=l2.info['id'], level='info')['channels'])
    p2 = only_one(l2.rpc.getpeer(l1.info['id'], 'info')['channels'])
    assert p1['msatoshi_to_us'] == 10**6 * 1000
    assert p1['msatoshi_total'] == 10**6 * 1000
    assert p2['msatoshi_to_us'] == 0
    assert p2['msatoshi_total'] == 10**6 * 1000


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_bad_opening(node_factory):
    # l1 asks for a too-long locktime
    l1 = node_factory.get_node(options={'watchtime-blocks': 100})
    l2 = node_factory.get_node(options={'max-locktime-blocks': 99})
    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('Handed peer, entering loop')
    l2.daemon.wait_for_log('Handed peer, entering loop')

    l1.fundwallet(10**6 + 1000000)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    l2.daemon.wait_for_log('to_self_delay 100 larger than 99')


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
@unittest.skipIf(TEST_NETWORK != 'regtest', "Fee computation and limits are network specific")
@pytest.mark.slow_test
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_opening_tiny_channel(node_factory):
    # Test custom min-capacity-sat parameters
    #
    #  [l1]-----> [l2] (~6000)  - technical minimal value that wont be rejected
    #      \
    #       o---> [l3] (10000) - the current default
    #        \
    #         o-> [l4] (20000)  - a node with a higher minimal value
    #
    # For each:
    #  1. Try to establish channel with capacity 1sat smaller than min_capacity_sat
    #  2. Try to establish channel with capacity exact min_capacity_sat
    #
    # BOLT2
    # The receiving node MAY fail the channel if:
    #  - funding_satoshis is too small
    #  - it considers `feerate_per_kw` too small for timely processing or unreasonably large.
    #
    dustlimit = 546
    reserves = 2 * dustlimit
    min_commit_tx_fees = basic_fee(7500)
    overhead = reserves + min_commit_tx_fees
    if EXPERIMENTAL_FEATURES or EXPERIMENTAL_DUAL_FUND:
        # Gotta fund those anchors too!
        overhead += 660

    l2_min_capacity = 1               # just enough to get past capacity filter
    l3_min_capacity = 10000           # the current default
    l4_min_capacity = 20000           # a server with more than default minimum

    opts = [{'min-capacity-sat': 0},
            {'min-capacity-sat': l2_min_capacity},
            {'min-capacity-sat': l3_min_capacity},
            {'min-capacity-sat': l4_min_capacity}]
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)

    with pytest.raises(RpcError, match=r'They sent [error|warning].*channel capacity is .*, which is below .*sat'):
        l1.fundchannel(l2, l2_min_capacity + overhead - 1)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, l2_min_capacity + overhead)

    with pytest.raises(RpcError, match=r'They sent [error|warning].*channel capacity is .*, which is below .*sat'):
        l1.fundchannel(l3, l3_min_capacity + overhead - 1)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.fundchannel(l3, l3_min_capacity + overhead)

    with pytest.raises(RpcError, match=r'They sent [error|warning].*channel capacity is .*, which is below .*sat'):
        l1.fundchannel(l4, l4_min_capacity + overhead - 1)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
    l1.fundchannel(l4, l4_min_capacity + overhead)

    # Note that this check applies locally too, so you can't open it if
    # you would reject it.
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r"channel capacity is .*, which is below .*sat"):
        l3.fundchannel(l2, l3_min_capacity + overhead - 1)
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l3.fundchannel(l2, l3_min_capacity + overhead)


def test_second_channel(node_factory):
    l1, l2, l3 = node_factory.get_nodes(3)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.fundchannel(l2, 10**6)
    l1.fundchannel(l3, 10**6)


def test_channel_abandon(node_factory, bitcoind):
    """Our open tx isn't mined, we doublespend it away"""
    l1, l2 = node_factory.get_nodes(2)

    SATS = 10**6

    # Add some for fees
    l1.fundwallet(SATS + 10000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], SATS, feerate='1875perkw')

    opening_utxo = only_one([o for o in l1.rpc.listfunds()['outputs'] if o['reserved']])
    psbt = l1.rpc.utxopsbt(0, "253perkw", 0, [opening_utxo['txid'] + ':' + str(opening_utxo['output'])], reserve=False, reservedok=True)['psbt']

    # We expect a reservation for 2016 blocks; unreserve it.
    reservations = only_one(l1.rpc.unreserveinputs(psbt, reserve=2015)['reservations'])
    assert reservations['reserved']
    assert reservations['reserved_to_block'] == bitcoind.rpc.getblockchaininfo()['blocks'] + 1

    assert only_one(l1.rpc.unreserveinputs(psbt, reserve=1)['reservations'])['reserved'] is False

    # Now it's unreserved, we can doublespend it (as long as we exceed
    # previous fee to RBF!).
    withdraw = l1.rpc.withdraw(l1.rpc.newaddr()['bech32'], "all")

    assert bitcoind.rpc.decoderawtransaction(withdraw['tx'])['vout'][0]['value'] > SATS / 10**8
    bitcoind.generate_block(1, wait_for_mempool=withdraw['txid'])

    # FIXME: lightningd should notice channel will never now open!
    print(l1.rpc.listpeers())
    assert (only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state']
            == 'CHANNELD_AWAITING_LOCKIN')


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_disconnect(node_factory):
    # These should all make us fail
    disconnects = ['-WIRE_INIT',
                   '+WIRE_INIT']
    l1 = node_factory.get_node(disconnect=disconnects)
    l2 = node_factory.get_node()

    with pytest.raises(RpcError):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Should have 3 connect fails.
    for d in disconnects:
        l1.daemon.wait_for_log('{}-.*Failed connected out'
                               .format(l2.info['id']))

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_disconnect_opener(node_factory):
    # Now error on opener side during channel open.
    disconnects = ['-WIRE_OPEN_CHANNEL',
                   '+WIRE_OPEN_CHANNEL',
                   '-WIRE_FUNDING_CREATED']
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['-WIRE_OPEN_CHANNEL2',
                       '+WIRE_OPEN_CHANNEL2',
                       '-WIRE_TX_ADD_INPUT',
                       '+WIRE_TX_ADD_INPUT',
                       '-WIRE_TX_ADD_OUTPUT',
                       '+WIRE_TX_ADD_OUTPUT',
                       '-WIRE_TX_COMPLETE',
                       '+WIRE_TX_COMPLETE']

    l1 = node_factory.get_node(disconnect=disconnects)
    l2 = node_factory.get_node(may_reconnect=EXPERIMENTAL_DUAL_FUND)

    l1.fundwallet(2000000)

    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.fundchannel(l2.info['id'], 25000)
        assert l1.rpc.getpeer(l2.info['id']) is None

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 25000)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_disconnect_fundee(node_factory):
    # Now error on fundee side during channel open.
    disconnects = ['-WIRE_ACCEPT_CHANNEL',
                   '+WIRE_ACCEPT_CHANNEL']
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['-WIRE_ACCEPT_CHANNEL2',
                       '+WIRE_ACCEPT_CHANNEL2',
                       '-WIRE_TX_COMPLETE',
                       '+WIRE_TX_COMPLETE']

    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.fundwallet(2000000)

    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.fundchannel(l2.info['id'], 25000)
        assert l1.rpc.getpeer(l2.info['id']) is None

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 25000)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.developer
@pytest.mark.openchannel('v2')
def test_disconnect_fundee_v2(node_factory):
    # Now error on fundee side during channel open, with them funding
    disconnects = ['-WIRE_ACCEPT_CHANNEL2',
                   '+WIRE_ACCEPT_CHANNEL2',
                   '-WIRE_TX_ADD_INPUT',
                   '+WIRE_TX_ADD_INPUT',
                   '-WIRE_TX_ADD_OUTPUT',
                   '+WIRE_TX_ADD_OUTPUT',
                   '-WIRE_TX_COMPLETE',
                   '+WIRE_TX_COMPLETE']

    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects,
                               options={'funder-policy': 'match',
                                        'funder-policy-mod': 100,
                                        'funder-fuzz-percent': 0,
                                        'funder-lease-requests-only': False})

    l1.fundwallet(2000000)
    l2.fundwallet(2000000)

    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.fundchannel(l2.info['id'], 25000)
        assert l1.rpc.getpeer(l2.info['id']) is None

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 25000)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_disconnect_half_signed(node_factory):
    # Now, these are the corner cases.  Fundee sends funding_signed,
    # but opener doesn't receive it.
    disconnects = ['-WIRE_FUNDING_SIGNED']
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['-WIRE_COMMITMENT_SIGNED']
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.fundwallet(2000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 25000)

    # Peer remembers, opener doesn't.
    assert l1.rpc.getpeer(l2.info['id']) is None
    assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_signed(node_factory):
    # This will fail *after* both sides consider channel opening.
    disconnects = ['+WIRE_FUNDING_SIGNED']
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['+WIRE_COMMITMENT_SIGNED']

    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)

    l1.fundwallet(2000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 25000)

    # They haven't forgotten each other.
    assert l1.rpc.getpeer(l2.info['id'])['id'] == l2.info['id']
    assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

    # Technically, this is async to fundchannel (and could reconnect first)
    if EXPERIMENTAL_DUAL_FUND:
        l1.daemon.wait_for_logs(['sendrawtx exit 0',
                                 'Peer has reconnected, state DUALOPEND_OPEN_INIT'])
    else:
        l1.daemon.wait_for_logs(['sendrawtx exit 0',
                                 'Peer has reconnected, state CHANNELD_AWAITING_LOCKIN'])

    l1.bitcoin.generate_block(6)

    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(' to CHANNELD_NORMAL')


@pytest.mark.skip('needs blackhold support')
@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_openingd(node_factory):
    # Openingd thinks we're still opening; opener reconnects..
    disconnects = ['0WIRE_ACCEPT_CHANNEL']

    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['0WIRE_ACCEPT_CHANNEL2']

    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundwallet(2000000)

    # l2 closes on l1, l1 forgets.
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 25000)
    assert l1.rpc.getpeer(l2.info['id']) is None

    # Reconnect.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We should get a message about reconnecting.
    l2.daemon.wait_for_log('Killing opening daemon: Reconnected')
    l2.daemon.wait_for_log('Handed peer, entering loop')

    # Should work fine.
    l1.rpc.fundchannel(l2.info['id'], 25000)
    l1.daemon.wait_for_log('sendrawtx exit 0')

    l1.bitcoin.generate_block(3)

    # Just to be sure, second openingd hand over to channeld. This log line is about channeld being started
    l2.daemon.wait_for_log(r'channeld-chan#[0-9]: pid [0-9]+, msgfd [0-9]+')


@pytest.mark.skip('needs blackhold support')
@pytest.mark.developer
def test_reconnect_gossiping(node_factory):
    # connectd thinks we're still gossiping; peer reconnects.
    disconnects = ['0INVALID 33333']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Make sure l2 knows about l1
    wait_for(lambda: l2.rpc.listpeers(l1.info['id'])['peers'] != [])

    l2.rpc.sendcustommsg(l1.info['id'], bytes([0x82, 0x35]).hex())
    wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('processing now old peer gone')


@flaky
@pytest.mark.developer("needs dev-disconnect")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_no_update(node_factory, executor, bitcoind):
    """Test that funding_locked is retransmitted on reconnect if new channel

    This tests if the `funding_locked` is sent if we receive a
    `channel_reestablish` message with `next_commitment_number` == 1
    and our `next_commitment_number` == 1.

    This test makes extensive use of disconnects followed by automatic
    reconnects. See comments for details.

    """
    disconnects = ["-WIRE_FUNDING_LOCKED", "-WIRE_SHUTDOWN"]
    # Allow bad gossip because it might receive WIRE_CHANNEL_UPDATE before
    # announcement of the disconnection
    l1 = node_factory.get_node(may_reconnect=True, allow_bad_gossip=True)
    l2 = node_factory.get_node(disconnect=disconnects, may_reconnect=True)

    # For channeld reconnection
    l1.rpc.connect(l2.info["id"], "localhost", l2.port)

    # LightningNode.fundchannel will fund the channel and generate a
    # block. The block triggers the funding_locked message, which
    # causes a disconnect. The retransmission is then caused by the
    # automatic retry.
    fundchannel_exec = executor.submit(l1.fundchannel, l2, 10**6, False)
    if l1.config('experimental-dual-fund'):
        l1.daemon.wait_for_log(r"dualopend.* Retransmitting funding_locked for channel")
    else:
        l1.daemon.wait_for_log(r"channeld.* Retransmitting funding_locked for channel")
    sync_blockheight(bitcoind, [l1, l2])
    fundchannel_exec.result()
    l1.stop()

    # For closingd reconnection
    l1.daemon.start()
    # Close will trigger the -WIRE_SHUTDOWN and we then wait for the
    # automatic reconnection to trigger the retransmission.
    l1.rpc.close(l2.info['id'], 0)
    l2.daemon.wait_for_log(r"channeld.* Retransmitting funding_locked for channel")
    l1.daemon.wait_for_log(r"CLOSINGD_COMPLETE")


def test_connect_stresstest(node_factory, executor):
    # This test is unreliable, but it's better than nothing.
    l1, l2, l3 = node_factory.get_nodes(3, opts={'may_reconnect': True})

    # Hack l3 into a clone of l2, to stress reconnect code.
    l3.stop()
    shutil.copyfile(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'hsm_secret'),
                    os.path.join(l3.daemon.lightning_dir, TEST_NETWORK, 'hsm_secret'))
    l3.start()
    l3.info = l3.rpc.getinfo()

    assert l3.info['id'] == l2.info['id']

    # We fire off random connect/disconnect commands.
    actions = [
        (l2.rpc.connect, l1.info['id'], 'localhost', l1.port),
        (l3.rpc.connect, l1.info['id'], 'localhost', l1.port),
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


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_normal(node_factory):
    # Should reconnect fine even if locked message gets lost.
    disconnects = ['-WIRE_FUNDING_LOCKED',
                   '+WIRE_FUNDING_LOCKED']
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 10**6)


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_sender_add1(node_factory):
    # Fail after add is OK, will cause payment failure though.
    # Make sure it doesn't send commit before it sees disconnect though.
    disconnects = ['-WIRE_UPDATE_ADD_HTLC',
                   '+WIRE_UPDATE_ADD_HTLC']

    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True,
                               options={'commit-time': 2000},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_reconnect_sender_add1', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l2.rpc.listinvoices('test_reconnect_sender_add1')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1x1x1'}]

    for i in range(0, len(disconnects)):
        with pytest.raises(RpcError):
            l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
            l1.rpc.waitsendpay(rhash)

        # Wait for reconnection.
        l1.daemon.wait_for_log('Already have funding locked in')

    # This will send commit, so will reconnect as required.
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_sender_add(node_factory):
    disconnects = ['-WIRE_COMMITMENT_SIGNED',
                   '+WIRE_COMMITMENT_SIGNED',
                   '-WIRE_REVOKE_AND_ACK',
                   '+WIRE_REVOKE_AND_ACK']
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['=WIRE_COMMITMENT_SIGNED'] + disconnects

    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'testpayment', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1x1x1'}]

    # This will send commit, so will reconnect as required.
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    # Should have printed this for every reconnect.
    for i in range(0, len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_receiver_add(node_factory):
    disconnects = ['-WIRE_COMMITMENT_SIGNED',
                   '+WIRE_COMMITMENT_SIGNED',
                   '-WIRE_REVOKE_AND_ACK',
                   '+WIRE_REVOKE_AND_ACK']

    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['=WIRE_COMMITMENT_SIGNED'] + disconnects

    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(may_reconnect=True, feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'testpayment2', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1x1x1'}]
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    for i in range(len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'


@pytest.mark.developer
def test_reconnect_receiver_fulfill(node_factory):
    # Ordering matters: after +WIRE_UPDATE_FULFILL_HTLC, channeld
    # will continue and try to send WIRE_COMMITMENT_SIGNED: if
    # that's the next failure, it will do two in one run.
    disconnects = ['+WIRE_UPDATE_FULFILL_HTLC',
                   '-WIRE_UPDATE_FULFILL_HTLC',
                   '-WIRE_COMMITMENT_SIGNED',
                   '+WIRE_COMMITMENT_SIGNED',
                   '-WIRE_REVOKE_AND_ACK',
                   '+WIRE_REVOKE_AND_ACK']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'testpayment2', 'desc')
    rhash = inv['payment_hash']
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'unpaid'

    route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1x1x1'}]
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    for i in range(len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'


@flaky
@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_shutdown_reconnect(node_factory):
    disconnects = ['-WIRE_SHUTDOWN',
                   '+WIRE_SHUTDOWN']
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    chan, _ = l1.fundchannel(l2, 10**6)
    l1.pay(l2, 200000000)

    assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

    # This should wait until we're closed.
    l1.rpc.close(chan)

    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
    l2.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')

    l1.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')
    l2.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')

    # And should put closing into mempool (happens async, so
    # CLOSINGD_COMPLETE may come first).
    l1.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    l2.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1


@flaky
@pytest.mark.developer
def test_reconnect_remote_sends_no_sigs(node_factory):
    """We re-announce, even when remote node doesn't send its announcement_signatures on reconnect.
    """
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True, opts={'may_reconnect': True})

    # When l1 restarts (with rescan=1), make it think it hasn't
    # reached announce_depth, so it wont re-send announcement_signatures
    def no_blocks_above(req):
        if req['params'][0] > 107:
            return {"result": None,
                    "error": {"code": -8, "message": "Block height out of range"}, "id": req['id']}
        else:
            return {'result': l1.bitcoin.rpc.getblockhash(req['params'][0]),
                    "error": None, 'id': req['id']}

    l1.daemon.rpcproxy.mock_rpc('getblockhash', no_blocks_above)
    l1.restart()

    # l2 will now uses (REMOTE's) announcement_signatures it has stored
    wait_for(lambda: only_one(l2.rpc.listpeers()['peers'][0]['channels'])['status'] == [
        'CHANNELD_NORMAL:Reconnected, and reestablished.',
        'CHANNELD_NORMAL:Funding transaction locked. Channel announced.'])

    # But l2 still sends its own sigs on reconnect
    l2.daemon.wait_for_logs([r'peer_out WIRE_ANNOUNCEMENT_SIGNATURES',
                             r'peer_out WIRE_ANNOUNCEMENT_SIGNATURES'])

    # l1 only did send them the first time
    assert(''.join(l1.daemon.logs).count(r'peer_out WIRE_ANNOUNCEMENT_SIGNATURES') == 1)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_shutdown_awaiting_lockin(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'funding-confirms': 3})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundwallet(10**6 + 1000000)
    chanid = l1.rpc.fundchannel(l2.info['id'], 10**6)['channel_id']

    # Technically, this is async to fundchannel.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)

    l1.rpc.close(chanid)

    l1_state = 'DUALOPEND' if l1.config('experimental-dual-fund') else 'CHANNELD'
    l2_state = 'DUALOPEND' if l1.config('experimental-dual-fund') else 'CHANNELD'
    l1.daemon.wait_for_log('{}_AWAITING_LOCKIN to CHANNELD_SHUTTING_DOWN'.format(l1_state))
    l2.daemon.wait_for_log('{}_AWAITING_LOCKIN to CHANNELD_SHUTTING_DOWN'.format(l2_state))

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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])
    outputs = {r['status']: r['value'] for r in l1.db_query(
        'SELECT status, SUM(value) AS value FROM outputs GROUP BY status;')}

    # The 10m out is spent and we have a change output of 9m-fee
    assert outputs[0] > 8990000
    assert outputs[2] == 10000000


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_all_too_much(node_factory):
    """Add more than max possible funds, fund a channel using all funds we can.
    """
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    addr, txid = l1.fundwallet(2**24 + 10000)
    l1.rpc.fundchannel(l2.info['id'], "all")

    # One reserved, confirmed output spent above, and one change.
    outputs = l1.rpc.listfunds()['outputs']

    spent = only_one([o for o in outputs if o['status'] == 'confirmed'])

    assert spent['txid'] == txid
    assert spent['address'] == addr
    assert spent['reserved'] is True

    pending = only_one([o for o in outputs if o['status'] != 'confirmed'])
    assert pending['status'] == 'unconfirmed'
    assert pending['reserved'] is False
    assert only_one(l1.rpc.listfunds()['channels'])['channel_total_sat'] == 2**24 - 1


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_fail(node_factory, bitcoind):
    """Add some funds, fund a channel without enough funds"""
    # Previous runs with same bitcoind can leave funds!
    max_locktime = 5 * 6 * 24
    l1 = node_factory.get_node(random_hsm=True, options={'max-locktime-blocks': max_locktime})
    l2 = node_factory.get_node(options={'watchtime-blocks': max_locktime + 1})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    funds = 1000000

    addr = l1.rpc.newaddr()['bech32']
    l1.bitcoin.rpc.sendtoaddress(addr, funds / 10**8)
    bitcoind.generate_block(1)

    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fail because l1 dislikes l2's huge locktime.
    with pytest.raises(RpcError, match=r'to_self_delay \d+ larger than \d+'):
        l1.rpc.fundchannel(l2.info['id'], int(funds / 10))

    # dual-funded channels disconnect on failure
    if not l1.config('experimental-dual-fund'):
        assert only_one(l1.rpc.listpeers()['peers'])['connected']
        assert only_one(l2.rpc.listpeers()['peers'])['connected']
    else:
        assert len(l1.rpc.listpeers()['peers']) == 0
        assert len(l2.rpc.listpeers()['peers']) == 0

    # Restart l2 without ridiculous locktime.
    del l2.daemon.opts['watchtime-blocks']
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We don't have enough left to cover fees if we try to spend it all.
    with pytest.raises(RpcError, match=r'not afford'):
        l1.rpc.fundchannel(l2.info['id'], funds)

    # Should still be connected (we didn't contact the peer)
    assert only_one(l1.rpc.listpeers()['peers'])['connected']
    l2.daemon.wait_for_log('Handed peer, entering loop')
    assert only_one(l2.rpc.listpeers()['peers'])['connected']

    # This works.
    l1.rpc.fundchannel(l2.info['id'], int(funds / 10))


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_toolarge(node_factory, bitcoind):
    """Try to create a giant channel"""
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Send funds.
    amount = 2**24
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)

    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fail to open (too large)
    with pytest.raises(RpcError, match=r'Amount exceeded 16777215'):
        l1.rpc.fundchannel(l2.info['id'], amount)

    # This should work.
    amount = amount - 1
    l1.rpc.fundchannel(l2.info['id'], amount)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
def test_v2_open(node_factory, bitcoind, chainparams):
    l1, l2 = node_factory.get_nodes(2)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    l1.rpc.fundchannel(l2.info['id'], 'all')

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')

    # Send a payment over the channel
    p = l2.rpc.invoice(100000, 'testpayment', 'desc')
    l1.rpc.pay(p['bolt11'])
    result = l1.rpc.waitsendpay(p['payment_hash'])
    assert(result['status'] == 'complete')


@pytest.mark.openchannel('v1')
def test_funding_push(node_factory, bitcoind, chainparams):
    """ Try to push peer some sats """
    # We track balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    l1 = node_factory.get_node(options={'plugin': coin_mvt_plugin})
    l2 = node_factory.get_node(options={'plugin': coin_mvt_plugin})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Send funds.
    amount = 2**24
    push_sat = 20000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)

    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fail to open (try to push too much)
    with pytest.raises(RpcError, match=r'Requested to push_msat of 20000000msat is greater than available funding amount 10000sat'):
        l1.rpc.fundchannel(l2.info['id'], 10000, push_msat=push_sat * 1000)

    # This should work.
    amount = amount - 1
    l1.rpc.fundchannel(l2.info['id'], amount, push_msat=push_sat * 1000)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    funds = only_one(l1.rpc.listfunds()['channels'])
    assert funds['channel_sat'] + push_sat == funds['channel_total_sat']

    chanid = first_channel_id(l2, l1)
    channel_mvts_1 = [
        {'type': 'chain_mvt', 'credit': 16777215000, 'debit': 0, 'tags': ['channel_open', 'opener']},
        {'type': 'channel_mvt', 'credit': 0, 'debit': 20000000, 'tags': ['pushed'], 'fees': '0msat'},
    ]
    channel_mvts_2 = [
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tags': ['channel_open']},
        {'type': 'channel_mvt', 'credit': 20000000, 'debit': 0, 'tags': ['pushed'], 'fees': '0msat'},
    ]
    check_coin_moves(l1, chanid, channel_mvts_1, chainparams)
    check_coin_moves(l2, chanid, channel_mvts_2, chainparams)

    assert account_balance(l1, chanid) == (amount - push_sat) * 1000


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@pytest.mark.developer
def test_funding_by_utxos(node_factory, bitcoind):
    """Fund a channel with specific utxos"""
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=False)

    # Get 3 differents utxo
    l1.fundwallet(0.01 * 10**8)
    l1.fundwallet(0.01 * 10**8)
    l1.fundwallet(0.01 * 10**8)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) == 3)

    utxos = [utxo["txid"] + ":" + str(utxo["output"]) for utxo in l1.rpc.listfunds()["outputs"]]

    # Fund with utxos we don't own
    with pytest.raises(RpcError, match=r"Unknown UTXO "):
        l3.rpc.fundchannel(l2.info["id"], int(0.01 * 10**8), utxos=utxos)

    # Fund with an empty array
    with pytest.raises(RpcError, match=r"Please specify an array of \\'txid:output_index\\', not \"*\""):
        l1.rpc.fundchannel(l2.info["id"], int(0.01 * 10**8), utxos=[])

    # Fund a channel from some of the utxos, without change
    l1.rpc.fundchannel(l2.info["id"], "all", utxos=utxos[0:2])

    # Fund a channel from the rest of utxos, with change
    l1.rpc.connect(l3.info["id"], "localhost", l3.port)
    l1.rpc.fundchannel(l3.info["id"], int(0.007 * 10**8), utxos=[utxos[2]])

    # Fund another channel with already reserved utxos
    with pytest.raises(RpcError, match=r"UTXO.*already reserved"):
        l1.rpc.fundchannel(l3.info["id"], int(0.01 * 10**8), utxos=utxos)

    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])

    # Fund another channel with already spent utxos
    with pytest.raises(RpcError, match=r"Already spent UTXO "):
        l1.rpc.fundchannel(l3.info["id"], int(0.01 * 10**8), utxos=utxos)


@pytest.mark.developer("needs dev_forget_channel")
@pytest.mark.openchannel('v1')
def test_funding_external_wallet_corners(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)

    amount = 2**24
    l1.fundwallet(amount + 10000000)

    amount = amount - 1

    # make sure we can generate PSBTs.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) != 0)

    # Some random (valid) psbt
    psbt = l1.rpc.fundpsbt(amount, '253perkw', 250, reserve=False)['psbt']

    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.fundchannel_start(l2.info['id'], amount)

    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.fundchannel_complete(l2.info['id'], psbt)

    # Should not be able to continue without being in progress.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r'No channel funding in progress.'):
        l1.rpc.fundchannel_complete(l2.info['id'], psbt)

    # Fail to open (too large)
    with pytest.raises(RpcError, match=r'Amount exceeded 16777215'):
        l1.rpc.fundchannel_start(l2.info['id'], amount + 1)

    start = l1.rpc.fundchannel_start(l2.info['id'], amount)
    with pytest.raises(RpcError, match=r'Already funding channel'):
        l1.rpc.fundchannel(l2.info['id'], amount)

    # Can't complete with incorrect amount (unchecked on Elements)
    if TEST_NETWORK == 'regtest':
        wrongamt = l1.rpc.txprepare([{start['funding_address']: amount - 1}])
        with pytest.raises(RpcError, match=r'Output to open channel is .*, should be .*'):
            l1.rpc.fundchannel_complete(l2.info['id'], wrongamt['psbt'])
        l1.rpc.txdiscard(wrongamt['txid'])

    # Can't complete with incorrect address.
    wrongaddr = l1.rpc.txprepare([{l1.rpc.newaddr()['bech32']: amount}])
    with pytest.raises(RpcError, match=r'No output to open channel'):
        l1.rpc.fundchannel_complete(l2.info['id'], wrongaddr['psbt'])
    l1.rpc.txdiscard(wrongaddr['txid'])

    l1.rpc.fundchannel_cancel(l2.info['id'])
    # Should be able to 'restart' after canceling
    amount2 = 1000000
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount2)['funding_address']

    # Create the funding transaction
    prep = l1.rpc.txprepare([{funding_addr: amount2}])
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # Be sure fundchannel_complete is successful
    assert l1.rpc.fundchannel_complete(l2.info['id'], prep['psbt'])['commitments_secured']

    # Peer shouldn't be able to cancel channel
    with pytest.raises(RpcError, match=r'Cannot cancel channel that was initiated by peer'):
        l2.rpc.fundchannel_cancel(l1.info['id'])

    # We can cancel channel after fundchannel_complete
    assert l1.rpc.fundchannel_cancel(l2.info['id'])['cancelled']
    # But must unreserve inputs manually.
    l1.rpc.txdiscard(prep['txid'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']
    prep = l1.rpc.txprepare([{funding_addr: amount}])

    assert l1.rpc.fundchannel_complete(l2.info['id'], prep['psbt'])['commitments_secured']

    # Check that can still cancel when peer is disconnected
    l1.rpc.disconnect(l2.info['id'], force=True)
    wait_for(lambda: not only_one(l1.rpc.listpeers()['peers'])['connected'])

    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state']
             == 'CHANNELD_AWAITING_LOCKIN')

    assert l1.rpc.fundchannel_cancel(l2.info['id'])['cancelled']
    assert len(l1.rpc.listpeers()['peers']) == 0

    # l2 still has the channel open/waiting
    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state']
             == 'CHANNELD_AWAITING_LOCKIN')

    # on reconnect, channel should get destroyed
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('Reestablish on UNKNOWN channel')
    wait_for(lambda: len(l1.rpc.listpeers()['peers']) == 0)
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # But must unreserve inputs manually.
    l1.rpc.txdiscard(prep['txid'])

    # we have to connect again, because we got disconnected when everything errored
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']
    prep = l1.rpc.txprepare([{funding_addr: amount}])
    # A successful funding_complete will always have a commitments_secured that is true,
    # otherwise it would have failed
    assert l1.rpc.fundchannel_complete(l2.info['id'], prep['psbt'])['commitments_secured']
    l1.rpc.txsend(prep['txid'])
    with pytest.raises(RpcError, match=r'.* been broadcast.*'):
        l1.rpc.fundchannel_cancel(l2.info['id'])
    l1.rpc.close(l2.info['id'])


@pytest.mark.developer("needs dev_forget_channel")
@pytest.mark.openchannel('v2')
def test_funding_v2_corners(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)

    amount = 2**24
    l1.fundwallet(amount + 10000000)

    amount = amount - 1

    # make sure we can generate PSBTs.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) != 0)

    # Some random (valid) psbt
    psbt = l1.rpc.fundpsbt(amount, '253perkw', 250, reserve=False)['psbt']
    nonexist_chanid = '11' * 32

    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.openchannel_init(l2.info['id'], amount, psbt)

    with pytest.raises(RpcError, match=r'Unknown channel'):
        l1.rpc.openchannel_update(nonexist_chanid, psbt)

    # Should not be able to continue without being in progress.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r'Unknown channel'):
        l1.rpc.openchannel_signed(nonexist_chanid, psbt)

    # Fail to open (too large)
    with pytest.raises(RpcError, match=r'Amount exceeded 16777215'):
        l1.rpc.openchannel_init(l2.info['id'], amount + 1, psbt)

    start = l1.rpc.openchannel_init(l2.info['id'], amount, psbt)
    with pytest.raises(RpcError, match=r'Channel funding in-progress. DUALOPEND_OPEN_INIT'):
        l1.rpc.fundchannel(l2.info['id'], amount)

    # We can abort a channel
    l1.rpc.openchannel_abort(start['channel_id'])

    # Should be able to 'restart' after canceling
    amount2 = 1000000
    l1.rpc.unreserveinputs(psbt)
    psbt = l1.rpc.fundpsbt(amount2, '253perkw', 250, reserve=False)['psbt']
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    start = l1.rpc.openchannel_init(l2.info['id'], amount2, psbt)

    # Check that we're connected.
    # This caused a valgrind crash prior to this commit
    assert only_one(l2.rpc.listpeers()['peers'])

    # Disconnect peer.
    l1.rpc.disconnect(l2.info['id'], force=True)
    wait_for(lambda: len(l1.rpc.listpeers()['peers']) == 0)

    with pytest.raises(RpcError, match=r'Unknown channel'):
        l1.rpc.openchannel_abort(start['channel_id'])

    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)
    with pytest.raises(RpcError, match=r'Unknown channel'):
        l2.rpc.openchannel_abort(start['channel_id'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    start = l1.rpc.openchannel_init(l2.info['id'], amount2, psbt)

    # Be sure fundchannel_complete is successful
    assert l1.rpc.openchannel_update(start['channel_id'], start['psbt'])['commitments_secured']


@unittest.skipIf(SLOW_MACHINE and not VALGRIND, "Way too taxing on CI machines")
@pytest.mark.openchannel('v1')
def test_funding_cancel_race(node_factory, bitcoind, executor):
    l1 = node_factory.get_node()

    # make sure we can generate PSBTs.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 200000 / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) != 0)

    if node_factory.valgrind:
        num = 5
    else:
        num = 100

    # Allow the other nodes to log unexpected WIRE_FUNDING_CREATED messages
    nodes = node_factory.get_nodes(num, opts={'allow_broken_log': True})

    num_complete = 0
    num_cancel = 0

    for count, n in enumerate(nodes):
        l1.rpc.connect(n.info['id'], 'localhost', n.port)
        start = l1.rpc.fundchannel_start(n.info['id'], "100000sat")

        prep = l1.rpc.txprepare([{start['funding_address']: "100000sat"}])

        # Submit two of each at once.
        completes = []
        cancels = []

        # Switch order around.
        for i in range(4):
            if (i + count) % 2 == 0:
                completes.append(executor.submit(l1.rpc.fundchannel_complete, n.info['id'], prep['psbt']))
            else:
                cancels.append(executor.submit(l1.rpc.fundchannel_cancel, n.info['id']))

        # Only up to one should succeed.
        success = False
        for c in completes:
            try:
                c.result(TIMEOUT)
                num_complete += 1
                assert not success
                success = True
            except RpcError:
                pass

        # At least one of these must succeed, regardless of whether
        # the completes succeeded or not.
        cancelled = False
        for c in cancels:
            try:
                c.result(TIMEOUT)
                cancelled = True
            except RpcError:
                pass
        # cancel always succeeds, as per Sequential Consistency.
        # Either the cancel occurred before complete, in which
        # case it prevents complete from succeeding, or it
        # occurred after complete, in which case it errors the
        # channel to force the remote to forget it.
        assert cancelled
        num_cancel += 1
        # Free up funds for next time
        l1.rpc.txdiscard(prep['txid'])

    print("Cancelled {} complete {}".format(num_cancel, num_complete))
    assert num_cancel == len(nodes)

    # We should have raced at least once!
    if not node_factory.valgrind:
        assert num_cancel > 0
        assert num_complete > 0

    # Speed up shutdown by stopping them all concurrently
    executor.map(lambda n: n.stop(), node_factory.nodes)


@unittest.skipIf(SLOW_MACHINE and not VALGRIND, "Way too taxing on CI machines")
@pytest.mark.openchannel('v2')
def test_funding_v2_cancel_race(node_factory, bitcoind, executor):
    l1 = node_factory.get_node()

    # make sure we can generate PSBTs.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 2000000 / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) != 0)

    if node_factory.valgrind:
        num = 5
    else:
        num = 100

    nodes = node_factory.get_nodes(num)

    num_complete = 0
    num_cancel = 0
    amount = 100000

    for count, n in enumerate(nodes):
        l1.rpc.connect(n.info['id'], 'localhost', n.port)
        psbt = l1.rpc.fundpsbt(amount, '7500perkw', 250, reserve=False,
                               excess_as_change=True,
                               min_witness_weight=110)['psbt']
        start = l1.rpc.openchannel_init(n.info['id'], amount, psbt)

        # Submit two of each at once.
        completes = []
        cancels = []

        # Switch order around.
        for i in range(4):
            if (i + count) % 2 == 0:
                completes.append(executor.submit(l1.rpc.openchannel_update,
                                                 start['channel_id'],
                                                 start['psbt']))
            else:
                cancels.append(executor.submit(l1.rpc.openchannel_abort,
                                               start['channel_id']))

        # Only up to one should succeed.
        success = False
        for c in completes:
            try:
                c.result(TIMEOUT)
                num_complete += 1
                assert not success
                success = True
            except RpcError:
                pass

        for c in cancels:
            try:
                c.result(TIMEOUT)
                num_cancel += 1
            except RpcError:
                pass
        # Free up funds for next time
        l1.rpc.unreserveinputs(psbt)

    print("Cancelled {} complete {}".format(num_cancel, num_complete))

    # We should have raced at least once!
    if not node_factory.valgrind:
        assert num_cancel > 0
        assert num_complete > 0

    # Speed up shutdown by stopping them all concurrently
    executor.map(lambda n: n.stop(), node_factory.nodes)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', "External wallet support doesn't work with elements yet.")
def test_funding_close_upfront(node_factory, bitcoind):
    opts = {'plugin': os.path.join(os.getcwd(), 'tests/plugins/openchannel_hook_accepter.py')}

    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options=opts)

    # The 'accepter_close_to' plugin uses the channel funding amount
    # to determine whether or not to include a 'close_to' address
    amt_normal = 100000     # continues without returning a close_to
    amt_addr = 100003       # returns valid regtest address

    remote_valid_addr = 'bcrt1q7gtnxmlaly9vklvmfj06amfdef3rtnrdazdsvw'

    def has_normal_channels(l1, l2):
        return any([c['state'] == 'CHANNELD_AWAITING_LOCKIN'
                    or c['state'] == 'CHANNELD_NORMAL'
                    for c in only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels']])

    def _fundchannel(l1, l2, amount, close_to):
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        assert(l1.rpc.listpeers()['peers'][0]['id'] == l2.info['id'])

        # Make sure both consider any previous channels closed.
        wait_for(lambda: not has_normal_channels(l1, l2))
        wait_for(lambda: not has_normal_channels(l2, l1))

        _, resp = l1.fundchannel(l2, amount, close_to=close_to)
        if close_to:
            assert resp['close_to']
        else:
            assert 'close_to' not in resp

        for node in [l1, l2]:
            channel = node.rpc.listpeers()['peers'][0]['channels'][-1]
            assert amount * 1000 == channel['msatoshi_total']

    def _close(src, dst, addr=None):
        """Close the channel from src to dst, with the specified address.

        Returns the address of the outputs in the close tx. Raises an
        error if some expectations are not met.

        """
        r = l1.rpc.close(l2.info['id'], destination=addr)
        assert r['type'] == 'mutual'
        tx = bitcoind.rpc.decoderawtransaction(r['tx'])

        addrs = [scriptpubkey_addr(vout['scriptPubKey']) for vout in tx['vout']]
        bitcoind.generate_block(1, wait_for_mempool=[r['txid']])
        sync_blockheight(bitcoind, [l1, l2])
        return addrs

    # check that normal peer close works
    _fundchannel(l1, l2, amt_normal, None)
    _close(l1, l2)

    # check that you can provide a closing address upfront
    addr = l1.rpc.newaddr()['bech32']
    _fundchannel(l1, l2, amt_normal, addr)
    # confirm that it appears in listpeers
    assert addr == only_one(l1.rpc.listpeers()['peers'])['channels'][1]['close_to_addr']
    assert _close(l1, l2) == [addr]

    # check that passing in the same addr to close works
    addr = bitcoind.rpc.getnewaddress()
    _fundchannel(l1, l2, amt_normal, addr)
    assert addr == only_one(l1.rpc.listpeers()['peers'])['channels'][2]['close_to_addr']
    assert _close(l1, l2, addr) == [addr]

    # check that remote peer closing works as expected (and that remote's close_to works)
    _fundchannel(l1, l2, amt_addr, addr)
    # send some money to remote so that they have a closeout
    l1.rpc.pay(l2.rpc.invoice((amt_addr // 2) * 1000, 'test_remote_close_to', 'desc')['bolt11'])
    assert only_one(l2.rpc.listpeers()['peers'])['channels'][-1]['close_to_addr'] == remote_valid_addr
    # The tx outputs must be one of the two permutations
    assert _close(l2, l1) in ([addr, remote_valid_addr], [remote_valid_addr, addr])

    # check that passing in a different addr to close causes an RPC error
    addr2 = l1.rpc.newaddr()['bech32']
    _fundchannel(l1, l2, amt_normal, addr)
    with pytest.raises(RpcError, match=r'does not match previous shutdown script'):
        l1.rpc.close(l2.info['id'], destination=addr2)


@unittest.skipIf(TEST_NETWORK != 'regtest', "External wallet support doesn't work with elements yet.")
@pytest.mark.openchannel('v1')
def test_funding_external_wallet(node_factory, bitcoind):
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'funding-confirms': 2},
                                                 {'funding-confirms': 2}, {}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert(l1.rpc.listpeers()['peers'][0]['id'] == l2.info['id'])

    amount = 2**24 - 1
    address = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']
    assert len(address) > 0

    peer = l1.rpc.listpeers()['peers'][0]
    # Peer should still be connected and in state waiting for funding_txid
    assert peer['id'] == l2.info['id']
    r = re.compile('Funding channel start: awaiting funding_txid with output to .*')
    assert any(r.match(line) for line in peer['channels'][0]['status'])
    assert 'OPENINGD' in peer['channels'][0]['state']

    # Trying to start a second funding should not work, it's in progress.
    with pytest.raises(RpcError, match=r'Already funding channel'):
        l1.rpc.fundchannel_start(l2.info['id'], amount)

    # 'Externally' fund the address from fundchannel_start
    psbt = bitcoind.rpc.walletcreatefundedpsbt([], [{address: amount / 10**8}])['psbt']
    assert l1.rpc.fundchannel_complete(l2.info['id'], psbt)['commitments_secured']

    # Broadcast the transaction manually
    process = bitcoind.rpc.walletprocesspsbt(psbt)
    assert process['complete'] is True
    tx = bitcoind.rpc.finalizepsbt(process['psbt'])
    txid = bitcoind.rpc.sendrawtransaction(tx['hex'])
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Funding tx {} depth 1 of 2'.format(txid))

    # Check that tx is broadcast by a third party can be catched.
    # Only when the transaction (broadcast by a third pary) is onchain, we can catch it.
    with pytest.raises(RpcError, match=r'.* been broadcast.*'):
        l1.rpc.fundchannel_cancel(l2.info['id'])

    # Confirm that channel locks in
    bitcoind.generate_block(1)

    for node in [l1, l2]:
        node.daemon.wait_for_log(r'State changed from CHANNELD_AWAITING_LOCKIN to CHANNELD_NORMAL')
        channel = node.rpc.listpeers()['peers'][0]['channels'][0]
        assert amount * 1000 == channel['msatoshi_total']

    # Test that we don't crash if peer disconnects after fundchannel_start
    l2.connect(l3)
    l2.rpc.fundchannel_start(l3.info["id"], amount)
    l3.rpc.close(l2.info["id"])


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v1')  # We manually turn on dual-funding for select nodes
def test_multifunding_v1_v2_mixed(node_factory, bitcoind):
    '''
    Simple test for multifundchannel, using v1 + v2
    '''
    options = [{'experimental-dual-fund': None},
               {'funder-policy': 'match',
                'funder-policy-mod': 100,
                'funder-fuzz-percent': 0,
                'experimental-dual-fund': None},
               {'funder-policy': 'match',
                'funder-policy-mod': 100,
                'funder-fuzz-percent': 0,
                'experimental-dual-fund': None},
               {}]

    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=options)

    l1.fundwallet(2000000)
    l2.fundwallet(2000000)
    l3.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 50000}]

    l1.rpc.multifundchannel(destinations)
    bitcoind.generate_block(6, wait_for_mempool=1)

    for node in [l1, l2, l3, l4]:
        node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    for ldest in [l2, l3, l4]:
        inv = ldest.rpc.invoice(5000, 'inv', 'inv')['bolt11']
        l1.rpc.pay(inv)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
def test_multifunding_v2_exclusive(node_factory, bitcoind):
    '''
    Simple test for multifundchannel, using v2
    '''
    # Two of three will reply with inputs of their own
    options = [{},
               {'funder-policy': 'match',
                'funder-policy-mod': 100,
                'funder-fuzz-percent': 0,
                'funder-lease-requests-only': False},
               {'funder-policy': 'match',
                'funder-policy-mod': 100,
                'funder-fuzz-percent': 0,
                'funder-lease-requests-only': False},
               {}]
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=options)

    l1.fundwallet(2000000)
    l2.fundwallet(2000000)
    l3.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 50000}]

    l1.rpc.multifundchannel(destinations)
    bitcoind.generate_block(6, wait_for_mempool=1)

    for node in [l1, l2, l3, l4]:
        node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    # For dual-funded channels, pay from accepter to initiator
    for ldest in [l2, l3]:
        inv = l1.rpc.invoice(5000, 'inv' + ldest.info['id'], 'inv')['bolt11']
        ldest.rpc.pay(inv)

    # Then pay other direction
    for ldest in [l2, l3, l4]:
        inv = ldest.rpc.invoice(10000, 'inv', 'inv')['bolt11']
        l1.rpc.pay(inv)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_multifunding_simple(node_factory, bitcoind):
    '''
    Simple test for multifundchannel.
    '''
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    l1.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 50000}]

    l1.rpc.multifundchannel(destinations)
    bitcoind.generate_block(6, wait_for_mempool=1)

    for node in [l1, l2, l3, l4]:
        node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    for ldest in [l2, l3, l4]:
        inv = ldest.rpc.invoice(5000, 'inv', 'inv')['bolt11']
        l1.rpc.pay(inv)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_multifunding_one(node_factory, bitcoind):
    '''
    Test that multifunding can still fund to one destination.
    '''
    l1, l2, l3 = node_factory.get_nodes(3)

    l1.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000}]

    l1.rpc.multifundchannel(destinations)

    # Now check if we connect to the node first before
    # multifundchannel.
    l1.rpc.connect(l3.info['id'], 'localhost', port=l3.port)
    # Omit the connect hint.
    destinations = [{"id": '{}'.format(l3.info['id']),
                     "amount": 50000}]

    l1.rpc.multifundchannel(destinations, minconf=0)

    bitcoind.generate_block(6, wait_for_mempool=1)
    for node in [l1, l2, l3]:
        node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    for ldest in [l2, l3]:
        inv = ldest.rpc.invoice(5000, 'inv', 'inv')['bolt11']
        l1.rpc.pay(inv)


@pytest.mark.developer("needs dev-disconnect")
@pytest.mark.openchannel('v1')
def test_multifunding_disconnect(node_factory):
    '''
    Test disconnection during multifundchannel
    '''
    # TODO: Note that -WIRE_FUNDING_SIGNED does not
    # work.
    # See test_disconnect_half_signed.
    # If disconnected when the peer believes it sent
    # WIRE_FUNDING_SIGNED but before we actually
    # receive it, the peer continues to monitor our
    # funding tx, but we have forgotten it and will
    # never send it.
    disconnects = ["-WIRE_INIT",
                   "-WIRE_ACCEPT_CHANNEL",
                   "+WIRE_ACCEPT_CHANNEL"]
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)
    l3 = node_factory.get_node()

    l1.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000}]

    # Funding to l2 will fail, and we should properly
    # inform l3 to back out as well.
    for d in disconnects:
        with pytest.raises(RpcError):
            l1.rpc.multifundchannel(destinations)

    # TODO: failing at the fundchannel_complete phase
    # (-WIRE_FUNDING_SIGNED +-WIRE_FUNDING_SIGNED)
    # leaves the peer (l2 in this case) in a state
    # where it is waiting for an incoming channel,
    # even though we no longer have a channel going to
    # that peer.
    # Reconnecting with the peer will clear up that
    # confusion, but then the peer will disconnect
    # after a random amount of time.

    destinations = [{"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000}]

    # This should succeed.
    l1.rpc.multifundchannel(destinations)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_multifunding_wumbo(node_factory):
    '''
    Test wumbo channel imposition in multifundchannel.
    '''
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{'large-channels': None},
                                              {'large-channels': None},
                                              {}])

    l1.fundwallet(1 << 26)

    # This should fail.
    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 1 << 24}]
    with pytest.raises(RpcError, match='Amount exceeded'):
        l1.rpc.multifundchannel(destinations)

    # This should succeed.
    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 1 << 24},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000}]
    l1.rpc.multifundchannel(destinations)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Fees on elements are different")
@pytest.mark.developer("uses dev-fail")
@pytest.mark.openchannel('v1')  # v2 the weight calculation is off by 3
def test_multifunding_feerates(node_factory, bitcoind):
    '''
    Test feerate parameters for multifundchannel
    '''
    funding_tx_feerate = '10000perkw'
    commitment_tx_feerate_int = 2000
    commitment_tx_feerate = str(commitment_tx_feerate_int) + 'perkw'

    l1, l2, l3 = node_factory.get_nodes(3, opts={'log-level': 'debug'})

    l1.fundwallet(1 << 26)

    def _connect_str(node):
        return '{}@localhost:{}'.format(node.info['id'], node.port)

    destinations = [{"id": _connect_str(l2), 'amount': 50000}]

    res = l1.rpc.multifundchannel(destinations, feerate=funding_tx_feerate,
                                  commitment_feerate=commitment_tx_feerate)

    entry = bitcoind.rpc.getmempoolentry(res['txid'])
    weight = entry['weight']

    expected_fee = int(funding_tx_feerate[:-5]) * weight // 1000
    assert expected_fee == entry['fees']['base'] * 10 ** 8

    assert only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])['feerate']['perkw'] == commitment_tx_feerate_int
    assert only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])['feerate']['perkb'] == commitment_tx_feerate_int * 4

    txfee = only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])['last_tx_fee_msat']

    # We get the expected close txid, force close the channel, then fish
    # the details about the transaction out of the mempoool entry
    close_txid = only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])['scratch_txid']
    l1.rpc.dev_fail(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])
    entry = bitcoind.rpc.getmempoolentry(close_txid)

    # Because of how the anchor outputs protocol is designed,
    # we *always* pay for 2 anchor outs and their weight
    if EXPERIMENTAL_FEATURES or EXPERIMENTAL_DUAL_FUND:  # opt_anchor_outputs
        weight = 1124
    else:
        # the commitment transactions' feerate is calculated off
        # of this fixed weight
        weight = 724

    expected_fee = int(commitment_tx_feerate[:-5]) * weight // 1000

    # At this point we only have one anchor output on the
    # tx, but we subtract out the extra anchor output amount
    # from the to_us output, so it ends up inflating
    # our fee by that much.
    if EXPERIMENTAL_FEATURES or EXPERIMENTAL_DUAL_FUND:  # opt_anchor_outputs
        expected_fee += 330

    assert expected_fee == entry['fees']['base'] * 10 ** 8
    assert Millisatoshi(str(expected_fee) + 'sat') == txfee


def test_multifunding_param_failures(node_factory):
    '''
    Test that multifunding handles errors in parameters.
    '''
    l1, l2, l3 = node_factory.get_nodes(3)

    l1.fundwallet(1 << 26)

    # No connection hint to unconnected node.
    destinations = [{"id": '{}'.format(l2.info['id']),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000}]
    with pytest.raises(RpcError):
        l1.rpc.multifundchannel(destinations)

    # Duplicated destination.
    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000}]
    with pytest.raises(RpcError):
        l1.rpc.multifundchannel(destinations)

    # Empty destinations.
    with pytest.raises(RpcError):
        l1.rpc.multifundchannel([])

    # Required destination fields missing.
    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port)}]
    with pytest.raises(RpcError):
        l1.rpc.multifundchannel(destinations)
    destinations = [{"amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000}]
    with pytest.raises(RpcError):
        l1.rpc.multifundchannel(destinations)


@pytest.mark.openchannel('v1')
@pytest.mark.developer("disconnect=... needs DEVELOPER=1")
def test_multifunding_best_effort(node_factory, bitcoind):
    '''
    Check that best_effort flag works.
    '''
    disconnects = ["-WIRE_INIT",
                   "-WIRE_ACCEPT_CHANNEL",
                   "-WIRE_FUNDING_SIGNED"]
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()
    l3 = node_factory.get_node(disconnect=disconnects)
    l4 = node_factory.get_node()

    l1.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 50000}]

    for i, d in enumerate(disconnects):
        # Should succeed due to best-effort flag.
        l1.rpc.multifundchannel(destinations, minchannels=2)
        bitcoind.generate_block(6, wait_for_mempool=1)

        # Only l3 should fail to have channels.
        for node in [l1, l2, l4]:
            node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

        # There should be working channels to l2 and l4.
        for ldest in [l2, l4]:
            inv = ldest.rpc.invoice(5000, 'i{}'.format(i), 'i{}'.format(i))['bolt11']
            l1.rpc.pay(inv)

        # Function to find the SCID of the channel that is
        # currently open.
        # Cannot use LightningNode.get_channel_scid since
        # it assumes the *first* channel found is the one
        # wanted, but in our case we close channels and
        # open again, so multiple channels may remain
        # listed.
        def get_funded_channel_scid(n1, n2):
            peers = n1.rpc.listpeers(n2.info['id'])['peers']
            assert len(peers) == 1
            peer = peers[0]
            channels = peer['channels']
            assert channels
            for c in channels:
                state = c['state']
                if state in ('CHANNELD_AWAITING_LOCKIN', 'CHANNELD_NORMAL'):
                    return c['short_channel_id']
            assert False

        # Now close channels to l2 and l4, for the next run.
        l1.rpc.close(get_funded_channel_scid(l1, l2))
        l1.rpc.close(get_funded_channel_scid(l1, l4))

        for node in [l1, l2, l4]:
            node.daemon.wait_for_log(r'to CLOSINGD_COMPLETE')

    # With 2 down, it will fail to fund channel
    l2.stop()
    l3.stop()
    with pytest.raises(RpcError, match=r'(Connection refused|Bad file descriptor)'):
        l1.rpc.multifundchannel(destinations, minchannels=2)

    # This works though.
    l1.rpc.multifundchannel(destinations, minchannels=1)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_while_offline(node_factory, bitcoind):
    l1 = node_factory.get_node()
    addr = l1.rpc.newaddr()['bech32']
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


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_channel_persistence(node_factory, bitcoind, executor):
    # Start two nodes and open a channel (to remember). l2 will
    # mysteriously die while committing the first HTLC so we can
    # check that HTLCs reloaded from the DB work.
    # Feerates identical so we don't get gratuitous commit to update them
    disable_commit_after = 1
    if EXPERIMENTAL_DUAL_FUND:
        disable_commit_after = 2

    l1 = node_factory.get_node(may_reconnect=True, feerates=(7500, 7500, 7500,
                                                             7500))
    l2 = node_factory.get_node(options={'dev-disable-commit-after': disable_commit_after},
                               may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Neither node should have a channel open, they are just connected
    for n in (l1, l2):
        assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 0)

    l1.fundchannel(l2, 100000)

    peers = l1.rpc.listpeers()['peers']
    assert(only_one(peers[0]['channels'])['state'] == 'CHANNELD_NORMAL')

    # Both nodes should now have exactly one channel in the database
    for n in (l1, l2):
        assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 1)

    # Fire off a sendpay request, it'll get interrupted by a restart
    executor.submit(l1.pay, l2, 10000)
    # Wait for it to be committed to, i.e., stored in the DB
    l1.daemon.wait_for_log('peer_in WIRE_FUNDING_LOCKED')
    l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # Stop l2, l1 will reattempt to connect
    print("Killing l2 in mid HTLC")
    l2.daemon.kill()

    # Clear the disconnect and timer stop so we can proceed normally
    del l2.daemon.opts['dev-disable-commit-after']

    # Wait for l1 to notice
    wait_for(lambda: 'connected' not in only_one(l1.rpc.listpeers()['peers'][0]['channels']))

    # Now restart l2 and it should reload peers/channels from the DB
    l2.start()
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 1)

    # Wait for the restored HTLC to finish
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99990000)

    wait_for(lambda: len([p for p in l1.rpc.listpeers()['peers'] if p['connected']]))
    wait_for(lambda: len([p for p in l2.rpc.listpeers()['peers'] if p['connected']]))

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
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)

    # L1 must notice.
    l1.daemon.wait_for_log(' to ONCHAIN')


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_private_channel(node_factory):
    l1, l2 = node_factory.line_graph(2, announce_channels=False, wait_for_announce=False)
    l3, l4 = node_factory.line_graph(2, announce_channels=True, wait_for_announce=True)

    assert l1.daemon.is_in_log('Will open private channel with node {}'.format(l2.info['id']))
    assert not l2.daemon.is_in_log('Will open private channel with node {}'.format(l1.info['id']))
    assert not l3.daemon.is_in_log('Will open private channel with node {}'.format(l4.info['id']))

    l3.daemon.wait_for_log('Received node_announcement for node {}'.format(l4.info['id']))
    l4.daemon.wait_for_log('Received node_announcement for node {}'.format(l3.info['id']))

    assert not l1.daemon.is_in_log('Received node_announcement for node {}'.format(l2.info['id']))
    assert not l2.daemon.is_in_log('Received node_announcement for node {}'.format(l1.info['id']))

    # test for 'private' flag in rpc output
    assert only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])['private']
    # check non-private channel
    assert not only_one(only_one(l4.rpc.listpeers(l3.info['id'])['peers'])['channels'])['private']


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_channel_reenable(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True}, fundchannel=True, wait_for_announce=True)

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


@pytest.mark.developer
def test_update_fee(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=True)
    chanid = l1.get_channel_scid(l2)

    # Make l1 send out feechange.
    l1.set_feerates((14000, 11000, 7500, 3750))

    # Now make sure an HTLC works.
    # (First wait for route propagation.)
    l1.wait_channel_active(chanid)
    sync_blockheight(bitcoind, [l1, l2])

    # Make payments.
    l1.pay(l2, 200000000)
    # First payment causes fee update.
    l2.daemon.wait_for_log('peer updated fee to 11000')
    l2.pay(l1, 100000000)

    # Now shutdown cleanly.
    l1.rpc.close(chanid)

    l1.daemon.wait_for_log(' to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log(' to CLOSINGD_COMPLETE')

    # And should put closing into mempool.
    l1.wait_for_channel_onchain(l2.info['id'])
    l2.wait_for_channel_onchain(l1.info['id'])

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(99)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@pytest.mark.developer
def test_fee_limits(node_factory, bitcoind):
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=[{'dev-max-fee-multiplier': 5, 'may_reconnect': True,
                                                      'allow_warning': True},
                                                     {'dev-max-fee-multiplier': 5, 'may_reconnect': True,
                                                      'allow_warning': True},
                                                     {'ignore-fee-limits': True, 'may_reconnect': True},
                                                     {}])

    node_factory.join_nodes([l1, l2], fundchannel=True)

    # Kick off fee adjustment using HTLC.
    l1.pay(l2, 1000)

    # L1 asks for stupid low fee (will actually hit the floor of 253)
    l1.stop()
    l1.set_feerates((15, 15, 15, 15), False)
    l1.start()

    l1.daemon.wait_for_log('Peer transient failure in CHANNELD_NORMAL: channeld WARNING: .*: update_fee 253 outside range 1875-75000')

    # Closes, but does not error.  Make sure it's noted in their status though.
    assert 'update_fee 253 outside range 1875-75000' in only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])['status'][0]
    assert 'update_fee 253 outside range 1875-75000' in only_one(only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['channels'])['status'][0]

    # Make l2 accept those fees, and it should recover.
    l2.stop()
    l2.set_feerates((15, 15, 15, 15), False)
    l2.start()

    l1.rpc.close(l2.info['id'])

    # Make sure the resolution of this one doesn't interfere with the next!
    # Note: may succeed, may fail with insufficient fee, depending on how
    # bitcoind feels!
    l2.daemon.wait_for_log('sendrawtx exit')
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2])

    # Trying to open a channel with too low a fee-rate is denied
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
    with pytest.raises(RpcError, match='They sent error .* feerate_per_kw 253 below minimum'):
        l1.fundchannel(l4, 10**6)

    # Restore to normal.
    l1.stop()
    l1.set_feerates((15000, 11000, 7500, 3750), False)
    l1.start()

    # Try with node which sets --ignore-fee-limits
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    chan, _ = l1.fundchannel(l3, 10**6)

    # Kick off fee adjustment using HTLC.
    l1.pay(l3, 1000)

    # Try stupid high fees
    l1.stop()
    l1.set_feerates((15000, 11000 * 10, 7500, 3750), False)
    l1.start()

    l3.daemon.wait_for_log('peer_in WIRE_UPDATE_FEE')
    l3.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # We need to wait until both have committed and revoked the
    # old state, otherwise we'll still try to commit with the old
    # 15sat/byte fee
    l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

    # This should wait for close to complete
    l1.rpc.close(chan)


@pytest.mark.developer("needs dev-no-fake-fees")
def test_update_fee_dynamic(node_factory, bitcoind):
    # l1 has no fee estimates to start.
    l1 = node_factory.get_node(options={'log-level': 'io',
                                        'dev-no-fake-fees': True}, start=False)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    l1.start()
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Fails due to lack of fee estimate.
    with pytest.raises(RpcError, match='Cannot estimate fees'):
        l1.fundchannel(l2, 10**6)

    # Explicit feerate works.
    l1.fundchannel(l2, 10**6, feerate='10000perkw')

    l1.set_feerates((15000, 11000, 7500, 3750))

    # It will send UPDATE_FEE when it tries to send HTLC.
    inv = l2.rpc.invoice(5000, 'test_update_fee_dynamic', 'test_update_fee_dynamic')['bolt11']
    l1.rpc.pay(inv)

    l2.daemon.wait_for_log('peer_in.*UPDATE_FEE')

    # Now we take it away again!
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    # Make sure that registers!  (DEVELOPER means polling every second)
    time.sleep(2)

    inv = l2.rpc.invoice(5000, 'test_update_fee_dynamic2', 'test_update_fee_dynamic2')['bolt11']
    l1.rpc.pay(inv)

    # Won't update fee.
    assert not l2.daemon.is_in_log('peer_in.*UPDATE_FEE',
                                   start=l2.daemon.logsearch_start)

    # Bring it back.
    l1.set_feerates((14000, 10000, 7000, 3000))

    # It will send UPDATE_FEE when it tries to send HTLC.
    inv = l2.rpc.invoice(5000, 'test_update_fee_dynamic3', 'test_update_fee_dynamic')['bolt11']
    l1.rpc.pay(inv)

    l2.daemon.wait_for_log('peer_in.*UPDATE_FEE')


@pytest.mark.developer
def test_update_fee_reconnect(node_factory, bitcoind):
    # Disconnect after commitsig for fee update.
    disconnects = ['+WIRE_COMMITMENT_SIGNED*3']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects, may_reconnect=True,
                               feerates=(15000, 15000, 15000, 3750))
    # We match l2's later feerate, so we agree on same closing tx for simplicity.
    l2 = node_factory.get_node(may_reconnect=True,
                               feerates=(14000, 15000, 14000, 3750))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chan, _ = l1.fundchannel(l2, 10**6)

    # Make an HTLC just to get us to do feechanges.
    l1.pay(l2, 1000)

    # Make l1 send out feechange; triggers disconnect/reconnect.
    # (Note: < 10% change, so no smoothing here!)
    l1.set_feerates((14000, 14000, 14000, 3750))
    l1.daemon.wait_for_log('Setting REMOTE feerate to 14000')
    l2.daemon.wait_for_log('Setting LOCAL feerate to 14000')
    l1.daemon.wait_for_log(r'dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    # Wait for reconnect....
    l1.daemon.wait_for_log('Feerate:.*LOCAL now 14000')

    l1.pay(l2, 200000000)
    l2.pay(l1, 100000000)

    # They should both have gotten commits with correct feerate.
    assert l1.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')
    assert l2.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')

    # Now shutdown cleanly.
    l1.rpc.close(chan)

    # And should put closing into mempool.
    l1.wait_for_channel_onchain(l2.info['id'])
    l2.wait_for_channel_onchain(l1.info['id'])

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(99)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@pytest.mark.developer("Too slow without --dev-bitcoind-poll")
def test_multiple_channels(node_factory):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    for i in range(3):
        # FIXME: we shouldn't disconnect on close?
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('Handed peer, entering loop')
        l2.daemon.wait_for_log('Handed peer, entering loop')
        chan, _ = l1.fundchannel(l2, 10**6)

        l1.rpc.close(chan)

        # If we don't wait for l2 to make the transition we can end up
        # attempting to re-estabilishing the channel
        l2.daemon.wait_for_log(
            r'State changed from CLOSINGD_SIGEXCHANGE to CLOSINGD_COMPLETE'
        )

    channels = only_one(l1.rpc.listpeers()['peers'])['channels']
    assert len(channels) == 3
    # Most in state ONCHAIN, last is CLOSINGD_COMPLETE
    for i in range(len(channels) - 1):
        assert channels[i]['state'] == 'ONCHAIN'
    assert channels[-1]['state'] == 'CLOSINGD_COMPLETE'


@pytest.mark.developer
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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

    # The entry in the channels table should still be there
    assert l1.db_query("SELECT count(*) as c FROM channels;")[0]['c'] == 1
    assert l2.db_query("SELECT count(*) as c FROM channels;")[0]['c'] == 1


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_peerinfo(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts={'may_reconnect': True})

    if l1.config('experimental-dual-fund'):
        lfeatures = expected_peer_features(extra=[21, 29])
        nfeatures = expected_node_features(extra=[21, 29])
    else:
        lfeatures = expected_peer_features()
        nfeatures = expected_node_features()

    # Gossiping but no node announcement yet
    assert l1.rpc.getpeer(l2.info['id'])['connected']
    assert len(l1.rpc.getpeer(l2.info['id'])['channels']) == 0
    assert l1.rpc.getpeer(l2.info['id'])['features'] == lfeatures

    # Fund a channel to force a node announcement
    chan, _ = l1.fundchannel(l2, 10**6)
    # Now proceed to funding-depth and do a full gossip round
    bitcoind.generate_block(5)
    l1.daemon.wait_for_logs(['Received node_announcement for node ' + l2.info['id']])
    l2.daemon.wait_for_logs(['Received node_announcement for node ' + l1.info['id']])

    # Should have announced the same features as told to peer.
    nodes1 = l1.rpc.listnodes(l2.info['id'])['nodes']
    nodes2 = l2.rpc.listnodes(l2.info['id'])['nodes']
    peer1 = l1.rpc.getpeer(l2.info['id'])
    peer2 = l2.rpc.getpeer(l1.info['id'])
    # peer features != to node features now because of keysend, which adds a node feature
    assert only_one(nodes1)['features'] == nfeatures
    assert only_one(nodes2)['features'] == nfeatures
    assert peer1['features'] == lfeatures
    assert peer2['features'] == lfeatures

    # If it reconnects after db load, it should know features.
    l1.restart()
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'])
    wait_for(lambda: l2.rpc.getpeer(l1.info['id'])['connected'])
    assert l1.rpc.getpeer(l2.info['id'])['features'] == lfeatures
    assert l2.rpc.getpeer(l1.info['id'])['features'] == lfeatures

    # Close the channel to forget the peer
    l1.rpc.close(chan)

    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    wait_for(lambda: not only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])

    # Make sure close tx hits mempool before we mine blocks.
    bitcoind.generate_block(100, wait_for_mempool=1)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

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
    l1.fundchannel(l3, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # disconnecting a non gossiping peer results in error
    with pytest.raises(RpcError, match=r'Peer is in state CHANNELD_NORMAL'):
        l1.rpc.disconnect(l3.info['id'])


@pytest.mark.developer("needs --dev-max-funding-unconfirmed-blocks")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_fundee_forget_funding_tx_unconfirmed(node_factory, bitcoind):
    """Test that fundee will forget the channel if
    the funding tx has been unconfirmed for too long.
    """
    # Keep this low (default is 2016), since everything
    # is much slower in VALGRIND mode and wait_for_log
    # could time out before lightningd processes all the
    # blocks.
    blocks = 200
    # opener
    l1 = node_factory.get_node()
    # peer
    l2 = node_factory.get_node(options={"dev-max-funding-unconfirmed-blocks": blocks})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Give opener some funds.
    l1.fundwallet(10**7)
    # Let blocks settle.
    time.sleep(1)

    def mock_sendrawtransaction(r):
        return {'id': r['id'], 'error': {'code': 100, 'message': 'sendrawtransaction disabled'}}

    # Prevent opener from broadcasting funding tx (any tx really).
    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_sendrawtransaction)

    # Fund the channel.
    # The process will complete, but opener will be unable
    # to broadcast and confirm funding tx.
    with pytest.raises(RpcError, match=r'sendrawtransaction disabled'):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    # Generate blocks until unconfirmed.
    bitcoind.generate_block(blocks)

    # fundee will forget channel!
    l2.daemon.wait_for_log('Forgetting channel: It has been {} blocks'.format(blocks))

    # fundee will also forget and disconnect from peer.
    assert len(l2.rpc.listpeers(l1.info['id'])['peers']) == 0


@pytest.mark.developer("needs dev_fail")
def test_no_fee_estimate(node_factory, bitcoind, executor):
    l1 = node_factory.get_node(start=False, options={'dev-no-fake-fees': True})

    # Fail any fee estimation requests until we allow them further down
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    l1.start()

    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Can't fund a channel.
    l1.fundwallet(10**7)
    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    # Can't withdraw either.
    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all')

    # Can't use feerate names, either.
    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all', 'urgent')

    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all', 'normal')

    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all', 'slow')

    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.fundchannel(l2.info['id'], 10**6, 'urgent')

    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.fundchannel(l2.info['id'], 10**6, 'normal')

    with pytest.raises(RpcError, match=r'Cannot estimate fees'):
        l1.rpc.fundchannel(l2.info['id'], 10**6, 'slow')

    # Can with manual feerate.
    l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 10000, '1500perkb')
    l1.rpc.fundchannel(l2.info['id'], 10**6, '2000perkw', minconf=0)

    # Make sure we clean up cahnnel for later attempt.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.rpc.dev_fail(l2.info['id'])
    l1.daemon.wait_for_log('Failing due to dev-fail command')
    l1.wait_for_channel_onchain(l2.info['id'])
    bitcoind.generate_block(6)
    wait_for(lambda: only_one(l1.rpc.getpeer(l2.info['id'])['channels'])['state'] == 'ONCHAIN')
    wait_for(lambda: only_one(l2.rpc.getpeer(l1.info['id'])['channels'])['state'] == 'ONCHAIN')

    # But can accept incoming connections.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.fundchannel(l1, 10**6)

    # Can do HTLCs.
    l2.pay(l1, 10**5)

    # Can do mutual close.
    l1.rpc.close(l2.info['id'])
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) > 0)
    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l1, l2])

    # Can do unilateral close.
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.fundchannel(l1, 10**6)
    l2.pay(l1, 10**9 // 2)
    l1.rpc.dev_fail(l2.info['id'])
    l1.daemon.wait_for_log('Failing due to dev-fail command')
    l1.wait_for_channel_onchain(l2.info['id'])
    bitcoind.generate_block(5)
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) > 0)
    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l1, l2])

    # Start estimatesmartfee.
    l1.set_feerates((15000, 11000, 7500, 3750), True)

    # Can now fund a channel (as a test, use slow feerate).
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    sync_blockheight(bitcoind, [l1])
    l1.rpc.fundchannel(l2.info['id'], 10**6, 'slow')

    # Can withdraw (use urgent feerate). `minconf` may be needed depending on
    # the previous `fundchannel` selecting all confirmed outputs.
    l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all', 'urgent', minconf=0)


@pytest.mark.developer("needs --dev-disconnect")
def test_opener_feerate_reconnect(node_factory, bitcoind):
    # l1 updates fees, then reconnect so l2 retransmits commitment_signed.
    disconnects = ['-WIRE_COMMITMENT_SIGNED*3']
    l1 = node_factory.get_node(may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects, may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)

    # Need a payment otherwise it won't update fee.
    l1.pay(l2, 10**9 // 2)

    # create fee update, causing disconnect.
    l1.set_feerates((15000, 11000, 7500, 3750))
    l2.daemon.wait_for_log(r'dev_disconnect: \-WIRE_COMMITMENT_SIGNED')

    # Wait until they reconnect.
    l1.daemon.wait_for_log('Peer transient failure in CHANNELD_NORMAL')
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'])

    # Should work normally.
    l1.pay(l2, 200000000)


def test_opener_simple_reconnect(node_factory, bitcoind):
    """Sanity check that reconnection works with completely unused channels"""
    # Set fees even so it doesn't send any commitments.
    l1 = node_factory.get_node(may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)

    l1.rpc.disconnect(l2.info['id'], True)

    # Wait until they reconnect.
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'])

    # Should work normally.
    l1.pay(l2, 200000000)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "sqlite3-specific DB rollback")
@pytest.mark.developer("needs LIGHTNINGD_DEV_LOG_IO")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_dataloss_protection(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True, options={'log-level': 'io'},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True, options={'log-level': 'io'},
                               feerates=(7500, 7500, 7500, 7500), allow_broken_log=True)

    lf = expected_peer_features()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l1 should send out WIRE_INIT (0010)
    l1.daemon.wait_for_log(r"\[OUT\] 0010.*"
                           # lflen
                           + format(len(lf) // 2, '04x')
                           + lf)

    l1.fundchannel(l2, 10**6)
    l2.stop()

    # Save copy of the db.
    dbpath = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3")
    orig_db = open(dbpath, "rb").read()
    l2.start()

    # l1 should have sent WIRE_CHANNEL_REESTABLISH with extra fields.
    l1.daemon.wait_for_log(r"\[OUT\] 0088"
                           # channel_id
                           "[0-9a-f]{64}"
                           # next_local_commitment_number
                           "0000000000000001"
                           # next_remote_revocation_number
                           "0000000000000000"
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
    l1.daemon.wait_for_logs([r"\[IN\] 0085"] * 2)
    l2.daemon.wait_for_logs([r"\[IN\] 0085"] * 2)

    l2.restart()

    # l1 should have sent WIRE_CHANNEL_REESTABLISH with extra fields.
    l1.daemon.wait_for_log(r"\[OUT\] 0088"
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
    l1.wait_for_channel_onchain(l2.info['id'])

    # l2 must NOT drop to chain.
    l2.daemon.wait_for_log("Cannot broadcast our commitment tx: they have a future one")
    assert not l2.daemon.is_in_log('sendrawtx exit 0',
                                   start=l2.daemon.logsearch_start)

    closetxid = only_one(bitcoind.rpc.getrawmempool(False))

    # l2 should still recover something!
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log("ERROR: Unknown commitment #[0-9], recovering our funds!")

    # Restarting l2, and it should remember from db.
    l2.restart()

    l2.daemon.wait_for_log("ERROR: Unknown commitment #[0-9], recovering our funds!")
    bitcoind.generate_block(100)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # l2 should have it in wallet.
    assert (closetxid, "confirmed") in set([(o['txid'], o['status']) for o in l2.rpc.listfunds()['outputs']])


@pytest.mark.developer("needs dev_disconnect")
def test_restart_multi_htlc_rexmit(node_factory, bitcoind, executor):
    # l1 disables commit timer once we send first htlc, dies on commit
    l1, l2 = node_factory.line_graph(2, opts=[{'disconnect': ['-WIRE_COMMITMENT_SIGNED'],
                                               'may_reconnect': True,
                                               'dev-disable-commit-after': 0},
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

    # Payments will fail due to restart, but we can see results in listsendpays.
    print(l1.rpc.listsendpays())
    wait_for(lambda: [p['status'] for p in l1.rpc.listsendpays()['payments']] == ['complete', 'complete'])


@pytest.mark.developer("needs dev_disconnect")
def test_fulfill_incoming_first(node_factory, bitcoind):
    """Test that we handle the case where we completely resolve incoming htlc
    before fulfilled outgoing htlc"""

    # We agree on fee change first, then add HTLC, then remove; stop after remove.
    disconnects = ['+WIRE_COMMITMENT_SIGNED*3']
    # We manually reconnect l2 & l3, after 100 blocks; hence allowing manual
    # reconnect, but disabling auto connect, and massive cltv so 2/3 doesn't
    # time out.
    l1, l2, l3 = node_factory.line_graph(3, opts=[{'disable-mpp': None},
                                                  {'may_reconnect': True,
                                                   'dev-no-reconnect': None},
                                                  {'may_reconnect': True,
                                                   'dev-no-reconnect': None,
                                                   'disconnect': disconnects,
                                                   'cltv-final': 200}],
                                         wait_for_announce=True)

    # This succeeds.
    l1.rpc.pay(l3.rpc.invoice(200000000, 'test_fulfill_incoming_first', 'desc')['bolt11'])

    # l1 can shutdown, fine.
    l1.rpc.close(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])
    bitcoind.generate_block(100)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Now, l2 should restore from DB fine, even though outgoing HTLC no longer
    # has an incoming.
    l2.restart()

    # Manually reconnect l2->l3.
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Fulfill should be retransmitted OK (ignored result).
    l2.rpc.close(l3.info['id'])
    l2.wait_for_channel_onchain(l3.info['id'])
    bitcoind.generate_block(100)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')
    l3.daemon.wait_for_log('onchaind complete, forgetting peer')


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
@pytest.mark.slow_test
def test_restart_many_payments(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True)

    # On my laptop, these take 89 seconds and 12 seconds
    if node_factory.valgrind:
        num = 2
    else:
        num = 5

    nodes = node_factory.get_nodes(num * 2, opts={'may_reconnect': True})
    innodes = nodes[:num]
    outnodes = nodes[num:]

    # Fund up-front to save some time.
    dests = {l1.rpc.newaddr()['bech32']: (10**6 + 1000000) / 10**8 * num}
    for n in innodes:
        dests[n.rpc.newaddr()['bech32']] = (10**6 + 1000000) / 10**8
    bitcoind.rpc.sendmany("", dests)
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1] + innodes)

    # Nodes with channels into the main node
    for n in innodes:
        n.rpc.connect(l1.info['id'], 'localhost', l1.port)
        n.rpc.fundchannel(l1.info['id'], 10**6)

    # Nodes with channels out of the main node
    for n in outnodes:
        l1.rpc.connect(n.info['id'], 'localhost', n.port)
        # OK to use change from previous fundings
        l1.rpc.fundchannel(n.info['id'], 10**6, minconf=0)

    # Now mine them, get scids
    mine_funding_to_announce(bitcoind, [l1] + nodes,
                             num_blocks=6, wait_for_mempool=num * 2)

    wait_for(lambda: [only_one(n.rpc.listpeers()['peers'])['channels'][0]['state'] for n in nodes] == ['CHANNELD_NORMAL'] * len(nodes))

    inchans = []
    for n in innodes:
        inchans.append(only_one(n.rpc.listpeers()['peers'])['channels'][0]['short_channel_id'])

    outchans = []
    for n in outnodes:
        outchans.append(only_one(n.rpc.listpeers()['peers'])['channels'][0]['short_channel_id'])

    # Now make sure every node sees every channel.
    for n in nodes + [l1]:
        wait_for(lambda: [c['public'] for c in n.rpc.listchannels()['channels']] == [True] * len(nodes) * 2)

    # Manually create routes, get invoices
    Payment = namedtuple('Payment', ['innode', 'route', 'payment_hash', 'payment_secret'])

    to_pay = []
    for i in range(len(innodes)):
        # This one will cause WIRE_INCORRECT_CLTV_EXPIRY from l1.
        route = [{'msatoshi': 100001001,
                  'id': l1.info['id'],
                  'delay': 10,
                  'channel': inchans[i]},
                 {'msatoshi': 100000000,
                  'id': outnodes[i].info['id'],
                  'delay': 5,
                  'channel': outchans[i]}]
        inv = outnodes[i].rpc.invoice(100000000, "invoice", "invoice")
        payment_hash = inv['payment_hash']
        to_pay.append(Payment(innodes[i], route, payment_hash, inv['payment_secret']))

        # This one should be routed through to the outnode.
        route = [{'msatoshi': 100001001,
                  'id': l1.info['id'],
                  'delay': 11,
                  'channel': inchans[i]},
                 {'msatoshi': 100000000,
                  'id': outnodes[i].info['id'],
                  'delay': 5,
                  'channel': outchans[i]}]
        inv = outnodes[i].rpc.invoice(100000000, "invoice2", "invoice2")
        payment_hash = inv['payment_hash']
        to_pay.append(Payment(innodes[i], route, payment_hash, inv['payment_secret']))

    # sendpay is async.
    for p in to_pay:
        p.innode.rpc.sendpay(p.route, p.payment_hash, p.payment_secret)

    # Now restart l1 while traffic is flowing...
    l1.restart()

    # Wait for them to finish.
    for n in innodes:
        wait_for(lambda: 'pending' not in [p['status'] for p in n.rpc.listsendpays()['payments']])


@pytest.mark.skip('needs blackhold support')
@pytest.mark.developer("need dev-disconnect")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_fail_unconfirmed(node_factory, bitcoind, executor):
    """Test that if we crash with an unconfirmed connection to a known
    peer, we don't have a dangling peer in db"""
    if EXPERIMENTAL_DUAL_FUND:
        disconnect = ['=WIRE_OPEN_CHANNEL2']
    else:
        disconnect = ['=WIRE_OPEN_CHANNEL']
    # = is a NOOP disconnect, but sets up file.
    l1 = node_factory.get_node(disconnect=disconnect)
    l2 = node_factory.get_node()

    # First one, we close by mutual agreement.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 200000, wait_for_active=True)
    l1.rpc.close(l2.info['id'])

    # Make sure it's closed
    l1.wait_for_channel_onchain(l2.info['id'])
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('State changed from CLOSINGD_COMPLETE to FUNDING_SPEND_SEEN')

    l1.stop()
    # Mangle disconnect file so this time it blackholes....
    with open(l1.daemon.disconnect_file, "w") as f:
        if EXPERIMENTAL_DUAL_FUND:
            f.write("0WIRE_OPEN_CHANNEL2\n")
        else:
            f.write("0WIRE_OPEN_CHANNEL\n")
    l1.start()

    # Now we establish a new channel, which gets stuck.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundwallet(10**7)
    executor.submit(l1.rpc.fundchannel, l2.info['id'], 100000)

    l1.daemon.wait_for_log("dev_disconnect")

    # Now complete old channel.
    bitcoind.generate_block(100)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # And crash l1, which is stuck.
    l1.daemon.kill()

    # Now, restart and see if it can connect OK.
    del l1.daemon.opts['dev-disconnect']
    l1.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 200000, wait_for_active=True)


@pytest.mark.skip('needs blackhold support')
@pytest.mark.developer("need dev-disconnect")
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
def test_fail_unconfirmed_openchannel2(node_factory, bitcoind, executor):
    """Test that if we crash with an unconfirmed connection to a known
    peer, we don't have a dangling peer in db"""
    # = is a NOOP disconnect, but sets up file.
    l1 = node_factory.get_node(disconnect=['=WIRE_OPEN_CHANNEL2'])
    l2 = node_factory.get_node()

    # First one, we close by mutual agreement.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 200000, wait_for_active=True)
    l1.rpc.close(l2.info['id'])

    # Make sure it's closed
    l1.wait_for_channel_onchain(l2.info['id'])
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('State changed from CLOSINGD_COMPLETE to FUNDING_SPEND_SEEN')

    l1.stop()
    # Mangle disconnect file so this time it blackholes....
    with open(l1.daemon.disconnect_file, "w") as f:
        f.write("0WIRE_OPEN_CHANNEL2\n")
    l1.start()

    # Now we establish a new channel, which gets stuck.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundwallet(10**7)
    executor.submit(l1.rpc.fundchannel, l2.info['id'], 100000)

    l1.daemon.wait_for_log("dev_disconnect")

    # Now complete old channel.
    bitcoind.generate_block(100)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # And crash l1, which is stuck.
    l1.daemon.kill()

    # Now, restart and see if it can connect OK.
    del l1.daemon.opts['dev-disconnect']
    l1.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 200000, wait_for_active=True)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_change_chaining(node_factory, bitcoind):
    """Test change chaining of unconfirmed fundings

    Change chaining is the case where one transaction is broadcast but not
    confirmed yet and we already build a followup on top of the change. If the
    first transaction doesn't confirm we may end up creating a series of
    unconfirmable transactions. This is why we generally disallow chaining.

    """
    l1, l2, l3 = node_factory.get_nodes(3)
    l1.fundwallet(10**8)  # This will create an output with 1 confirmation

    # Now fund a channel from l1 to l2, that should succeed, with minconf=1 but not before
    l1.connect(l2)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 10**7, minconf=2)
    l1.rpc.fundchannel(l2.info['id'], 10**7)  # Defaults to minconf=1

    # We don't have confirmed outputs anymore, so this should fail without minconf=0
    l1.connect(l3)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l3.info['id'], 10**7)  # Defaults to minconf=1
    l1.rpc.fundchannel(l3.info['id'], 10**7, minconf=0)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Fees on elements are different")
def test_feerate_spam(node_factory, chainparams):
    l1, l2 = node_factory.line_graph(2)

    # We constrain the value the opener has at its disposal so we get the
    # REMOTE feerate we are looking for below. This may be fragile and depends
    # on the transactions we generate.
    slack = 45000000

    # Pay almost everything to l2.
    l1.pay(l2, 10**9 - slack)

    # It will send this once (may have happened before line_graph's wait)
    wait_for(lambda: l1.daemon.is_in_log('Setting REMOTE feerate to 11000'))
    wait_for(lambda: l1.daemon.is_in_log('peer_out WIRE_UPDATE_FEE'))

    # Now change feerates to something l1 can't afford.
    l1.set_feerates((100000, 100000, 100000, 100000))

    # It will raise as far as it can (48000) (30000 for option_anchor_outputs)
    maxfeerate = 30000 if EXPERIMENTAL_FEATURES else 48000
    l1.daemon.wait_for_log('Setting REMOTE feerate to {}'.format(maxfeerate))
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE')

    # But it won't do it again once it's at max.
    with pytest.raises(TimeoutError):
        l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE', timeout=5)


@pytest.mark.developer("need dev-feerate")
def test_feerate_stress(node_factory, executor):
    # Third node makes HTLC traffic less predictable.
    l1, l2, l3 = node_factory.line_graph(3, opts={'commit-time': 100,
                                                  'may_reconnect': True})

    l1.pay(l2, 10**9 // 2)
    scid12 = l1.get_channel_scid(l2)
    scid23 = l2.get_channel_scid(l3)

    routel1l3 = [{'msatoshi': '10002msat', 'id': l2.info['id'], 'delay': 11, 'channel': scid12},
                 {'msatoshi': '10000msat', 'id': l3.info['id'], 'delay': 5, 'channel': scid23}]
    routel2l1 = [{'msatoshi': '10000msat', 'id': l1.info['id'], 'delay': 5, 'channel': scid12}]

    rate = 1875
    NUM_ATTEMPTS = 25
    l1done = 0
    l2done = 0
    prev_log = 0
    while l1done < NUM_ATTEMPTS and l2done < NUM_ATTEMPTS:
        try:
            r = random.randrange(6)
            if r == 5:
                l1.rpc.sendpay(routel1l3, "{:064x}".format(l1done))
                l1done += 1
            elif r == 4:
                l2.rpc.sendpay(routel2l1, "{:064x}".format(l2done))
                l2done += 1
            elif r > 0:
                l1.rpc.call('dev-feerate', [l2.info['id'], rate])
                rate += 5
            else:
                l2.rpc.disconnect(l1.info['id'], True)
                time.sleep(1)
        except RpcError:
            time.sleep(0.01)
            assert not l1.daemon.is_in_log('Bad.*signature', start=prev_log)
            prev_log = len(l1.daemon.logs)

    # Make sure it's reconnected, and wait for last payment.
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'])
    # We can get TEMPORARY_CHANNEL_FAILURE due to disconnect, too.
    with pytest.raises(RpcError, match='WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS|WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l1.rpc.waitsendpay("{:064x}".format(l1done - 1))
    with pytest.raises(RpcError, match='WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS|WIRE_TEMPORARY_CHANNEL_FAILURE'):
        l2.rpc.waitsendpay("{:064x}".format(l2done - 1))
    l1.rpc.call('dev-feerate', [l2.info['id'], rate - 5])
    assert not l1.daemon.is_in_log('Bad.*signature')
    assert not l2.daemon.is_in_log('Bad.*signature')


@pytest.mark.developer("need dev_disconnect")
@pytest.mark.slow_test
def test_pay_disconnect_stress(node_factory, executor):
    """Expose race in htlc restoration in channeld: 50% chance of failure"""
    if node_factory.valgrind:
        NUM_RUNS = 2
    else:
        NUM_RUNS = 5
    for i in range(NUM_RUNS):
        l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True},
                                                  {'may_reconnect': True,
                                                   'disconnect': ['=WIRE_UPDATE_ADD_HTLC',
                                                                  '-WIRE_COMMITMENT_SIGNED']}])

        scid12 = l1.get_channel_scid(l2)
        routel2l1 = [{'msatoshi': '10000msat', 'id': l1.info['id'], 'delay': 5, 'channel': scid12}]

        # Get invoice from l1 to pay.
        inv = l1.rpc.invoice(10000, "invoice", "invoice")
        payhash1 = inv['payment_hash']

        # Start balancing payment.
        fut = executor.submit(l1.pay, l2, 10**9 // 2)

        # As soon as reverse payment is accepted, reconnect.
        while True:
            l2.rpc.sendpay(routel2l1, payhash1, payment_secret=inv['payment_secret'])
            try:
                # This will usually fail with Capacity exceeded
                l2.rpc.waitsendpay(payhash1, timeout=TIMEOUT)
                break
            except RpcError:
                pass

        fut.result()


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_wumbo_channels(node_factory, bitcoind):
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{'large-channels': None},
                                              {'large-channels': None},
                                              {}])
    conn = l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)

    expected_features = expected_peer_features(wumbo_channels=True)
    if l1.config('experimental-dual-fund'):
        expected_features = expected_peer_features(wumbo_channels=True,
                                                   extra=[21, 29])

    assert conn['features'] == expected_features
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['features'] == expected_features

    # Now, can we open a giant channel?
    l1.fundwallet(1 << 26)
    l1.rpc.fundchannel(l2.info['id'], 1 << 24)

    # Get that mined, and announced.
    bitcoind.generate_block(6, wait_for_mempool=1)

    # Connect l3, get gossip.
    l3.rpc.connect(l1.info['id'], 'localhost', port=l1.port)
    wait_for(lambda: len(l3.rpc.listnodes(l1.info['id'])['nodes']) == 1)
    wait_for(lambda: 'features' in only_one(l3.rpc.listnodes(l1.info['id'])['nodes']))

    # Make sure channel capacity is what we expected.
    assert ([c['amount_msat'] for c in l3.rpc.listchannels()['channels']]
            == [Millisatoshi(str(1 << 24) + "sat")] * 2)

    # Make sure channel features are right from channel_announcement
    assert ([c['features'] for c in l3.rpc.listchannels()['channels']]
            == [expected_channel_features(wumbo_channels=True)] * 2)

    # Make sure we can't open a wumbo channel if we don't agree.
    with pytest.raises(RpcError, match='Amount exceeded'):
        l1.rpc.fundchannel(l3.info['id'], 1 << 24)

    # But we can open and announce a normal one.
    l1.rpc.fundchannel(l3.info['id'], 'all')
    bitcoind.generate_block(6, wait_for_mempool=1)
    wait_for(lambda: l1.channel_state(l3) == 'CHANNELD_NORMAL')

    # Make sure l2 sees correct size.
    wait_for(lambda: [c['amount_msat'] for c in l2.rpc.listchannels(l1.get_channel_scid(l3))['channels']]
             == [Millisatoshi(str((1 << 24) - 1) + "sat")] * 2)

    # Make sure 'all' works with wumbo peers.
    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: l1.channel_state(l2) == 'ONCHAIN')

    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all')
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: 'CHANNELD_NORMAL' in [c['state'] for c in only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels']])

    # Exact amount depends on fees, but it will be wumbo!
    amount = [c['funding']['local_msat'] for c in only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'] if c['state'] == 'CHANNELD_NORMAL'][0]
    assert amount > Millisatoshi(str((1 << 24) - 1) + "sat")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_channel_features(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], 0.1)
    bitcoind.generate_block(1)
    wait_for(lambda: l1.rpc.listfunds()['outputs'] != [])

    l1.rpc.fundchannel(l2.info['id'], 'all')

    # We should see features in unconfirmed channels.
    chan = only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])
    assert 'option_static_remotekey' in chan['features']
    if EXPERIMENTAL_FEATURES or l1.config('experimental-dual-fund'):
        assert 'option_anchor_outputs' in chan['features']

    # l2 should agree.
    assert only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['features'] == chan['features']

    # Confirm it.
    bitcoind.generate_block(1)
    wait_for(lambda: only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_NORMAL')

    chan = only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])
    assert 'option_static_remotekey' in chan['features']
    if EXPERIMENTAL_FEATURES or l1.config('experimental-dual-fund'):
        assert 'option_anchor_outputs' in chan['features']

    # l2 should agree.
    assert only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['features'] == chan['features']


@pytest.mark.developer("need dev-force-features")
def test_nonstatic_channel(node_factory, bitcoind):
    """Smoke test for a channel without option_static_remotekey"""
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{},
                                           # needs at least 15 to connect
                                           # (and 9 is a dependent)
                                           {'dev-force-features': '9,15////'}])
    chan = only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])
    assert 'option_static_remotekey' not in chan['features']
    assert 'option_anchor_outputs' not in chan['features']

    l1.pay(l2, 1000)
    l1.rpc.close(l2.info['id'])


@pytest.mark.skip('needs blackhold support')
@pytest.mark.developer("need --dev-timeout-secs")
@pytest.mark.openchannel('v1')
def test_connection_timeout(node_factory):
    # l1 hears nothing back after sending INIT, should time out.
    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'dev-timeout-secs': 1,
                                           'disconnect': ['0WIRE_INIT', '0WIRE_INIT']},
                                          {}])

    with pytest.raises(RpcError, match='timed out'):
        l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.daemon.wait_for_log('conn timed out')

    with pytest.raises(RpcError, match=r'(reset by peer|peer closed connection)'):
        l2.rpc.connect(l1.info['id'], 'localhost', port=l1.port)
    l1.daemon.wait_for_log('conn timed out')


@pytest.mark.developer("needs --dev-disconnect")
def test_htlc_retransmit_order(node_factory, executor):
    NUM_HTLCS = 10
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True,
                                            'feerates': (7500, 7500, 7500, 7500),
                                            'disconnect': ['=WIRE_UPDATE_ADD_HTLC*' + str(NUM_HTLCS),
                                                           '-WIRE_COMMITMENT_SIGNED'],
                                            'dev-disable-commit-after': 0},
                                           {'may_reconnect': True}])
    invoices = [l2.rpc.invoice(1000, str(x), str(x)) for x in range(NUM_HTLCS)]

    routestep = {
        'msatoshi': 1000,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'  # note: can be bogus for 1-hop direct payments
    }
    for inv in invoices:
        executor.submit(l1.rpc.sendpay, [routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])

    l1.daemon.wait_for_log('dev_disconnect')
    l1.rpc.call('dev-reenable-commit', [l2.info['id']])
    l1.daemon.wait_for_log('dev_disconnect')

    # Now reconnect.
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)

    for inv in invoices:
        result = l1.rpc.waitsendpay(inv['payment_hash'])
        assert(result['status'] == 'complete')

    # If order was wrong, we'll get a LOG_BROKEN and fixtures will complain.


@unittest.skipIf(True, "Currently failing, see tracking issue #4265")
@pytest.mark.openchannel('v1')
def test_fundchannel_start_alternate(node_factory, executor):
    ''' Test to see what happens if two nodes start channeling to
    each other alternately.
    Issue #4108
    '''
    l1, l2 = node_factory.get_nodes(2)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.rpc.fundchannel_start(l2.info['id'], 100000)

    fut = executor.submit(l2.rpc.fundchannel_start, l1.info['id'], 100000)
    with pytest.raises(RpcError):
        fut.result(10)


@pytest.mark.openchannel('v2')
def test_openchannel_init_alternate(node_factory, executor):
    ''' Test to see what happens if two nodes start channeling to
    each other alternately.
    '''
    l1, l2 = node_factory.get_nodes(2)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundwallet(2000000)
    l2.fundwallet(2000000)

    psbt1 = l1.rpc.fundpsbt('1000000msat', '253perkw', 250)['psbt']
    psbt2 = l2.rpc.fundpsbt('1000000msat', '253perkw', 250)['psbt']
    init = l1.rpc.openchannel_init(l2.info['id'], 100000, psbt1)

    fut = executor.submit(l2.rpc.openchannel_init, l1.info['id'], '1000000msat', psbt2)
    with pytest.raises(RpcError):
        fut.result(10)

    # FIXME: Clean up so it doesn't hang. Ok if these fail.
    for node in [l1, l2]:
        try:
            node.rpc.openchannel_abort(init['channel_id'])
        except RpcError:
            # Ignoring all errors
            print("nothing to do")


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "upgrade protocol not available")
@pytest.mark.developer("dev-force-features required")
def test_upgrade_statickey(node_factory, executor):
    """l1 doesn't have option_static_remotekey, l2 offers it."""
    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-force-features': ["-13", "-21"]},
                                              {'may_reconnect': True}])

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.daemon.wait_for_logs([r"They sent current_channel_type \[\]",
                             r"They offered upgrade to \[12\]"])
    l2.daemon.wait_for_log(r"They sent desired_channel_type \[12\]")

    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')
    l2.daemon.wait_for_log('option_static_remotekey enabled at 1/1')

    # Make sure it's committed to db!
    wait_for(lambda: l1.db_query('SELECT local_static_remotekey_start, remote_static_remotekey_start FROM channels;') == [{'local_static_remotekey_start': 1, 'remote_static_remotekey_start': 1}])

    # They will consider themselves upgraded.
    l1.rpc.disconnect(l2.info['id'], force=True)
    # They won't offer upgrade!
    assert not l1.daemon.is_in_log("They offered upgrade",
                                   start=l1.daemon.logsearch_start)
    l1.daemon.wait_for_log(r"They sent current_channel_type \[12\]")
    l2.daemon.wait_for_log(r"They sent desired_channel_type \[12\]")


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "upgrade protocol not available")
@pytest.mark.developer("dev-force-features required")
def test_upgrade_statickey_onchaind(node_factory, executor, bitcoind):
    """We test penalty before/after, and unilateral before/after"""
    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'dev-force-features': ["-13", "-21"],
                                               # We try to cheat!
                                               'allow_broken_log': True},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None}])

    # TEST 1: Cheat from pre-upgrade.
    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')

    # Make sure another commitment happens, sending failed payment.
    routestep = {
        'msatoshi': 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'  # note: can be bogus for 1-hop direct payments
    }
    l1.rpc.sendpay([routestep], '00' * 32, payment_secret='00' * 32)
    with pytest.raises(RpcError, match=r'WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        l1.rpc.waitsendpay('00' * 32)

    # Make sure l2 gets REVOKE_AND_ACK from previous.
    l2.daemon.wait_for_log('peer_in WIRE_UPDATE_ADD_HTLC')
    l2.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')
    l2.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # Pre-statickey penalty works.
    bitcoind.rpc.sendrawtransaction(tx)
    bitcoind.generate_block(1)

    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM')
    bitcoind.generate_block(100)
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # TEST 2: Cheat from post-upgrade.
    node_factory.join_nodes([l1, l2])
    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')
    l2.daemon.wait_for_log('option_static_remotekey enabled at 1/1')

    l1.pay(l2, 1000000)

    # We will try to cheat later.
    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    l1.pay(l2, 1000000)

    # Pre-statickey penalty works.
    bitcoind.rpc.sendrawtransaction(tx)
    bitcoind.generate_block(1)

    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM')
    bitcoind.generate_block(100)
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # TEST 3: Unilateral close from pre-upgrade
    node_factory.join_nodes([l1, l2])

    # Give them both something for onchain close.
    l1.pay(l2, 1000000)

    # Make sure it's completely quiescent.
    l1.daemon.wait_for_log("chan#3: Removing out HTLC 0 state RCVD_REMOVE_ACK_REVOCATION FULFILLED")

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('option_static_remotekey enabled at 3/3')

    # But this is the *pre*-update commit tx!
    l2.stop()
    l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    bitcoind.generate_block(1, wait_for_mempool=1)
    l2.start()

    # They should both handle it fine.
    l1.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')
    l2.daemon.wait_for_logs(['Ignoring output .*: THEIR_UNILATERAL/OUTPUT_TO_US',
                             'Ignoring output .*: THEIR_UNILATERAL/DELAYED_OUTPUT_TO_THEM'])
    bitcoind.generate_block(5)
    bitcoind.generate_block(100, wait_for_mempool=1)

    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # TEST 4: Unilateral close from post-upgrade
    node_factory.join_nodes([l1, l2])

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')

    # Move to static_remotekey.
    l1.pay(l2, 1000000)

    l2.stop()
    l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    bitcoind.generate_block(1, wait_for_mempool=1)
    l2.start()

    # They should both handle it fine.
    l1.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')
    l2.daemon.wait_for_logs(['Ignoring output .*: THEIR_UNILATERAL/OUTPUT_TO_US',
                             'Ignoring output .*: THEIR_UNILATERAL/DELAYED_OUTPUT_TO_THEM'])

    bitcoind.generate_block(5)
    bitcoind.generate_block(100, wait_for_mempool=1)

    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "upgrade protocol not available")
@pytest.mark.developer("dev-force-features, dev-disconnect required")
def test_upgrade_statickey_fail(node_factory, executor, bitcoind):
    """We reconnect at all points during retransmit, and we won't upgrade."""
    l1_disconnects = ['-WIRE_COMMITMENT_SIGNED',
                      '-WIRE_REVOKE_AND_ACK']
    l2_disconnects = ['-WIRE_REVOKE_AND_ACK',
                      '-WIRE_COMMITMENT_SIGNED']

    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'disconnect': l1_disconnects,
                                               'dev-force-features': ["-13", "-21"],
                                               # Don't have feerate changes!
                                               'feerates': (7500, 7500, 7500, 7500)},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'disconnect': l2_disconnects,
                                               'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_htlcs.py'),
                                               'hold-time': 10000,
                                               'hold-result': 'fail'}])

    # This HTLC will fail
    l1.rpc.sendpay([{'msatoshi': 1000, 'id': l2.info['id'], 'delay': 5, 'channel': '1x1x1'}], '00' * 32, payment_secret='00' * 32)

    # Each one should cause one disconnection, no upgrade.
    for d in l1_disconnects + l2_disconnects:
        l1.daemon.wait_for_log('Peer connection lost')
        l2.daemon.wait_for_log('Peer connection lost')
        assert not l1.daemon.is_in_log('option_static_remotekey enabled')
        assert not l2.daemon.is_in_log('option_static_remotekey enabled')
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        line1 = l1.daemon.wait_for_log('No upgrade')
        line2 = l2.daemon.wait_for_log('No upgrade')

    # On the last reconnect, it retransmitted revoke_and_ack.
    assert re.search('No upgrade: we retransmitted', line1)
    assert re.search('No upgrade: pending changes', line2)

    # Make sure we already skip the first of these.
    l1.daemon.wait_for_log('billboard perm: Reconnected, and reestablished.')
    assert 'option_static_remotekey' not in only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['features']
    assert 'option_static_remotekey' not in only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['features']

    sleeptime = 1
    while True:
        # Now when we reconnect, despite having an HTLC, we're quiescent.
        l1.rpc.disconnect(l2.info['id'], force=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        oldstart = l1.daemon.logsearch_start
        l1.daemon.wait_for_log('billboard perm: Reconnected, and reestablished.')
        if not l1.daemon.is_in_log('No upgrade:', start=oldstart):
            break

        # Give it some processing time before reconnect...
        time.sleep(sleeptime)
        sleeptime += 1

    l1.daemon.logsearch_start = oldstart
    assert l1.daemon.wait_for_log('option_static_remotekey enabled at 2/2')
    assert l2.daemon.wait_for_log('option_static_remotekey enabled at 2/2')
    assert 'option_static_remotekey' in only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['features']
    assert 'option_static_remotekey' in only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['features']


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "quiescence is experimental")
@pytest.mark.developer("quiescence triggering is dev only")
def test_quiescence(node_factory, executor):
    l1, l2 = node_factory.line_graph(2)

    # Works fine.
    l1.pay(l2, 1000)

    assert l1.rpc.call('dev-quiesce', [l2.info['id']]) == {}

    # Both should consider themselves quiescent.
    l1.daemon.wait_for_log("STFU complete: we are quiescent")
    l2.daemon.wait_for_log("STFU complete: we are quiescent")

    # Should not be able to increase fees.
    l1.rpc.call('dev-feerate', [l2.info['id'], 9999])

    try:
        l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE', 5)
        assert False
    except TimeoutError:
        pass


def test_htlc_failed_noclose(node_factory):
    """Test a bug where the htlc timeout would kick in even if the HTLC failed"""
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice(1000, "test", "test")
    routestep = {
        'msatoshi': FUNDAMOUNT * 1000,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'  # note: can be bogus for 1-hop direct payments
    }

    # This fails at channeld
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match="Capacity exceeded"):
        l1.rpc.waitsendpay(inv['payment_hash'])

    # Send a second one, too: make sure we don't crash.
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match="Capacity exceeded"):
        l1.rpc.waitsendpay(inv['payment_hash'])

    time.sleep(35)
    assert l1.rpc.getpeer(l2.info['id'])['connected']


@pytest.mark.developer("dev-no-reconnect required")
def test_old_feerate(node_factory):
    """Test retransmission of old, now-unacceptable, feerate"""
    l1, l2 = node_factory.line_graph(2, opts={'feerates': (75000, 75000, 75000, 75000),
                                              'may_reconnect': True,
                                              'dev-no-reconnect': None})

    l1.pay(l2, 1000)
    l1.rpc.disconnect(l2.info['id'], force=True)

    # Drop acceptable feerate by l2
    l2.set_feerates((7000, 7000, 7000, 7000))
    l2.restart()

    # Minor change to l1, so it sends update_fee
    l1.set_feerates((74900, 74900, 74900, 74900))
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # This will timeout if l2 didn't accept fee.
    l1.pay(l2, 1000)


@pytest.mark.developer("needs --dev-allow-localhost")
def test_websocket(node_factory):
    ws_port = reserve()
    port1, port2 = reserve(), reserve()
    # We need a wildcard to show the websocket bug, but we need a real
    # address to give us something to announce.
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'experimental-websocket-port': ws_port,
                                            'addr': [':' + str(port1),
                                                     '127.0.0.1: ' + str(port2)],
                                            'dev-allow-localhost': None},
                                           {'dev-allow-localhost': None}],
                                     wait_for_announce=True)
    assert l1.rpc.listconfigs()['experimental-websocket-port'] == ws_port

    # Adapter to turn websocket into a stream "connection"
    class BinWebSocket(object):
        def __init__(self, hostname, port):
            self.ws = websocket.WebSocket()
            self.ws.connect("ws://" + hostname + ":" + str(port))
            self.recvbuf = bytes()

        def send(self, data):
            self.ws.send(data, websocket.ABNF.OPCODE_BINARY)

        def recv(self, maxlen):
            while len(self.recvbuf) < maxlen:
                self.recvbuf += self.ws.recv()

            ret = self.recvbuf[:maxlen]
            self.recvbuf = self.recvbuf[maxlen:]
            return ret

    ws = BinWebSocket('localhost', ws_port)
    lconn = wire.LightningConnection(ws,
                                     wire.PublicKey(bytes.fromhex(l1.info['id'])),
                                     wire.PrivateKey(bytes([1] * 32)),
                                     is_initiator=True)

    l1.daemon.wait_for_log('Websocket connection in from')

    # Perform handshake.
    lconn.shake()

    # Expect to receive init msg.
    msg = lconn.read_message()
    assert int.from_bytes(msg[0:2], 'big') == 16

    # Echo same message back.
    lconn.send_message(msg)

    # Now try sending a ping, ask for 50 bytes
    msg = bytes((0, 18, 0, 50, 0, 0))
    lconn.send_message(msg)

    # Could actually reply with some gossip msg!
    while True:
        msg = lconn.read_message()
        if int.from_bytes(msg[0:2], 'big') == 19:
            break

    # Check node_announcement has websocket
    assert (only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['addresses']
            == [{'type': 'ipv4', 'address': '127.0.0.1', 'port': port2}, {'type': 'websocket', 'port': ws_port}])


@pytest.mark.developer("dev-disconnect required")
def test_ping_timeout(node_factory):
    # Disconnects after this, but doesn't know it.
    l1_disconnects = ['xWIRE_PING']

    l1, l2 = node_factory.line_graph(2, opts=[{'dev-no-reconnect': None,
                                               'disconnect': l1_disconnects},
                                              {}])
    # Takes 15-45 seconds, then another to try second ping
    l1.daemon.wait_for_log('Last ping unreturned: hanging up',
                           timeout=45 + 45 + 5)
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'] is False)
