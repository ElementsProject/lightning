from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from decimal import Decimal
from pyln.client import RpcError, Millisatoshi
import pyln.proto.wire as wire
from utils import (
    only_one, wait_for, sync_blockheight, TIMEOUT,
    expected_peer_features, expected_node_features,
    expected_channel_features,
    check_coin_moves, first_channel_id, account_balance, basic_fee,
    scriptpubkey_addr, default_ln_port,
    mine_funding_to_announce, first_scid,
    CHANNEL_SIZE
)
from pyln.testing.utils import SLOW_MACHINE, VALGRIND, EXPERIMENTAL_DUAL_FUND, FUNDAMOUNT

import os
import pytest
import random
import re
import time
import unittest
import websocket
import ssl


def test_connect_basic(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)
    l1id = l1.info['id']
    l2id = l2.info['id']

    # These should be in openingd.
    assert l1.rpc.getpeer(l2id)['connected']
    assert l2.rpc.getpeer(l1id)['connected']
    assert len(l1.rpc.listpeerchannels(l2id)['channels']) == 0
    assert len(l2.rpc.listpeerchannels(l1id)['channels']) == 0

    # Reconnect should be a noop
    ret = l1.rpc.connect(l2id, 'localhost', port=l2.port)
    assert ret['id'] == l2id
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l2.port}

    ret = l2.rpc.connect(l1id, host='localhost', port=l1.port)
    assert ret['id'] == l1id
    # FIXME: This gives a bogus address (since they connected to us): better to give none!
    assert 'address' in ret

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()['peers']) == 1
    assert len(l2.rpc.listpeers()['peers']) == 1

    # Should get reasonable error if unknown addr for peer.
    with pytest.raises(RpcError, match=r'Unable to connect, no address known'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e')

    # Should get reasonable error if connection refuse.
    with pytest.raises(RpcError, match=r'Connection establishment: Connection refused'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', 1)

    # Should get reasonable error if wrong key for peer.
    with pytest.raises(RpcError, match=r'Cryptographic handshake: peer closed connection \(wrong key\?\)'):
        l1.rpc.connect('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', l2.port)

    # test new `num_channels` param
    assert l1.rpc.listpeers(l2id)['peers'][0]['num_channels'] == 0
    l1.fundchannel(l2)
    assert l1.rpc.listpeers(l2id)['peers'][0]['num_channels'] == 1
    l1.fundchannel(l2)
    assert l1.rpc.listpeers(l2id)['peers'][0]['num_channels'] == 2


def test_remote_addr(node_factory, bitcoind):
    """Check address discovery (BOLT1 #917) init remote_addr works as designed:

       `node_announcement` update must only be send out when:
        - at least two peers
        - we have a channel with
        - report the same `remote_addr`

        We perform logic tests on L2, setup:
         l1 --> [l2] <-- l3
    """
    # don't announce anything per se
    opts = {'may_reconnect': True,
            'dev-allow-localhost': None,
            'dev-no-reconnect': None,
            'announce-addr-discovered': True}
    l1, l2, l3 = node_factory.get_nodes(3, opts)

    # Disable announcing local autobind addresses with dev-allow-localhost.
    # We need to have l2 opts 'bind-addr' to the (generated) value of 'addr'.
    # So we stop, set 'bind-addr' option, delete 'addr' and restart first.
    l2.stop()
    l2.daemon.opts['bind-addr'] = l2.daemon.opts['addr']
    del l2.daemon.opts['addr']
    l2.start()
    assert len(l2.rpc.getinfo()['address']) == 0

    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    logmsg = l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")
    # check 'listpeers' contains the 'remote_addr' as logged
    assert logmsg.endswith(l2.rpc.listpeers()['peers'][0]['remote_addr'])

    # Fund first channel so initial node_announcement is send
    # and also check no addresses have been announced yet
    l1.fundchannel(l2)
    bitcoind.generate_block(5)
    l1.daemon.wait_for_log(f"Received node_announcement for node {l2.info['id']}")
    assert(len(l1.rpc.listnodes(l2.info['id'])['nodes'][0]['addresses']) == 0)
    assert len(l2.rpc.getinfo()['address']) == 0

    def_port = default_ln_port(l2.info["network"])

    # when we restart l1 with a channel and reconnect, node_announcement update
    # must not yet be send as we need the same `remote_addr` confirmed from a
    # another peer we have a channel with.
    # Note: In this state l2 stores remote_addr as reported by l1
    assert not l2.daemon.is_in_log("Update our node_announcement for discovered address: 127.0.0.1:{}".format(def_port))
    l1.restart()
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")

    # Now l1 sees l2 but without announced addresses.
    assert(len(l1.rpc.listnodes(l2.info['id'])['nodes'][0]['addresses']) == 0)
    assert not l2.daemon.is_in_log("Update our node_announcement for discovered address: 127.0.0.1:{}".format(def_port))
    assert len(l2.rpc.getinfo()['address']) == 0

    # connect second node. This will trigger `node_announcement` update.
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")
    l2.daemon.wait_for_log("Update our node_announcement for discovered address: 127.0.0.1:{}".format(def_port))

    # check l1 sees the updated node announcement via CLI listnodes
    l1.daemon.wait_for_log(f"Received node_announcement for node {l2.info['id']}")
    address = l1.rpc.listnodes(l2.info['id'])['nodes'][0]['addresses'][0]
    assert address['type'] == "ipv4"
    assert address['address'] == "127.0.0.1"
    assert address['port'] == def_port

    # also check l2 returns the announced address (and port) via CLI getinfo
    getinfo = l2.rpc.getinfo()
    assert len(getinfo['address']) == 1
    assert getinfo['address'][0]['type'] == 'ipv4'
    assert getinfo['address'][0]['address'] == '127.0.0.1'
    assert getinfo['address'][0]['port'] == def_port


def test_remote_addr_disabled(node_factory, bitcoind):
    """Simply tests that IP address discovery announcements can be turned off

       We perform logic tests on L2, setup:
        l1 --> [l2] <-- l3
    """
    opts = {'dev-allow-localhost': None,
            'announce-addr-discovered': False,
            'may_reconnect': True,
            'dev-no-reconnect': None}
    l1, l2, l3 = node_factory.get_nodes(3, opts=[opts, opts, opts])

    # l1->l2
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")
    l1.fundchannel(l2)
    bitcoind.generate_block(6)
    l1.daemon.wait_for_log(f"Received node_announcement for node {l2.info['id']}")
    # l2->l3
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")
    l2.fundchannel(l3)
    bitcoind.generate_block(6)
    l3.daemon.wait_for_log(f"Received node_announcement for node {l2.info['id']}")

    # restart both and wait for channels to be ready
    l1.restart()
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log(f"{l1.info['id']}.*Already have funding locked in")
    l3.restart()
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.daemon.wait_for_log(f"{l3.info['id']}.*Already have funding locked in")

    # if ip discovery would have been enabled, we would have send an updated
    # node_announcement by now. Check we didn't...
    bitcoind.generate_block(6)  # ugly, but we need to wait for gossip...
    assert not l2.daemon.is_in_log("Update our node_announcement for discovered address")


def test_remote_addr_port(node_factory, bitcoind):
    """Check address discovery (BOLT1 #917) can be done with non-default TCP ports
       We perform logic tests on L2, setup same as above:
         l1 --> [l2] <-- l3
    """
    port = 1234
    opts = {'dev-allow-localhost': None,
            'may_reconnect': True,
            'dev-no-reconnect': None,
            'announce-addr-discovered-port': port}
    l1, l2, l3 = node_factory.get_nodes(3, opts=[opts, opts, opts])

    # Disable announcing local autobind addresses with dev-allow-localhost.
    # We need to have l2 opts 'bind-addr' to the (generated) value of 'addr'.
    # So we stop, set 'bind-addr' option, delete 'addr' and restart first.
    l2.stop()
    l2.daemon.opts['bind-addr'] = l2.daemon.opts['addr']
    del l2.daemon.opts['addr']
    l2.start()
    assert len(l2.rpc.getinfo()['address']) == 0

    # l1->l2
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")
    l1.fundchannel(l2)
    bitcoind.generate_block(5)
    l1.daemon.wait_for_log(f"Received node_announcement for node {l2.info['id']}")
    # l2->l3
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.daemon.wait_for_log("Peer says it sees our address as: 127.0.0.1:[0-9]{5}")
    l2.fundchannel(l3)
    bitcoind.generate_block(5)

    # restart both and wait for channels to be ready
    l1.restart()
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log("Already have funding locked in")
    l3.restart()
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # if ip discovery would have been enabled, we would have send an updated
    # node_announcement by now. Check we didn't...
    l2.daemon.wait_for_logs(["Already have funding locked in",
                             "Update our node_announcement for discovered address"])
    info = l2.rpc.getinfo()
    assert len(info['address']) == 1
    assert info['address'][0]['type'] == 'ipv4'
    assert info['address'][0]['address'] == '127.0.0.1'
    assert info['address'][0]['port'] == port


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
    hang_port = int(match.groups()[0])

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
    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['to_us_msat'] == 10**6 * 1000
    assert p1['total_msat'] == 10**6 * 1000
    assert p2['to_us_msat'] == 0
    assert p2['total_msat'] == 10**6 * 1000


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_bad_opening(node_factory):
    # l1 asks for a too-long locktime
    l1 = node_factory.get_node(options={'watchtime-blocks': 2017})
    l2 = node_factory.get_node()
    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    assert ret['id'] == l2.info['id']

    l1.daemon.wait_for_log('Handed peer, entering loop')
    l2.daemon.wait_for_log('Handed peer, entering loop')

    l1.fundwallet(10**6 + 1000000)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    l2.daemon.wait_for_log('to_self_delay 2017 larger than 2016')


@unittest.skipIf(TEST_NETWORK != 'regtest', "Fee computation and limits are network specific")
@pytest.mark.slow_test
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@pytest.mark.parametrize("anchors", [False, True])
def test_opening_tiny_channel(node_factory, anchors):
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
    if anchors:
        min_commit_tx_fees = basic_fee(3750, True)
    else:
        min_commit_tx_fees = basic_fee(7500, False)
    overhead = reserves + min_commit_tx_fees
    if anchors:
        # Gotta fund those anchors too!
        overhead += 660

    l2_min_capacity = 1               # just enough to get past capacity filter
    l3_min_capacity = 10000           # the current default
    l4_min_capacity = 20000           # a server with more than default minimum

    opts = [{'min-capacity-sat': 0, 'dev-no-reconnect': None},
            {'min-capacity-sat': l2_min_capacity, 'dev-no-reconnect': None},
            {'min-capacity-sat': l3_min_capacity, 'dev-no-reconnect': None},
            {'min-capacity-sat': l4_min_capacity, 'dev-no-reconnect': None}]
    if anchors is False:
        for opt in opts:
            opt['dev-force-features'] = "-23"
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)

    with pytest.raises(RpcError, match=r'They sent (ERROR|WARNING|ABORT).*channel capacity is .*, which is below .*sat'):
        l1.fundchannel(l2, l2_min_capacity + overhead - 1)
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']

    l1.fundchannel(l2, l2_min_capacity + overhead)

    with pytest.raises(RpcError, match=r'They sent (ERROR|WARNING|ABORT).*channel capacity is .*, which is below .*sat'):
        l1.fundchannel(l3, l3_min_capacity + overhead - 1)
    assert only_one(l1.rpc.listpeers(l3.info['id'])['peers'])['connected']
    l1.fundchannel(l3, l3_min_capacity + overhead)

    with pytest.raises(RpcError, match=r'They sent (ERROR|WARNING|ABORT).*channel capacity is .*, which is below .*sat'):
        l1.fundchannel(l4, l4_min_capacity + overhead - 1)
    assert only_one(l1.rpc.listpeers(l4.info['id'])['peers'])['connected']
    l1.fundchannel(l4, l4_min_capacity + overhead)

    # Note that this check applies locally too, so you can't open it if
    # you would reject it.
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r"channel capacity is .*, which is below .*sat"):
        l3.fundchannel(l2, l3_min_capacity + overhead - 1)

    assert only_one(l3.rpc.listpeers(l2.info['id'])['peers'])['connected']
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

    # Add some for fees/emergency-reserve
    l1.fundwallet(SATS + 35000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], SATS, feerate='1875perkw')

    opening_utxo = only_one([o for o in l1.rpc.listfunds()['outputs'] if o['reserved']])
    psbt = l1.rpc.utxopsbt(0, "253perkw", 0, [opening_utxo['txid'] + ':' + str(opening_utxo['output'])], reserve=0, reservedok=True)['psbt']

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
    assert (only_one(l1.rpc.listpeerchannels()['channels'])['state']
            == 'CHANNELD_AWAITING_LOCKIN')


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
                       '=WIRE_TX_COMPLETE']

    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=EXPERIMENTAL_DUAL_FUND,
                               options={'dev-no-reconnect': None})
    l2 = node_factory.get_node(may_reconnect=EXPERIMENTAL_DUAL_FUND,
                               options={'dev-no-reconnect': None})

    l1.fundwallet(2000000)

    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)
        # First peer valishes, but later it just disconnects
        wait_for(lambda: all([p['connected'] is False for p in l1.rpc.listpeers()['peers']]))

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()['peers']) == 1
    assert len(l2.rpc.listpeers()['peers']) == 1


def test_remote_disconnect(node_factory):
    l1, l2 = node_factory.get_nodes(2)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: l2.rpc.listpeers()['peers'] != [])
    l2.rpc.disconnect(l1.info['id'])

    # l1 should notice!
    wait_for(lambda: l1.rpc.listpeers()['peers'] == [])


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
            l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)
        # First peer valishes, but later it just disconnects
        wait_for(lambda: all([p['connected'] is False for p in l1.rpc.listpeers()['peers']]))

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()) == 1
    assert len(l2.rpc.listpeers()) == 1


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
def test_disconnect_fundee_v2(node_factory):
    # Now error on fundee side during channel open, with them funding
    disconnects = ['-WIRE_ACCEPT_CHANNEL2',
                   '+WIRE_ACCEPT_CHANNEL2',
                   '-WIRE_TX_ADD_INPUT',
                   '+WIRE_TX_ADD_INPUT',
                   '-WIRE_TX_ADD_OUTPUT',
                   '+WIRE_TX_ADD_OUTPUT',
                   '-WIRE_TX_COMPLETE']

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
            l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)
        assert l1.rpc.getpeer(l2.info['id']) is None

    # This one will succeed.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)

    # Should still only have one peer!
    assert len(l1.rpc.listpeers()['peers']) == 1
    assert len(l2.rpc.listpeers()['peers']) == 1


@pytest.mark.openchannel('v1')
def test_disconnect_half_signed(node_factory):
    # Now, these are the corner cases.  Fundee sends funding_signed,
    # but opener doesn't receive it.
    disconnects = ['-WIRE_FUNDING_SIGNED']
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.fundwallet(2000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)

    # Peer remembers, opener doesn't.
    wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])
    assert len(l2.rpc.listpeerchannels(l1.info['id'])['channels']) == 1


@pytest.mark.openchannel('v2')
def test_disconnect_half_signed_v2(node_factory):
    # Now, these are the corner cases.
    # L1 remembers the channel, L2 doesn't
    disconnects = ['-WIRE_TX_COMPLETE']
    l1 = node_factory.get_node(disconnect=disconnects)
    l2 = node_factory.get_node()

    l1.fundwallet(2000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)

    # Opener remembers, peer doesn't.
    wait_for(lambda: l2.rpc.listpeers(l1.info['id'])['peers'] == [])
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)
    assert len(l1.rpc.listpeerchannels(l2.info['id'])['channels']) == 1


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
    l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)

    # They haven't forgotten each other.
    assert l1.rpc.getpeer(l2.info['id'])['id'] == l2.info['id']
    assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

    # Technically, this is async to fundchannel (and could reconnect first)
    if EXPERIMENTAL_DUAL_FUND:
        l1.daemon.wait_for_logs(['sendrawtx exit 0',
                                 'Peer has reconnected, state DUALOPEND_OPEN_COMMITTED'])
    else:
        l1.daemon.wait_for_logs(['sendrawtx exit 0',
                                 'Peer has reconnected, state CHANNELD_AWAITING_LOCKIN'])

    l1.bitcoin.generate_block(6)

    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(' to CHANNELD_NORMAL')


@pytest.mark.skip('needs blackhold support')
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
        l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)
    assert l1.rpc.getpeer(l2.info['id']) is None

    # Reconnect.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We should get a message about reconnecting.
    l2.daemon.wait_for_log('Killing opening daemon: Reconnected')
    l2.daemon.wait_for_log('Handed peer, entering loop')

    # Should work fine.
    l1.rpc.fundchannel(l2.info['id'], CHANNEL_SIZE)
    l1.daemon.wait_for_log('sendrawtx exit 0')

    l1.bitcoin.generate_block(3)

    # Just to be sure, second openingd hand over to channeld. This log line is about channeld being started
    l2.daemon.wait_for_log(r'channeld-chan#[0-9]: pid [0-9]+, msgfd [0-9]+')


@pytest.mark.skip('needs blackhold support')
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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_no_update(node_factory, executor, bitcoind):
    """Test that channel_ready is retransmitted on reconnect if new channel

    This tests if the `channel_ready` is sent if we receive a
    `channel_reestablish` message with `next_commitment_number` == 1
    and our `next_commitment_number` == 1.

    This test makes extensive use of disconnects followed by automatic
    reconnects. See comments for details.

    """
    disconnects = ["-WIRE_CHANNEL_READY", "-WIRE_SHUTDOWN"]
    # Allow bad gossip because it might receive WIRE_CHANNEL_UPDATE before
    # announcement of the disconnection
    l1 = node_factory.get_node(may_reconnect=True, allow_bad_gossip=True)
    l2 = node_factory.get_node(disconnect=disconnects, may_reconnect=True)

    # For channeld reconnection
    l1.rpc.connect(l2.info["id"], "localhost", l2.port)

    # LightningNode.fundchannel will fund the channel and generate a
    # block. The block triggers the channel_ready message, which
    # causes a disconnect. The retransmission is then caused by the
    # automatic retry.
    fundchannel_exec = executor.submit(l1.fundchannel, l2, 10**6, False)
    if l1.config('experimental-dual-fund'):
        l1.daemon.wait_for_log(r"dualopend.* Retransmitting channel_ready for channel")
    else:
        l1.daemon.wait_for_log(r"channeld.* Retransmitting channel_ready for channel")
    sync_blockheight(bitcoind, [l1, l2])
    fundchannel_exec.result()
    l1.stop()

    # For closingd reconnection
    l1.daemon.start()
    # Close will trigger the -WIRE_SHUTDOWN and we then wait for the
    # automatic reconnection to trigger the retransmission.
    l1.rpc.close(l2.info['id'], 0)
    l2.daemon.wait_for_log(r"channeld.* Retransmitting channel_ready for channel")
    l1.daemon.wait_for_log(r"CLOSINGD_COMPLETE")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reconnect_normal(node_factory):
    # Should reconnect fine even if locked message gets lost.
    disconnects = ['-WIRE_CHANNEL_READY',
                   '+WIRE_CHANNEL_READY']
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 10**6)


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

    route = [{'amount_msat': amt, 'id': l2.info['id'], 'delay': 5, 'channel': first_scid(l1, l2)}]

    for i in range(0, len(disconnects)):
        with pytest.raises(RpcError):
            l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
            l1.rpc.waitsendpay(rhash)

        # Wait for reconnection.
        l1.daemon.wait_for_log('Already have funding locked in')

    # This will send commit, so will reconnect as required.
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])


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

    route = [{'amount_msat': amt, 'id': l2.info['id'], 'delay': 5, 'channel': first_scid(l1, l2)}]

    # This will send commit, so will reconnect as required.
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    # Should have printed this for every reconnect.
    for i in range(0, len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')


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

    route = [{'amount_msat': amt, 'id': l2.info['id'], 'delay': 5, 'channel': first_scid(l1, l2)}]
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    for i in range(len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'


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

    route = [{'amount_msat': amt, 'id': l2.info['id'], 'delay': 5, 'channel': first_scid(l1, l2)}]
    l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
    for i in range(len(disconnects)):
        l1.daemon.wait_for_log('Already have funding locked in')
    assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'


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


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "sqlite3-specific DB manip")
def test_reconnect_remote_sends_no_sigs(node_factory):
    """We re-announce, even when remote node doesn't send its announcement_signatures on reconnect.
    """
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True, opts={'may_reconnect': True,
                                                                      'dev-no-reconnect': None})

    # Wipe l2's gossip_store
    l2.stop()
    gs_path = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'gossip_store')
    os.unlink(gs_path)
    l2.start()

    # l2 will now uses (REMOTE's) announcement_signatures it has stored
    wait_for(lambda: l2.rpc.listchannels()['channels'] != [])

    # Remove remote signatures from l1 so it asks for them (and delete gossip store)
    l1.db_manip("UPDATE channels SET remote_ann_node_sig=NULL, remote_ann_bitcoin_sig=NULL")
    gs_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store')
    os.unlink(gs_path)
    l1.restart()

    l1.connect(l2)
    l1needle = l1.daemon.logsearch_start
    l2needle = l2.daemon.logsearch_start

    # l1 asks once, l2 replies once.
    # Make sure we get all the msgs!
    time.sleep(5)

    l1.daemon.wait_for_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')
    l2.daemon.wait_for_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')

    l1msgs = [l.split()[4] for l in l1.daemon.logs[l1needle:] if 'WIRE_ANNOUNCEMENT_SIGNATURES' in l]
    assert l1msgs == ['peer_out', 'peer_in']

    # l2 only sends one.
    assert len([l for l in l2.daemon.logs[l2needle:] if 'peer_out WIRE_ANNOUNCEMENT_SIGNATURES' in l]) == 1


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_shutdown_awaiting_lockin(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'funding-confirms': 3})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundwallet(10**6 + 1000000)
    chanid = l1.rpc.fundchannel(l2.info['id'], 10**6)['channel_id']

    # Technically, this is async to fundchannel.
    bitcoind.generate_block(1, wait_for_mempool=1)

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

    bitcoind.generate_block(1, wait_for_mempool=1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(100)

    # Won't disconnect!
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'] == [])


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

    # Keeps emergency reserve!
    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    if 'anchors/even' in only_one(l1.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        assert outputs == [{'value': 25000}]
    else:
        assert outputs == []


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_all_too_much(node_factory):
    """Add more than max possible funds, fund a channel using all funds we can.
    """
    # l2 isn't wumbo, so channel should not be!
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=[{}, {'dev-force-features': '-19'}])

    addr, txid = l1.fundwallet(2**24 + 35000)
    l1.rpc.fundchannel(l2.info['id'], "all")
    assert l1.daemon.is_in_log("'all' was too large for non-wumbo channel, trimming")

    # One reserved, confirmed output spent above, and one change.
    outputs = l1.rpc.listfunds()['outputs']

    spent = only_one([o for o in outputs if o['status'] == 'confirmed'])

    assert spent['txid'] == txid
    assert spent['address'] == addr
    assert spent['reserved'] is True

    pending = only_one([o for o in outputs if o['status'] != 'confirmed'])
    assert pending['status'] == 'unconfirmed'
    assert pending['reserved'] is False
    assert only_one(l1.rpc.listfunds()['channels'])['amount_msat'] == Millisatoshi(str(2**24 - 1) + "sat")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_fail(node_factory, bitcoind):
    """Add some funds, fund a channel without enough funds"""
    max_locktime = 2016
    l1 = node_factory.get_node()
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

    # channels do not disconnect on failure
    only_one(l1.rpc.listpeers()['peers'])
    only_one(l2.rpc.listpeers()['peers'])

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
    l2 = node_factory.get_node(options={'dev-force-features': '-19'})
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
    push_msat = 20000 * 1000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)

    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fail to open (try to push too much)
    with pytest.raises(RpcError, match=r'Requested to push_msat of 20000000msat is greater than available funding amount 10000sat'):
        l1.rpc.fundchannel(l2.info['id'], 10000, push_msat=push_msat)

    # This should work.
    amount = amount - 1
    l1.rpc.fundchannel(l2.info['id'], amount, push_msat=push_msat)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    funds = only_one(l1.rpc.listfunds()['channels'])
    assert funds['our_amount_msat'] + push_msat == funds['amount_msat']

    chanid = first_channel_id(l2, l1)
    channel_mvts_1 = [
        {'type': 'chain_mvt', 'credit_msat': 16777215000, 'debit_msat': 0, 'tags': ['channel_open', 'opener']},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 20000000, 'tags': ['pushed'], 'fees_msat': '0msat'},
    ]
    channel_mvts_2 = [
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 0, 'tags': ['channel_open']},
        {'type': 'channel_mvt', 'credit_msat': 20000000, 'debit_msat': 0, 'tags': ['pushed'], 'fees_msat': '0msat'},
    ]
    check_coin_moves(l1, chanid, channel_mvts_1, chainparams)
    check_coin_moves(l2, chanid, channel_mvts_2, chainparams)

    assert account_balance(l1, chanid) == amount * 1000 - push_msat


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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


@pytest.mark.openchannel('v1')
def test_funding_external_wallet_corners(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2, opts={'may_reconnect': True,
                                             'dev-no-reconnect': None})

    # We have Wumbo, it's ok!
    amount = 2**24
    l1.fundwallet(amount + 10000000)

    # make sure we can generate PSBTs.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) != 0)

    # Some random (valid) psbt
    psbt = l1.rpc.fundpsbt(amount, '253perkw', 250, reserve=0)['psbt']

    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.fundchannel_start(l2.info['id'], amount)

    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.fundchannel_complete(l2.info['id'], psbt)

    # Should not be able to continue without being in progress.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r'No channel funding in progress.'):
        l1.rpc.fundchannel_complete(l2.info['id'], psbt)

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

    # Cancelling does NOT cause disconnection.
    only_one(l1.rpc.listpeers(l2.info['id'])['peers'])
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

    # Does not disconnect!
    only_one(l1.rpc.listpeers(l2.info['id'])['peers'])
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']
    prep = l1.rpc.txprepare([{funding_addr: amount}])

    assert l1.rpc.fundchannel_complete(l2.info['id'], prep['psbt'])['commitments_secured']

    # Check that can still cancel when peer is disconnected
    l1.rpc.disconnect(l2.info['id'], force=True)
    wait_for(lambda: not only_one(l1.rpc.listpeers()['peers'])['connected'])

    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['state']
             == 'CHANNELD_AWAITING_LOCKIN')

    assert l1.rpc.fundchannel_cancel(l2.info['id'])['cancelled']
    assert len(l1.rpc.listpeers()['peers']) == 0

    # on reconnect, channel should get destroyed
    # FIXME: if peer disconnects too fast, we get
    # "disconnected during connection"
    try:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    except RpcError as err:
        assert "disconnected during connection" in err.error

    l1.daemon.wait_for_log('Unknown channel .* for WIRE_CHANNEL_REESTABLISH')
    wait_for(lambda: len(l1.rpc.listpeers()['peers']) == 0)
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # But must unreserve inputs manually.
    l1.rpc.txdiscard(prep['txid'])

    # we have to connect again, because we got disconnected when everything errored
    wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])
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


@pytest.mark.openchannel('v2')
def test_funding_v2_corners(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)

    # We have wumbo, it's OK
    amount = 2**24
    l1.fundwallet(amount + 10000000)

    # make sure we can generate PSBTs.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()["outputs"]) != 0)

    # Some random (valid) psbt
    psbt = l1.rpc.fundpsbt(amount, '253perkw', 250, reserve=0)['psbt']
    nonexist_chanid = '11' * 32

    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.openchannel_init(l2.info['id'], amount, psbt)

    with pytest.raises(RpcError, match=r'Unknown channel'):
        l1.rpc.openchannel_update(nonexist_chanid, psbt)

    # Should not be able to continue without being in progress.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r'Unknown channel'):
        l1.rpc.openchannel_signed(nonexist_chanid, psbt)

    start = l1.rpc.openchannel_init(l2.info['id'], amount, psbt)
    # We can abort a channel
    l1.rpc.openchannel_abort(start['channel_id'])

    # Should be able to 'restart' after canceling
    amount2 = 1000000
    l1.rpc.unreserveinputs(psbt)
    psbt = l1.rpc.fundpsbt(amount2, '253perkw', 250, reserve=0)['psbt']
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    start = l1.rpc.openchannel_init(l2.info['id'], amount2, psbt)

    # Check that we're connected.
    # This caused a valgrind crash prior to this commit
    assert only_one(l2.rpc.listpeers()['peers'])

    # Disconnect peer.
    l1.rpc.disconnect(l2.info['id'], force=True)
    # FIXME: dualopend doesn't notice that connectd has closed peer conn
    # (until we reconnect!)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.disconnect(l2.info['id'])
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
    nodes = node_factory.get_nodes(num, opts={})

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
        psbt = l1.rpc.fundpsbt(amount, '7500perkw', 250, reserve=0,
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
        if l1.rpc.listpeers(l2.info['id'])['peers'] == []:
            return False
        return any([c['state'] == 'CHANNELD_AWAITING_LOCKIN'
                    or c['state'] == 'CHANNELD_NORMAL'
                    for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']])

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
            channel = node.rpc.listpeerchannels()['channels'][-1]
            assert amount * 1000 == channel['total_msat']

    def _close(src, dst, addr=None):
        """Close the channel from src to dst, with the specified address.

        Returns the address of the outputs in the close tx. Raises an
        error if some expectations are not met.

        """
        r = l1.rpc.close(l2.info['id'], destination=addr)
        assert r['type'] == 'mutual'
        tx = bitcoind.rpc.decoderawtransaction(only_one(r['txs']))

        addrs = [scriptpubkey_addr(vout['scriptPubKey']) for vout in tx['vout']]
        bitcoind.generate_block(1, wait_for_mempool=[only_one(r['txids'])])
        sync_blockheight(bitcoind, [l1, l2])
        return addrs

    # check that normal peer close works
    _fundchannel(l1, l2, amt_normal, None)
    _close(l1, l2)

    # check that you can provide a closing address upfront
    addr = l1.rpc.newaddr()['bech32']
    _fundchannel(l1, l2, amt_normal, addr)
    # confirm that it appears in listpeerchannels
    assert addr == l1.rpc.listpeerchannels()['channels'][1]['close_to_addr']
    assert _close(l1, l2) == [addr]

    # check that passing in the same addr to close works
    addr = bitcoind.rpc.getnewaddress()
    _fundchannel(l1, l2, amt_normal, addr)
    assert addr == l1.rpc.listpeerchannels()['channels'][2]['close_to_addr']
    assert _close(l1, l2, addr) == [addr]

    # check that remote peer closing works as expected (and that remote's close_to works)
    _fundchannel(l1, l2, amt_addr, addr)
    # send some money to remote so that they have a closeout
    l1.rpc.pay(l2.rpc.invoice((amt_addr // 2) * 1000, 'test_remote_close_to', 'desc')['bolt11'])
    assert l2.rpc.listpeerchannels()['channels'][-1]['close_to_addr'] == remote_valid_addr
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

    channels = l1.rpc.listpeerchannels(peer['id'])['channels']
    assert len(channels) == 1, f"Channels for peer {peer['id']} need to be not empty"
    assert any(r.match(line) for line in channels[0]['status'])
    assert 'OPENINGD' in channels[0]['state']

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
        channel = node.rpc.listpeerchannels()['channels'][0]
        assert amount * 1000 == channel['total_msat']

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

    # There should be change!
    tx = l1.rpc.multifundchannel(destinations)['tx']
    decoded = bitcoind.rpc.decoderawtransaction(tx)
    assert len(decoded['vout']) == len(destinations) + 1
    # Feerate should be about right, too!
    fee = Decimal(2000000) / 10**8 * len(decoded['vin']) - sum(v['value'] for v in decoded['vout'])
    assert 7450 < fee * 10**8 / decoded['weight'] * 1000 < 7550

    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4], wait_for_mempool=1)

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
    mine_funding_to_announce(bitcoind, [l1, l2, l3], num_blocks=6, wait_for_mempool=1)

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
    bitcoind.generate_block(1, wait_for_mempool=1)
    # Don't have others reject channel_announcement as too far in future.
    sync_blockheight(bitcoind, [l1, l2, l3, l4])
    bitcoind.generate_block(5)

    for node in [l1, l2, l3, l4]:
        node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    for ldest in [l2, l3, l4]:
        inv = ldest.rpc.invoice(5000, 'inv', 'inv')['bolt11']
        l1.rpc.pay(inv)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_listpeers_crash(node_factory, bitcoind, executor):
    '''
    Test for listpeers crash during dual-funding start
    '''
    l1, l2 = node_factory.get_nodes(2)

    do_listpeers = True

    # Do lots of listpeers while this is happening
    def lots_of_listpeers(node):
        while do_listpeers:
            node.rpc.listpeers()

    fut = executor.submit(lots_of_listpeers, l1)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundwallet(10**6 + 1000000)
    l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']

    do_listpeers = False
    fut.result()


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

    mine_funding_to_announce(bitcoind, [l1, l2, l3], num_blocks=6)

    for node in [l1, l2, l3]:
        node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

    for ldest in [l2, l3]:
        inv = ldest.rpc.invoice(5000, 'inv', 'inv')['bolt11']
        l1.rpc.pay(inv)


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
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'dev-no-reconnect': None},
                                                 {'dev-no-reconnect': None,
                                                  'disconnect': disconnects},
                                                 {'dev-no-reconnect': None}])

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
        wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])

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
    Test wumbo channel imposition in multifundchannel.  l3 not wumbo :(
    '''
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{}, {},
                                                 {'dev-force-features': '-19'}])

    l1.fundwallet(1 << 26)

    # This should fail.
    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 1 << 24}]
    with pytest.raises(RpcError, match='Amount exceeded'):
        l1.rpc.multifundchannel(destinations)

    # Open failure doesn't cause disconnect
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']

    # This should succeed.
    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 1 << 24},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000}]
    l1.rpc.multifundchannel(destinations)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Fees on elements are different")
@pytest.mark.openchannel('v1')  # v2 the weight calculation is off by 3
@pytest.mark.parametrize("anchors", [False, True])
def test_multifunding_feerates(node_factory, bitcoind, anchors):
    '''
    Test feerate parameters for multifundchannel
    '''
    funding_tx_feerate = '10000perkw'
    commitment_tx_feerate_int = 2000
    commitment_tx_feerate = str(commitment_tx_feerate_int) + 'perkw'

    opts = {'log-level': 'debug'}
    if anchors is False:
        opts['dev-force-features'] = "-23"
    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)

    l1.fundwallet(1 << 26)

    def _connect_str(node):
        return '{}@localhost:{}'.format(node.info['id'], node.port)

    destinations = [{"id": _connect_str(l2), 'amount': 50000}]

    res = l1.rpc.multifundchannel(destinations, feerate=funding_tx_feerate,
                                  commitment_feerate=commitment_tx_feerate)

    entry = bitcoind.rpc.getmempoolentry(res['txid'])
    weight = entry['weight']

    # If signature is unexpectedly short, we get a spurious failure here!
    res = bitcoind.rpc.decoderawtransaction(res['tx'])
    weight += 71 - len(res['vin'][0]['txinwitness'][0]) // 2
    expected_fee = int(funding_tx_feerate[:-5]) * weight // 1000
    assert expected_fee == entry['fees']['base'] * 10 ** 8

    # anchors ignores commitment_feerate!
    if anchors:
        commitment_tx_feerate_int = 3750
        commitment_tx_feerate = str(commitment_tx_feerate_int) + 'perkw'

    assert only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['feerate']['perkw'] == commitment_tx_feerate_int
    assert only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['feerate']['perkb'] == commitment_tx_feerate_int * 4

    txfee = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['last_tx_fee_msat']

    # We get the expected close txid, force close the channel, then fish
    # the details about the transaction out of the mempoool entry
    close_txid = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['scratch_txid']
    l1.rpc.dev_fail(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])
    entry = bitcoind.rpc.getmempoolentry(close_txid)

    # Because of how the anchor outputs protocol is designed,
    # we *always* pay for 2 anchor outs and their weight
    if anchors:
        weight = 1124
    else:
        # the commitment transactions' feerate is calculated off
        # of this fixed weight
        weight = 724

    expected_fee = commitment_tx_feerate_int * weight // 1000

    # At this point we only have one anchor output on the
    # tx, but we subtract out the extra anchor output amount
    # from the to_us output, so it ends up inflating
    # our fee by that much.
    if anchors:
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
    l1.rpc.check_request_schemas = False
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
            channels = n1.rpc.listpeerchannels(n2.info['id'])['channels']
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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(os.environ.get("TEST_CHECK_DBSTMTS", None) == "1",
                 "We kill l2, dblog plugin replay will be unreliable")
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

    channels = l1.rpc.listpeerchannels()['channels']
    assert(only_one(channels)['state'] == 'CHANNELD_NORMAL')

    # Both nodes should now have exactly one channel in the database
    for n in (l1, l2):
        assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 1)

    # Fire off a sendpay request, it'll get interrupted by a restart
    executor.submit(l1.pay, l2, 10000)
    # Wait for it to be committed to, i.e., stored in the DB
    l1.daemon.wait_for_log('peer_in WIRE_CHANNEL_READY')
    l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # Stop l2, l1 will reattempt to connect
    print("Killing l2 in mid HTLC")
    l2.daemon.kill()

    # Clear the disconnect and timer stop so we can proceed normally
    del l2.daemon.opts['dev-disable-commit-after']

    # Wait for l1 to notice
    wait_for(lambda: 'connected' not in l1.rpc.listpeerchannels()['channels'])

    # Now restart l2 and it should reload peers/channels from the DB
    l2.start()
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 1)

    # Wait for the restored HTLC to finish
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['to_us_msat'] == 99990000)

    wait_for(lambda: len([p for p in l1.rpc.listpeers()['peers'] if p['connected']]))
    wait_for(lambda: len([p for p in l2.rpc.listpeers()['peers'] if p['connected']]))

    # Now make sure this is really functional by sending a payment
    l1.pay(l2, 10000)

    # L1 doesn't actually update to_us_msat until it receives
    # revoke_and_ack from L2, which can take a little bit.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['to_us_msat'] == 99980000)
    assert only_one(l2.rpc.listpeerchannels()['channels'])['to_us_msat'] == 20000

    # Finally restart l1, and make sure it remembers
    l1.restart()
    assert only_one(l1.rpc.listpeerchannels()['channels'])['to_us_msat'] == 99980000

    # Keep l1 from sending its onchain tx
    def censoring_sendrawtx(r):
        return {'id': r['id'], 'result': {}}

    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', censoring_sendrawtx)

    # Now make sure l1 is watching for unilateral closes
    l2.rpc.dev_fail(l1.info['id'])
    l2.daemon.wait_for_log('Failing due to dev-fail command')
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)

    # L1 must notice.
    l1.daemon.wait_for_log(' to ONCHAIN')


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
    assert only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['private']
    # check non-private channel
    assert not only_one(l4.rpc.listpeerchannels(l3.info['id'])['channels'])['private']


def test_channel_reenable(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True}, fundchannel=True, wait_for_announce=True)

    l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))
    l2.daemon.wait_for_log('Received node_announcement for node {}'.format(l1.info['id']))

    # Both directions should be active before the restart
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])

    # Restart l2, will cause l1 to reconnect
    l2.stop()
    wait_for(lambda: [c['peer_connected'] for c in l1.rpc.listpeerchannels()['channels']] == [False])
    l2.start()

    # Updates may be suppressed if redundant; just test results.
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])
    wait_for(lambda: [c['peer_connected'] for c in l1.rpc.listpeerchannels()['channels']] == [True])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels()['channels']] == [True, True])
    wait_for(lambda: [c['peer_connected'] for c in l2.rpc.listpeerchannels()['channels']] == [True])


def test_update_fee(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=True)
    chanid = l1.get_channel_scid(l2)

    # Make l1 send out feechange.
    l1.set_feerates((14000, 11000, 7500, 3750))

    # Make payments.
    l1.pay(l2, 200000000)
    # First payment causes fee update.
    if 'anchors/even' in only_one(l2.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        l2.daemon.wait_for_log('peer updated fee to 3755')
    else:
        l2.daemon.wait_for_log('peer updated fee to 11005')
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
    assert 'ignore_fee_limits' not in only_one(l2.rpc.listpeerchannels()['channels'])
    assert 'ignore_fee_limits' not in only_one(l1.rpc.listpeerchannels()['channels'])

    # L1 asks for stupid low fee (will actually hit the floor of 253)
    l1.stop()
    l1.set_feerates((15, 15, 15, 15), False)
    # We need to increase l2's floor, so it rejects l1.
    l2.set_feerates((15000, 11000, 7500, 3750, 2000))
    l1.start()

    if 'anchors/even' in only_one(l1.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        fee = 1255
    else:
        fee = 258
    l1.daemon.wait_for_log(f'Received WARNING .*: update_fee {fee} outside range 2000-75000')
    # They hang up on *us*
    l1.daemon.wait_for_log('Peer transient failure in CHANNELD_NORMAL: channeld: Owning subdaemon channeld died')

    # Disconnects, but does not error.  Make sure it's noted in their status though.
    # FIXME: does not happen for l1!
    # assert 'update_fee 253 outside range 1875-75000' in only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['status'][0]
    assert f'update_fee {fee} outside range 2000-75000' in only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['status'][0]

    assert only_one(l2.rpc.listpeerchannels()['channels'])['feerate']['perkw'] != fee
    # Make l2 accept those fees, and it should recover.
    assert only_one(l2.rpc.setchannel(l1.get_channel_scid(l2), ignorefeelimits=True)['channels'])['ignore_fee_limits'] is True
    assert only_one(l2.rpc.listpeerchannels()['channels'])['ignore_fee_limits'] is True

    # Now we stay happy (and connected!)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['feerate']['perkw'] == fee)
    assert only_one(l2.rpc.listpeerchannels()['channels'])['peer_connected'] is True

    # This will fail to mutual close, since l2 won't ignore insane *close* fees!
    assert l1.rpc.close(l2.info['id'], unilateraltimeout=5)['type'] == 'unilateral'

    # Make sure the resolution of this one doesn't interfere with the next!
    # Note: may succeed, may fail with insufficient fee, depending on how
    # bitcoind feels!
    l1.daemon.wait_for_log('sendrawtx exit')
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2])

    # Trying to open a channel with too low a fee-rate is denied
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
    with pytest.raises(RpcError, match='They sent (ERROR|WARNING) .* feerate_per_kw .* below minimum'):
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
    l1.set_feerates((15000, 15000, 15000, 15000, 15000), False)
    l1.start()

    l3.daemon.wait_for_log('peer_in WIRE_UPDATE_FEE')
    l3.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # We need to wait until both have committed and revoked the
    # old state, otherwise we'll still try to commit with the old
    # 15sat/byte fee
    l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

    l1.rpc.close(chan)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'Assumes anchors')
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

    # Explicit feerate does not work still (doesn't apply for anchors!)
    # We could make it, but we need a separate commitment feerate for
    # anchors vs non-anchors, so easier after anchors are compulsory.
    with pytest.raises(RpcError, match='Cannot estimate fees'):
        l1.fundchannel(l2, 10**6, feerate='10000perkw')

    l1.set_feerates((2000, 2000, 2000, 2000))
    l1.fundchannel(l2, 10**6)

    l1.set_feerates((15000, 11000, 7500, 3750))

    # It will send UPDATE_FEE when it tries to send HTLC.
    inv = l2.rpc.invoice(5000, 'test_update_fee_dynamic', 'test_update_fee_dynamic')['bolt11']
    l1.rpc.pay(inv)

    l2.daemon.wait_for_log('peer_in.*UPDATE_FEE')

    # Now we take it away again!
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    # Make sure that registers!  (--developer means polling every second)
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
    l1.set_feerates((14000, 14000, 14000, 14000))
    l1.daemon.wait_for_log('Setting REMOTE feerate to 14005')
    l2.daemon.wait_for_log('Setting LOCAL feerate to 14005')
    l1.daemon.wait_for_log(r'dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    # Wait for reconnect....
    l1.daemon.wait_for_log('Feerate:.*LOCAL now 14005')

    l1.pay(l2, 200000000)
    l2.pay(l1, 100000000)

    # They should both have gotten commits with correct feerate.
    assert l1.daemon.is_in_log('got commitsig [0-9]*: feerate 14005')
    assert l2.daemon.is_in_log('got commitsig [0-9]*: feerate 14005')

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


def test_multiple_channels(node_factory):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert ret['id'] == l2.info['id']

    for i in range(3):
        chan, _ = l1.fundchannel(l2, 10**6)

        l1.rpc.close(chan)

        # If we don't wait for l2 to make the transition we can end up
        # attempting to re-estabilishing the channel
        l2.daemon.wait_for_log(
            r'State changed from CLOSINGD_SIGEXCHANGE to CLOSINGD_COMPLETE'
        )

    channels = l1.rpc.listpeerchannels()['channels']
    assert len(channels) == 3
    # Most in state ONCHAIN, last is CLOSINGD_COMPLETE
    for i in range(len(channels) - 1):
        assert channels[i]['state'] == 'ONCHAIN'
    assert channels[-1]['state'] == 'CLOSINGD_COMPLETE'


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
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'] == [])

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

    lfeatures = expected_peer_features()
    nfeatures = expected_node_features()

    # Gossiping but no node announcement yet
    assert l1.rpc.getpeer(l2.info['id'])['connected']
    assert len(l1.rpc.listpeerchannels(l2.info['id'])['channels']) == 0
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

    # Make sure close tx hits mempool before we mine blocks.
    bitcoind.generate_block(100, wait_for_mempool=1)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')
    assert l1.rpc.listpeerchannels(l2.info['id'])['channels'] == []
    assert l2.rpc.listpeerchannels(l1.info['id'])['channels'] == []

    # The only channel was closed, everybody should have forgotten the nodes
    assert l1.rpc.listnodes()['nodes'] == []
    assert l2.rpc.listnodes()['nodes'] == []


def test_disconnectpeer(node_factory, bitcoind):
    l1, l2, l3 = node_factory.get_nodes(3, opts={'may_reconnect': False})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Gossiping
    assert l1.rpc.getpeer(l2.info['id'])['connected']
    assert len(l1.rpc.listpeerchannels(l2.info['id'])['channels']) == 0
    assert l1.rpc.getpeer(l3.info['id'])['connected']
    assert len(l1.rpc.listpeerchannels(l3.info['id'])['channels']) == 0
    wait_for(lambda: l2.rpc.getpeer(l1.info['id']) is not None)

    # Disconnect l2 from l1
    l1.rpc.disconnect(l2.info['id'])

    # Make sure listpeers no longer returns the disconnected node
    assert l1.rpc.getpeer(l2.info['id']) is None
    wait_for(lambda: l2.rpc.getpeer(l1.info['id']) is None)

    # Make sure you cannot disconnect after disconnecting
    with pytest.raises(RpcError, match=r'Unknown peer'):
        l1.rpc.disconnect(l2.info['id'])
    with pytest.raises(RpcError, match=r'Unknown peer'):
        l2.rpc.disconnect(l1.info['id'])

    # Fund channel l1 -> l3
    l1.fundchannel(l3, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # disconnecting a non gossiping peer results in error
    with pytest.raises(RpcError, match=r'Peer has \(at least one\) channel in state CHANNELD_NORMAL'):
        l1.rpc.disconnect(l3.info['id'])


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
    blocks = 50
    # opener
    l1 = node_factory.get_node()
    # peer
    l2 = node_factory.get_node(options={"dev-max-funding-unconfirmed-blocks": blocks})
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Give opener some funds.
    l1.fundwallet(10**7)

    def mock_sendrawtransaction(r):
        return {'id': r['id'], 'error': {'code': 100, 'message': 'sendrawtransaction disabled'}}

    def mock_donothing(r):
        return {'id': r['id'], 'result': {'success': True}}

    # Prevent opener from broadcasting funding tx (any tx really).
    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_sendrawtransaction)
    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_donothing)

    # Fund the channel.
    # The process will complete, but opener will be unable
    # to broadcast and confirm funding tx.
    with pytest.raises(RpcError, match=r'sendrawtransaction disabled'):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    # Generate blocks until unconfirmed.
    bitcoind.generate_block(blocks)

    # fundee will forget channel!
    # (Note that we let the last number be anything (hence the {}\d)
    l2.daemon.wait_for_log(r'Forgetting channel: It has been {}\d blocks'.format(str(blocks)[:-1]))

    # fundee will also forget, but not disconnect from peer.
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'] == [])


@pytest.mark.openchannel('v2')
def test_fundee_node_unconfirmed(node_factory, bitcoind):
    """Test that fundee will successfully broadcast and
    funder still has correct UTXOs/correctly advances the channel
    """
    # opener
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    # Give opener some funds.
    l1.fundwallet(10**7)

    start_amount = only_one(l1.rpc.listfunds()['outputs'])['amount_msat']

    def mock_sendrawtransaction(r):
        return {'id': r['id'], 'error': {'code': 100, 'message': 'sendrawtransaction disabled'}}

    def mock_donothing(r):
        time.sleep(10)
        return bitcoind.rpc.sendrawtransaction(r['params'][0])

    # Prevent both from broadcasting funding tx (any tx really).
    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_sendrawtransaction)
    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_donothing)

    # Fund the channel.
    # The process will complete, but opener will be unable
    # to broadcast and confirm funding tx.
    with pytest.raises(RpcError, match=r'sendrawtransaction disabled'):
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    # Generate blocks until unconfirmed.
    bitcoind.generate_block(1, wait_for_mempool=1)

    # Check that l1 opened the channel
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')
    end_amount = only_one(l1.rpc.listfunds()['outputs'])['amount_msat']
    # We should be out the onchaind fees
    assert start_amount > end_amount + Millisatoshi(10 ** 7 * 100)


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

    # With anchors, not even with manual feerate!
    l1.rpc.withdraw(l2.rpc.newaddr()['bech32'], 10000, '1500perkb')
    if TEST_NETWORK == 'regtest':
        with pytest.raises(RpcError, match=r'Cannot estimate fees'):
            l1.rpc.fundchannel(l2.info['id'], 10**6, '2000perkw', minconf=0)

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
    l1.daemon.wait_for_logs(['Peer transient failure in CHANNELD_NORMAL',
                             'peer_disconnect_done'])
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
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_dataloss_protection(node_factory, bitcoind):
    l1 = node_factory.get_node(may_reconnect=True, options={'log-level': 'io'},
                               allow_warning=True,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(may_reconnect=True, options={'log-level': 'io'},
                               broken_log='Cannot broadcast our commitment tx: they have a future one|Unknown commitment .*, recovering our funds',
                               feerates=(7500, 7500, 7500, 7500))

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
    l2.daemon.wait_for_log("Peer permanent failure in CHANNELD_NORMAL:.*Awaiting unilateral close")

    # l2 must NOT drop to chain.
    l2.daemon.wait_for_log("Cannot broadcast our commitment tx: they have a future one")
    assert not l2.daemon.is_in_log('sendrawtx exit 0',
                                   start=l2.daemon.logsearch_start)

    # l1 should receive error and drop to chain
    l1.daemon.wait_for_log("They sent ERROR.*Awaiting unilateral close")
    l1.wait_for_channel_onchain(l2.info['id'])

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


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "sqlite3-specific DB rollback")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_dataloss_protection_no_broadcast(node_factory, bitcoind):
    # If l2 sends an old version, but *doesn't* send an error, l1 should not broadcast tx.
    # (https://github.com/lightning/bolts/issues/934)
    l1 = node_factory.get_node(may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500),
                               allow_warning=True,
                               options={'dev-no-reconnect': None})
    l2 = node_factory.get_node(may_reconnect=True,
                               feerates=(7500, 7500, 7500, 7500),
                               broken_log='Cannot broadcast our commitment tx: they have a future one',
                               disconnect=['-WIRE_ERROR'],
                               options={'dev-no-reconnect': None})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)
    l2.stop()

    # Save copy of the db.
    dbpath = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3")
    orig_db = open(dbpath, "rb").read()
    l2.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # After an htlc, we should get different results (two more commits)
    l1.pay(l2, 200000000)

    # Make sure both sides consider it completely settled (has received both
    # REVOKE_AND_ACK)
    l1.daemon.wait_for_logs(["peer_in WIRE_REVOKE_AND_ACK"] * 2)
    l2.daemon.wait_for_logs(["peer_in WIRE_REVOKE_AND_ACK"] * 2)

    # Now, move l2 back in time.
    l2.stop()
    # Save new db
    new_db = open(dbpath, "rb").read()
    # Overwrite with OLD db.
    open(dbpath, "wb").write(orig_db)
    l2.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l2 should freak out!  But fail when trying to send error
    l2.daemon.wait_for_logs(["Peer permanent failure in CHANNELD_NORMAL:.* Awaiting unilateral close",
                             'dev_disconnect: -WIRE_ERROR'])

    # l1 should NOT drop to chain, since it didn't receive an error.
    time.sleep(5)
    assert bitcoind.rpc.getrawmempool(False) == []

    # fix up l2.
    l2.stop()
    open(dbpath, "wb").write(new_db)
    l2.start()

    # All is forgiven
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.pay(l2, 200000000)


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
    l1.daemon.disconnect = None
    l1.start()

    # Payments will fail due to restart, but we can see results in listsendpays.
    print(l1.rpc.listsendpays())
    wait_for(lambda: [p['status'] for p in l1.rpc.listsendpays()['payments']] == ['complete', 'complete'])


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


@pytest.mark.skip('needs blackhold support')
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
    l1.daemon.disconnect = None
    l1.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 200000, wait_for_active=True)


@pytest.mark.skip('needs blackhold support')
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
    l1.daemon.disconnect = None
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
    if 'anchors/even' in only_one(l1.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        wait_for(lambda: l1.daemon.is_in_log('Setting REMOTE feerate to 3755'))
    else:
        wait_for(lambda: l1.daemon.is_in_log('Setting REMOTE feerate to 11005'))
    wait_for(lambda: l1.daemon.is_in_log('peer_out WIRE_UPDATE_FEE'))

    # Now change feerates to something l1 can't afford.
    l1.set_feerates((200000, 200000, 200000, 200000))

    # It will raise as far as it can (30551)
    if 'anchors/even' in only_one(l1.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        maxfeerate = 30551
    else:
        maxfeerate = 48000
    l1.daemon.wait_for_log('Setting REMOTE feerate to {}'.format(maxfeerate))
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE')

    # But it won't do it again once it's at max.
    with pytest.raises(TimeoutError):
        l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE', timeout=5)


def test_feerate_stress(node_factory, executor):
    # Third node makes HTLC traffic less predictable.
    l1, l2, l3 = node_factory.line_graph(3, opts={'commit-time': 100,
                                                  'may_reconnect': True,
                                                  'dev-fast-reconnect': None})

    l1.pay(l2, 10**9 // 2)
    scid12 = l1.get_channel_scid(l2)
    scid23 = l2.get_channel_scid(l3)

    routel1l3 = [{'amount_msat': '10002msat', 'id': l2.info['id'], 'delay': 11, 'channel': scid12},
                 {'amount_msat': '10000msat', 'id': l3.info['id'], 'delay': 5, 'channel': scid23}]
    routel2l1 = [{'amount_msat': '10000msat', 'id': l1.info['id'], 'delay': 5, 'channel': scid12}]

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

    # Wait for last payment
    # We can get TEMPORARY_CHANNEL_FAILURE due to disconnect, too.
    if l1done != 0:
        with pytest.raises(RpcError, match='WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS|WIRE_TEMPORARY_CHANNEL_FAILURE'):
            l1.rpc.waitsendpay("{:064x}".format(l1done - 1), timeout=TIMEOUT)
    if l2done != 0:
        with pytest.raises(RpcError, match='WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS|WIRE_TEMPORARY_CHANNEL_FAILURE'):
            l2.rpc.waitsendpay("{:064x}".format(l2done - 1), timeout=TIMEOUT)

    # Make sure it's reconnected, then try adjusting feerates
    wait_for(lambda: l1.rpc.getpeer(l2.info['id'])['connected'] and l2.rpc.getpeer(l1.info['id'])['connected'])

    l1.rpc.call('dev-feerate', [l2.info['id'], rate - 5])
    time.sleep(1)

    assert not l1.daemon.is_in_log('Bad.*signature')
    assert not l2.daemon.is_in_log('Bad.*signature')


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
        routel2l1 = [{'amount_msat': '10000msat', 'id': l1.info['id'], 'delay': 5, 'channel': scid12}]

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
    # l3 is not wumbo.
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{}, {}, {'dev-force-features': '-19'}])
    conn = l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)

    expected_features = expected_peer_features()
    assert conn['features'] == expected_features
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['features'] == expected_features

    # Now, can we open a giant channel?
    l1.fundwallet(1 << 26)
    l1.rpc.fundchannel(l2.info['id'], 1 << 24)

    # Get that mined, and announced.
    bitcoind.generate_block(6, wait_for_mempool=1)

    # Make sure l3 is ready to receive channel announcement!
    sync_blockheight(bitcoind, [l1, l2, l3])
    # Connect l3, get gossip.
    l3.rpc.connect(l1.info['id'], 'localhost', port=l1.port)

    # Make sure channel capacity is what we expected (might need to wait for
    # both channel updates!
    wait_for(lambda: [c['amount_msat'] for c in l3.rpc.listchannels()['channels']]
             == [Millisatoshi(str(1 << 24) + "sat")] * 2)

    # Make sure channel features are right from channel_announcement
    assert ([c['features'] for c in l3.rpc.listchannels()['channels']]
            == [expected_channel_features()] * 2)

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
    wait_for(lambda: l2.channel_state(l1) == 'ONCHAIN')

    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all')
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: 'CHANNELD_NORMAL' in [c['state'] for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']])
    wait_for(lambda: 'CHANNELD_NORMAL' in [c['state'] for c in l2.rpc.listpeerchannels(l1.info['id'])['channels']])

    # Exact amount depends on fees, but it will be wumbo!
    chan = only_one([c for c in l1.rpc.listpeerchannels(l2.info['id'])['channels'] if c['state'] == 'CHANNELD_NORMAL'])
    amount = chan['funding']['local_funds_msat']
    assert amount > Millisatoshi(str((1 << 24) - 1) + "sat")

    # We should know we can spend that much!
    spendable = chan['spendable_msat']
    assert spendable > Millisatoshi(str((1 << 24) - 1) + "sat")

    # So should peer.
    chan = only_one([c for c in l2.rpc.listpeerchannels(l1.info['id'])['channels'] if c['state'] == 'CHANNELD_NORMAL'])
    assert chan['receivable_msat'] == spendable

    # And we can wumbo pay, right?
    inv = l2.rpc.invoice(str(1 << 24) + "sat", "test_wumbo_channels", "wumbo payment")
    assert 'warning_mpp' not in inv

    l1.rpc.pay(inv['bolt11'])
    # Done in a single shot!
    assert len(l1.rpc.listsendpays()['payments']) == 1


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@pytest.mark.parametrize("anchors", [False, True])
def test_channel_features(node_factory, bitcoind, anchors):
    if TEST_NETWORK == 'regtest':
        if anchors is False:
            opts = {'dev-force-features': "-23"}
        else:
            opts = {}
    else:
        # We have to force this ON for elements!
        if anchors is False:
            opts = {}
        else:
            opts = {'dev-force-features': "+23"}
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)

    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], 0.1)
    bitcoind.generate_block(1)
    wait_for(lambda: l1.rpc.listfunds()['outputs'] != [])

    l1.rpc.fundchannel(l2.info['id'], 'all')

    # We should see features in unconfirmed channels.
    chan = only_one(l1.rpc.listpeerchannels()['channels'])
    assert 'option_static_remotekey' in chan['features']
    if anchors:
        assert 'option_anchors' in chan['features']

    # l2 should agree.
    assert only_one(l2.rpc.listpeerchannels()['channels'])['features'] == chan['features']

    # Confirm it.
    bitcoind.generate_block(1)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    chan = only_one(l1.rpc.listpeerchannels()['channels'])
    assert 'option_static_remotekey' in chan['features']
    if anchors:
        assert 'option_anchors' in chan['features']

    # l2 should agree.
    assert only_one(l2.rpc.listpeerchannels()['channels'])['features'] == chan['features']


def test_nonstatic_channel(node_factory, bitcoind):
    """Smoke test for a channel without option_static_remotekey"""
    l1, l2 = node_factory.get_nodes(2,
                                    # This forces us to allow send/recv of non-static-remotekey!
                                    opts={'dev-any-channel-type': None})
    l1.fundwallet(2000000)
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])
    bitcoind.generate_block(1, wait_for_mempool=1)

    chan = only_one(l1.rpc.listpeerchannels()['channels'])
    assert 'option_static_remotekey' not in chan['features']
    assert 'option_anchor' not in chan['features']
    assert 'option_anchors_zero_fee_htlc_tx' not in chan['features']
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    l1.pay(l2, 1000)
    l1.rpc.close(l2.info['id'])


@pytest.mark.skip('needs blackhold support')
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
        'amount_msat': 1000,
        'id': l2.info['id'],
        'delay': 5,
        'channel': first_scid(l1, l2)
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


def test_upgrade_statickey(node_factory, executor):
    """l1 doesn't have option_static_remotekey, l2 offers it."""
    l1, l2 = node_factory.get_nodes(2, opts=[{'may_reconnect': True,
                                              'experimental-upgrade-protocol': None,
                                              # This forces us to allow sending non-static-remotekey!
                                              'dev-any-channel-type': None},
                                             {'may_reconnect': True,
                                              # This forces us to accept non-static-remotekey!
                                              'dev-any-channel-type': None,
                                              'experimental-upgrade-protocol': None}])

    l1.fundwallet(2000000)
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])

    # Now reconnect.
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


def test_upgrade_statickey_onchaind(node_factory, executor, bitcoind):
    """We test penalty before/after, and unilateral before/after"""
    l1, l2 = node_factory.get_nodes(2, opts=[{'may_reconnect': True,
                                              'experimental-upgrade-protocol': None,
                                              # This forces us to allow sending non-static-remotekey!
                                              'dev-any-channel-type': None,
                                              # We try to cheat!
                                              'broken_log': r"onchaind-chan#[0-9]*: Could not find resolution for output .*: did \*we\* cheat\?"},
                                             {'may_reconnect': True,
                                              # This forces us to allow non-static-remotekey!
                                              'dev-any-channel-type': None,
                                              'experimental-upgrade-protocol': None}])

    l1.fundwallet(FUNDAMOUNT + 1000)
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    # TEST 1: Cheat from pre-upgrade.
    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')

    # Make sure another commitment happens, sending failed payment.
    routestep = {
        'amount_msat': 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': first_scid(l1, l2)
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

    _, txid, blocks = l2.wait_for_onchaind_tx('OUR_PENALTY_TX',
                                              'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM')
    assert blocks == 0

    bitcoind.generate_block(100, wait_for_mempool=txid)
    # This works even if they disconnect and listpeerchannels() is empty:
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'] == [])

    # TEST 2: Cheat from post-upgrade.
    l1.fundwallet(FUNDAMOUNT + 1000)
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')
    l2.daemon.wait_for_log('option_static_remotekey enabled at 1/1')
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    l1.pay(l2, 1000000)

    # We will try to cheat later.
    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    l1.pay(l2, 1000000)

    # Pre-statickey penalty works.
    bitcoind.rpc.sendrawtransaction(tx)
    bitcoind.generate_block(1)

    _, txid, blocks = l2.wait_for_onchaind_tx('OUR_PENALTY_TX',
                                              'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM')
    assert blocks == 0

    bitcoind.generate_block(100, wait_for_mempool=txid)
    # This works even if they disconnect and listpeers() is empty:
    wait_for(lambda: len(l1.rpc.listpeerchannels()['channels']) == 0)
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels']) == 0)

    # TEST 3: Unilateral close from pre-upgrade
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.fundwallet(FUNDAMOUNT + 1000)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

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
    _, txid, blocks = l1.wait_for_onchaind_tx('OUR_DELAYED_RETURN_TO_WALLET',
                                              'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
    assert blocks == 4
    l2.daemon.wait_for_logs(['Ignoring output .*: THEIR_UNILATERAL/OUTPUT_TO_US',
                             'Ignoring output .*: THEIR_UNILATERAL/DELAYED_OUTPUT_TO_THEM'])
    bitcoind.generate_block(4)
    bitcoind.generate_block(100, wait_for_mempool=txid)

    # This works even if they disconnect and listpeerchannels() is empty:
    wait_for(lambda: len(l1.rpc.listpeerchannels()['channels']) == 0)
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels']) == 0)

    # TEST 4: Unilateral close from post-upgrade
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('option_static_remotekey enabled at 1/1')

    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    # Move to static_remotekey.
    l1.pay(l2, 1000000)

    l2.stop()
    l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    bitcoind.generate_block(1, wait_for_mempool=1)
    l2.start()

    # They should both handle it fine.
    _, txid, blocks = l1.wait_for_onchaind_tx('OUR_DELAYED_RETURN_TO_WALLET',
                                              'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
    assert blocks == 4
    l2.daemon.wait_for_logs(['Ignoring output .*: THEIR_UNILATERAL/OUTPUT_TO_US',
                             'Ignoring output .*: THEIR_UNILATERAL/DELAYED_OUTPUT_TO_THEM'])

    bitcoind.generate_block(4)
    bitcoind.generate_block(100, wait_for_mempool=txid)

    # This works even if they disconnect and listpeerchannels() is empty:
    wait_for(lambda: len(l2.rpc.listpeerchannels()['channels']) == 0)


def test_upgrade_statickey_fail(node_factory, executor, bitcoind):
    """We reconnect at all points during retransmit, and we won't upgrade."""
    l1_disconnects = ['-WIRE_COMMITMENT_SIGNED',
                      '-WIRE_REVOKE_AND_ACK']
    l2_disconnects = ['-WIRE_REVOKE_AND_ACK',
                      '-WIRE_COMMITMENT_SIGNED']

    l1, l2 = node_factory.get_nodes(2, opts=[{'may_reconnect': True,
                                              'dev-no-reconnect': None,
                                              'disconnect': l1_disconnects,
                                              # This allows us to send non-static-remotekey!
                                              'dev-any-channel-type': None,
                                              'experimental-upgrade-protocol': None,
                                              # Don't have feerate changes!
                                              'feerates': (7500, 7500, 7500, 7500)},
                                             {'may_reconnect': True,
                                              'dev-no-reconnect': None,
                                              'experimental-upgrade-protocol': None,
                                              # This forces us to accept non-static-remotekey!
                                              'dev-any-channel-type': None,
                                              'disconnect': l2_disconnects,
                                              'plugin': os.path.join(os.getcwd(), 'tests/plugins/hold_htlcs.py'),
                                              'hold-time': 10000,
                                              'hold-result': 'fail'}])
    l1.fundwallet(FUNDAMOUNT + 1000)
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l1.rpc.fundchannel(l2.info['id'], 'all', channel_type=[])
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')

    # This HTLC will fail
    l1.rpc.sendpay([{'amount_msat': 1000, 'id': l2.info['id'], 'delay': 5, 'channel': first_scid(l1, l2)}], '00' * 32, payment_secret='00' * 32)

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
    assert 'option_static_remotekey' not in only_one(l1.rpc.listpeerchannels()['channels'])['features']
    assert 'option_static_remotekey' not in only_one(l2.rpc.listpeerchannels()['channels'])['features']

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
    assert 'option_static_remotekey' in only_one(l1.rpc.listpeerchannels()['channels'])['features']
    assert 'option_static_remotekey' in only_one(l2.rpc.listpeerchannels()['channels'])['features']


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
        'amount_msat': FUNDAMOUNT * 1000,
        'id': l2.info['id'],
        'delay': 5,
        'channel': first_scid(l1, l2)
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


@pytest.mark.openchannel('v2')
def test_multichan_stress(node_factory, executor, bitcoind):
    """Test multiple channels between same nodes"""
    l1, l2, l3 = node_factory.line_graph(3, opts={'may_reconnect': True,
                                                  'dev-no-reconnect': None})

    # Now fund *second* channel l2->l3 (slightly larger)
    bitcoind.rpc.sendtoaddress(l2.rpc.newaddr()['bech32'], 0.1)
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l2])
    l2.rpc.fundchannel(l3.info['id'], '0.01001btc')
    assert(len(l2.rpc.listpeerchannels(l3.info['id'])['channels']) == 2)
    assert(len(l3.rpc.listpeerchannels(l2.info['id'])['channels']) == 2)

    # Make sure gossip works.
    mine_funding_to_announce(bitcoind, [l1, l2, l3], num_blocks=6, wait_for_mempool=1)
    wait_for(lambda: len(l1.rpc.listchannels(source=l3.info['id'])['channels']) == 2)

    def send_many_payments():
        for i in range(30):
            inv = l3.rpc.invoice(100, "label-" + str(i), "desc")['bolt11']
            try:
                l1.rpc.pay(inv)
            except RpcError:
                pass

    # Send a heap of payments, while reconnecting...
    fut = executor.submit(send_many_payments)

    for i in range(10):
        l3.rpc.disconnect(l2.info['id'], force=True)
        l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    fut.result(TIMEOUT)

    wait_for(lambda: only_one(l3.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    inv = l3.rpc.invoice(50000000, "invoice4", "invoice4")
    l1.rpc.pay(inv['bolt11'])


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


def test_websocket(node_factory):
    ws_port = node_factory.get_unused_port()
    port = node_factory.get_unused_port()
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'addr': ':' + str(port),
                                            'bind-addr': 'ws:127.0.0.1: ' + str(ws_port),
                                            'dev-allow-localhost': None},
                                           {'dev-allow-localhost': None}],
                                     wait_for_announce=True)
    # Some depend on ipv4 vs ipv6 behaviour...
    for b in l1.rpc.getinfo()['binding']:
        if b['type'] == 'ipv4':
            assert b == {'type': 'ipv4', 'address': '0.0.0.0', 'port': port}
        elif b['type'] == 'ipv6':
            assert b == {'type': 'ipv6', 'address': '::', 'port': port}
        else:
            assert b == {'type': 'websocket',
                         'address': '127.0.0.1',
                         'subtype': 'ipv4',
                         'port': ws_port}

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

    # Check node_announcement does NOT have websocket
    assert not any([a['type'] == 'websocket'
                    for a in only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['addresses']])


def test_ping_timeout(node_factory):
    # Disconnects after this, but doesn't know it.
    l1_disconnects = ['xWIRE_PING']

    # We remove the gossip_queries feature: otherwise the peer can try to do
    # a gossip sync, and so we never get the period of no-traffic required to
    # trigger a ping!
    l1, l2 = node_factory.get_nodes(2, opts=[{'dev-no-reconnect': None,
                                              'dev-force-features': -7,
                                              'disconnect': l1_disconnects},
                                             {'dev-no-ping-timer': None,
                                              'dev-force-features': -7}])
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Ping timers runs at 15-45 seconds, *but* only fires if also 60 seconds
    # after previous traffic.
    l1.daemon.wait_for_log('dev_disconnect: xWIRE_PING', timeout=60 + 45 + 5)

    # Next pign will cause hangup
    l1.daemon.wait_for_log('Last ping unreturned: hanging up', timeout=45 + 5)
    wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_multichan(node_factory, executor, bitcoind):
    """Test multiple channels between same nodes"""
    l1, l2, l3 = node_factory.line_graph(3, opts={'may_reconnect': True})

    scid12 = l1.get_channel_scid(l2)
    scid23a = l2.get_channel_scid(l3)

    # Now fund *second* channel l2->l3 (slightly larger)
    bitcoind.rpc.sendtoaddress(l2.rpc.newaddr()['bech32'], 0.1)
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3])
    l2.rpc.fundchannel(l3.info['id'], '0.01001btc')
    assert(len(l2.rpc.listpeerchannels(l3.info['id'])['channels']) == 2)
    assert(len(l3.rpc.listpeerchannels(l2.info['id'])['channels']) == 2)

    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2, l3])
    # Make sure new channel is also CHANNELD_NORMAL
    wait_for(lambda: [c['state'] for c in l2.rpc.listpeerchannels(l3.info['id'])['channels']] == ["CHANNELD_NORMAL", "CHANNELD_NORMAL"])

    # Dance around to get the *other* scid.
    wait_for(lambda: all(['short_channel_id' in c for c in l3.rpc.listpeerchannels()['channels']]))
    scids = [c['short_channel_id'] for c in l3.rpc.listpeerchannels()['channels']]
    assert len(scids) == 2

    if scids[0] == scid23a:
        scid23b = scids[1]
    else:
        assert scids[1] == scid23a
        scid23b = scids[0]

    # Test paying by each,
    route = [{'amount_msat': 100001001,
              'id': l2.info['id'],
              'delay': 11,
              # Unneeded
              'channel': scid12},
             {'amount_msat': 100000000,
              'id': l3.info['id'],
              'delay': 5,
              'channel': scid23a}]

    before = l2.rpc.listpeerchannels(l3.info['id'])['channels']
    inv1 = l3.rpc.invoice(100000000, "invoice", "invoice")
    l1.rpc.sendpay(route, inv1['payment_hash'], payment_secret=inv1['payment_secret'])
    l1.rpc.waitsendpay(inv1['payment_hash'])

    # Wait until HTLCs fully settled
    wait_for(lambda: [c['htlcs'] for c in l2.rpc.listpeerchannels(l3.info['id'])['channels']] == [[], []])
    after = l2.rpc.listpeerchannels(l3.info['id'])['channels']

    if before[0]['short_channel_id'] == scid23a:
        chan23a_idx = 0
        chan23b_idx = 1
    else:
        chan23a_idx = 1
        chan23b_idx = 0

    # Gratuitous reconnect
    with pytest.raises(RpcError, match=r"Peer has \(at least one\) channel"):
        l3.rpc.disconnect(l2.info['id'])
    l3.rpc.disconnect(l2.info['id'], force=True)
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Check it used the larger channel!
    assert before[chan23a_idx]['to_us_msat'] == after[chan23a_idx]['to_us_msat']
    assert before[chan23b_idx]['to_us_msat'] != after[chan23b_idx]['to_us_msat']

    before = l2.rpc.listpeerchannels(l3.info['id'])['channels']
    route[1]['channel'] = scid23b
    inv2 = l3.rpc.invoice(100000000, "invoice2", "invoice2")
    l1.rpc.sendpay(route, inv2['payment_hash'], payment_secret=inv2['payment_secret'])
    l1.rpc.waitsendpay(inv2['payment_hash'])
    # Wait until HTLCs fully settled
    wait_for(lambda: [c['htlcs'] for c in l2.rpc.listpeerchannels(l3.info['id'])['channels']] == [[], []])
    after = l2.rpc.listpeerchannels(l3.info['id'])['channels']

    # Now the first channel is larger!
    assert before[chan23a_idx]['to_us_msat'] != after[chan23a_idx]['to_us_msat']
    assert before[chan23b_idx]['to_us_msat'] == after[chan23b_idx]['to_us_msat']

    # Make sure gossip works.
    bitcoind.generate_block(5)
    sync_blockheight(bitcoind, [l1, l2, l3])

    wait_for(lambda: len(l1.rpc.listchannels(source=l3.info['id'])['channels']) == 2)

    chans = l1.rpc.listchannels(source=l3.info['id'])['channels']
    if chans[0]['short_channel_id'] == scid23a:
        chan23a = chans[0]
        chan23b = chans[1]
    else:
        chan23a = chans[1]
        chan23b = chans[0]

    assert chan23a['amount_msat'] == Millisatoshi(1000000000)
    assert chan23a['short_channel_id'] == scid23a
    assert chan23b['amount_msat'] == Millisatoshi(1001000000)
    assert chan23b['short_channel_id'] == scid23b

    # We can close one, other one is still fine.
    with pytest.raises(RpcError, match="Peer has multiple channels"):
        l2.rpc.close(l3.info['id'])

    l2.rpc.close(scid23b)
    bitcoind.generate_block(13, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2, l3])

    # Gossip works as expected.
    wait_for(lambda: len(l1.rpc.listchannels(source=l3.info['id'])['channels']) == 1)
    assert only_one(l1.rpc.listchannels(source=l3.info['id'])['channels'])['short_channel_id'] == scid23a

    # We can actually pay by *closed* scid (at least until it's completely forgotten)
    route[1]['channel'] = scid23a
    inv3 = l3.rpc.invoice(100000000, "invoice3", "invoice3")
    l1.rpc.sendpay(route, inv3['payment_hash'], payment_secret=inv3['payment_secret'])
    l1.rpc.waitsendpay(inv3['payment_hash'])

    # Restart with multiple channels works.
    l3.restart()
    # FIXME: race against autoconnect can cause spurious failure (but we connect!)
    try:
        l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    except RpcError:
        wait_for(lambda: only_one(l3.rpc.listpeers(l2.info['id'])['peers'])['connected'])

    inv4 = l3.rpc.invoice(100000000, "invoice4", "invoice4")
    l1.rpc.pay(inv4['bolt11'])

    # A good place to test listhtlcs!
    wait_for(lambda: all([h['state'] == 'RCVD_REMOVE_ACK_REVOCATION' for h in l1.rpc.listhtlcs()['htlcs']]))

    l1htlcs = l1.rpc.listhtlcs()['htlcs']
    assert l1htlcs == l1.rpc.listhtlcs(scid12)['htlcs']
    assert l1htlcs == [{"short_channel_id": scid12,
                        "id": 0,
                        "expiry": 117,
                        "direction": "out",
                        "amount_msat": Millisatoshi(100001001),
                        "payment_hash": inv1['payment_hash'],
                        "state": "RCVD_REMOVE_ACK_REVOCATION"},
                       {"short_channel_id": scid12,
                        "id": 1,
                        "expiry": 117,
                        "direction": "out",
                        "amount_msat": Millisatoshi(100001001),
                        "payment_hash": inv2['payment_hash'],
                        "state": "RCVD_REMOVE_ACK_REVOCATION"},
                       {"short_channel_id": scid12,
                        "id": 2,
                        "expiry": 135,
                        "direction": "out",
                        "amount_msat": Millisatoshi(100001001),
                        "payment_hash": inv3['payment_hash'],
                        "state": "RCVD_REMOVE_ACK_REVOCATION"},
                       {"short_channel_id": scid12,
                        "id": 3,
                        "expiry": 135,
                        "direction": "out",
                        "amount_msat": Millisatoshi(100001001),
                        "payment_hash": inv4['payment_hash'],
                        "state": "RCVD_REMOVE_ACK_REVOCATION"}]

    # Reverse direction, should match l2's view of channel.
    for h in l1htlcs:
        h['direction'] = 'in'
        h['state'] = 'SENT_REMOVE_ACK_REVOCATION'
    assert l2.rpc.listhtlcs(scid12)['htlcs'] == l1htlcs


def test_mutual_reconnect_race(node_factory, executor, bitcoind):
    """Test simultaneous reconnect between nodes"""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
                                              'dev-no-reconnect': None})

    def send_many_payments():
        for i in range(20):
            time.sleep(0.5)
            inv = l2.rpc.invoice(
                100 - i,  # Ensure prior chanhints don't block us
                "label-" + str(i),
                "desc"
            )['bolt11']
            try:
                l1.rpc.pay(inv)
            except RpcError:
                pass

    # Send a heap of payments, while reconnecting...
    fut = executor.submit(send_many_payments)

    for i in range(10):
        try:
            l1.rpc.disconnect(l2.info['id'], force=True)
        except RpcError:
            pass
        time.sleep(1)
        # Aim for both at once!
        executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
        executor.submit(l2.rpc.connect, l1.info['id'], 'localhost', l1.port)

    # Wait for things to settle down, then make sure we're actually connected.
    # Naively, you'd think we should be, but in fact, two connects which race
    # can (do!) result in both disconnecting, thinking the other side is more
    # recent.
    time.sleep(1)
    if not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Now payments should finish!
    fut.result(TIMEOUT)

    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    inv = l2.rpc.invoice(100000000, "invoice4", "invoice4")
    l1.rpc.pay(inv['bolt11'])


def test_no_reconnect_awating_unilateral(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})
    l2.stop()

    # Close immediately.
    l1.rpc.close(l2.info['id'], 1)

    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'AWAITING_UNILATERAL')

    # After switching to AWAITING_UNILATERAL it will *not* try to reconnect.
    l1.daemon.wait_for_log("State changed from CHANNELD_SHUTTING_DOWN to AWAITING_UNILATERAL")
    time.sleep(10)

    assert not l1.daemon.is_in_log('Will try reconnect', start=l1.daemon.logsearch_start)


def test_peer_disconnected_reflected_in_channel_state(node_factory):
    """
    Make sure that if a node is disconnected we have the value correct value
    across listpeer and listpeerchannels.
    """
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})
    l2.stop()

    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['peer_connected'] is False)


def test_peer_disconnected_has_featurebits(node_factory):
    """
    Make sure that if a node is restarted, it still remembers feature
    bits from a peer it has a channel with but isn't connected to
    """
    l1, l2 = node_factory.line_graph(2)

    expected_features = expected_peer_features()

    l1_features = only_one(l2.rpc.listpeers()['peers'])['features']
    l2_features = only_one(l1.rpc.listpeers()['peers'])['features']
    assert l1_features == expected_features
    assert l2_features == expected_features

    l1.stop()
    l2.stop()

    # Ensure we persisted feature bits and return them even when disconnected
    l1.start()

    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'])['features'] == expected_features)


def test_reconnect_no_additional_transient_failure(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None}])
    l1id = l1.info['id']
    l2id = l2.info['id']
    # We wait until conenction is established and channel is NORMAL
    l2.daemon.wait_for_logs([f"{l1id}-connectd: Handed peer, entering loop",
                             f"{l1id}-chan#1: State changed from CHANNELD_AWAITING_LOCKIN to CHANNELD_NORMAL"])
    # We now stop l1
    l1.stop()
    # We wait for l2 to disconnect, ofc we also see an expected "Peer transient failure" here.
    l2.daemon.wait_for_logs([f"{l1id}-channeld-chan#1: Peer connection lost",
                             f"{l1id}-lightningd: peer_disconnect_done",
                             f"{l1id}-chan#1: Peer transient failure in CHANNELD_NORMAL: channeld: Owning subdaemon channeld died"])

    # When we restart l1 we should not see another Peer transient failure message.
    offset1 = l1.daemon.logsearch_start
    l1.start()

    # We wait until l2 is fine again with l1
    l2.daemon.wait_for_log(f"{l1id}-connectd: Handed peer, entering loop")

    time.sleep(5)

    # We should not see a "Peer transient failure" after restart of l1
    assert not l1.daemon.is_in_log(f"{l2id}-chan#1: Peer transient failure in CHANNELD_NORMAL: Disconnected", start=offset1)


@pytest.mark.xfail(strict=True)
def test_offline(node_factory):
    # if get_node starts it, it'll expect an address, so do it manually.
    l1 = node_factory.get_node(options={"offline": None}, start=False)
    l1.daemon.start()

    # we expect it to log offline mode an not to create any listener
    assert l1.daemon.is_in_log("Started in offline mode!")
    assert not l1.daemon.is_in_log("connectd: Created listener on")


def test_last_stable_connection(node_factory):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})

    # We wait a minute to be stable.
    STABLE_TIME = 60
    assert 'last_stable_connection' not in only_one(l1.rpc.listpeerchannels()['channels'])
    assert 'last_stable_connection' not in only_one(l2.rpc.listpeerchannels()['channels'])

    recon_time = time.time()

    # This take a minute, so don't fail if TIMEOUT is set to 10.
    wait_for(lambda: 'last_stable_connection' in only_one(l1.rpc.listpeerchannels()['channels']), timeout=STABLE_TIME + 15)
    l1stable = only_one(l1.rpc.listpeerchannels()['channels'])['last_stable_connection']
    wait_for(lambda: 'last_stable_connection' in only_one(l2.rpc.listpeerchannels()['channels']))
    l2stable = only_one(l2.rpc.listpeerchannels()['channels'])['last_stable_connection']

    # Disconnect, and/or restart then reconnect.
    l1.rpc.disconnect(l2.info['id'], force=True)
    recon_time = time.time()
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    assert only_one(l1.rpc.listpeerchannels()['channels'])['last_stable_connection'] == l1stable
    assert only_one(l2.rpc.listpeerchannels()['channels'])['last_stable_connection'] == l2stable
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['last_stable_connection'] != l1stable, timeout=STABLE_TIME + 15)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['last_stable_connection'] != l2stable)

    assert only_one(l1.rpc.listpeerchannels()['channels'])['last_stable_connection'] > recon_time + STABLE_TIME
    assert only_one(l2.rpc.listpeerchannels()['channels'])['last_stable_connection'] > recon_time + STABLE_TIME


def test_wss_proxy(node_factory):
    wss_port = node_factory.get_unused_port()
    ws_port = node_factory.get_unused_port()
    port = node_factory.get_unused_port()
    wss_proxy_certs = node_factory.directory + '/wss-proxy-certs'
    l1 = node_factory.get_node(options={'addr': ':' + str(port),
                                        'bind-addr': 'ws:127.0.0.1:' + str(ws_port),
                                        'wss-bind-addr': '127.0.0.1:' + str(wss_port),
                                        'wss-certs': wss_proxy_certs,
                                        'dev-allow-localhost': None})

    # Some depend on ipv4 vs ipv6 behaviour...
    for b in l1.rpc.getinfo()['binding']:
        if b['type'] == 'ipv4':
            assert b == {'type': 'ipv4', 'address': '0.0.0.0', 'port': port}
        elif b['type'] == 'ipv6':
            assert b == {'type': 'ipv6', 'address': '::', 'port': port}
        else:
            assert b == {'type': 'websocket',
                         'address': '127.0.0.1',
                         'subtype': 'ipv4',
                         'port': ws_port}

    # Adapter to turn web secure socket into a stream "connection"
    class BindWebSecureSocket(object):
        def __init__(self, hostname, port):
            certfile = f'{wss_proxy_certs}/client.pem'
            keyfile = f'{wss_proxy_certs}/client-key.pem'
            self.ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE, "ssl_version": ssl.PROTOCOL_TLS_CLIENT, "certfile": certfile, "keyfile": keyfile})
            self.ws.connect("wss://" + hostname + ":" + str(port))
            self.recvbuf = bytes()

        def send(self, data):
            self.ws.send(data, websocket.ABNF.OPCODE_BINARY)

        def recv(self, maxlen):
            while len(self.recvbuf) < maxlen:
                self.recvbuf += self.ws.recv()

            ret = self.recvbuf[:maxlen]
            self.recvbuf = self.recvbuf[maxlen:]
            return ret

    # There can be a delay between the printing of "Websocket Secure Server Started"
    # and actually binding the port.  There's no obvious way to delay that message
    # it's done.  So we sleep here.
    time.sleep(10)

    wss = BindWebSecureSocket('localhost', wss_port)

    lconn = wire.LightningConnection(wss,
                                     wire.PublicKey(bytes.fromhex(l1.info['id'])),
                                     wire.PrivateKey(bytes([1] * 32)),
                                     is_initiator=True)

    # This might happen really early!
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log(r'Websocket Secure Server Started')

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


def test_connect_transient(node_factory):
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts={'may_reconnect': True})

    # This is not transient, because they have a channel
    node_factory.join_nodes([l1, l2])

    # Make sure it reconnects once it has a channel.
    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # This has no channel, and thus is a transient.
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

    l1.rpc.dev_connectd_exhaust_fds()

    # Connecting to l4 will discard connection to l3!
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
    assert l1.rpc.listpeers(l3.info['id'])['peers'] == []
    assert l1.daemon.is_in_log(fr"due to stress, randomly closing peer {l3.info['id']} \(score 0\)")


def test_connect_transient_pending(node_factory, bitcoind, executor):
    """Test that we kick out in-connection transient connections"""
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=[{},
                                                     {'dev-handshake-no-reply': None},
                                                     {'dev-handshake-no-reply': None},
                                                     {}])

    # This will block...
    fut1 = executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
    fut2 = executor.submit(l1.rpc.connect, l3.info['id'], 'localhost', l3.port)

    assert not l1.daemon.is_in_log("due to stress, closing transient connect attempt")

    # Wait until those connects in progress.
    l2.daemon.wait_for_log("Connect IN")
    l3.daemon.wait_for_log("Connect IN")

    # Now force exhaustion.
    l1.rpc.dev_connectd_exhaust_fds()

    # This one will kick out one of the others.
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)
    line = l1.daemon.wait_for_log("due to stress, closing transient connect attempt")
    peerid = re.search(r'due to stress, closing transient connect attempt to (.*)', line).groups()[0]

    with pytest.raises(RpcError, match="Terminated due to too many connections"):
        if peerid == l2.info['id']:
            fut1.result(TIMEOUT)
        else:
            fut2.result(TIMEOUT)


def test_injectonionmessage(node_factory):
    """Test for injectonionmessage API"""
    l1, l2 = node_factory.line_graph(2)

    # This is deterministic, so the onion message created by fetchinvoice can be replayed here
    # manually
    l2.rpc.offer("any")
    # We saved the output from `l1.rpc.fetchinvoice(offer['bolt12'], 200)` with some logging.
    l1.rpc.injectonionmessage(message='0002cb7cd2001e3c670d64135542dcefdf4a3f590eb142cee9277b317848471906caeabe4afeae7f4e31f6ca9c119b643d5369c5e55f892f205469a185f750697124a2bb7ccea1245ec12d76340bcf7371ba6d1c9ddfe09b4153fce524417c14a594fdbb5e7c698a5daffe77db946727a38711be2ecdebdd347d2a9f990810f2795b3c39b871d7c72a11534bd388ca2517630263d96d8cc72d146bae800638066175c85a8e8665160ea332ed7d27efc31c960604d61c3f83801c25cbb69ae3962c2ef13b1fa9adc8dcbe3dc8d9a5e27ff5669e076b02cafef8f2c88fc548e03642180d57606386ad6ce27640339747d40f26eb5b9e93881fc8c16d5896122032b64bb5f1e4be6f41f5fa4dbd7851989aeccd80b2d5f6f25427f171964146185a8eaa57891d91e49a4d378743231e19edd5994c3118c9a415958a5d9524a6ecc78c0205f5c0059a7fbcf1abad706a189b712476d112521c9a4650d0ff09890536acae755a2b07d00811044df28b288d3dc2d5ae3f8bf3cf7a2950e2167105dfad0fb8398ef08f36abcdb1bfd6aca3241c33810f0750f35bdfb7c60b1759275b7704ab1bc8f3ea375b3588eab10e4f948f12fe0a3c77b67bebeedbcced1de0f0715f9959e5497cda5f8f6ab76c15b3dcc99956465de1bf2855338930650f8e8e8c391d9bb8950125dd60d8289dade0556d9dc443761983e26adcc223412b756e2fd9ad64022859b6cab20e8ffc3cf39ae6045b2c3338b1145ee3719a098e58c425db764d7f9a5034dbb730c20202f79bc3c53fab78ecd530aa0e8f7698c9ea53cb96dc9c639282c362d31177c5b81979f46f2db6090b8e171db47287523f28c462e35ef489b51426387f2709c342083968153b5f8a51cd5716b38106bb0f21c5ccfc28dd7c74b71c8367ae8ca348f66a7996bbc535076a1f65d9109658ec042257ca7523488fb1807dc8bec42739ccae066739cf58083b4e2c65e52e1747a6ec2aa26338bb6f2c3195a2b160e26dec70a2cfde269fa7c10c45d346a8bcc313bb618324edadc0291d15f4dc00ca3a7ad7131045fdf6978ba52178f4699525efcb8d96561630e2f28eaa97c66c38c66301b6c6f0124b550db620b09f35b9d45d1441cab7d93be5e3c39b9becfab7f8d05dd3a7a6e27a1d3f23f1dd01e967f5206600619f75439181848f7f4148216c11314b4eaf64c28c268ad4b33ea821d57728e9a9e9e1b6c4bcf35d14958295fc5f92bd6846f33c46f5fa20f569b25bc916b94e554f27a37448f873497e13baef8c740a7587828cc4136dd21b8584e6983e376e91663f8f91559637738b400fb49940fc2df299dfd448604b63c2f5d1f1ec023636f3baf2be5730364afd38191726a7c0d9477b1f231da4d707aabc6ad8036488181dbdb16b48500f2333036629004504d3524f87ece6afb04c4ba03ea6fce069e98b1ab7bf51f237d7c0f40756744dd703c6023b6461b90730f701404e8dddfaff40a9a60e670be7729556241fc9cc8727a586e38b71616bff8772c873b37d920d51a6ad31219a24b12f268545e2cfeb9e662236ab639fd4ecf865612678471ff7b320c934a13ca1f2587fc6a90f839c3c81c0ff84b51330820431418918e8501844893b53c1e0de46d51a64cb769974a996c58ff06683ebdc46fd4bb8e857cecebab785a351c64fd486fb648d25936cb09327b70d22c243035d4343fa3d2d148e2df5cd928010e34ae42b0333e698142050d9405b39f3aa69cecf8a388afbc7f199077b911cb829480f0952966956fe57d815f0d2467f7b28af11f8820645b601c0e1ad72a4684ebc60287d23ec3502f4c65ca44f5a4a0d79e3a5718cd23e7538cb35c57673fb9a1173e5526e767768117c7fefc2e3718f44f790b27e61995fecc6aef05107e75355be301ebe1500c147bb655a159f', path_key='03ccf3faa19e8d124f27d495e3359f4002a6622b9a02df9a51b609826d354cda52')

    # We should get a reply!
    l1.daemon.wait_for_log('lightningd: Got onionmsg with pathsecret')


def test_connect_ratelimit(node_factory, bitcoind):
    """l1 has 5 peers, restarts, make sure we limit"""
    nodes = node_factory.get_nodes(6,
                                   opts=[{'dev-limit-connections-inflight': None, 'may_reconnect': True}] + [{'may_reconnect': True}] * 5)

    l1 = nodes[0]
    nodes = nodes[1:]

    addr = l1.rpc.newaddr()['bech32']
    for n in nodes:
        bitcoind.rpc.sendtoaddress(addr, (FUNDAMOUNT + 1000000) / 10**8)
    bitcoind.generate_block(1, wait_for_mempool=len(nodes))
    sync_blockheight(bitcoind, [l1])

    for n in nodes:
        l1.rpc.connect(n.info['id'], 'localhost', n.port)
        l1.rpc.fundchannel(n.info['id'], FUNDAMOUNT)

    # Make sure all channels are established and announced.
    bitcoind.generate_block(6, wait_for_mempool=len(nodes))
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == len(nodes) * 2)

    assert not l1.daemon.is_in_log('Unblocking for')

    l1.restart()

    # The first will be ok, but others should block and be unblocked.
    l1.daemon.wait_for_logs((['Unblocking for ']
                             + ['Too many connections, waiting'])
                            * (len(nodes) - 1))

    # And now they're all connected
    wait_for(lambda: [p['connected'] for p in l1.rpc.listpeers()['peers']] == [True] * len(nodes))


def test_onionmessage_forward_fail(node_factory, bitcoind):
    # The plugin will try to connect to l3, so it needs an advertized address.
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{},
                                               {'dev-allow-localhost': None,
                                                'may_reconnect': True,
                                                'plugin': os.path.join(os.getcwd(), 'tests/plugins/onionmessage_forward_fail_notification.py'),
                                                },
                                               {'dev-allow-localhost': None,
                                                'may_reconnect': True}])

    offer = l3.rpc.offer(300, "test_onionmessage_forward_fail")
    l2.rpc.disconnect(l3.info['id'], force=True)

    # The plugin in l2 fixes up the connection, so this works!
    l1.rpc.fetchinvoice(offer['bolt12'])

    l2.daemon.is_in_log('plugin-onionmessage_forward_fail_notification.py: Received onionmessage_forward_fail')
