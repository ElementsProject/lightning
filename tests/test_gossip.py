from fixtures import *  # noqa: F401,F403
from lightning import RpcError
from utils import wait_for, TIMEOUT, only_one

import json
import logging
import os
import pytest
import struct
import subprocess
import time
import unittest


with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"


@unittest.skipIf(not DEVELOPER, "needs --dev-broadcast-interval, --dev-channelupdate-interval")
def test_gossip_pruning(node_factory, bitcoind):
    """ Create channel and see it being updated in time before pruning
    """
    opts = {'dev-channel-update-interval': 5}
    l1, l2, l3 = node_factory.get_nodes(3, opts)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    scid1 = l1.fund_channel(l2, 10**6)
    scid2 = l2.fund_channel(l3, 10**6)

    bitcoind.generate_block(6)

    # Channels should be activated locally
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True] * 4)
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels()['channels']] == [True] * 4)
    wait_for(lambda: [c['active'] for c in l3.rpc.listchannels()['channels']] == [True] * 4)

    # All of them should send a keepalive message
    l1.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid1),
    ])
    l2.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid1),
        'Sending keepalive channel_update for {}'.format(scid2),
    ])
    l3.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid2),
    ])

    # Now kill l3, so that l2 and l1 can prune it from their view after 10 seconds

    # FIXME: This sleep() masks a real bug: that channeld sends a
    # channel_update message (to disable the channel) with same
    # timestamp as the last keepalive, and thus is ignored.  The minimal
    # fix is to backdate the keepalives 1 second, but maybe we should
    # simply have gossipd generate all updates?
    time.sleep(1)
    l3.stop()

    l1.daemon.wait_for_log("Pruning channel {} from network view".format(scid2))
    l2.daemon.wait_for_log("Pruning channel {} from network view".format(scid2))

    assert scid2 not in [c['short_channel_id'] for c in l1.rpc.listchannels()['channels']]
    assert scid2 not in [c['short_channel_id'] for c in l2.rpc.listchannels()['channels']]
    assert l3.info['id'] not in [n['nodeid'] for n in l1.rpc.listnodes()['nodes']]
    assert l3.info['id'] not in [n['nodeid'] for n in l2.rpc.listnodes()['nodes']]


@unittest.skipIf(not DEVELOPER, "needs --dev-broadcast-interval, --dev-no-reconnect")
def test_gossip_disable_channels(node_factory, bitcoind):
    """Simple test to check that channels get disabled correctly on disconnect and
    reenabled upon reconnecting

    """
    opts = {'dev-no-reconnect': None, 'may_reconnect': True}
    l1, l2 = node_factory.get_nodes(2, opts=opts)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid = l1.fund_channel(l2, 10**6)
    bitcoind.generate_block(5)

    def count_active(node):
        chans = node.rpc.listchannels()['channels']
        active = [c for c in chans if c['active']]
        return len(active)

    l1.wait_channel_active(scid)
    l2.wait_channel_active(scid)

    assert(count_active(l1) == 2)
    assert(count_active(l2) == 2)

    l2.restart()

    wait_for(lambda: count_active(l1) == 0)
    assert(count_active(l2) == 0)

    # Now reconnect, they should re-enable the channels
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    wait_for(lambda: count_active(l1) == 2)
    wait_for(lambda: count_active(l2) == 2)


@unittest.skipIf(not DEVELOPER, "needs --dev-allow-localhost")
def test_announce_address(node_factory, bitcoind):
    """Make sure our announcements are well formed."""

    # We do not allow announcement of duplicates.
    opts = {'announce-addr':
            ['4acth47i6kxnvkewtm6q7ib2s3ufpo5sqbsnzjpbi7utijcltosqemad.onion',
             'silkroad6ownowfk.onion',
             '1.2.3.4:1234',
             '::'],
            'log-level': 'io',
            'dev-allow-localhost': None}
    l1, l2 = node_factory.get_nodes(2, opts=[opts, {}])

    # It should warn about the collision between --addr=127.0.0.1:<ephem>
    # and --announce-addr=1.2.3.4:1234 (may happen before get_nodes returns).
    wait_for(lambda: l1.daemon.is_in_log('Cannot announce address 127.0.0.1:[0-9]*, already announcing 1.2.3.4:1234'))
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid = l1.fund_channel(l2, 10**6)
    bitcoind.generate_block(5)

    # Activate IO logging for l1.
    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])

    l1.wait_channel_active(scid)
    l2.wait_channel_active(scid)

    # We should see it send node announce (257 = 0x0101)
    l1.daemon.wait_for_log(r"\[OUT\] 0101.*004d010102030404d202000000000000000000000000000000002607039216a8b803f3acd758aa260704e00533f3e8f2aedaa8969b3d0fa03a96e857bbb28064dca5e147e934244b9ba50230032607'")


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_gossip_timestamp_filter(node_factory, bitcoind):
    # Need full IO logging so we can see gossip (from gossipd and channeld)
    l1, l2, l3 = node_factory.line_graph(3, opts={'log-level': 'io'}, fundchannel=False)

    # Full IO logging for connectds
    subprocess.run(['kill', '-USR1', l1.subd_pid('connectd')])
    subprocess.run(['kill', '-USR1', l2.subd_pid('connectd')])

    before_anything = int(time.time() - 1.0)

    # Make a public channel.
    chan12 = l1.fund_channel(l2, 10**5)
    bitcoind.generate_block(5)

    l3.wait_for_channel_updates([chan12])
    after_12 = int(time.time())
    # Full IO logging for l1's channeld
    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])

    # Make another one, different timestamp.
    chan23 = l2.fund_channel(l3, 10**5)
    bitcoind.generate_block(5)

    l1.wait_for_channel_updates([chan23])
    after_23 = int(time.time())

    # Make sure l1 has received all the gossip.
    wait_for(lambda: ['alias' in node for node in l1.rpc.listnodes()['nodes']] == [True, True, True])

    # l1 sets broad timestamp, will receive info about both channels again.
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=0,
                                     range=0xFFFFFFFF)
    before_sendfilter = l1.daemon.logsearch_start

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # 0x0101 = node_announcement
    # The order of node_announcements relative to others is undefined.
    l1.daemon.wait_for_logs([r'\[IN\] 0102',
                             r'\[IN\] 0102',
                             r'\[IN\] 0100',
                             r'\[IN\] 0100',
                             r'\[IN\] 0102',
                             r'\[IN\] 0102',
                             r'\[IN\] 0101',
                             r'\[IN\] 0101',
                             r'\[IN\] 0101'])

    # Now timestamp which doesn't overlap (gives nothing).
    before_sendfilter = l1.daemon.logsearch_start
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=0,
                                     range=before_anything)
    time.sleep(1)
    assert not l1.daemon.is_in_log(r'\[IN\] 0100', before_sendfilter)

    # Now choose range which will only give first update.
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=before_anything,
                                     range=after_12 - before_anything + 1)
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0100')
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    l1.daemon.wait_for_log(r'\[IN\] 0102')

    # Now choose range which will only give second update.
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=after_12,
                                     range=after_23 - after_12 + 1)
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0100')
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    l1.daemon.wait_for_log(r'\[IN\] 0102')


@unittest.skipIf(not DEVELOPER, "needs --dev-allow-localhost")
def test_connect_by_gossip(node_factory, bitcoind):
    """Test connecting to an unknown peer using node gossip
    """
    # l1 announces a bogus addresses.
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{'announce-addr':
                                               ['127.0.0.1:2',
                                                '[::]:2',
                                                '3fyb44wdhnd2ghhl.onion',
                                                'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion'],
                                               'dev-allow-localhost': None},
                                              {},
                                              {'dev-allow-localhost': None,
                                               'log-level': 'io'}])
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Nodes are gossiped only if they have channels
    chanid = l2.fund_channel(l3, 10**6)
    bitcoind.generate_block(5)

    # Let channel reach announcement depth
    l2.wait_channel_active(chanid)

    # Make sure l3 has given node announcement to l2.
    l2.daemon.wait_for_logs(['Received node_announcement for node {}'.format(l3.info['id'])])

    # Let l1 learn of l3 by node gossip
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_logs(['Received node_announcement for node {}'.format(l3.info['id'])])

    # Have l1 connect to l3 without explicit host and port.
    l1.rpc.connect(l3.info['id'])


@unittest.skipIf(not DEVELOPER, "DEVELOPER=1 needed to speed up gossip propagation, would be too long otherwise")
def test_gossip_jsonrpc(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=True, wait_for_announce=False)

    # Shouldn't send announce signatures until 6 deep.
    assert not l1.daemon.is_in_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')

    # Channels should be activated locally
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: len(l2.rpc.listchannels()['channels']) == 2)

    # Make sure we can route through the channel, will raise on failure
    l1.rpc.getroute(l2.info['id'], 100, 1)

    # Outgoing should be active, but not public.
    channels1 = l1.rpc.listchannels()['channels']
    channels2 = l2.rpc.listchannels()['channels']

    assert [c['active'] for c in channels1] == [True, True]
    assert [c['active'] for c in channels2] == [True, True]
    # The incoming direction will be considered public, hence check for out
    # outgoing only
    assert len([c for c in channels1 if not c['public']]) == 2
    assert len([c for c in channels2 if not c['public']]) == 2

    # Test listchannels-by-source
    channels1 = l1.rpc.listchannels(source=l1.info['id'])['channels']
    channels2 = l2.rpc.listchannels(source=l1.info['id'])['channels']
    assert only_one(channels1)['source'] == l1.info['id']
    assert only_one(channels1)['destination'] == l2.info['id']
    assert channels1 == channels2

    l2.rpc.listchannels()['channels']

    # Now proceed to funding-depth and do a full gossip round
    l1.bitcoin.generate_block(5)
    # Could happen in either order.
    l1.daemon.wait_for_logs(['peer_out WIRE_ANNOUNCEMENT_SIGNATURES',
                             'peer_in WIRE_ANNOUNCEMENT_SIGNATURES'])

    # Just wait for the update to kick off and then check the effect
    needle = "Received node_announcement for node"
    l1.daemon.wait_for_log(needle)
    l2.daemon.wait_for_log(needle)
    # Need to increase timeout, intervals cannot be shortened with DEVELOPER=0
    wait_for(lambda: len(l1.getactivechannels()) == 2, timeout=60)
    wait_for(lambda: len(l2.getactivechannels()) == 2, timeout=60)

    nodes = l1.rpc.listnodes()['nodes']
    assert set([n['nodeid'] for n in nodes]) == set([l1.info['id'], l2.info['id']])

    # Test listnodes with an arg, while we're here.
    n1 = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
    n2 = l1.rpc.listnodes(l2.info['id'])['nodes'][0]
    assert n1['nodeid'] == l1.info['id']
    assert n2['nodeid'] == l2.info['id']

    # Might not have seen other node-announce yet.
    assert n1['alias'].startswith('JUNIORBEAM')
    assert n1['color'] == '0266e4'
    if 'alias' not in n2:
        assert 'color' not in n2
        assert 'addresses' not in n2
    else:
        assert n2['alias'].startswith('SILENTARTIST')
        assert n2['color'] == '022d22'

    assert [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True]
    assert [c['public'] for c in l1.rpc.listchannels()['channels']] == [True, True]
    assert [c['active'] for c in l2.rpc.listchannels()['channels']] == [True, True]
    assert [c['public'] for c in l2.rpc.listchannels()['channels']] == [True, True]


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
def test_gossip_badsig(node_factory):
    """Make sure node announcement signatures are ok.

    This is a smoke test to see if signatures fail. This used to be the case
    occasionally before PR #276 was merged: we'd be waiting for the HSM to reply
    with a signature and would then regenerate the message, which might roll the
    timestamp, invalidating the signature.

    """
    l1, l2, l3 = node_factory.get_nodes(3)

    # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.fund_channel(l1, 10**6)
    l2.fund_channel(l3, 10**6)

    # Wait for route propagation.
    l1.bitcoin.generate_block(5)
    l1.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l3.info['id']))
    assert not l1.daemon.is_in_log('signature verification failed')
    assert not l2.daemon.is_in_log('signature verification failed')
    assert not l3.daemon.is_in_log('signature verification failed')


def test_gossip_weirdalias(node_factory, bitcoind):
    weird_name = '\t \n \" \n \r \n \\'
    normal_name = 'Normal name'
    opts = [
        {'alias': weird_name},
        {'alias': normal_name}
    ]
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    weird_name_json = json.encoder.JSONEncoder().encode(weird_name)[1:-1].replace('\\', '\\\\')
    aliasline = l1.daemon.is_in_log('Server started with public key .* alias')
    assert weird_name_json in str(aliasline)
    assert l2.daemon.is_in_log('Server started with public key .* alias {}'
                               .format(normal_name))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('openingd-{} chan #1: Handed peer, entering loop'.format(l1.info['id']))
    l2.fund_channel(l1, 10**6)
    bitcoind.generate_block(6)

    # They should gossip together.
    l1.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l2.info['id']))
    l2.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l1.info['id']))

    node = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
    assert node['alias'] == weird_name
    node = l2.rpc.listnodes(l1.info['id'])['nodes'][0]
    assert node['alias'] == weird_name


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-no-reconnect")
def test_gossip_persistence(node_factory, bitcoind):
    """Gossip for a while, restart and it should remember.

    Also tests for funding outpoint spends, and they should be persisted
    too.
    """
    opts = {'dev-no-reconnect': None, 'may_reconnect': True}
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    l1.fund_channel(l2, 10**6)
    l2.fund_channel(l3, 10**6)

    # Make channels public, except for l3 -> l4, which is kept local-only for now
    bitcoind.generate_block(5)
    l3.fund_channel(l4, 10**6)
    bitcoind.generate_block(1)

    def count_active(node):
        chans = node.rpc.listchannels()['channels']
        active = [c for c in chans if c['active']]
        return len(active)

    # Channels should be activated
    wait_for(lambda: count_active(l1) == 4)
    wait_for(lambda: count_active(l2) == 4)
    wait_for(lambda: count_active(l3) == 6)  # 4 public + 2 local

    # l1 restarts and doesn't connect, but loads from persisted store, all
    # local channels should be disabled, leaving only the two l2 <-> l3
    # directions
    l1.restart()
    wait_for(lambda: count_active(l1) == 2)

    # Now reconnect, they should re-enable the two l1 <-> l2 directions
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: count_active(l1) == 4)

    # Now spend the funding tx, generate a block and see others deleting the
    # channel from their network view
    l1.rpc.dev_fail(l2.info['id'])
    time.sleep(1)
    bitcoind.generate_block(1)

    wait_for(lambda: count_active(l1) == 2)
    wait_for(lambda: count_active(l2) == 2)
    wait_for(lambda: count_active(l3) == 4)  # 2 public + 2 local

    # We should have one local-only channel
    def count_non_public(node):
        chans = node.rpc.listchannels()['channels']
        nonpublic = [c for c in chans if not c['public']]
        return len(nonpublic)

    # The channel l3 -> l4 should be known only to them
    assert count_non_public(l1) == 0
    assert count_non_public(l2) == 0
    wait_for(lambda: count_non_public(l3) == 2)
    wait_for(lambda: count_non_public(l4) == 2)

    # Finally, it should also remember the deletion after a restart
    l3.restart()
    l4.restart()
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)
    wait_for(lambda: count_active(l3) == 4)  # 2 public + 2 local

    # Both l3 and l4 should remember their local-only channel
    wait_for(lambda: count_non_public(l3) == 2)
    wait_for(lambda: count_non_public(l4) == 2)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_routing_gossip_reconnect(node_factory):
    # Connect two peers, reconnect and then see if we resume the
    # gossip.
    disconnects = ['-WIRE_CHANNEL_ANNOUNCEMENT']
    l1 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l3 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.openchannel(l2, 20000)

    # Now open new channels and everybody should sync
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.openchannel(l3, 20000)

    # Settle the gossip
    for n in [l1, l2, l3]:
        wait_for(lambda: len(n.rpc.listchannels()['channels']) == 4)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_gossip_no_empty_announcements(node_factory, bitcoind):
    # Need full IO logging so we can see gossip
    opts = {'log-level': 'io'}
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    # l3 sends CHANNEL_ANNOUNCEMENT to l2, but not CHANNEL_UDPATE.
    l3 = node_factory.get_node(disconnect=['+WIRE_CHANNEL_ANNOUNCEMENT'],
                               options={'dev-no-reconnect': None},
                               may_reconnect=True)
    l4 = node_factory.get_node(may_reconnect=True)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    # Turn on IO logging for openingd (make sure it's ready!)
    l1.daemon.wait_for_log('openingd-.*: Handed peer, entering loop')
    subprocess.run(['kill', '-USR1', l1.subd_pid('openingd')])
    l2.daemon.wait_for_log('openingd-{}.*: Handed peer, entering loop'.format(l3.info['id']))
    subprocess.run(['kill', '-USR1', l2.subd_pid('openingd-{}'.format(l3.info['id']))])

    # Make an announced-but-not-updated channel.
    l3.fund_channel(l4, 10**5)
    bitcoind.generate_block(5)

    # 0x0100 = channel_announcement, which goes to l2 before l3 dies.
    l2.daemon.wait_for_log(r'\[IN\] 0100')

    # l3 actually disconnects from l4 *and* l2!  That means we never see
    # the (delayed) channel_update from l4.
    wait_for(lambda: not l3.rpc.listpeers(l4.info['id'])['peers'][0]['connected'])
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    # But it never goes to l1, as there's no channel_update.
    time.sleep(2)
    assert not l1.daemon.is_in_log(r'\[IN\] 0100')
    assert len(l1.rpc.listchannels()['channels']) == 0

    # If we reconnect, gossip will now flow.
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
def test_routing_gossip(node_factory, bitcoind):
    nodes = node_factory.get_nodes(5)

    for i in range(len(nodes) - 1):
        src, dst = nodes[i], nodes[i + 1]
        src.rpc.connect(dst.info['id'], 'localhost', dst.port)
        src.openchannel(dst, 20000)

    # Allow announce messages.
    bitcoind.generate_block(5)

    # Deep check that all channels are in there
    comb = []
    for i in range(len(nodes) - 1):
        comb.append((nodes[i].info['id'], nodes[i + 1].info['id']))
        comb.append((nodes[i + 1].info['id'], nodes[i].info['id']))

    def check_gossip(n):
        seen = []
        channels = n.rpc.listchannels()['channels']
        for c in channels:
            seen.append((c['source'], c['destination']))
        missing = set(comb) - set(seen)
        logging.debug("Node {id} is missing channels {chans}".format(
            id=n.info['id'],
            chans=missing)
        )
        return len(missing) == 0

    for n in nodes:
        wait_for(lambda: check_gossip(n))


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_gossip_query_channel_range(node_factory, bitcoind):
    l1, l2, l3, l4 = node_factory.line_graph(4, opts={'log-level': 'io'},
                                             fundchannel=False)

    # Make public channels on consecutive blocks
    l1.fundwallet(10**6)
    l2.fundwallet(10**6)

    num_tx = len(bitcoind.rpc.getrawmempool())
    l1.rpc.fundchannel(l2.info['id'], 10**5)['tx']
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == num_tx + 1)
    bitcoind.generate_block(1)

    num_tx = len(bitcoind.rpc.getrawmempool())
    l2.rpc.fundchannel(l3.info['id'], 10**5)['tx']
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == num_tx + 1)
    bitcoind.generate_block(1)

    # Get them both to gossip depth.
    bitcoind.generate_block(5)

    # Make sure l2 has received all the gossip.
    l2.daemon.wait_for_logs(['Received node_announcement for node ' + l1.info['id'],
                             'Received node_announcement for node ' + l3.info['id']])

    scid12 = only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'][0]['short_channel_id']
    scid23 = only_one(l3.rpc.listpeers(l2.info['id'])['peers'])['channels'][0]['short_channel_id']
    block12 = int(scid12.split('x')[0])
    block23 = int(scid23.split('x')[0])

    assert block23 == block12 + 1

    # l1 asks for all channels, gets both.
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=1000000)

    assert ret['final_first_block'] == 0
    assert ret['final_num_blocks'] == 1000000
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 2
    assert ret['short_channel_ids'][0] == scid12
    assert ret['short_channel_ids'][1] == scid23

    # Does not include scid12
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=block12)
    assert ret['final_first_block'] == 0
    assert ret['final_num_blocks'] == block12
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 0

    # Does include scid12
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=block12 + 1)
    assert ret['final_first_block'] == 0
    assert ret['final_num_blocks'] == block12 + 1
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 1
    assert ret['short_channel_ids'][0] == scid12

    # Doesn't include scid23
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=block23)
    assert ret['final_first_block'] == 0
    assert ret['final_num_blocks'] == block23
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 1
    assert ret['short_channel_ids'][0] == scid12

    # Does include scid23
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=block12,
                                         num=block23 - block12 + 1)
    assert ret['final_first_block'] == block12
    assert ret['final_num_blocks'] == block23 - block12 + 1
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 2
    assert ret['short_channel_ids'][0] == scid12
    assert ret['short_channel_ids'][1] == scid23

    # Only includes scid23
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=block23,
                                         num=1)
    assert ret['final_first_block'] == block23
    assert ret['final_num_blocks'] == 1
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 1
    assert ret['short_channel_ids'][0] == scid23

    # Past both
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=block23 + 1,
                                         num=1000000)
    assert ret['final_first_block'] == block23 + 1
    assert ret['final_num_blocks'] == 1000000
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 0

    # Turn on IO logging in l1 channeld.
    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])

    # Make l2 split reply into two (technically async)
    l2.rpc.dev_set_max_scids_encode_size(max=9)
    l2.daemon.wait_for_log('Set max_scids_encode_bytes to 9')
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=1000000)

    # Turns out it sends: 0+53, 53+26, 79+13, 92+7, 99+3, 102+2, 104+1, 105+999895
    l1.daemon.wait_for_logs([r'\[IN\] 0108'] * 8)

    # It should definitely have split
    assert ret['final_first_block'] != 0 or ret['final_num_blocks'] != 1000000
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 2
    assert ret['short_channel_ids'][0] == scid12
    assert ret['short_channel_ids'][1] == scid23
    l2.daemon.wait_for_log('queue_channel_ranges full: splitting')

    # Test overflow case doesn't split forever; should still only get 8 for this
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=1,
                                         num=429496000)
    l1.daemon.wait_for_logs([r'\[IN\] 0108'] * 8)

    # And no more!
    time.sleep(1)
    assert not l1.daemon.is_in_log(r'\[IN\] 0108', start=l1.daemon.logsearch_start)

    # This should actually be large enough for zlib to kick in!
    l3.fund_channel(l4, 10**5)
    bitcoind.generate_block(5)
    l2.daemon.wait_for_log('Received node_announcement for node ' + l4.info['id'])

    # Restore infinite encode size.
    l2.rpc.dev_set_max_scids_encode_size(max=(2**32 - 1))
    l2.daemon.wait_for_log('Set max_scids_encode_bytes to {}'
                           .format(2**32 - 1))

    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=65535)
    l1.daemon.wait_for_log(
        # WIRE_REPLY_CHANNEL_RANGE
        r'\[IN\] 0108'
        # chain_hash
        + '................................................................'
        # first_blocknum
        + '00000000'
        # number_of_blocks
        + '0000ffff'
        # complete
        + '01'
        # length
        + '....'
        # encoding
        + '01'
    )


# Long test involving 4 lightningd instances.
@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_report_routing_failure(node_factory, bitcoind):
    """Test routing failure and retrying of routing.
    """
    # The setup is as follows:
    #   l3-->l4
    #   ^   / |
    #   |  /  |
    #   | L   v
    #   l2<--l1
    #
    # l1 wants to pay to l4.
    # The shortest route is l1-l4, but l1 cannot
    # afford to pay to l1 because l4 has all the
    # funds.
    # This is a local failure.
    # The next shortest route is l1-l2-l4, but
    # l2 cannot afford to pay l4 for same reason.
    # This is a remote failure.
    # Finally the only possible path is
    # l1-l2-l3-l4.

    def fund_from_to_payer(lsrc, ldst, lpayer):
        lsrc.rpc.connect(ldst.info['id'], 'localhost', ldst.port)
        c = lsrc.fund_channel(ldst, 10000000)
        bitcoind.generate_block(5)
        lpayer.wait_for_channel_updates([c])

    # Setup
    # Construct lightningd
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    # Wire them up
    # The ordering below matters!
    # Particularly, l1 is payer and we will
    # wait for l1 to receive gossip for the
    # channel being made.
    channels = []
    for src, dst in [(l1, l2), (l2, l3), (l3, l4), (l4, l1), (l4, l2)]:
        src.rpc.connect(dst.info['id'], 'localhost', dst.port)
        channels.append(src.fund_channel(dst, 10**6))
    bitcoind.generate_block(5)

    for c in channels:
        l1.wait_channel_active(c)

    # Test
    inv = l4.rpc.invoice(1234567, 'inv', 'for testing')['bolt11']
    l1.rpc.pay(inv)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_query_short_channel_id(node_factory, bitcoind):
    l1 = node_factory.get_node(options={'log-level': 'io'})
    l2 = node_factory.get_node()
    l3 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Need full IO logging so we can see gossip (from openingd and channeld)
    l1.daemon.wait_for_log('openingd-.*: Handed peer, entering loop')
    subprocess.run(['kill', '-USR1', l1.subd_pid('openingd')])

    # Empty result tests.
    reply = l1.rpc.dev_query_scids(l2.info['id'], ['1x1x1', '2x2x2'])
    # 0x0105 = query_short_channel_ids
    l1.daemon.wait_for_log(r'\[OUT\] 0105.*0000000100000100010000020000020002')
    assert reply['complete']

    # Make channels public.
    scid12 = l1.fund_channel(l2, 10**5)
    scid23 = l2.fund_channel(l3, 10**5)
    bitcoind.generate_block(5)

    # It will know about everything.
    l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l3.info['id']))
    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])

    # This query should get channel announcements, channel updates, and node announcements.
    reply = l1.rpc.dev_query_scids(l2.info['id'], [scid23])
    # 0x0105 = query_short_channel_ids
    l1.daemon.wait_for_log(r'\[OUT\] 0105')
    assert reply['complete']

    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0100')
    # 0x0102 = channel_update
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    # 0x0101 = node_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0101')
    l1.daemon.wait_for_log(r'\[IN\] 0101')

    reply = l1.rpc.dev_query_scids(l2.info['id'], [scid12, scid23])
    assert reply['complete']
    # Technically, this order could be different, but this matches code.
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0100')
    # 0x0102 = channel_update
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0100')
    # 0x0102 = channel_update
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    l1.daemon.wait_for_log(r'\[IN\] 0102')
    # 0x0101 = node_announcement
    l1.daemon.wait_for_log(r'\[IN\] 0101')
    l1.daemon.wait_for_log(r'\[IN\] 0101')


def test_gossip_addresses(node_factory, bitcoind):
    l1 = node_factory.get_node(options={'announce-addr': [
        '[::]:3',
        '127.0.0.1:2',
        'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion',
        '3fyb44wdhnd2ghhl.onion:1234'
    ]})
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fund_channel(l2, 100000)
    bitcoind.generate_block(6)
    l2.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l1.info['id']))

    nodes = l2.rpc.listnodes(l1.info['id'])['nodes']
    assert len(nodes) == 1 and nodes[0]['addresses'] == [
        {'type': 'ipv4', 'address': '127.0.0.1', 'port': 2},
        {'type': 'ipv6', 'address': '::', 'port': 3},
        {'type': 'torv2', 'address': '3fyb44wdhnd2ghhl.onion', 'port': 1234},
        {'type': 'torv3', 'address': 'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion', 'port': 9735}
    ]


def test_gossip_store_load(node_factory):
    """Make sure we can read canned gossip store"""
    l1 = node_factory.get_node(start=False)
    with open(os.path.join(l1.daemon.lightning_dir, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("03"  # GOSSIP_VERSION
                                  "000001bc"  # len
                                  "521ef598"  # csum
                                  "1000"  # WIRE_GOSSIP_STORE_CHANNEL_ANNOUNCEMENT
                                  "01b00100bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a0000000001000000"
                                  "00000086"  # len
                                  "88c703c8"  # csum
                                  "1001"  # WIRE_GOSSIP_STORE_CHANNEL_UPDATE
                                  "008201021ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440000009000000000000003e8000003e800000001"
                                  "00000099"  # len
                                  "12abbbba"  # csum
                                  "1002"  # WIRE_GOSSIP_STORE_NODE_ANNOUNCEMENT
                                  "00950101cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log('gossip_store: Read 1/1/1/0 cannounce/cupdate/nannounce/cdelete from store in 744 bytes'))
    assert not l1.daemon.is_in_log('gossip_store.*truncating')


@unittest.skipIf(not DEVELOPER, "Needs fast gossip propagation")
def test_node_reannounce(node_factory, bitcoind):
    "Test that we reannounce a node when parameters change"
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
                                              'log_all_io': True})
    bitcoind.generate_block(5)

    # Wait for node_announcement for l1.
    l2.daemon.wait_for_log(r'\[IN\] 0101.*{}'.format(l1.info['id']))
    # Wait for it to process it.
    wait_for(lambda: l2.rpc.listnodes(l1.info['id'])['nodes'] != [])
    wait_for(lambda: 'alias' in only_one(l2.rpc.listnodes(l1.info['id'])['nodes']))
    assert only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['alias'].startswith('JUNIORBEAM')

    l1.stop()
    l1.daemon.opts['alias'] = 'SENIORBEAM'
    l1.start()

    # Wait for l1 to send us its own node_announcement.
    nannouncement = l2.daemon.wait_for_log(r'{}.*\[IN\] 0101.*{}'.format(l1.info['id'], l1.info['id'])).split('[IN] ')[1]
    wait_for(lambda: only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['alias'] == 'SENIORBEAM')

    # Restart should re-xmit exact same update on reconnect.
    l1.restart()

    # l1 should retransmit it exactly the same (no timestamp change!)
    l2.daemon.wait_for_log(r'{}.*\[IN\] {}'.format(l1.info['id'], nannouncement))


def test_gossipwith(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    out = subprocess.run(['devtools/gossipwith',
                          '--initial-sync',
                          '--max-messages=5',
                          '{}@localhost:{}'.format(l1.info['id'], l1.port)],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

    num_msgs = 0
    while len(out):
        l, t = struct.unpack('>HH', out[0:4])
        # channel_announcement node_announcement or channel_update
        assert t == 256 or t == 257 or t == 258
        out = out[2 + l:]
        num_msgs += 1

    # one channel announcement, two channel_updates, two node announcements.
    assert num_msgs == 5


def test_gossip_notices_close(node_factory, bitcoind):
    # We want IO logging so we can replay a channel_announce to l1.
    l1 = node_factory.get_node(options={'log-level': 'io'})
    l2, l3 = node_factory.line_graph(2)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # FIXME: sending SIGUSR1 immediately may kill it before handler installed.
    l1.daemon.wait_for_log('Handed peer, entering loop')
    subprocess.run(['kill', '-USR1', l1.subd_pid('openingd')])

    bitcoind.generate_block(5)

    # Make sure l1 learns about channel.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: len(l1.rpc.listnodes()['nodes']) == 2)
    l1.rpc.disconnect(l2.info['id'])

    # Grab channel_announcement from io logs (ends in ')
    channel_announcement = l1.daemon.is_in_log(r'\[IN\] 0100').split(' ')[-1][:-1]
    channel_update = l1.daemon.is_in_log(r'\[IN\] 0102').split(' ')[-1][:-1]
    node_announcement = l1.daemon.is_in_log(r'\[IN\] 0101').split(' ')[-1][:-1]

    l2.rpc.close(l3.info['id'])
    wait_for(lambda: only_one(l2.rpc.listpeers(l3.info['id'])['peers'])['channels'][0]['state'] == 'CLOSINGD_COMPLETE')
    bitcoind.generate_block(1)

    wait_for(lambda: l1.rpc.listchannels()['channels'] == [])
    wait_for(lambda: l1.rpc.listnodes()['nodes'] == [])

    # FIXME: This is a hack: we should have a framework for canned conversations
    # This doesn't naturally terminate, so we give it 5 seconds.
    try:
        subprocess.run(['devtools/gossipwith',
                        '{}@localhost:{}'.format(l1.info['id'], l1.port),
                        channel_announcement,
                        channel_update,
                        node_announcement],
                       timeout=5, stdout=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        pass

    # l1 should reject it.
    assert(l1.rpc.listchannels()['channels'] == [])
    assert(l1.rpc.listnodes()['nodes'] == [])

    l1.stop()
    l1.start()
    assert(l1.rpc.listchannels()['channels'] == [])
    assert(l1.rpc.listnodes()['nodes'] == [])


def test_getroute_exclude(node_factory, bitcoind):
    """Test getroute's exclude argument"""
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True)

    # This should work
    route = l1.rpc.getroute(l4.info['id'], 1, 1)['route']

    # l1 id is > l2 id, so 1 means l1->l2
    chan_l1l2 = route[0]['channel'] + '/1'
    chan_l2l1 = route[0]['channel'] + '/0'

    # This should not
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l1l2])

    # Blocking the wrong way should be fine.
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l1])

    # Now, create an alternate (better) route.
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid = l2.fund_channel(l4, 1000000, wait_for_active=False)
    bitcoind.generate_block(5)

    # We don't wait above, because we care about it hitting l1.
    l1.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scid),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid)])

    # l3 id is > l2 id, so 1 means l3->l2
    # chan_l3l2 = route[1]['channel'] + '/1'
    chan_l2l3 = route[1]['channel'] + '/0'

    # l4 is > l2
    # chan_l4l2 = scid + '/1'
    chan_l2l4 = scid + '/0'

    # This works
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3])

    # This works
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l4])

    # This doesn't
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3, chan_l2l4])
