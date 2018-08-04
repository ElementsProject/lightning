from fixtures import *  # noqa: F401,F403
from utils import wait_for

import json
import logging
import os
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

    bitcoind.rpc.generate(6)

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
    bitcoind.rpc.generate(5)

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
            'log-level': 'io'}
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
    l1.daemon.wait_for_log("\[OUT\] 0101.*004d010102030404d202000000000000000000000000000000002607039216a8b803f3acd758aa260704e00533f3e8f2aedaa8969b3d0fa03a96e857bbb28064dca5e147e934244b9ba50230032607'")


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

    l3.wait_for_routes([chan12])
    after_12 = int(time.time())
    # Full IO logging for l1's channeld
    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])

    # Make another one, different timestamp.
    chan23 = l2.fund_channel(l3, 10**5)
    bitcoind.generate_block(5)

    l1.wait_for_routes([chan23])
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
    l1.daemon.wait_for_logs(['\[IN\] 0102',
                             '\[IN\] 0102',
                             '\[IN\] 0100',
                             '\[IN\] 0100',
                             '\[IN\] 0102',
                             '\[IN\] 0102',
                             '\[IN\] 0101',
                             '\[IN\] 0101',
                             '\[IN\] 0101'])

    # Now timestamp which doesn't overlap (gives nothing).
    before_sendfilter = l1.daemon.logsearch_start
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=0,
                                     range=before_anything)
    time.sleep(1)
    assert not l1.daemon.is_in_log('\[IN\] 0100', before_sendfilter)

    # Now choose range which will only give first update.
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=before_anything,
                                     range=after_12 - before_anything + 1)
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log('\[IN\] 0100')
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    l1.daemon.wait_for_log('\[IN\] 0102')
    l1.daemon.wait_for_log('\[IN\] 0102')

    # Now choose range which will only give second update.
    l1.rpc.dev_send_timestamp_filter(id=l2.info['id'],
                                     first=after_12,
                                     range=after_23 - after_12 + 1)
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log('\[IN\] 0100')
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    l1.daemon.wait_for_log('\[IN\] 0102')
    l1.daemon.wait_for_log('\[IN\] 0102')


@unittest.skipIf(not DEVELOPER, "needs --dev-allow-localhost")
def test_connect_by_gossip(node_factory, bitcoind):
    """Test connecting to an unknown peer using node gossip
    """
    l1, l2, l3 = node_factory.get_nodes(3)
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
    l1, l2 = node_factory.line_graph(2, fundchannel=True, announce=False)

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

    # Now proceed to funding-depth and do a full gossip round
    l1.bitcoin.generate_block(5)
    # Could happen in either order.
    l1.daemon.wait_for_logs(['peer_out WIRE_ANNOUNCEMENT_SIGNATURES',
                             'peer_in WIRE_ANNOUNCEMENT_SIGNATURES'])

    # Just wait for the update to kick off and then check the effect
    needle = "Received channel_update for channel"
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
    l2.fund_channel(l1, 10**6)
    bitcoind.rpc.generate(6)

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
    bitcoind.rpc.generate(5)
    l3.fund_channel(l4, 10**6)
    l1.bitcoin.rpc.generate(1)

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
    l1.bitcoin.rpc.generate(1)

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

    # Turn on IO logging for connectd
    subprocess.run(['kill', '-USR1', l1.subd_pid('connectd')])
    subprocess.run(['kill', '-USR1', l2.subd_pid('connectd')])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    # Make an announced-but-not-updated channel.
    l3.fund_channel(l4, 10**5)
    bitcoind.generate_block(5)

    # 0x0100 = channel_announcement, which goes to l2 before l3 dies.
    l2.daemon.wait_for_log('\[IN\] 0100')

    # l3 actually disconnects from l4 *and* l2!  That means we never see
    # the (delayed) channel_update from l4.
    wait_for(lambda: not l3.rpc.listpeers(l4.info['id'])['peers'][0]['connected'])
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    # But it never goes to l1, as there's no channel_update.
    time.sleep(2)
    assert not l1.daemon.is_in_log('\[IN\] 0100')
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
        wait_for(lambda: check_gossip(n), interval=1)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_gossip_query_channel_range(node_factory, bitcoind):
    l1, l2, l3, l4 = node_factory.line_graph(4, opts={'log-level': 'io'},
                                             fundchannel=False)

    # Make public channels.
    scid12 = l1.fund_channel(l2, 10**5)
    block12 = int(scid12.split(':')[0])
    scid23 = l2.fund_channel(l3, 10**5)
    block23 = int(scid23.split(':')[0])
    bitcoind.generate_block(5)

    # Make sure l2 has received all the gossip.
    l2.daemon.wait_for_logs(['Received node_announcement for node ' + l1.info['id'],
                             'Received node_announcement for node ' + l3.info['id']])

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

    # Make l2 split reply into two.
    l2.rpc.dev_set_max_scids_encode_size(max=9)
    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=1000000)

    # It should definitely have split
    assert ret['final_first_block'] != 0 or ret['final_num_blocks'] != 1000000
    assert ret['final_complete']
    assert len(ret['short_channel_ids']) == 2
    assert ret['short_channel_ids'][0] == scid12
    assert ret['short_channel_ids'][1] == scid23
    l2.daemon.wait_for_log('queue_channel_ranges full: splitting')

    # This should actually be large enough for zlib to kick in!
    l3.fund_channel(l4, 10**5)
    bitcoind.generate_block(5)
    l2.daemon.wait_for_log('Received node_announcement for node ' + l4.info['id'])

    # Turn on IO logging in l1 channeld.
    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])

    # Restore infinite encode size.
    l2.rpc.dev_set_max_scids_encode_size(max=(2**32 - 1))
    l2.daemon.wait_for_log('Set max_scids_encode_bytes to {}'
                           .format(2**32 - 1))

    ret = l1.rpc.dev_query_channel_range(id=l2.info['id'],
                                         first=0,
                                         num=65535)
    l1.daemon.wait_for_log(
        # WIRE_REPLY_CHANNEL_RANGE
        '\[IN\] 0108' +
        # chain_hash
        '................................................................' +
        # first_blocknum
        '00000000' +
        # number_of_blocks
        '0000ffff' +
        # complete
        '01' +
        # length
        '....' +
        # encoding
        '01'
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
        lpayer.wait_for_routes([c])

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

    # Need full IO logging so we can see gossip (from connectd and channeld)
    subprocess.run(['kill', '-USR1', l1.subd_pid('connectd')])

    # Empty result tests.
    reply = l1.rpc.dev_query_scids(l2.info['id'], ['1:1:1', '2:2:2'])
    # 0x0105 = query_short_channel_ids
    l1.daemon.wait_for_log('\[OUT\] 0105.*0000000100000100010000020000020002')
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
    l1.daemon.wait_for_log('\[OUT\] 0105')
    assert reply['complete']

    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log('\[IN\] 0100')
    # 0x0102 = channel_update
    l1.daemon.wait_for_log('\[IN\] 0102')
    l1.daemon.wait_for_log('\[IN\] 0102')
    # 0x0101 = node_announcement
    l1.daemon.wait_for_log('\[IN\] 0101')
    l1.daemon.wait_for_log('\[IN\] 0101')

    reply = l1.rpc.dev_query_scids(l2.info['id'], [scid12, scid23])
    assert reply['complete']
    # Technically, this order could be different, but this matches code.
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log('\[IN\] 0100')
    # 0x0102 = channel_update
    l1.daemon.wait_for_log('\[IN\] 0102')
    l1.daemon.wait_for_log('\[IN\] 0102')
    # 0x0100 = channel_announcement
    l1.daemon.wait_for_log('\[IN\] 0100')
    # 0x0102 = channel_update
    l1.daemon.wait_for_log('\[IN\] 0102')
    l1.daemon.wait_for_log('\[IN\] 0102')
    # 0x0101 = node_announcement
    l1.daemon.wait_for_log('\[IN\] 0101')
    l1.daemon.wait_for_log('\[IN\] 0101')


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
