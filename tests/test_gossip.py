from collections import Counter
from ephemeral_port_reserve import reserve
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from utils import (
    wait_for, TIMEOUT, only_one, sync_blockheight, expected_node_features, COMPAT
)

import json
import logging
import math
import os
import pytest
import struct
import subprocess
import time
import unittest
import socket


with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"


@unittest.skipIf(not DEVELOPER, "needs --dev-fast-gossip-prune")
def test_gossip_pruning(node_factory, bitcoind):
    """ Create channel and see it being updated in time before pruning
    """
    l1, l2, l3 = node_factory.get_nodes(3, opts={'dev-fast-gossip-prune': None})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    scid1, _ = l1.fundchannel(l2, 10**6)
    scid2, _ = l2.fundchannel(l3, 10**6)

    bitcoind.generate_block(6)

    # Channels should be activated locally
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True] * 4)
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels()['channels']] == [True] * 4)
    wait_for(lambda: [c['active'] for c in l3.rpc.listchannels()['channels']] == [True] * 4)

    # All of them should send a keepalive message (after 30 seconds)
    l1.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid1),
    ], timeout=50)
    l2.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid1),
        'Sending keepalive channel_update for {}'.format(scid2),
    ])
    l3.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid2),
    ])

    # Now kill l2, so that l1 and l3 will prune from their view after 60 seconds
    l2.stop()

    # We check every 60/4 seconds, and takes 60 seconds since last update.
    l1.daemon.wait_for_log("Pruning channel {} from network view".format(scid2),
                           timeout=80)
    l3.daemon.wait_for_log("Pruning channel {} from network view".format(scid1))

    assert scid2 not in [c['short_channel_id'] for c in l1.rpc.listchannels()['channels']]
    assert scid1 not in [c['short_channel_id'] for c in l3.rpc.listchannels()['channels']]
    assert l3.info['id'] not in [n['nodeid'] for n in l1.rpc.listnodes()['nodes']]
    assert l1.info['id'] not in [n['nodeid'] for n in l3.rpc.listnodes()['nodes']]


@unittest.skipIf(not DEVELOPER, "needs --dev-fast-gossip, --dev-no-reconnect")
def test_gossip_disable_channels(node_factory, bitcoind):
    """Simple test to check that channels get disabled correctly on disconnect and
    reenabled upon reconnecting

    """
    opts = {'dev-no-reconnect': None, 'may_reconnect': True}
    l1, l2 = node_factory.get_nodes(2, opts=opts)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 10**6)
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

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 10**6)
    bitcoind.generate_block(5)

    l1.wait_channel_active(scid)
    l2.wait_channel_active(scid)

    # We should see it send node announce with all addresses (257 = 0x0101)
    # local ephemeral port is masked out.
    l1.daemon.wait_for_log(r"\[OUT\] 0101.*54"
                           "010102030404d2"
                           "017f000001...."
                           "02000000000000000000000000000000002607"
                           "039216a8b803f3acd758aa2607"
                           "04e00533f3e8f2aedaa8969b3d0fa03a96e857bbb28064dca5e147e934244b9ba50230032607")


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_gossip_timestamp_filter(node_factory, bitcoind):
    # Updates get backdated 5 seconds with --dev-fast-gossip.
    backdate = 5
    l1, l2, l3, l4 = node_factory.line_graph(4, fundchannel=False)

    before_anything = int(time.time())

    # Make a public channel.
    chan12, _ = l1.fundchannel(l2, 10**5)
    bitcoind.generate_block(5)

    l3.wait_for_channel_updates([chan12])
    after_12 = int(time.time())

    # Make another one, different timestamp.
    time.sleep(1)
    chan23, _ = l2.fundchannel(l3, 10**5)
    bitcoind.generate_block(5)

    l1.wait_for_channel_updates([chan23])
    after_23 = int(time.time())

    # Make sure l4 has received all the gossip.
    wait_for(lambda: ['alias' in node for node in l4.rpc.listnodes()['nodes']] == [True, True, True])

    msgs = l4.query_gossip('gossip_timestamp_filter',
                           '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
                           '0', '0xFFFFFFFF',
                           filters=['0109'])

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # 0x0101 = node_announcement
    # The order of node_announcements relative to others is undefined.
    types = Counter([m[0:4] for m in msgs])
    assert types == Counter(['0100'] * 2 + ['0102'] * 4 + ['0101'] * 3)

    # Now timestamp which doesn't overlap (gives nothing).
    msgs = l4.query_gossip('gossip_timestamp_filter',
                           '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
                           '0', before_anything - backdate,
                           filters=['0109'])
    assert msgs == []

    # Now choose range which will only give first update.
    msgs = l4.query_gossip('gossip_timestamp_filter',
                           '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
                           before_anything - backdate,
                           after_12 - before_anything + 1,
                           filters=['0109'])

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    types = Counter([m[0:4] for m in msgs])
    assert types['0100'] == 1
    assert types['0102'] == 2

    # Now choose range which will only give second update.
    msgs = l4.query_gossip('gossip_timestamp_filter',
                           '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
                           after_12 - backdate,
                           after_23 - after_12 + 1,
                           filters=['0109'])

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    types = Counter([m[0:4] for m in msgs])
    assert types['0100'] == 1
    assert types['0102'] == 2


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
    chanid, _ = l2.fundchannel(l3, 10**6)
    bitcoind.generate_block(5)

    # Let channel reach announcement depth
    l2.wait_channel_active(chanid)

    # Make sure l3 has given node announcement to l2.
    l2.daemon.wait_for_logs(['Received node_announcement for node {}'.format(l3.info['id'])])

    # Let l1 learn of l3 by node gossip
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_logs(['Received node_announcement for node {}'.format(l3.info['id'])])

    # Have l1 connect to l3 without explicit host and port.
    ret = l1.rpc.connect(l3.info['id'])
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l3.port}

    # Now give it *wrong* port (after we make sure l2 isn't listening), it should fall back.
    l1.rpc.disconnect(l3.info['id'])
    l2.stop()
    ret = l1.rpc.connect(l3.info['id'], 'localhost', l2.port)
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l3.port}


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


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-fast-gossip")
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
    l2.fundchannel(l1, 10**6)
    l2.fundchannel(l3, 10**6)

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
    weird_name_json = json.encoder.JSONEncoder().encode(weird_name)[1:-1]
    aliasline = l1.daemon.is_in_log('Server started with public key .* alias')
    assert weird_name_json in str(aliasline)
    assert l2.daemon.is_in_log('Server started with public key .* alias {}'
                               .format(normal_name))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('Handed peer, entering loop')
    l2.fundchannel(l1, 10**6)
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

    scid12, _ = l1.fundchannel(l2, 10**6)
    scid23, _ = l2.fundchannel(l3, 10**6)

    # Make channels public, except for l3 -> l4, which is kept local-only for now
    bitcoind.generate_block(5)
    scid34, _ = l3.fundchannel(l4, 10**6)
    bitcoind.generate_block(1)

    def active(node):
        chans = node.rpc.listchannels()['channels']
        return sorted([c['short_channel_id'] for c in chans if c['active']])

    def non_public(node):
        chans = node.rpc.listchannels()['channels']
        return sorted([c['short_channel_id'] for c in chans if not c['public']])

    # Channels should be activated
    wait_for(lambda: active(l1) == [scid12, scid12, scid23, scid23])
    wait_for(lambda: active(l2) == [scid12, scid12, scid23, scid23])
    # This one sees its private channel
    wait_for(lambda: active(l3) == [scid12, scid12, scid23, scid23, scid34, scid34])

    # l1 restarts and doesn't connect, but loads from persisted store, all
    # local channels should be disabled, leaving only the two l2 <-> l3
    # directions
    l1.restart()
    wait_for(lambda: active(l1) == [scid23, scid23])

    # Now reconnect, they should re-enable the two l1 <-> l2 directions
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: active(l1) == [scid12, scid12, scid23, scid23])

    # Now spend the funding tx, generate a block and see others deleting the
    # channel from their network view
    l1.rpc.dev_fail(l2.info['id'])

    # We need to wait for the unilateral close to hit the mempool
    bitcoind.generate_block(1, wait_for_mempool=1)

    wait_for(lambda: active(l1) == [scid23, scid23])
    wait_for(lambda: active(l2) == [scid23, scid23])
    wait_for(lambda: active(l3) == [scid23, scid23, scid34, scid34])

    # The channel l3 -> l4 should be known only to them
    assert non_public(l1) == []
    assert non_public(l2) == []
    wait_for(lambda: non_public(l3) == [scid34, scid34])
    wait_for(lambda: non_public(l4) == [scid34, scid34])

    # Finally, it should also remember the deletion after a restart
    l3.restart()
    l4.restart()
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)
    wait_for(lambda: active(l3) == [scid23, scid23, scid34, scid34])

    # Both l3 and l4 should remember their local-only channel
    wait_for(lambda: non_public(l3) == [scid34, scid34])
    wait_for(lambda: non_public(l4) == [scid34, scid34])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_routing_gossip_reconnect(node_factory):
    # Connect two peers, reconnect and then see if we resume the
    # gossip.
    disconnects = ['-WIRE_CHANNEL_ANNOUNCEMENT']
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{'disconnect': disconnects,
                                               'may_reconnect': True},
                                              {'may_reconnect': True},
                                              {}])
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.openchannel(l2, 25000)

    # Now open new channels and everybody should sync
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.openchannel(l3, 25000)

    # Settle the gossip
    for n in [l1, l2, l3]:
        wait_for(lambda: len(n.rpc.listchannels()['channels']) == 4)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_gossip_no_empty_announcements(node_factory, bitcoind):
    # Need full IO logging so we can see gossip
    # l3 sends CHANNEL_ANNOUNCEMENT to l2, but not CHANNEL_UDPATE.
    l1, l2, l3, l4 = node_factory.line_graph(4, opts=[{'log-level': 'io'},
                                                      {'log-level': 'io'},
                                                      {'disconnect': ['+WIRE_CHANNEL_ANNOUNCEMENT'],
                                                       'may_reconnect': True},
                                                      {'may_reconnect': True}],
                                             fundchannel=False)

    # Make an announced-but-not-updated channel.
    l3.fundchannel(l4, 10**5)
    bitcoind.generate_block(5)

    # 0x0100 = channel_announcement, which goes to l2 before l3 dies.
    l2.daemon.wait_for_log(r'\[IN\] 0100')

    # But it never goes to l1, as there's no channel_update.
    time.sleep(2)
    assert not l1.daemon.is_in_log(r'\[IN\] 0100')
    assert len(l1.rpc.listchannels()['channels']) == 0

    # If we reconnect, gossip will now flow.
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-fast-gossip")
def test_routing_gossip(node_factory, bitcoind):
    nodes = node_factory.get_nodes(5)

    sync_blockheight(bitcoind, nodes)
    for i in range(len(nodes) - 1):
        src, dst = nodes[i], nodes[i + 1]
        src.rpc.connect(dst.info['id'], 'localhost', dst.port)
        src.openchannel(dst, 25000, confirm=False, wait_for_announce=False)
        sync_blockheight(bitcoind, nodes)

    # Avoid "bad gossip" caused by future announcements (a node below
    # confirmation height receiving and ignoring the announcement,
    # thus marking followup messages as bad).
    sync_blockheight(bitcoind, nodes)

    # Allow announce messages.
    bitcoind.generate_block(6)

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


@unittest.skipIf(not DEVELOPER, "needs dev-set-max-scids-encode-size")
def test_gossip_query_channel_range(node_factory, bitcoind, chainparams):
    l1, l2, l3, l4 = node_factory.line_graph(4, fundchannel=False)
    genesis_blockhash = chainparams['chain_hash']

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

    # Asks l2 for all channels, gets both.
    msgs = l2.query_gossip('query_channel_range',
                           chainparams['chain_hash'],
                           0, 1000000,
                           filters=['0109'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(1000000, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Does not include scid12
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, block12,
                           filters=['0109'])
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(block12, '08x') + '01'
                    # encoded_short_ids
                    '000100']

    # Does include scid12
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, block12 + 1,
                           filters=['0109'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(block12 + 1, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Doesn't include scid23
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, block23,
                           filters=['0109'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(block23, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Does include scid23
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           block12, block23 - block12 + 1,
                           filters=['0109'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(block12, '08x') + format(block23 - block12 + 1, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Only includes scid23
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           block23, 1,
                           filters=['0109'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(block23, '08x') + format(1, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Past both
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           block23 + 1, 1000000,
                           filters=['0109'])
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(block23 + 1, '08x') + format(1000000, '08x') + '01'
                    # encoded_short_ids
                    + '000100']

    # Make l2 split reply into two (technically async)
    l2.rpc.dev_set_max_scids_encode_size(max=9)
    l2.daemon.wait_for_log('Set max_scids_encode_bytes to 9')

    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, 1000000,
                           filters=['0109'])
    # It should definitely have split
    l2.daemon.wait_for_log('reply_channel_range: splitting 0-1 of 2')

    start = 0
    scids = '00'
    for m in msgs:
        assert m.startswith('0108' + genesis_blockhash)
        this_start = int(m[4 + 64:4 + 64 + 8], base=16)
        num = int(m[4 + 64 + 8:4 + 64 + 8 + 8], base=16)
        # Pull off end of packet, assume it's uncompressed, and no TLVs!
        scids += m[4 + 64 + 8 + 8 + 2 + 4 + 2:]
        assert this_start == start
        start += num

    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    assert scids == encoded

    # Test overflow case doesn't split forever; should still only get 2 for this
    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           1, 429496000,
                           filters=['0109'])
    assert len(msgs) == 2

    # This should actually be large enough for zlib to kick in!
    scid34, _ = l3.fundchannel(l4, 10**5)
    bitcoind.generate_block(5)
    l2.daemon.wait_for_log('Received node_announcement for node ' + l4.info['id'])

    # Restore infinite encode size.
    l2.rpc.dev_set_max_scids_encode_size(max=(2**32 - 1))
    l2.daemon.wait_for_log('Set max_scids_encode_bytes to {}'
                           .format(2**32 - 1))

    msgs = l2.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, 65535,
                           filters=['0109'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '01', scid12, scid23, scid34],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(65535, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]


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
        c, _ = lsrc.fundchannel(ldst, 10000000)
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
        print("src={}, dst={}".format(src.daemon.lightning_dir,
                                      dst.daemon.lightning_dir))
        c, _ = src.fundchannel(dst, 10**6)
        channels.append(c)
    bitcoind.generate_block(5)

    for c in channels:
        l1.wait_channel_active(c)

    # Test
    inv = l4.rpc.invoice(1234567, 'inv', 'for testing')['bolt11']
    l1.rpc.pay(inv)


@unittest.skipIf(not DEVELOPER, "needs fast gossip")
def test_query_short_channel_id(node_factory, bitcoind, chainparams):
    l1, l2, l3 = node_factory.get_nodes(3)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    chain_hash = chainparams['chain_hash']

    # Empty result tests.
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', '1x1x1', '2x2x2'],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()

    msgs = l1.query_gossip('query_short_channel_ids',
                           chain_hash,
                           encoded,
                           filters=['0109'])

    # Should just get the WIRE_REPLY_SHORT_CHANNEL_IDS_END = 262
    # (with chainhash and completeflag = 1)
    assert len(msgs) == 1
    assert msgs[0] == '0106{}01'.format(chain_hash)

    # Make channels public.
    scid12, _ = l1.fundchannel(l2, 10**5)
    scid23, _ = l2.fundchannel(l3, 10**5)
    bitcoind.generate_block(5)

    # It will know about everything.
    l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l3.info['id']))

    # This query should get channel announcements, channel updates, and node announcements.
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    msgs = l1.query_gossip('query_short_channel_ids',
                           chain_hash,
                           encoded,
                           filters=['0109'])

    assert len(msgs) == 6
    # 0x0100 = channel_announcement
    assert msgs[0].startswith('0100')
    # 0x0102 = channel_update
    assert msgs[1].startswith('0102')
    assert msgs[2].startswith('0102')
    # 0x0101 = node_announcement
    assert msgs[3].startswith('0101')
    assert msgs[4].startswith('0101')
    assert msgs[5] == '0106{}01'.format(chain_hash)

    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    msgs = l1.query_gossip('query_short_channel_ids',
                           chain_hash,
                           encoded,
                           filters=['0109'])

    # Technically, this order could be different, but this matches code.
    assert len(msgs) == 10
    # 0x0100 = channel_announcement
    assert msgs[0].startswith('0100')
    # 0x0102 = channel_update
    assert msgs[1].startswith('0102')
    assert msgs[2].startswith('0102')
    # 0x0100 = channel_announcement
    assert msgs[3].startswith('0100')
    # 0x0102 = channel_update
    assert msgs[4].startswith('0102')
    assert msgs[5].startswith('0102')
    # 0x0101 = node_announcement
    assert msgs[6].startswith('0101')
    assert msgs[7].startswith('0101')
    assert msgs[8].startswith('0101')
    assert msgs[9] == '0106{}01'.format(chain_hash)


def test_gossip_addresses(node_factory, bitcoind):
    l1 = node_factory.get_node(options={'announce-addr': [
        '[::]:3',
        '127.0.0.1:2',
        'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion',
        '3fyb44wdhnd2ghhl.onion:1234'
    ]})
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 100000)
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
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("09"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "00000082"  # len
                                  "fd421aeb"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440000009000000000000003e8000003e800000001"
                                  "00000095"  # len
                                  "f036515e"  # csum
                                  "5aab817c"  # timestamp
                                  "0101"      # WIRE_NODE_ANNOUNCEMENT
                                  "cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log(r'gossip_store: Read 1/1/1/0 cannounce/cupdate/nannounce/cdelete from store \(0 deleted\) in 770 bytes'))
    assert not l1.daemon.is_in_log('gossip_store.*truncating')


def test_gossip_store_load_announce_before_update(node_factory):
    """Make sure we can read canned gossip store with node_announce before update.  This happens when a channel_update gets replaced, leaving node_announce before it"""
    l1 = node_factory.get_node(start=False)
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("09"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "80000082"  # len (DELETED)
                                  "fd421aeb"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440000009000000000000003e8000003e800000001"
                                  "00000095"  # len
                                  "f036515e"  # csum
                                  "5aab817c"  # timestamp
                                  "0101"      # WIRE_NODE_ANNOUNCEMENT
                                  "cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"
                                  "00000082"  # len
                                  "fd421aeb"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440000009000000000000003e8000003e800000001"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log(r'gossip_store: Read 1/1/1/0 cannounce/cupdate/nannounce/cdelete from store \(0 deleted\) in 770 bytes'))
    assert not l1.daemon.is_in_log('gossip_store.*truncating')

    # Extra sanity check if we can.
    if DEVELOPER:
        l1.rpc.call('dev-compact-gossip-store')
        l1.restart()
        l1.rpc.call('dev-compact-gossip-store')


def test_gossip_store_load_amount_truncated(node_factory):
    """Make sure we can read canned gossip store with truncated amount"""
    l1 = node_factory.get_node(start=False, allow_broken_log=True)
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("09"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log(r'gossip_store: dangling channel_announcement. Moving to gossip_store.corrupt and truncating'))
    wait_for(lambda: l1.daemon.is_in_log(r'gossip_store: Read 0/0/0/0 cannounce/cupdate/nannounce/cdelete from store \(0 deleted\) in 1 bytes'))
    assert os.path.exists(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store.corrupt'))

    # Extra sanity check if we can.
    if DEVELOPER:
        l1.rpc.call('dev-compact-gossip-store')
        l1.restart()
        l1.rpc.call('dev-compact-gossip-store')


@unittest.skipIf(not DEVELOPER, "Needs fast gossip propagation")
def test_node_reannounce(node_factory, bitcoind):
    "Test that we reannounce a node when parameters change"
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
                                              'log-level': 'io'})
    bitcoind.generate_block(5)

    # Wait for node_announcement for l1.
    l2.daemon.wait_for_log(r'\[IN\] 0101.*{}'.format(l1.info['id']))
    # Wait for it to process it.
    wait_for(lambda: l2.rpc.listnodes(l1.info['id'])['nodes'] != [])
    wait_for(lambda: 'alias' in only_one(l2.rpc.listnodes(l1.info['id'])['nodes']))
    assert only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['alias'].startswith('JUNIORBEAM')

    lfeatures = expected_node_features()
    if l1.config('experimental-dual-fund'):
        lfeatures = expected_node_features(extra=[223])

    # Make sure it gets features correct.
    assert only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['features'] == lfeatures

    l1.stop()
    l1.daemon.opts['alias'] = 'SENIORBEAM'
    # It won't update within 5 seconds, so sleep.
    time.sleep(5)
    l1.start()

    wait_for(lambda: only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['alias'] == 'SENIORBEAM')

    # Get node_announcements.
    msgs = l1.query_gossip('gossip_timestamp_filter',
                           '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
                           '0', '0xFFFFFFFF',
                           # Filter out gossip_timestamp_filter,
                           # channel_announcement and channel_updates.
                           filters=['0109', '0102', '0100'])

    assert len(msgs) == 2
    assert (bytes("SENIORBEAM", encoding="utf8").hex() in msgs[0]
            or bytes("SENIORBEAM", encoding="utf8").hex() in msgs[1])

    # Restart should re-xmit exact same update on reconnect!
    l1.restart()

    msgs2 = l1.query_gossip('gossip_timestamp_filter',
                            '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
                            '0', '0xFFFFFFFF',
                            # Filter out gossip_timestamp_filter,
                            # channel_announcement and channel_updates.
                            filters=['0109', '0102', '0100'])
    assert msgs == msgs2
    # Won't have queued up another one, either.
    assert not l1.daemon.is_in_log('node_announcement: delaying')


def test_gossipwith(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    out = subprocess.run(['devtools/gossipwith',
                          '--initial-sync',
                          '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                          '{}@localhost:{}'.format(l1.info['id'], l1.port)],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

    num_msgs = 0
    while len(out):
        l, t = struct.unpack('>HH', out[0:4])
        # channel_announcement node_announcement, channel_update or timestamp_filter
        assert t == 256 or t == 257 or t == 258 or t == 265
        out = out[2 + l:]
        if t != 265:
            num_msgs += 1

    # one channel announcement, two channel_updates, two node announcements.
    assert num_msgs == 5


def test_gossip_notices_close(node_factory, bitcoind):
    # We want IO logging so we can replay a channel_announce to l1;
    # We also *really* do feed it bad gossip!
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'log-level': 'io',
                                                  'allow_bad_gossip': True},
                                                 {},
                                                 {}])
    node_factory.join_nodes([l2, l3])
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    bitcoind.generate_block(5)

    # Make sure l1 learns about channel and nodes.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: ['alias' in n for n in l1.rpc.listnodes()['nodes']] == [True, True])
    l1.rpc.disconnect(l2.info['id'])

    # Grab channel_announcement from io logs (ends in ')
    channel_announcement = l1.daemon.is_in_log(r'\[IN\] 0100').split(' ')[-1][:-1]
    channel_update = l1.daemon.is_in_log(r'\[IN\] 0102').split(' ')[-1][:-1]
    node_announcement = l1.daemon.is_in_log(r'\[IN\] 0101').split(' ')[-1][:-1]

    txid = l2.rpc.close(l3.info['id'])['txid']
    wait_for(lambda: only_one(l2.rpc.listpeers(l3.info['id'])['peers'])['channels'][0]['state'] == 'CLOSINGD_COMPLETE')
    bitcoind.generate_block(1, txid)

    wait_for(lambda: l1.rpc.listchannels()['channels'] == [])
    wait_for(lambda: l1.rpc.listnodes()['nodes'] == [])

    subprocess.run(['devtools/gossipwith',
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l1.info['id'], l1.port),
                    channel_announcement,
                    channel_update,
                    node_announcement],
                   timeout=TIMEOUT)

    # l1 should reject it.
    assert(l1.rpc.listchannels()['channels'] == [])
    assert(l1.rpc.listnodes()['nodes'] == [])

    l1.stop()
    l1.start()
    assert(l1.rpc.listchannels()['channels'] == [])
    assert(l1.rpc.listnodes()['nodes'] == [])


def test_getroute_exclude_duplicate(node_factory):
    """Test that accidentally duplicating the same channel or same node
    in the exclude list will not have permanent effects.
    """

    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    # Starting route
    route = l1.rpc.getroute(l2.info['id'], 1, 1)['route']
    # l1 id is > l2 id, so 1 means l1->l2
    chan_l1l2 = route[0]['channel'] + '/1'

    # This should fail to find a route as the only viable channel
    # is excluded, and worse, is excluded twice.
    with pytest.raises(RpcError):
        l1.rpc.getroute(l2.info['id'], 1, 1, exclude=[chan_l1l2, chan_l1l2])

    # This should still succeed since nothing is excluded anymore
    # and in particular should return the exact same route as
    # earlier.
    route2 = l1.rpc.getroute(l2.info['id'], 1, 1)['route']
    assert route == route2

    # This should also fail to find a route as the only viable channel
    # is excluded, and worse, is excluded twice.
    with pytest.raises(RpcError):
        l1.rpc.getroute(l2.info['id'], 1, 1, exclude=[l2.info['id'], l2.info['id']])

    # This should still succeed since nothing is excluded anymore
    # and in particular should return the exact same route as
    # earlier.
    route3 = l1.rpc.getroute(l2.info['id'], 1, 1)['route']
    assert route == route3


@unittest.skipIf(not DEVELOPER, "gossip propagation is slow without DEVELOPER=1")
def test_getroute_exclude(node_factory, bitcoind):
    """Test getroute's exclude argument"""
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5)
    node_factory.join_nodes([l1, l2, l3, l4], wait_for_announce=True)

    # This should work
    route = l1.rpc.getroute(l4.info['id'], 1, 1)['route']

    # l1 id is > l2 id, so 1 means l1->l2
    chan_l1l2 = route[0]['channel'] + '/1'
    chan_l2l1 = route[0]['channel'] + '/0'

    # This should not
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l1l2])

    # This should also not
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l2.info['id']])

    # Blocking the wrong way should be fine.
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l1])

    # Now, create an alternate (better) route.
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid, _ = l2.fundchannel(l4, 1000000, wait_for_active=False)
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

    # This works
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id']])

    # This doesn't
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3, chan_l2l4])

    # This doesn't
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], chan_l2l4])

    l1.rpc.connect(l5.info['id'], 'localhost', l5.port)
    scid15, _ = l1.fundchannel(l5, 1000000, wait_for_active=False)
    l5.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid54, _ = l5.fundchannel(l4, 1000000, wait_for_active=False)
    bitcoind.generate_block(5)

    # We don't wait above, because we care about it hitting l1.
    l1.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scid15),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid15),
                             r'update for channel {}/0 now ACTIVE'
                             .format(scid54),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid54)])

    # This works now
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], chan_l2l4])

    # This works now
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], l5.info['id']])

    # This doesn't work
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], l5.info['id'], chan_l2l4])

    # This doesn't work
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3, l5.info['id'], chan_l2l4])


@unittest.skipIf(not DEVELOPER, "need dev-compact-gossip-store")
def test_gossip_store_local_channels(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=False)

    # We see this channel, even though it's not announced, because it's local.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)

    l2.stop()
    l1.restart()

    # We should still see local channels!
    time.sleep(3)  # Make sure store is loaded
    chans = l1.rpc.listchannels()['channels']
    assert len(chans) == 2

    # Now compact store
    l1.rpc.call('dev-compact-gossip-store')
    l1.restart()

    time.sleep(3)  # Make sure store is loaded
    # We should still see local channels!
    chans = l1.rpc.listchannels()['channels']
    assert len(chans) == 2


@unittest.skipIf(not DEVELOPER, "need dev-compact-gossip-store")
def test_gossip_store_private_channels(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, announce_channels=False)

    # We see this channel, even though it's not announced, because it's local.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)

    l2.stop()
    l1.restart()

    # We should still see local channels!
    time.sleep(3)  # Make sure store is loaded
    chans = l1.rpc.listchannels()['channels']
    assert len(chans) == 2

    # Now compact store
    l1.rpc.call('dev-compact-gossip-store')
    l1.restart()

    time.sleep(3)  # Make sure store is loaded
    # We should still see local channels!
    chans = l1.rpc.listchannels()['channels']
    assert len(chans) == 2


def setup_gossip_store_test(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundchannel=False)

    # Create channel.
    scid23, _ = l2.fundchannel(l3, 10**6)

    # Have that channel announced.
    bitcoind.generate_block(5)
    # Make sure we've got node_announcements
    wait_for(lambda: ['alias' in n for n in l2.rpc.listnodes()['nodes']] == [True, True])

    # Now, replace the one channel_update, so it's past the node announcements.
    l2.rpc.setchannelfee(l3.info['id'], 20, 1000)
    # Old base feerate is 1.
    wait_for(lambda: sum([c['base_fee_millisatoshi'] for c in l2.rpc.listchannels()['channels']]) == 21)

    # Create another channel, which will stay private.
    scid12, _ = l1.fundchannel(l2, 10**6)

    # Now insert channel_update for previous channel; now they're both past the
    # node announcements.
    l3.rpc.setchannelfee(l2.info['id'], 20, 1000)
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l2.rpc.listchannels(scid23)['channels']] == [20, 20])

    # Replace both (private) updates for scid12.
    l1.rpc.setchannelfee(l2.info['id'], 20, 1000)
    l2.rpc.setchannelfee(l1.info['id'], 20, 1000)
    wait_for(lambda: [c['base_fee_millisatoshi'] for c in l2.rpc.listchannels(scid12)['channels']] == [20, 20])

    # Records in store now looks (something) like:
    #    DELETED: private channel_announcement (scid23)
    #    DELETED: private channel_update (scid23/0)
    #    DELETED: private channel_update (scid23/1)
    #  delete channel (scid23)
    #  channel_announcement (scid23)
    #  channel_amount
    #    DELETED: channel_update (scid23/0)
    #    DELETED: channel_update (scid23/1)
    #  node_announcement
    #  node_announcement
    #  channel_update (scid23)
    #  private channel_announcement (scid12)
    #    DELETED: private channel_update (scid12/0)
    #    DELETED: private channel_update (scid12/1)
    #  channel_update (scid23)
    #  private_channel_update (scid12)
    #  private_channel_update (scid12)
    return l2


@unittest.skipIf(not DEVELOPER, "need dev-compact-gossip-store")
def test_gossip_store_compact_noappend(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    # It should truncate this, not leave junk!
    with open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'gossip_store.tmp'), 'wb') as f:
        f.write(bytearray.fromhex("07deadbeef"))

    l2.rpc.call('dev-compact-gossip-store')
    l2.restart()
    wait_for(lambda: l2.daemon.is_in_log('gossip_store: Read '))
    assert not l2.daemon.is_in_log('gossip_store:.*truncate')


@unittest.skipIf(not DEVELOPER, "updates are delayed without --dev-fast-gossip")
def test_gossip_store_load_complex(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    l2.restart()

    wait_for(lambda: l2.daemon.is_in_log('gossip_store: Read '))


@unittest.skipIf(not DEVELOPER, "need dev-compact-gossip-store")
def test_gossip_store_compact(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    # Now compact store.
    l2.rpc.call('dev-compact-gossip-store')

    # Should still be connected.
    time.sleep(1)
    assert len(l2.rpc.listpeers()['peers']) == 2

    # Should restart ok.
    l2.restart()
    wait_for(lambda: l2.daemon.is_in_log('gossip_store: Read '))


@unittest.skipIf(not DEVELOPER, "need dev-compact-gossip-store")
def test_gossip_store_compact_restart(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    # Should restart ok.
    l2.restart()
    wait_for(lambda: l2.daemon.is_in_log('gossip_store: Read '))

    # Now compact store.
    l2.rpc.call('dev-compact-gossip-store')


@unittest.skipIf(not DEVELOPER, "need dev-compact-gossip-store")
def test_gossip_store_load_no_channel_update(node_factory):
    """Make sure we can read truncated gossip store with a channel_announcement and no channel_update"""
    l1 = node_factory.get_node(start=False, allow_broken_log=True)

    # A channel announcement with no channel_update.
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("09"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "00000095"  # len
                                  "f036515e"  # csum
                                  "5aab817c"  # timestamp
                                  "0101"      # WIRE_NODE_ANNOUNCEMENT
                                  "cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"))

    l1.start()

    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log('gossip_store: Unupdated channel_announcement at 1. Moving to gossip_store.corrupt and truncating'))
    assert os.path.exists(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store.corrupt'))

    # This should actually result in an empty store.
    l1.rpc.call('dev-compact-gossip-store')

    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), "rb") as f:
        assert bytearray(f.read()) == bytearray.fromhex("09")


@unittest.skipIf(not DEVELOPER, "gossip without DEVELOPER=1 is slow")
def test_gossip_store_compact_on_load(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    l2.restart()

    wait_for(lambda: l2.daemon.is_in_log(r'gossip_store_compact_offline: [5-8] deleted, 9 copied'))

    wait_for(lambda: l2.daemon.is_in_log(r'gossip_store: Read 2/4/2/0 cannounce/cupdate/nannounce/cdelete from store \(0 deleted\) in [0-9]* bytes'))


def test_gossip_announce_invalid_block(node_factory, bitcoind):
    """bitcoind lags and we might get an announcement for a block we don't have.

    """
    # Need to slow down the poll interval so the announcement preceeds the
    # blockchain catchup, otherwise we won't call `getfilteredblock`.
    opts = {}
    if DEVELOPER:
        opts['dev-bitcoind-poll'] = TIMEOUT // 2

    l1 = node_factory.get_node(options=opts)
    bitcoind.generate_block(1)
    assert bitcoind.rpc.getblockchaininfo()['blocks'] == 102

    # Test gossip for an unknown block.
    subprocess.run(['devtools/gossipwith',
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l1.info['id'], l1.port),
                    # short_channel_id=103x1x1
                    '01008d9f3d16dbdd985c099b74a3c9a74ccefd52a6d2bd597a553ce9a4c7fac3bfaa7f93031932617d38384cc79533730c9ce875b02643893cacaf51f503b5745fc3aef7261784ce6b50bff6fc947466508b7357d20a7c2929cc5ec3ae649994308527b2cbe1da66038e3bfa4825b074237708b455a4137bdb541cf2a7e6395a288aba15c23511baaae722fdb515910e2b42581f9c98a1f840a9f71897b4ad6f9e2d59e1ebeaf334cf29617633d35bcf6e0056ca0be60d7c002337bbb089b1ab52397f734bcdb2e418db43d1f192195b56e60eefbf82acf043d6068a682e064db23848b4badb20d05594726ec5b59267f4397b093747c23059b397b0c5620c4ab37a000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000670000010001022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d029053521d6ea7a52cdd55f733d0fb2d077c0373b0053b5b810d927244061b757302d6063d022691b2490ab454dee73a57c6ff5d308352b461ece69f3c284f2c2412'],
                   check=True, timeout=TIMEOUT)

    # Make sure it's OK once it's caught up.
    sync_blockheight(bitcoind, [l1])


def test_gossip_announce_unknown_block(node_factory, bitcoind):
    """Don't backfill the future!

    If we get a channel_announcement that is for a block height that is above
    our sync height we should not store the filteredblock in the blocks table,
    otherwise we end up with a duplicate when we finally catch up with the
    blockchain.

    """
    # Need to slow down the poll interval so the announcement preceeds the
    # blockchain catchup, otherwise we won't call `getfilteredblock`.
    opts = {}
    if DEVELOPER:
        opts['dev-bitcoind-poll'] = TIMEOUT // 2

    l1 = node_factory.get_node(options=opts)

    bitcoind.generate_block(2)
    assert bitcoind.rpc.getblockchaininfo()['blocks'] == 103

    # Test gossip for unknown block.
    subprocess.run(['devtools/gossipwith',
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l1.info['id'], l1.port),
                    # short_channel_id=103x1x1
                    '01008d9f3d16dbdd985c099b74a3c9a74ccefd52a6d2bd597a553ce9a4c7fac3bfaa7f93031932617d38384cc79533730c9ce875b02643893cacaf51f503b5745fc3aef7261784ce6b50bff6fc947466508b7357d20a7c2929cc5ec3ae649994308527b2cbe1da66038e3bfa4825b074237708b455a4137bdb541cf2a7e6395a288aba15c23511baaae722fdb515910e2b42581f9c98a1f840a9f71897b4ad6f9e2d59e1ebeaf334cf29617633d35bcf6e0056ca0be60d7c002337bbb089b1ab52397f734bcdb2e418db43d1f192195b56e60eefbf82acf043d6068a682e064db23848b4badb20d05594726ec5b59267f4397b093747c23059b397b0c5620c4ab37a000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000670000010001022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d029053521d6ea7a52cdd55f733d0fb2d077c0373b0053b5b810d927244061b757302d6063d022691b2490ab454dee73a57c6ff5d308352b461ece69f3c284f2c2412'],
                   check=True, timeout=TIMEOUT)

    # Make sure it's OK once it's caught up.
    sync_blockheight(bitcoind, [l1])


@unittest.skipIf(not DEVELOPER, "gossip without DEVELOPER=1 is slow")
def test_gossip_no_backtalk(node_factory):
    # l3 connects, gets gossip, but should *not* play it back.
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{}, {}, {'log-level': 'io'}])
    node_factory.join_nodes([l1, l2], wait_for_announce=True)

    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Will get channel_announce, then two channel_update and two node_announcement
    l3.daemon.wait_for_logs([r'\[IN\] 0100',
                             r'\[IN\] 0102', r'\[IN\] 0102',
                             r'\[IN\] 0101', r'\[IN\] 0101'])

    # With DEVELOPER, this is long enough for gossip flush.
    time.sleep(2)
    assert not l3.daemon.is_in_log(r'\[OUT\] 0100')


@unittest.skipIf(not DEVELOPER, "Needs --dev-gossip")
@unittest.skipIf(
    TEST_NETWORK != 'regtest',
    "Channel announcement contains genesis hash, receiving node discards on mismatch"
)
def test_gossip_ratelimit(node_factory, bitcoind):
    """Check that we ratelimit incoming gossip.

    We create a partitioned network, in which the first partition consisting
    of l1 and l2 is used to create an on-chain footprint and twe then feed
    canned gossip to the other partition consisting of l3. l3 should ratelimit
    the incoming gossip.

    """
    l3, = node_factory.get_nodes(
        1,
        opts=[{'dev-gossip-time': 1568096251}]
    )

    # Bump to block 102, so the following tx ends up in 103x1:
    bitcoind.generate_block(1)

    # We don't actually need to start l1 and l2, they're just there to create
    # an unspent outpoint matching the expected script. This is also more
    # stable against output ordering issues.
    tx = bitcoind.rpc.createrawtransaction(
        [],
        [
            # Fundrawtransaction will fill in the first output with the change
            {"bcrt1qtwxd8wg5eanumk86vfeujvp48hfkgannf77evggzct048wggsrxsum2pmm": 0.01000000}
        ]
    )
    tx = bitcoind.rpc.fundrawtransaction(tx, {'changePosition': 0})['hex']
    tx = bitcoind.rpc.signrawtransactionwithwallet(tx)['hex']
    txid = bitcoind.rpc.sendrawtransaction(tx)
    wait_for(lambda: txid in bitcoind.rpc.getrawmempool())

    # Make the tx gossipable:
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l3, ])

    def channel_fees(node):
        channels = node.rpc.listchannels()['channels']
        return [c['fee_per_millionth'] for c in channels]

    # Here are some ones I generated earlier (by removing gossip
    # ratelimiting)
    subprocess.check_call(
        [
            'devtools/gossipwith',
            '--max-messages=0',
            '{}@localhost:{}'.format(l3.info['id'], l3.port),
            # announcement
            '0100987b271fc95a37dbed78e6159e0ab792cda64603780454ce80832b4e31f63a6760abc8fdc53be35bb7cfccd125ee3d15b4fbdfb42165098970c19c7822bb413f46390e0c043c777226927eacd2186a03f064e4bdc30f891cb6e4990af49967d34b338755e99d728987e3d49227815e17f3ab40092434a59e33548e870071176db7d44d8c8f4c4cac27ae6554eb9350e97d47617e3a1355296c78e8234446fa2f138ad1b03439f18520227fb9e9eb92689b3a0ed36e6764f5a41777e9a2a4ce1026d19a4e4d8f7715c13ac2d6bf3238608a1ccf9afd91f774d84d170d9edddebf7460c54d49bd6cd81410bc3eeeba2b7278b1b5f7e748d77d793f31086847d582000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000670000010001022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d590266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c0351802e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5702324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b',
            # first update is free
            '010225bfd9c5e2c5660188a14deb4002cd645ee67f00ad3b82146e46711ec460cb0c6819fdd1c680cb6d24e3906679ef071f13243a04a123e4b83310ebf0518ffd4206226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d773ffb010100060000000000000000000000010000000a000000003b023380'
        ],
        timeout=TIMEOUT
    )

    # Wait for it to process channel.
    wait_for(lambda: channel_fees(l3) == [10])

    subprocess.check_call(
        [
            'devtools/gossipwith',
            '--max-messages=0',
            '{}@localhost:{}'.format(l3.info['id'], l3.port),
            # next 4 are let through...
            '01023a892ad9c9953a54ad3b8e2e03a93d1c973241b62f9a5cd1f17d5cdf08de0e8b4fcd24aa8bd45a48b788fe9dab3d416f28dfa390bc900ec0176ec5bd1afd435706226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d77400001010006000000000000000000000014000003e9000000003b023380',
            '010245966763623ebc16796165263d4b21711ef04ebf3929491e695ff89ed2b8ccc0668ceb9e35e0ff5b8901d95732a119c1ed84ac99861daa2de462118f7b70049f06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d77400101010006000000000000000000000014000003ea000000003b023380',
            '0102c479b7684b9db496b844f6925f4ffd8a27c5840a020d1b537623c1545dcd8e195776381bbf51213e541a853a4a49a0faf84316e7ccca5e7074901a96bbabe04e06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d77400201010006000000000000000000000014000003eb000000003b023380',
            # timestamp=1568096259, fee_proportional_millionths=1004
            '01024b866012d995d3d7aec7b7218a283de2d03492dbfa21e71dd546ec2e36c3d4200453420aa02f476f99c73fe1e223ea192f5fa544b70a8319f2a216f1513d503d06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d77400301010006000000000000000000000014000003ec000000003b023380',
            # update 5 marks you as a nasty spammer!
            '01025b5b5a0daed874ab02bd3356d38190ff46bbaf5f10db5067da70f3ca203480ca78059e6621c6143f3da4e454d0adda6d01a9980ed48e71ccd0c613af73570a7106226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d77400401010006000000000000000000000014000003ed000000003b023380'
        ],
        timeout=TIMEOUT
    )

    wait_for(lambda: channel_fees(l3) == [1004])

    # 24 seconds later, it will accept another.
    l3.rpc.call('dev-gossip-set-time', [1568096251 + 24])

    subprocess.run(['devtools/gossipwith',
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l3.info['id'], l3.port),
                    # update 6: timestamp=1568096284 fee_proportional_millionths=1006
                    '010282d24bcd984956bd9b891848404ee59d89643923b21641d2c2c0770a51b8f5da00cef82458add970f0b654aa4c8d54f68a9a1cc6470a35810303b09437f1f73d06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f00006700000100015d77401c01010006000000000000000000000014000003ee000000003b023380'],
                   check=True, timeout=TIMEOUT)

    wait_for(lambda: channel_fees(l3) == [1006])


def check_socket(ip_addr, port):
    result = True
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # let's also check for fatal and try it ;-)
    try:
        result = sock.connect_ex((ip_addr, port))
        sock.close()
    except Exception:
        return False

    return not result


@unittest.skipIf(not DEVELOPER, "needs a running Tor service instance at port 9151 or 9051")
def test_statictor_onions(node_factory):
    """First basic tests ;-)

    Assume that tor is configured and just test
    if we see the right onion address for our blob
    """
    # please define your values
    torip = '127.0.0.1'
    torips = '127.0.0.1:9051'
    torport = 9050
    torserviceport = 9051
    portA, portB = reserve(), reserve()

    if not check_socket(format(torip), torserviceport):
        return

    if not check_socket(format(torip), torport):
        return

    l1 = node_factory.get_node(may_fail=True, options={
        'bind-addr': '127.0.0.1:{}'.format(portA),
        'addr': ['statictor:{}'.format(torips)]
    })
    l2 = node_factory.get_node(may_fail=True, options={
        'bind-addr': '127.0.0.1:{}'.format(portB),
        'addr': ['statictor:{}/torblob=11234567890123456789012345678901'.format(torips)]
    })

    assert l1.daemon.is_in_log('127.0.0.1:{}'.format(l1.port))
    assert l2.daemon.is_in_log('x2y4zvh4fn5q3eouuh7nxnc7zeawrqoutljrup2xjtiyxgx3emgkemad.onion:9735,127.0.0.1:{}'.format(l2.port))


@unittest.skipIf(not DEVELOPER, "needs a running Tor service instance at port 9151 or 9051")
def test_torport_onions(node_factory):
    """First basic tests for torport ;-)

    Assume that tor is configured and just test
    if we see the right onion address for our blob
    """
    # please define your values
    torip = '127.0.0.1'
    torips = '127.0.0.1:9051'
    torport = 9050
    torserviceport = 9051

    if not check_socket(torip, torserviceport):
        return

    if not check_socket(torip, torport):
        return

    portA, portB = reserve(), reserve()

    l1 = node_factory.get_node(may_fail=True, options={'bind-addr': '127.0.0.1:{}'.format(portA), 'addr': ['statictor:{}/torport=45321'.format(torips)]})
    l2 = node_factory.get_node(may_fail=True, options={'bind-addr': '127.0.0.1:{}'.format(portB), 'addr': ['statictor:{}/torport=45321/torblob=11234567890123456789012345678901'.format(torips)]})

    assert l1.daemon.is_in_log('45321,127.0.0.1:{}'.format(l1.port))
    assert l2.daemon.is_in_log('x2y4zvh4fn5q3eouuh7nxnc7zeawrqoutljrup2xjtiyxgx3emgkemad.onion:45321,127.0.0.1:{}'.format(l2.port))


@unittest.skipIf(not COMPAT, "needs COMPAT to convert obsolete gossip_store")
def test_gossip_store_upgrade_v7_v8(node_factory):
    """Version 8 added feature bits to local channel announcements"""
    l1 = node_factory.get_node(start=False)

    # A channel announcement with no channel_update.
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("07000000428ce4d2d8000000000daf00"
                                  "00670000010001022d223620a359a47f"
                                  "f7f7ac447c85c46c923da53389221a00"
                                  "54c11c1e3ca31d5900000000000f4240"
                                  "000d8000000000000000000000000000"
                                  "00008e3af3badf000000001006008a01"
                                  "02005a9911d425effd461f803a380f05"
                                  "e72d3332eb6e9a7c6c58405ae61eacde"
                                  "4e2da18240ffb3d5c595f85e4f78b594"
                                  "c59e4d01c0470edd4f5afe645026515e"
                                  "fe06226e46111a0b59caaf126043eb5b"
                                  "bf28c34f3a5e332a1fc7b2b73cf18891"
                                  "0f00006700000100015eaa5eb0010100"
                                  "06000000000000000000000001000000"
                                  "0a000000003b0233800000008e074a6e"
                                  "0f000000001006008a0102463de636b2"
                                  "f46ccd6c23259787fc39dc4fdb983510"
                                  "1651879325b18cf1bb26330127e51ce8"
                                  "7a111b05ef92fe00a9a089979dc49178"
                                  "200f49139a541e7078cdc506226e4611"
                                  "1a0b59caaf126043eb5bbf28c34f3a5e"
                                  "332a1fc7b2b73cf188910f0000670000"
                                  "0100015eaa5eb0010000060000000000"
                                  "000000000000010000000a000000003b"
                                  "023380"))

    l1.start()

    assert l1.rpc.listchannels()['channels'] == [
        {'source': '022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59',
         'destination': '0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518',
         'short_channel_id': '103x1x1',
         'public': False,
         'satoshis': 1000000,
         'amount_msat': Millisatoshi(1000000000),
         'message_flags': 1,
         'channel_flags': 0,
         'active': False,
         'last_update': 1588223664,
         'base_fee_millisatoshi': 1,
         'fee_per_millionth': 10,
         'delay': 6,
         'htlc_minimum_msat': Millisatoshi(0),
         'htlc_maximum_msat': Millisatoshi(990000000),
         # This store was created on an experimental branch (OPT_ONION_MESSAGES)
         'features': '80000000000000000000000000'},
        {'source': '0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518',
         'destination': '022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59',
         'short_channel_id': '103x1x1',
         'public': False,
         'satoshis': 1000000,
         'amount_msat': Millisatoshi(1000000000),
         'message_flags': 1,
         'channel_flags': 1,
         'active': False,
         'last_update': 1588223664,
         'base_fee_millisatoshi': 1,
         'fee_per_millionth': 10,
         'delay': 6,
         'htlc_minimum_msat': Millisatoshi(0),
         'htlc_maximum_msat': Millisatoshi(990000000),
         'features': '80000000000000000000000000'}]


@unittest.skipIf(not DEVELOPER, "devtools are for devs anyway")
def test_routetool(node_factory):
    """Test that route tool can see unpublished channels"""
    l1, l2 = node_factory.line_graph(2)

    subprocess.run(['devtools/route',
                    os.path.join(l1.daemon.lightning_dir,
                                 TEST_NETWORK,
                                 'gossip_store'),
                    l1.info['id'],
                    l2.info['id']],
                   check=True, timeout=TIMEOUT)


def test_addgossip(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=True, wait_for_announce=True,
                                     opts={'log-level': 'io'})

    # We should get two node_announcements, one channel_announcement, and two
    # channel_update.
    l3 = node_factory.get_node()

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # 0x0101 = node_announcement
    ann = l1.daemon.is_in_log(r"\[OUT\] 0100.*")
    if ann is None:
        ann = l2.daemon.is_in_log(r"\[OUT\] 0100.*")

    upd1 = l1.daemon.is_in_log(r"\[OUT\] 0102.*")
    upd2 = l2.daemon.is_in_log(r"\[OUT\] 0102.*")

    nann1 = l1.daemon.is_in_log(r"\[OUT\] 0101.*")
    nann2 = l2.daemon.is_in_log(r"\[OUT\] 0101.*")

    # Feed them to l3 (Each one starts with TIMESTAMP chanid-xxx: [OUT] ...)
    l3.rpc.addgossip(ann.split()[3])

    l3.rpc.addgossip(upd1.split()[3])
    l3.rpc.addgossip(upd2.split()[3])
    l3.rpc.addgossip(nann1.split()[3])
    l3.rpc.addgossip(nann2.split()[3])

    # In this case, it can actually have to wait, since it does scid lookup.
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: len(l3.rpc.listnodes()['nodes']) == 2)

    # Now corrupt an update
    badupdate = upd1.split()[3]
    if badupdate.endswith('f'):
        badupdate = badupdate[:-1] + 'e'
    else:
        badupdate = badupdate[:-1] + 'f'

    with pytest.raises(RpcError, match='Bad signature'):
        l3.rpc.addgossip(badupdate)
