from fixtures import *  # noqa: F401,F403
from test_lightningd import wait_for

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
