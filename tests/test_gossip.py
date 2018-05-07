from fixtures import *  # noqa: F401,F403
from test_lightningd import wait_for

import os
import time
import unittest


DEVELOPER = os.getenv("DEVELOPER", "0") == "1"


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
def test_gossip_pruning(node_factory, bitcoind):
    """ Create channel and see it being updated in time before pruning
    """
    opts = {'channel-update-interval': 5}
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
