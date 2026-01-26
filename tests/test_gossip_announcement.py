from fixtures import *  # noqa: F401,F403
from pyln.testing.utils import wait_for
import time


def test_channel_announcement_after_restart_with_saved_sigs(node_factory, bitcoind):

    l1, l2 = node_factory.line_graph(
        2,
        fundchannel=True,
        announce_channels=True,
        wait_for_announce=False,
        opts={'may_reconnect': True}
    )

    bitcoind.generate_block(6)

    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['state'] == 'CHANNELD_NORMAL')

    time.sleep(2)

    channels_before = l1.rpc.listchannels()['channels']
    scid = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['short_channel_id']

    print(f"Channel SCID: {scid}")
    print(f"Channels before restart: {len(channels_before)}")

    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['state'] == 'CHANNELD_NORMAL')

    bitcoind.generate_block(6)

    def channel_announced():
        channels = l1.rpc.listchannels(scid)['channels']
        return len(channels) == 2

    wait_for(channel_announced, timeout=30)

    channels = l1.rpc.listchannels(scid)['channels']
    assert len(channels) == 2
    print(f"SUCCESS: Both channel directions announced after restart!")


def test_channel_announcement_reconnect_without_restart(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(
        2,
        fundchannel=True,
        announce_channels=True,
        wait_for_announce=True,
        opts={'may_reconnect': True}
    )

    scid = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['short_channel_id']

    channels = l1.rpc.listchannels(scid)['channels']
    assert len(channels) == 2

    l1.rpc.disconnect(l2.info['id'], force=True)
    time.sleep(1)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['state'] == 'CHANNELD_NORMAL')

    channels = l1.rpc.listchannels(scid)['channels']
    assert len(channels) == 2
    print(f"SUCCESS: Channel still announced after reconnect!")
