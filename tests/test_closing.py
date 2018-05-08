from fixtures import *  # noqa: F401,F403

import os


DEVELOPER = os.getenv("DEVELOPER", "0") == "1"


def test_closing_id(node_factory):
    """Test closing using peer ID and full channel ID
    """
    l1, l2 = node_factory.get_nodes(2)

    # Close by full channel ID.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)
    cid = l2.rpc.listpeers()['peers'][0]['channels'][0]['channel_id']
    l2.rpc.close(cid)
    l1.daemon.wait_for_log("Forgetting remote peer .*")
    l2.daemon.wait_for_log("Forgetting remote peer .*")

    # Close by peer ID.
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l1.daemon.wait_for_log("hand_back_peer .*: now local again")
    l2.fund_channel(l1, 10**6)
    pid = l1.info['id']
    l2.rpc.close(pid)
    l1.daemon.wait_for_log("Forgetting remote peer .*")
    l2.daemon.wait_for_log("Forgetting remote peer .*")
