from fixtures import *  # noqa: F401,F403


def test_db_dangling_peer_fix(node_factory):
    # This was taken from test_fail_unconfirmed() node.
    l1 = node_factory.get_node(dbfile='dangling-peer.sqlite3.xz')
    l2 = node_factory.get_node()

    # Must match entry in db
    assert l2.info['id'] == '022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59'

    # This time it should work! (Connect *in* since l1 thinks it has UTXOs
    # it doesn't have).
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Make sure l2 has register connection
    l2.daemon.wait_for_log('Handed peer, entering loop')
    l2.fund_channel(l1, 200000, wait_for_active=True)
