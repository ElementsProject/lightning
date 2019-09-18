from fixtures import *  # noqa: F401,F403
from utils import wait_for, sync_blockheight, COMPAT
from fixtures import TEST_NETWORK

import os
import unittest


@unittest.skipIf(TEST_NETWORK != 'regtest', "The DB migration is network specific due to the chain var.")
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


@unittest.skipIf(TEST_NETWORK != 'regtest', "Address is network specific")
def test_block_backfill(node_factory, bitcoind, chainparams):
    """Test whether we backfill data from the blockchain correctly.

    For normal operation we will process any block after the initial start
    height, or rescan height, but for gossip we actually also need to backfill
    the blocks we skipped initially. We do so on-demand, whenever we see a
    channel_announcement referencing a blockheight we haven't processed yet,
    we fetch the entire block, extract P2WSH outputs and ask `bitcoin
    gettxout` for each of them. We then store the block header in the `blocks`
    table and the unspent outputs in the `utxoset` table.

    The test consist of two nodes opening a channel at height X, and an
    unrelated P2WSH transaction being sent at the same height (will be used to
    check for completeness of the backfill). Then a second node starts at
    height X+100 and connect to one of the nodes. It should not have the block
    in its DB before connecting. After connecting it should sync the gossip,
    triggering a backfill of block X, and all associated P2WSH outputs.

    """
    # Need to manually open the channels later since otherwise we can't have a
    # tx in the same block (`line_graph` with `fundchannel=True` generates
    # blocks).
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    # Get some funds to l1
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 1)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    # Now send the needle we will go looking for later:
    bitcoind.rpc.sendtoaddress('bcrt1qtwxd8wg5eanumk86vfeujvp48hfkgannf77evggzct048wggsrxsum2pmm', 0.00031337)
    l1.rpc.fundchannel(l2.info['id'], 10**6, announce=True)
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 2)

    # Confirm and get some distance between the funding and the l3 wallet birth date
    bitcoind.generate_block(100)
    wait_for(lambda: len(l1.rpc.listnodes()['nodes']) == 2)

    # Start the tester node, and connect it to l1. l0 should sync the gossip
    # and call out to `bitcoind` to backfill the block.
    l3 = node_factory.get_node()
    heights = [r['height'] for r in l3.db_query("SELECT height FROM blocks")]
    assert(103 not in heights)

    l3.rpc.connect(l1.info['id'], 'localhost', l1.port)

    # Make sure we have backfilled the block
    wait_for(lambda: len(l3.rpc.listnodes()['nodes']) == 2)
    heights = [r['height'] for r in l3.db_query("SELECT height FROM blocks")]
    assert(103 in heights)

    # Make sure we also have the needle we added to the haystack above
    assert(31337 in [r['satoshis'] for r in l3.db_query("SELECT satoshis FROM utxoset")])

    # Now close the channel and make sure `l3` cleans up correctly:
    txid = l1.rpc.close(l2.info['id'])['txid']
    bitcoind.generate_block(1, wait_for_mempool=txid)
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 0)


# Test that the max-channel-id is set correctly between
# restarts (with forgotten channel)
def test_max_channel_id(node_factory, bitcoind):
    # Create a channel between two peers.
    # Close the channel and have 100 blocks happen (forget channel)
    # Restart node, create channel again. Should succeed.
    l1, l2 = node_factory.line_graph(2, fundchannel=True, wait_for_announce=True)
    sync_blockheight(bitcoind, [l1, l2])

    # Now shutdown cleanly.
    l1.rpc.close(l2.info['id'], 0)

    l1.daemon.wait_for_log(' to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log(' to CLOSINGD_COMPLETE')

    # And should put closing into mempool.
    l1.wait_for_channel_onchain(l2.info['id'])
    l2.wait_for_channel_onchain(l1.info['id'])

    bitcoind.generate_block(101)
    wait_for(lambda: l1.rpc.listpeers()['peers'] == [])
    wait_for(lambda: l2.rpc.listpeers()['peers'] == [])

    # Stop l2, and restart
    l2.stop()
    l2.start()

    # Reconnect
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Fundchannel again, should succeed.
    l1.rpc.fundchannel(l2.info['id'], 10**5)


@unittest.skipIf(not COMPAT, "needs COMPAT to convert obsolete db")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This test is based on a sqlite3 snapshot")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The network must match the DB snapshot")
def test_scid_upgrade(node_factory):

    # Created through the power of sed "s/X'\([0-9]*\)78\([0-9]*\)78\([0-9]*\)'/X'\13A\23A\3'/"
    l1 = node_factory.get_node(dbfile='oldstyle-scids.sqlite3.xz')

    assert l1.db_query('SELECT short_channel_id from channels;') == [{'short_channel_id': '103x1x1'}]
    assert l1.db_query('SELECT failchannel from payments;') == [{'failchannel': '103x1x1'}]
