from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import wait_for, sync_blockheight, COMPAT, VALGRIND, DEVELOPER, only_one

import base64
import os
import pytest
import time
import unittest


@unittest.skipIf(TEST_NETWORK != 'regtest', "The DB migration is network specific due to the chain var.")
def test_db_dangling_peer_fix(node_factory, bitcoind):
    # Make sure bitcoind doesn't think it's going backwards
    bitcoind.generate_block(104)
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

    # Make sure that l3 doesn't ask for more gossip and get a reply about
    # the closed channel (hence Bad gossip msgs in log).
    l3.daemon.wait_for_log('seeker: state = NORMAL')

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
def test_scid_upgrade(node_factory, bitcoind):
    bitcoind.generate_block(1)

    # Created through the power of sed "s/X'\([0-9]*\)78\([0-9]*\)78\([0-9]*\)'/X'\13A\23A\3'/"
    l1 = node_factory.get_node(dbfile='oldstyle-scids.sqlite3.xz')

    assert l1.db_query('SELECT short_channel_id from channels;') == [{'short_channel_id': '103x1x1'}]
    assert l1.db_query('SELECT failchannel from payments;') == [{'failchannel': '103x1x1'}]


@unittest.skipIf(not COMPAT, "needs COMPAT to convert obsolete db")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This test is based on a sqlite3 snapshot")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The network must match the DB snapshot")
def test_last_tx_psbt_upgrade(node_factory, bitcoind):
    bitcoind.generate_block(12)

    prior_txs = ['02000000018DD699861B00061E50937A233DB584BF8ED4C0BF50B44C0411F71B031A06455000000000000EF7A9800350C300000000000022002073356CFF7E1588F14935EF138E142ABEFB5F7E3D51DE942758DCD5A179449B6250A90600000000002200202DF545EA882889846C52FC5E111AC07CE07E0C09418AC15743A6F6284C2A4FA720A1070000000000160014E89954FAC8F7A2DCE51E095D7BEB5271C3F7DA56EF81DC20', '02000000018A0AE4C63BCDF9D78B07EB4501BB23404FDDBC73973C592793F047BE1495074B010000000074D99980010A2D0F00000000002200203B8CB644781CBECA96BE8B2BF1827AFD908B3CFB5569AC74DAB9395E8DDA39E4C9555420', '020000000135DAB2996E57762E3EC158C0D57D39F43CA657E882D93FC24F5FEBAA8F36ED9A0100000000566D1D800350C30000000000002200205679A7D06E1BD276AA25F56E9E4DF7E07D9837EFB0C5F63604F10CD9F766A03ED4DD0600000000001600147E5B5C8F4FC1A9484E259F92CA4CBB7FA2814EA49A6C070000000000220020AB6226DEBFFEFF4A741C01367FA3C875172483CFB3E327D0F8C7AA4C51EDECAA27AA4720']

    l1 = node_factory.get_node(dbfile='last_tx_upgrade.sqlite3.xz')

    b64_last_txs = [base64.b64encode(x['last_tx']).decode('utf-8') for x in l1.db_query('SELECT last_tx FROM channels ORDER BY id;')]
    for i in range(len(b64_last_txs)):
        bpsbt = b64_last_txs[i]
        psbt = bitcoind.rpc.decodepsbt(bpsbt)
        tx = prior_txs[i]
        assert psbt['tx']['txid'] == bitcoind.rpc.decoderawtransaction(tx)['txid']
        funding_input = only_one(psbt['inputs'])
        # Every opened channel was funded with the same amount: 1M sats
        assert funding_input['witness_utxo']['amount'] == Decimal('0.01')
        assert funding_input['witness_utxo']['scriptPubKey']['type'] == 'witness_v0_scripthash'
        assert funding_input['witness_script']['type'] == 'multisig'

    l1.stop()
    # Test again, but this time with a database with a closed channel + forgotten peer
    # We need to get to block #232 from block #113
    bitcoind.generate_block(232 - 113)
    # We need to give it a chance to update
    time.sleep(2)

    l2 = node_factory.get_node(dbfile='last_tx_closed.sqlite3.xz')
    last_txs = [x['last_tx'] for x in l2.db_query('SELECT last_tx FROM channels ORDER BY id;')]

    # The first tx should be psbt, the second should still be hex
    bitcoind.rpc.decodepsbt(base64.b64encode(last_txs[0]).decode('utf-8'))
    bitcoind.rpc.decoderawtransaction(last_txs[1].hex())


@unittest.skipIf(VALGRIND and not DEVELOPER, "Without developer valgrind will complain about debug symbols missing")
def test_optimistic_locking(node_factory, bitcoind):
    """Have a node run against a DB, then change it under its feet, crashing it.

    We start a node, wait for it to settle its write so we have a window where
    we can interfere, and watch the world burn (safely).
    """
    l1 = node_factory.get_node(may_fail=True, allow_broken_log=True)

    sync_blockheight(bitcoind, [l1])
    l1.rpc.getinfo()
    time.sleep(1)
    l1.db.execute("UPDATE vars SET intval = intval + 1 WHERE name = 'data_version';")

    # Now trigger any DB write and we should be crashing.
    with pytest.raises(RpcError, match=r'Connection to RPC server lost.'):
        l1.rpc.newaddr()

    assert(l1.daemon.is_in_log(r'Optimistic lock on the database failed'))
