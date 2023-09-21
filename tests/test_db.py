from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import wait_for, sync_blockheight, COMPAT, TIMEOUT, scid_to_int

import base64
import os
import pytest
import re
import shutil
import subprocess
import time
import unittest


@unittest.skipIf(TEST_NETWORK != 'regtest', "The DB migration is network specific due to the chain var.")
def test_db_dangling_peer_fix(node_factory, bitcoind):
    # Make sure bitcoind doesn't think it's going backwards
    bitcoind.generate_block(104)
    # This was taken from test_fail_unconfirmed() node.
    l1 = node_factory.get_node(dbfile='dangling-peer.sqlite3.xz',
                               options={'database-upgrade': True})
    l2 = node_factory.get_node()

    # Must match entry in db
    assert l2.info['id'] == '022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59'

    # This time it should work! (Connect *in* since l1 thinks it has UTXOs
    # it doesn't have).
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Make sure l2 has register connection
    l2.daemon.wait_for_log('Handed peer, entering loop')
    l2.fundchannel(l1, 200000, wait_for_active=True)


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
    bitcoind.generate_block(13, wait_for_mempool=txid)
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
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'] == [])

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
    l1 = node_factory.get_node(dbfile='oldstyle-scids.sqlite3.xz',
                               start=False, expect_fail=True,
                               allow_broken_log=True)

    # Will refuse to upgrade (if not in a release!)
    version = subprocess.check_output(['lightningd/lightningd',
                                       '--version']).decode('utf-8').splitlines()[0]
    if not re.match('^v[0-9.]*$', version):
        l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
        # Will have exited with non-zero status.
        assert l1.daemon.proc.wait(TIMEOUT) != 0
        assert l1.daemon.is_in_stderr('Refusing to irreversibly upgrade db from version [0-9]* to [0-9]* in non-final version ' + version + r' \(use --database-upgrade=true to override\)')

    l1.daemon.opts['database-upgrade'] = False
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert l1.daemon.proc.wait(TIMEOUT) != 0
    assert l1.daemon.is_in_stderr(r'Refusing to upgrade db from version [0-9]* to [0-9]* \(database-upgrade=false\)')

    l1.daemon.opts['database-upgrade'] = True
    l1.daemon.start()
    assert l1.db_query('SELECT scid FROM channels;') == [{'scid': scid_to_int('103x1x1')}]
    assert l1.db_query('SELECT failscid FROM payments;') == [{'failscid': scid_to_int('103x1x1')}]


@unittest.skipIf(not COMPAT, "needs COMPAT to convert obsolete db")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This test is based on a sqlite3 snapshot")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The network must match the DB snapshot")
def test_last_tx_inflight_psbt_upgrade(node_factory, bitcoind):
    bitcoind.generate_block(12)

    # FIXME: Re-add dynamic checks once PSBTv2 support is in both Core/Elements, or get python support
    # These PSBTs were manually checked for 0.001 BTC multisig witness utxos in a single input
    upgraded_psbts = ['cHNidP8BAgQCAAAAAQMEmj7WIAEEAQEBBQECAQYBAwH7BAIAAAAAAQEroIYBAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzSICAuO9OACYZsnajsSqmcxOqcbA3UbfFcYe8M4fJxKRcU5XRjBDAiBgFZ+8xOkvxfBoC9QdAhBuX6zhpvKsqWw8QeN2gK1b4wIfQdSIq+vNMfnFZqLyv3Un4s7i2MzHUiTs2morB/t/SwEBAwQBAAAAAQVHUiECMkJm3oQDs6sVegnx94TVh69hgxyZjBUbzCG7dMKyMUshAuO9OACYZsnajsSqmcxOqcbA3UbfFcYe8M4fJxKRcU5XUq4iBgIyQmbehAOzqxV6CfH3hNWHr2GDHJmMFRvMIbt0wrIxSwhK0xNpAAAAACIGAuO9OACYZsnajsSqmcxOqcbA3UbfFcYe8M4fJxKRcU5XCBq8wdAAAAAAAQ4gnMyi5Z2GOwC1vYNb97qTzCV5MtLHzb5R7+LuSp0p38sBDwQBAAAAARAEnbDigAABAwhKAQAAAAAAAAEEIgAgvnk1p3ypq3CkuLGQaCVjd2f+08AIJKqQyYiYNYfWhIgAAQMI8IIBAAAAAAABBCIAIJ9GhN2yis3HOVm8GU0aJd+Qb2HtAw9S0WPm8eJH0yy7AA==', 'cHNidP8BAgQCAAAAAQMEmj7WIAEEAQEBBQECAQYBAwH7BAIAAAAAAQEroIYBAAAAAAAiACBbjNO5FM9nzdj6YnPJMDU902R2c0+9liECwt9TuQiAzSICAuO9OACYZsnajsSqmcxOqcbA3UbfFcYe8M4fJxKRcU5XRzBEAiBWXvsSYMpD69abqr7X9XurE6B6GkhyI5JeGuKYByBukAIgUmk9q/g3PIS9HjTVJ4OmRoSZAMKLFdsowq15Sl9OAD8BAQMEAQAAAAEFR1IhAjJCZt6EA7OrFXoJ8feE1YevYYMcmYwVG8whu3TCsjFLIQLjvTgAmGbJ2o7EqpnMTqnGwN1G3xXGHvDOHycSkXFOV1KuIgYCMkJm3oQDs6sVegnx94TVh69hgxyZjBUbzCG7dMKyMUsIStMTaQAAAAAiBgLjvTgAmGbJ2o7EqpnMTqnGwN1G3xXGHvDOHycSkXFOVwgavMHQAAAAAAEOICL56+OPVCCFRbaBrX9zp641BKCcggH1Amc9NOKEJGh8AQ8EAQAAAAEQBJ2w4oAAAQMISgEAAAAAAAABBCIAIL55Nad8qatwpLixkGglY3dn/tPACCSqkMmImDWH1oSIAAEDCPCCAQAAAAAAAQQiACCfRoTdsorNxzlZvBlNGiXfkG9h7QMPUtFj5vHiR9MsuwA=']

    l1 = node_factory.get_node(dbfile='upgrade_inflight.sqlite3.xz',
                               options={'database-upgrade': True})

    b64_last_txs = [base64.b64encode(x['last_tx']).decode('utf-8') for x in l1.db_query('SELECT last_tx FROM channel_funding_inflights ORDER BY channel_id, funding_feerate;')]
    for i in range(len(b64_last_txs)):
        assert b64_last_txs[i] == upgraded_psbts[i]


@unittest.skipIf(not COMPAT, "needs COMPAT to convert obsolete db")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This test is based on a sqlite3 snapshot")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The network must match the DB snapshot")
def test_last_tx_psbt_upgrade(node_factory, bitcoind):
    bitcoind.generate_block(12)

    # FIXME: Re-add dynamic checks once PSBTv2 support is in both Core/Elements, or get python support
    # These PSBTs were manually checked for 0.01 BTC multisig witness utxos in a single input
    upgraded_psbts = ['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']

    l1 = node_factory.get_node(dbfile='last_tx_upgrade.sqlite3.xz',
                               options={'database-upgrade': True})

    b64_last_txs = [base64.b64encode(x['last_tx']).decode('utf-8') for x in l1.db_query('SELECT last_tx FROM channels ORDER BY id;')]
    for i in range(len(b64_last_txs)):
        assert b64_last_txs[i] == upgraded_psbts[i]

    l1.stop()
    # Test again, but this time with a database with a closed channel + forgotten peer
    # We need to get to block #232 from block #113
    bitcoind.generate_block(232 - 113)
    # We need to give it a chance to update
    time.sleep(2)

    l2 = node_factory.get_node(dbfile='last_tx_closed.sqlite3.xz',
                               options={'database-upgrade': True})
    last_txs = [x['last_tx'] for x in l2.db_query('SELECT last_tx FROM channels ORDER BY id;')]

    # The first tx should be psbt, the second should still be hex (Newer Core version required for better error message)
    assert last_txs[0][:4] == b'psbt'

    bitcoind.rpc.decoderawtransaction(last_txs[1].hex())


@pytest.mark.slow_test
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This test is based on a sqlite3 snapshot")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The network must match the DB snapshot")
def test_backfill_scriptpubkeys(node_factory, bitcoind):
    bitcoind.generate_block(214)

    script_map = [
        {
            "txid": "2513F3340D493489811EAB440AC05650B5BC06290358972EB6A55533A9EED96A",
            "scriptpubkey": "001438C10854C11E10CB3786460143C963C8530DF891",
        }, {
            "txid": "E380E18B6E810A464634B3A94B95AAA06B36A8982FD9D9D294982726EDC77DD3",
            "scriptpubkey": "001407DB91DA65EF06B385F4EA20BA05FAF286165C0B",
        }, {
            "txid": "E9AE7C9A346F9B9E35868176F311F3F2EE5DB8B94A065963E26954E119C49A79",
            "scriptpubkey": "00147E5B5C8F4FC1A9484E259F92CA4CBB7FA2814EA4",
        }, {
            "txid": "4C88F50BF00518E4FE3434ACA42351D5AC5FEEE17C35595DFBC3D1F4279F6EC1",
            "scriptpubkey": "0014D0EAC62FDCEE2D1881259BE9CDA4C43DE9050DB8",
        }, {
            "txid": "55265C3CAFE98C355FE0A440DCC005CF5C3145280EAD44D6B903A45D2DF3619C",
            "scriptpubkey": "0014D0EAC62FDCEE2D1881259BE9CDA4C43DE9050DB8",
        }, {
            "txid": "06F6D1D29B175146381EAB59924EC438572D18A3701F8E4FDF4EE17DE78D31E3",
            "scriptpubkey": "A9149551336F1E360F5AFB977F24CE72C744A82463D187",
        }, {
            "txid": "91BCEC7867F3F97F4F575D1D9DEDF5CF22BDDE643B36C2D9E6097048334EE32A",
            "scriptpubkey": "0014DFA9D65F06088E922A661C29797EE616F793C863",
        },
    ]

    # Test the first time, all entries are with option_static_remotekey
    l1 = node_factory.get_node(node_id=3, dbfile='pubkey_regen.sqlite.xz',
                               # Our db had the old non-DER sig in psbt!
                               allow_broken_log=True,
                               options={'database-upgrade': True})
    results = l1.db_query('SELECT hex(prev_out_tx) AS txid, hex(scriptpubkey) AS script FROM outputs')
    scripts = [{'txid': x['txid'], 'scriptpubkey': x['script']} for x in results]
    for exp, actual in zip(script_map, scripts):
        assert exp == actual

    # Test again, without option_static_remotekey
    script_map_2 = [
        {
            "txid": "FF89677793AC6F39E4AEB9D393B45F1E3D902CBFA26B521C5C438345A6D36E54",
            "scriptpubkey": "001438C10854C11E10CB3786460143C963C8530DF891",
        }, {
            "txid": "0F0685CCEE067638629B1CB27111EB0E15E19B75B1F5D368FC10D216D48FF4A5",
            "scriptpubkey": "001407DB91DA65EF06B385F4EA20BA05FAF286165C0B",
        }, {
            "txid": "822466946527F940A53B823C507A319FDC91CCE55E455D916C9FE13B982058FA",
            "scriptpubkey": "00144A94D23CD5A438531AADD86A0237FE11B9EA4E09",
        }, {
            "txid": "383145E40C8A9F45A0409E080DA5861C9E754B1EC8DD5EFA8A84DEB158E61C88",
            "scriptpubkey": "0014D0EAC62FDCEE2D1881259BE9CDA4C43DE9050DB8",
        }, {
            "txid": "D221BE9B7CDB5FDB58B34D59B30304B7C4C2DF9C3BF73A4AE0E0265642FEC560",
            "scriptpubkey": "0014D0EAC62FDCEE2D1881259BE9CDA4C43DE9050DB8",
        }, {
            "txid": "420F06E91CEE996D8E75E0565D776A96E8959ECA11E799FFE14522C2D43CCFA5",
            "scriptpubkey": "A9149551336F1E360F5AFB977F24CE72C744A82463D187",
        }, {
            "txid": "9F6127316EBED57E7702A4DF19D6FC0EC23A8FAB9BC0D4AD82C29D3F93C525CD",
            "scriptpubkey": "0014E445493A382C798AF195724DFF67DE4C9250AEC6",
        }
    ]

    l1.stop()

    l2 = node_factory.get_node(node_id=3, dbfile='pubkey_regen_commitment_point.sqlite3.xz',
                               # Our db had the old non-DER sig in psbt!
                               allow_broken_log=True,
                               options={'database-upgrade': True})
    results = l2.db_query('SELECT hex(prev_out_tx) AS txid, hex(scriptpubkey) AS script FROM outputs')
    scripts = [{'txid': x['txid'], 'scriptpubkey': x['script']} for x in results]
    for exp, actual in zip(script_map_2, scripts):
        assert exp == actual

    # Also check that the full_channel_id has been filled in
    results = l2.db_query('SELECT hex(full_channel_id) AS cid, hex(funding_tx_id) as txid, funding_tx_outnum FROM channels')

    def _chan_id(txid, outnum):
        chanid = bytearray.fromhex(txid)
        chanid[-1] ^= outnum % 256
        chanid[-2] ^= outnum // 256
        return chanid.hex()

    for row in results:
        assert _chan_id(row['txid'], row['funding_tx_outnum']) == row['cid'].lower()


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


@unittest.skipIf(os.environ.get('TEST_DB_PROVIDER', None) != 'postgres', "Only applicable to postgres")
def test_psql_key_value_dsn(node_factory, db_provider, monkeypatch):
    from pyln.testing.db import PostgresDb

    # Override get_dsn method to use the key-value style DSN
    def get_dsn(self):
        print("hello")
        return "postgres://host=127.0.0.1 port={port} user=postgres password=password dbname={dbname}".format(
            port=self.port, dbname=self.dbname
        )

    monkeypatch.setattr(PostgresDb, "get_dsn", get_dsn)
    l1 = node_factory.get_node()
    opt = [o for o in l1.daemon.cmd_line if '--wallet' in o][0]
    assert('host=127.0.0.1' in opt)


@unittest.skipIf(
    TEST_NETWORK != 'regtest',
    "The DB migration is network specific due to the chain var."
)
@unittest.skipIf(
    os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3',
    "This test is based on a sqlite3 snapshot"
)
def test_local_basepoints_cache(bitcoind, node_factory):
    """XXX started caching the local basepoints as well as the remote ones.

    This tests that we can successfully migrate a DB from the
    pre-caching state to the caching state, by simply starting the
    node up once, issue the HSMd requests, and then store them in the
    DB.

    """
    # Reestablish the blockheight we had when generating the DB
    bitcoind.generate_block(6)
    l1 = node_factory.get_node(
        dbfile='no-local-basepoints.sqlite3.xz',
        start=False,
        # Our db had the old non-DER sig in psbt!
        allow_broken_log=True,
        options={'database-upgrade': True}
    )

    fields = [
        "revocation_basepoint_local",
        "payment_basepoint_local",
        "htlc_basepoint_local",
        "delayed_payment_basepoint_local",
    ]
    q = "SELECT {fields} FROM channels".format(fields=", ".join(fields))

    # Make sure the DB doesn't have the fields yet.
    missing = l1.db.query("SELECT * FROM channels")[0]
    for f in fields:
        assert(f not in missing)

    # Starting this should cause us to migrate the DB, but none of
    # these fields will be set.
    l1.start()

    present = l1.db.query(q)[0]
    for f in fields:
        assert(f in present)
        assert(present[f] is not None)

    # New channels should automatically have the basepoints cached.
    l2, l3 = node_factory.line_graph(2)
    present = l2.db.query(q)[0]
    for f in fields:
        assert(f in present)
        assert(present[f] is not None)

    # Restarting will ask hsmd and verify they're unchanged. Remove
    # after we verified.
    l1.restart()
    l2.restart()


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Tests a feature unique to SQLITE3 backend")
def test_sqlite3_builtin_backup(bitcoind, node_factory):
    l1 = node_factory.get_node(start=False)

    # Figure out the path to the actual db.
    main_db_file = l1.db.path
    # Create a backup copy in the same location with the suffix .bak
    backup_db_file = main_db_file + ".bak"

    # Provide the --wallet option and start.
    l1.daemon.opts['wallet'] = "sqlite3://" + main_db_file + ':' + backup_db_file
    l1.start()

    # Get an address and put some funds.
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 1)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    # Stop the node.
    l1.stop()

    # Copy the backup over the main db file.
    shutil.copyfile(backup_db_file, main_db_file)

    # Remove the --wallet option and start.
    del l1.daemon.opts['wallet']
    l1.start()

    # Should still see the funds.
    assert(len(l1.rpc.listfunds()['outputs']) == 1)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Don't know how to swap dbs in Postgres")
def test_db_sanity_checks(bitcoind, node_factory):
    l1, l2 = node_factory.get_nodes(2, opts=[{'allow_broken_log': True,
                                              'may_fail': True}, {}])

    l1.stop()
    l2.stop()

    # Provide the --wallet option and start with wrong db
    l1.daemon.opts['wallet'] = "sqlite3://" + l2.db.path
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    l1.daemon.wait_for_log(r'\*\*BROKEN\*\* wallet: Wallet node_id does not match HSM')
    # Will have exited with non-zero status.
    assert l1.daemon.proc.wait(TIMEOUT) != 0
    assert l1.daemon.is_in_stderr('Wallet sanity check failed')

    # Now try wrong network,
    l1.daemon.opts['wallet'] = "sqlite3://" + l1.db.path
    l1.daemon.opts['network'] = "bitcoin"

    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    l1.daemon.wait_for_log(r'\*\*BROKEN\*\* wallet: Wallet blockchain hash does not match network blockchain hash')
    # Will have exited with non-zero status.
    assert l1.daemon.proc.wait(TIMEOUT) != 0
    assert l1.daemon.is_in_stderr('Wallet sanity check failed')


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Canned db used")
@unittest.skipIf(not COMPAT, "needs COMPAT to convert obsolete db")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The DB migration is network specific due to the chain var.")
def test_db_forward_migrate(bitcoind, node_factory):
    # For posterity, here is how I generated the db, in v0.12.1:
    # l1, l2, l3, l4, l5 = node_factory.get_nodes(5)

    # node_factory.join_nodes([l2, l1, l3], True, FUNDAMOUNT, True, True)
    # node_factory.join_nodes([l4, l1, l5], True, FUNDAMOUNT, True, True)

    # # Both ends remembered
    # l2.rpc.pay(l3.rpc.invoice(10000, 'test_db_forward_migrate', 'test_db_forward_migrate')['bolt11'])

    # # Both ends forgotten
    # l4.rpc.pay(l5.rpc.invoice(10000, 'test_db_forward_migrate', 'test_db_forward_migrate')['bolt11'])

    # # Outgoing forgotten
    # l2.rpc.pay(l5.rpc.invoice(10000, 'test_db_forward_migrate2', 'test_db_forward_migrate2')['bolt11'])

    # # Incoming forgotten
    # l4.rpc.pay(l3.rpc.invoice(10000, 'test_db_forward_migrate2', 'test_db_forward_migrate2')['bolt11'])

    # time.sleep(5)
    # l4.rpc.close(l1.info['id'])
    # l5.rpc.close(l1.info['id'])
    # bitcoind.generate_block(100, wait_for_mempool=2)
    # l4.rpc.disconnect(l1.info['id'])
    # l5.rpc.disconnect(l1.info['id'])

    # wait_for(lambda: l1.rpc.listpeers(l4.info['id'])['peers'] == [])
    # wait_for(lambda: l1.rpc.listpeers(l5.info['id'])['peers'] == [])
    # assert False
    bitcoind.generate_block(113)
    l1 = node_factory.get_node(dbfile='v0.12.1-forward.sqlite3.xz',
                               options={'database-upgrade': True})

    assert l1.rpc.getinfo()['fees_collected_msat'] == 4
    assert len(l1.rpc.listforwards()['forwards']) == 4

    # The two null in_htlc_id are replaced with bogus entries!
    assert sum([f['in_htlc_id'] > 0xFFFFFFFFFFFF for f in l1.rpc.listforwards()['forwards']]) == 2

    # Make sure autoclean can handle these!
    l1.stop()
    l1.daemon.opts['autoclean-succeededforwards-age'] = 2
    l1.daemon.opts['autoclean-cycle'] = 1
    l1.start()
    wait_for(lambda: l1.rpc.listforwards()['forwards'] == [])
