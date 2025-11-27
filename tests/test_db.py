from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import wait_for, sync_blockheight, COMPAT, TIMEOUT, scid_to_int, only_one

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
    addr = l1.rpc.newaddr()['p2tr']
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
    txid = only_one(l1.rpc.close(l2.info['id'])['txids'])
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
                               broken_log='Refusing to irreversibly upgrade db from version 104 to|Refusing to upgrade db from version 104 to')

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

    faildetail_types = l1.db_query(
        "SELECT id, typeof(faildetail) as type "
        "FROM payments WHERE faildetail IS NOT NULL"
    )
    for row in faildetail_types:
        assert row['type'] == 'text', \
            f"Payment {row['id']}: faildetail has type {row['type']}, expected 'text'"


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
    upgraded_psbts = ['cHNidP8BAgQCAAAAAQME74HcIAEEAQEBBQEDAQYBAwH7BAIAAAAAAQErQEIPAAAAAAAiACCiWhNhgwfpKsHIgLqGzpSdj8cCpITLFVpVRddsOobajiICAjJCZt6EA7OrFXoJ8feE1YevYYMcmYwVG8whu3TCsjFLRzBEAiBhqTjjdJx2TqTNUwYJgmjhH6p8FJnbnj/N/Jv0dEiQmwIgXG/ki8U0iN0YPbrhpl7goGhXUj/8+JRg0uKLJrkHLrsBAQMEAQAAAAEFR1IhAgZUBJOphZmWemHEUXLfSWgeOYpssIkKUG5092wtK+JCIQIyQmbehAOzqxV6CfH3hNWHr2GDHJmMFRvMIbt0wrIxS1KuIgYCBlQEk6mFmZZ6YcRRct9JaB45imywiQpQbnT3bC0r4kIIWA8TsgAAAAAiBgIyQmbehAOzqxV6CfH3hNWHr2GDHJmMFRvMIbt0wrIxSwhK0xNpAAAAAAEOII3WmYYbAAYeUJN6Iz21hL+O1MC/ULRMBBH3GwMaBkVQAQ8EAAAAAAEQBA73qYAAAQMIUMMAAAAAAAABBCIAIHM1bP9+FYjxSTXvE44UKr77X349Ud6UJ1jc1aF5RJtiAAEDCFCpBgAAAAAAAQQiACAt9UXqiCiJhGxS/F4RGsB84H4MCUGKwVdDpvYoTCpPpwABAwggoQcAAAAAAAEEFgAU6JlU+sj3otzlHglde+tSccP32lYA', 'cHNidP8BAgQCAAAAAQMEyVVUIAEEAQEBBQEBAQYBAwH7BAIAAAAAAQErQEIPAAAAAAAiACCc/dpuVjOUiLE7shRAGtPlr79BRDvRhJ8hBBZO3bJRByICAxP/QAbXElyp14Ex6p9hEOLadukdgNzFadkHQ0ihJIfuRzBEAiAQ/J3PtNddIXEyryGKmbLynVXAvdkXrx8G5/T1pVITngIgJC025b1L/xcPPl45Ji2ALELKkiAWsbbzX1Q7puxXmIcBAQMEAQAAAAEFR1IhAxP/QAbXElyp14Ex6p9hEOLadukdgNzFadkHQ0ihJIfuIQOI2tHiwIqqDuBYIsYi6cjqpiDUm7OrVyYYs3tDORxObVKuIgYDiNrR4sCKqg7gWCLGIunI6qYg1Juzq1cmGLN7QzkcTm0IAhKTyQAAAAAiBgMT/0AG1xJcqdeBMeqfYRDi2nbpHYDcxWnZB0NIoSSH7ghHnxq3AAAAAAEOIIoK5MY7zfnXiwfrRQG7I0BP3bxzlzxZJ5PwR74UlQdLAQ8EAQAAAAEQBHTZmYAAAQMICi0PAAAAAAABBCIAIDuMtkR4HL7Klr6LK/GCev2Qizz7VWmsdNq5OV6N2jnkAA==', 'cHNidP8BAgQCAAAAAQMEJ6pHIAEEAQEBBQEDAQYBAwH7BAIAAAAAAQErQEIPAAAAAAAiACBDLtwFmNIlFK0EyoFBTkL9Mby9xfFU9ESjJb90SmpQVSICAtYGPQImkbJJCrRU3uc6V8b/XTCDUrRh7OafPChPLCQSRzBEAiBysjZc3nD4W4nb/ZZwVo6y7g9xG1booVx2O3EamX/8HQIgYVfgTi/7A9g3deDEezVSG0i9w8PY+nCOZIzsI5QurTwBAQMEAQAAAAEFR1IhAtYGPQImkbJJCrRU3uc6V8b/XTCDUrRh7OafPChPLCQSIQL1LAIQ1bBdOKDAHzFr4nrQf62xABX0l6zPp4t8PNtctlKuIgYC9SwCENWwXTigwB8xa+J60H+tsQAV9Jesz6eLfDzbXLYIx88ENgAAAAAiBgLWBj0CJpGySQq0VN7nOlfG/10wg1K0YezmnzwoTywkEgj9r2whAAAAAAEOIDXaspluV3YuPsFYwNV9OfQ8plfogtk/wk9f66qPNu2aAQ8EAQAAAAEQBFZtHYAAAQMIUMMAAAAAAAABBCIAIFZ5p9BuG9J2qiX1bp5N9+B9mDfvsMX2NgTxDNn3ZqA+AAEDCNTdBgAAAAAAAQQWABR+W1yPT8GpSE4ln5LKTLt/ooFOpAABAwiabAcAAAAAAAEEIgAgq2Im3r/+/0p0HAE2f6PIdRckg8+z4yfQ+MeqTFHt7KoA']

    l1 = node_factory.get_node(dbfile='last_tx_upgrade.sqlite3.xz',
                               # FIXME: gossipd gets upset, since it seems like the db with remote announcement_sigs was
                               # actually from l2, not l1.  But if we make this l1, then last_tx changes
                               broken_log='gossipd rejected our channel announcement',
                               allow_bad_gossip=True,
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
                               broken_log='gossipd rejected our channel announcement',
                               allow_bad_gossip=True,
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
                               broken_log='Forced database repair of psbt',
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
                               broken_log='Forced database repair of psbt',
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
    l1 = node_factory.get_node(may_fail=True, broken_log='lightningd:')

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
        broken_log='Forced database repair of psbt',
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
    addr = l1.rpc.newaddr('bech32')['bech32']
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
    l1, l2 = node_factory.get_nodes(2, opts=[{'may_fail': True, 'broken_log': 'Wallet node_id does not match HSM|Wallet blockchain hash does not match network blockchain hash'}, {}])

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


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Canned db used")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The DB migration is network specific due to the chain var.")
def test_channel_htlcs_id_change(bitcoind, node_factory):
    """Make sure we can add new htlcs to an old db, after upgrade.  This one was made with v25.02.1"""
    blocks = ['0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f754da9b9e16d987364f7c82d252ca2f12d18a26e5d23e1eb1d7b1aa19682e125fa632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000202ca43d107f9d8464432ae518142b8a95f32faeb9d0845ab7b14ab68f88dd695a600161d6e86fd1570ced17eb0bd04eafaeba5d858f1fc6e4bb5725b16e363c06fb632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020f307162dc0635d50588c7cf9924724eddcfa47d644c8e14eda56809c8fdc5c662c7126184f1c459ec34e135ecf61a28a4744c524f33f7be22c907d0ac09ec631fb632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020048b5a3b9aab523e33959b0ba0ad74a4173ba4f92004fffa63cf5a8df2e5d97755d3dd43b14a11b93997269d3b2822dc6c32fe2c884e71a06fd2a44e6d5d5294fc632868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020ea1de746b696135cc866a6466dc0d525aaf9dfff29b23a88912774ad6fb45a4399f6729562f98972ff1fbba8d4dfec0166ed02cb5d941d6485ae99e71c45542dfc632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204740057bea59c8cb0d8ca00cb52bc633e811c1f952d5f00301999f287ef6992111e1bf05db3f60476221404a450b1039431e24ea6782ac03cbbc8065f07a5be9fc632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025600ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207035a88f91001a8b64247e1c915d720572bb1db726bdbae2ece8e7fa2aa60c1fc147b6920d1b3c6a6bcaf85ce892a9738065cf2e7dda157a515adaed9816193afc632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025700ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d81feda5acf836f5f1ddae31958c0dee648b1774f8a00718abf011fb31586d4e1321d59cf56984166db825c4b088146b854dd0ab9daa7b811774c043830ccf08fd632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025800ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020eda7342391f80eac5187b77104b08869d8b49f9709e144191eda19f9a8eadf4054dfa4668c9bb47ee6cc9123384111e8bc3982c1bd728e3f7dce99eb5a8b263bfd632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025900ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205b377c8b494f510df15575b55add4027f5c8f45dd7956b7c9203c6e8c04af56b516b5621b541b4182811765ddd4aaf0bfc6f84d1db48dd85b546081c15a19245fd632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025a00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207a9109bf44630394f1ef6c289f5f2f37a67edc0722b4ae1b52acfef498d6c24501aa65e2c0242441b839f5926e43af661366556cbcfb3f38628ad2d06d02ce97fd632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025b00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207ee692277e5ec27ce5cdd07e92c8560cdc20edbd0530e695f6a6e1bdc721a64019764f29ef0e33a2d5081b85e754ffc629da1e494cf17b185fa51af127de234bfd632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025c00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a6215d577208ec7c92ce46650911d54f4ff4ad1de1fd9800a2aa47f72da4682ddec1b31bf108e44d50c7ae87f8177314a23f58df42a9fc538d71b254a0958a65fd632868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025d00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a153bb8ebadb3d1ee2f58cd063d4a1adfc36500eda665aaf1c8709a99277004ff1f79fe5475185a7f40add36ce4fac67ea7f033fff1c1ef1330c198055f7c4f9fe632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025e00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207b9e0c907f5bdd85a043b2ae51812b6563bfffebe1c1a6fcc877ba73f9cda077b3e5535c51d755c7751410f1505835c46452a79afaba304783c98c5b84a5620afe632868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025f00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b42f5935a58344f6e6b6eb24237530e7580142a90b8981d47f918dfced6cfc6e43d4f480d6caff3ecc19d9890cb812fb03c45649cdf63e37dd767e99c170ce9efe632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff026000ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002053aef976e40eb5bc5602111716358fa9c95c52414c909ee635465bb83270d850276c1a12fa00a58feb33b25ba5b1dcebbdb642e677e9268acbefd930cda0d158fe632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020798ce19b2e517c9665393bcfdbd7e12845c985ee0d1b67c27312dd4725b5df6807a7a4aa92581d948f04b31dc3edf9a7f78e2fdaa7c18db9f3a4a2f24cca101ffe632868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206b118d2792355bcfe8c8e6372fada18cc6bb3865da6a66839e52afbd2c70c46b5bfab6a2dbd8c1ebe198ce99970e115a2e2dab75d489a7134b2defb2928beeedfe632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d46df9175b7aebf3002354d1af19db1ad17c7519e4a9d124f63dcf9dd9e88a0b1c92ec314155e0f6e25445b6e90af4603a7e4de40e1ebb27ab54480af18d799dff632868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201ad7172c9b2e72c4f7a063a9ac00714ee7d87021ad632d122378191c95ba0e7447d02b22e7a700c83c1ab2e6298f1e7648602baf44fedc69e84b04800feba898ff632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020139e7622f9049d7f5b1933b5b3720df6ff66ed5871c31d8c76616252e032680196ea3d0907a6907410a24779f2b1405bd0f02abbe4c6c295ded791582711881bff632868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011600ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b3d3f0da9409fb3ec41b88a48de9a21966a20b985d5defad3340f9b556eab019292fc8c4b0cc59549e74b2e533543d4e5538c615bb032827aced29a554a393ebff632868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011700ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a51c90ac9400e69aa067c2886c88d435d8d5a6ded61ca460c30f86ce1781870222b5b426bb79223d4e0b7d13b6d0681fcea9ca1cd3b1945b498b1074ee1bb4d1ff632868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011800ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020235ca647b1085d61d70bec90eefb8d0650d97a1c84f9c74e415d97fbc8b8861bea1c98625bcf369d826f5c085ea4483f97ef2ba7b73fad8bf41bb286808ef490ff632868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011900ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a2b707b4fc545c196cee91df7ba53df24db8c789ae089ad6788709c0afb9d54aa775f22d0eadd5abed5b409ee3b0c926197172f161d93703dd1efbb9b5ccd00500642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011a00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205f1deae4a7d7bfb51190e77d2abb3b2d50392107674d6419e0d48adab0001a36cf37e50c68159177b43f79a9fa0ce0ae588f3d1a4f395c2d4ea4a13f00bd126900642868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011b00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d5cb0a316bf7c0fa7f28260f49107ca3f064fee8f8b7d1131281683854def04a6b9fbed7e3b268ddac4bdbdeebddb1c1726ca66718efc36a0c56e7c5aad06c3b00642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011c00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002064aee30b98e140d76bd4356813b2bab6db7e12d5fc034d5568001fde23df97572e3079719f7ba3d9e0a0694dd74e8df28e6d5d44bdfc096e22c8d9e13c16295800642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011d00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020459b1b50a3befc096e99bb02de91843558f97535e1f619834c558a880985342af5a082f855000f75d79a56c3d1b615cd323c7880af61aaeeeb2d14065503794800642868ffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011e00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207da92a8e0d3360b67797c79a8318c40fc881f58e12c7b653c1c9cdb3070a746a1ffe59d3ad3849e92ffc125a38aec8c599613f02dc2267e5bd1690f2366891f600642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011f00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020444b71db2f8a8f4a20c8aa2c164c82322d62f0b89f4c03299190828e8ef417320f61739671f8ae44f79e27e4aaf69698e341cdd065c211e3425cea435e62a3b501642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012000ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020ca41ecfd2f6704f726457ecffe6233808050b2e5d4637f207f4046447d826451bb917ac59876bd11d2cd127e733896e9cdf61f0ef354fea2225cdb69c49b7bb001642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020df63d71a7c0e3c161fa7fc8311739ce2ee7b452575a56035112ae2760260dc1339065149c48266a14f5a34bb2f097617e75aaf6b5717c491964e2423777debeb01642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204359965c27cc1c17c36d6d6f02f27bb04a7abfbac5cf6acf295892dfa197c878d38b58b8c05520e1474b234bbad291d0fa8979661912e03ffc4cb0c8ecfe0a0501642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d8a7b89f544d579c736da9a64cfe2ef44e348acd20c7303d7a749fd6bf0d4b1bec158fa4dc6e9d813e2342cc43e2f42f6bc0fa9f577545d310eb9d470109db3301642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000203f3603eaac55e36663514b0d4f2548bb5e2a3a5c160a2996eda23c81de5b465afd5ee0a6576796478259637eb5e7f806980755fdbd643006ed80b494640da11a01642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c2d7957d39c282ff23d41404f83dabbd32a5af101ec6a1be5341c03b17afe628dcb98c6f86163ac448373d4b03f67d5cf98c95208468e2bfb1ed45e0371bd96702642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012600ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020ed07939afc14c400376e8a2c207bc963c56de02521c61da9171a2d13a3c8023663694406fa436e2650b282594a1d664b2f2284880dcb25b812da965ba8b1829102642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012700ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c8a33feb63fe0ccc750c08c953f8a38f8383afeaf7b0b1162b2695927f2ec36b2c495a302fe73ce1565773698eee44bb8083c004c930e3a94ee272007647888d02642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012800ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c15d0f712f51ddb1294cbd72202f448fadb5a3bd2759970c1311651cf876df7638d0fe4906bcaab4b2ffad591a2f25943da366334194d58f4b8d95ce8cc397c202642868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012900ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205e83596475dbdd44ef9096f623deec738e09d5bdc46f691464f62259672be23e838abfd7bf84287e4b11575648067656b27f117345edd6f3e97e2833fa8ba35702642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012a00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020498fd02a29a84931e3d80ce6f18e4068f938d2738c1cdeb6fd8e432abf9d5e19680ff8a26d231e9884ea2ed67fe22de4ba1759cbef30dbc79c50633e68b07c3302642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012b00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002045715d0bb85a7458d1bf7dead97a48f27f1a098e2a355db1253a4bf3adf7d4264f9c6fd971c0938d344b47109e6ea8beb8945bef42638aed944e5dccc4ec8c4c03642868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012c00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e113899249de3b4cf73db7b9b0eee739be1d252a9185d28dc457c8ad454856510411aa232fc89a754681421ccec0771c2e212c9e9504d5098957e36ccd684c6d03642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012d00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204c6c47680c01e278eda10e233232931db7d72f2b0529ef122525cd3771d75000873ab317ab716155b6e491aa9543485d376634f988e565dafd72d25956b860aa03642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012e00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020f7c915367ce67e1b9255723ee892c4f3a4f066f75557d087a7756e526b15547ff1979709113d34934112aeeb4542f1f30a5f2bdaf3ce26fb57b0aa16b5acd40403642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012f00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e9907f4aa8166dde4cd566975b7519e09182aa05937076fd3bb430414526d83539864afe4e95169f0b02cb72ab2287620cf568cd212e626639def282bd0cafe403642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013000ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002017e0a4b663d6e73f5bd9769c12653b9766e0714c90d0c5507efdfccd5aa4db5244df7d41be8f7cd32fcc7d5fbc0c45cbcd69592d1aa0bf10a4cd613205872a1203642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002063fbd02a8af4eb523c97b195d6aa9da2336b5689fa2e43ca87bf374fe49ebe4e2ff6b9cac9a537b5d7d73682fa170e56970fc1f3aeee1745d070896e03af248004642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020eaf79334313919d101a27c540c28d0559ccf4dcf9f4e38f22ae42057c3242d067474176f5b7f5e896b36dd39aa21ab8f20cfeada6018a081eb51efe7d255add204642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206341b9ddc2955bed82b79c139aab6267c8576ff3ee2c53be4bbf9c7a4718b84f51b7d5e9342835288605001e46d3f3ea8b2630c7d7ec3868b545d8e672f60bec04642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002067a6d78064a0b24861c06b00960bbbc0ccfecabc67f381b41aae7de620e4e47725b1c16fcf95912eef719f918fbcf2a47d185887235a0dad151434a6295c5fa304642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204a44cc807d9aeb4f6b027858476ca3c9064fb30287cdf4beddff0024b96d8e3c425ad66293fc2453d75e52caf665dedfb1b6e41c8380bc1bdc44478eed53d7e304642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013600ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a9877e0795eef01c365125bdff949c5fd85d60cb041d74ea18ab0fe8279c711b7fec80a1fcb471e213f218a80a0f98d117e9de44af62de431107971fc46d981a04642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013700ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020ef3d58d8be0e8a6159b500ce889fa5b38afd3051ef1893b0152fd61ffa78f9543fa1d1c24770f120a19034e698641425dce8b0e8471f48b17c68b5fc9ef41d4f05642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013800ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020631103db119cdedd7a8f15887a0f022adfb5a9efb0b19a3c95057f31e394a95efa477d29b67b1960a1fe127466f9ba2fdab98840772e2d9c182ac79c840920e805642868ffff7f200500000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013900ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020addda44fbe7149150d61da1426b8696d036c446e3907315d54adfb9622be5061e89a51e9161bdb0599aad3ece22804c386a145ee359192b6340a0f540308a7cb05642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013a00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000202b69494286624cd6e36302c888f1a74795ebca3718e5c63b2ad7be51e6e3ef4283da010da0833f667c13ba17e21be35979fd9477dfb0941563372eb324a8041405642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013b00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205c7098269ba85dab3ac0f3d23f3ce96c642415937199ae48a147ab7393f43970c73865505a398001de890b17f6fe9039b6ef95c284e032aa07ed276b12381fda05642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013c00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e9d9a27804a2a9bb11d36495ae44c507879c9671828d4f6eb086f5653c87304efba1d5e8b85bb80f06d9973c84e4ecc7264c1404e285f629e23d465777f9892105642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013d00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a5a1310092f77f5606f67707762f33969541fe50befed88a32b995687a428f0c38ee80fa276489334766563ef1e90ccccc46071684f1af8b5ebea137cce4df3a06642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013e00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208ef80c3e90618558cc870d6ced56d4ba5b29663f61bb6953cd6fa3bc21d36e0fd1873e8b00f71d24b935d34eff87626e072780790bed9cd2906d961afa0b9dc106642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013f00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a241e2268806121a11beff9086af5fb70426b4dd15eb4afd207b1aea5289ae45a18cf47419d8bdc4fcef81b0c170e0195ce4c04571c7585d138712b9d253c71a06642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014000ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fc7157c7d646783cc601ebeaaa8c79f2052edb2e86e1171498e756f73406187b427aeab6a4d9c1b3a8f2a3bb025944816293642095e7183379a53a8bdcd0afdf06642868ffff7f200700000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b26b4ebc3b464469b2ca78503e6c8b2c89e0ae72251a48216997f225eb6b6956f3126172fe252d94af637d538275fa2458e9945a919d8097528a910c9bcb657906642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b689b990bc6f9aeeb158ca86bf939b3b127ba1a3b4f2eb4456c15499a05c6c1c54177c50f62d09933c72f46ee6ec89827a63692f5e4848ae068f72b57c50f77b06642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d18395722e2949e17d46817ab2098b90ac0ec01c9caba4f74680d3fe18c7526b91346ff0d926944d0fbdaa9165b86b7053c5ec9e54c80bd4b269018d8788e84607642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020def9e582123279e644778469d48222e13b72594fe76bdf8ca3c1bbafe38f586f6f5f5ee9ae2ede60518ceb762ca28180a5829320205ef0ff6ef1223d27eba36c07642868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002018b382d36c373f52c3820f473bbcd5cb9027d13e91ce6ad4c298fa9d28a97422110e3b049c6178084a280dbbad9baca64fb71e50e830c4ffa4bc55879a40168607642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014600ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a120ea6f582cedbb76fbbcc599918852c7653d18aa71e5483f26450ac486c368a2d6da77a833a1778439bb5486870ef09dbd5431c933e99dec536904a202d58d07642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014700ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fa1e3a93620154d7df9f57755cf8aecabf1f2f03bd22b4f664326f21025d7c51dd7aba5da276f5e45d4e8d1dcbaf7f8167306ed4566ecd9056ae412964d1ccec07642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014800ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002070441cf0b97aa204a92a593e74e2528b85664f97e8f8961ba9f1b8a3c42b194def57ec7a34ddeca72f716f0e9907786eae7fb4742344d9f2db81a513bc19245507642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014900ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209a80c2990358898686988c0b0c3d4f7d45c8546786c4973d1f1ed877e7c77348158a3424c5fb9827d03ed6df1e776178e31a27dc9e844efe08e9b24856b0257508642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014a00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206eae059b8c4a72281c850e371a6d184fb528b0e6c623dc369104a18b6f7d183b3b986364282187223be7ced89e11ab928d961e983fd2e317aeaa2f00f54e52a808642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014b00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020cf3f690c2247de6402e0333625bde40499e82226fbebb29edf5c4f97adfb792308481584f5bf35b80fab4ac1f7453f7cec7cb56e83026d2aa073476629f2814008642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014c00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020deeff547544b4a31e1e41343962d3c3df823b8f7385326bf61fcaa39c1f3f157eda0d56c1872e36782d20a564c4eeb7fb2de8c4e98a8db683fae5d6c1541f02c08642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014d00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020af94137e50627833cdb44aeed4ac4d9f77bd384060a753a384c2376746c55f0cce2bc856628623514b02f4c902765b3b9a069bf212d4e94492e587b832d1886a08642868ffff7f200d00000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014e00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205406a175f8c787dc32eb8f44da0f6c87b6f2b93b9756b65782da7c96938eb75fcff042bc51ac9a4269c1d2fd60e7daddd0410d54dd59df2dcfdb82047e2d3fcf08642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014f00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002053f2717e6c8112d459f1fb3fa8078b4d8b783d0a5c5af95ecf9486b7383afe7ff93209e92a5b2c68f8f358a2d8f6892add8297414ed5dde6f482d3b811bc94b709642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015000ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205c1295924ab79f006edef44821822c3aa54e95857e765f283a574d2507c1b47ca77fb07f57d0dcf4e0195b5a5d9b0c9680d63d69619c98b9c0156204533383bc09642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020434706382c1793d6960865ef6b9aa4b44b0ce1ce45fe49787e9182363777f15b604ab91223a77e31e73dcd57316941fac9bf71163dab9f3e99e52c00d8f6340509642868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207fc60d23ad54c74859db708618dc78806f330be76e078dc333c530fe8c2fb40fcce01f324f7a96eb5edbd5198919398157d948b67cea5e29ce580d0ffd20b5e909642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002021f1a012c6c4078361f16a2b7acaca0582b281446f702dfd19694f10c54a29677d26fa5c1378e056dd7ea80e6fee80ce239e02dd08a69689ed86f5dcf39a935b09642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208ca5829f9c0906f83d12626e3a313db8a9d85d3566d1035d0dc73785adede26a532f74472514979af91ff02c324cf3520731601e9e799d7c4887bd8b69f1c97009642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002074d3a7ed763c2553aaa9cd03a03b71cf3376d70411bc0da085698c3ca3b3745e1efda03edf67b4d133daa3d0a98ee590685ba91177fc78767c3d08d4a9c3fd690a642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015600ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209d890b5562ad55fc0c63473ecc17bdf26d59aaeb2978dcfe077f15f3b49c7236807c25aefa037187d354b13bdc08f3f289cc484d12732bc779cc5a0871f4237e0a642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015700ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020701c48dd64b0172277b977d4f5d56b388d33ca853df638dd253006b653d0bc59c0eb6738a48441b0e844128daa88f49620e88f8912e0dc0d2b6a75c9b131e8820a642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015800ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205e37a8ce71bd3ef414d950895661c9b34a24af3874b9ad18def117464363e655dfdd1a2271d924fbc13bb451f702ff75a15f06ef7cf41b157ed481219d5a846e0a642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015900ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209d7775132196caecb9c9cf402f75e253f7700f603d6f543e3f6700ab677d396d6970a5e5423a7b722e2d2aff99196f3aa32d341bb17a3d68feb5ebe3da33128a0a642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015a00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e5d0ee5a69855f69a51ed834f15ad1dfee8805e11dfe7fd543abe18e6fae555799885330c2d01b40b3ed79f47862f23ecbb57f1bbc1907357f6cdc2edf33c8c50a642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015b00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020738a43edf1c409c907cdbe0afe4539b7b7a5dec6bfd9a51bfb4f7112caf7e70bee11f4c823b6b4f4ac2c3644ef68916a28c28fb3849a6c863bbe0ae922abfbc40b642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015c00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209cd7549ad2524757f193f4051923374012b3698704be1efe326bc2180d283d231924520e5771308a76f773c77537cb04866e2d38b233f4671c93e2cc3148a60c0b642868ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015d00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201565f69256564bc83e1935f73f134a7e13867490bb9a534431d01f784de784004dcfd33733207b0ab5e86157c74cac5bc51c39af7691316f70c86304334e03c40b642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015e00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002095e095a43bdde66325ba7ec5eed54f4db0b1d514536c08eca59e725fbef63b01b727ea198dfdeaad944eaaf01fadba45cb19c0fba30ff8d1e97ecf798cd0384c0b642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015f00ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201710e1ced6e46eca0b38c9e1d23c167204d2c6e3cee95b0800ba0ce61cd9d67b9d305c60f63ef686d1c41beae95055245d632869003e5525837ca48ce76a3bce0b642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016000ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208d404c3e10a4a8814600bdddcef7ee90b47280b3849f9344e0833c2adc73641566669f631cdd9df34dcfb37e8729c6e73bdc396765a0a66a7e62544d7053ecac0b642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016100ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020bda9c22000f9de348bd7956d675c36fa4fa1355737b8bb9d70a89ae0c6f78464e197efda64074b8e1e175d66e740c9ee3102ad114f802c17af7701db991e07150c642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016200ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020203063601f8cb09ab8f6756407d388e5eba8506b36cb311e4dfabefc30bfc3360e790e5021ebd3c6ab54079ef9954b92ca997a6364bdc8405ea566a815f2b98f0c642868ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016300ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c71a529a9715390219692b68b1aa76e8939c549062a7f44885a87dedcd181863e570f8f59146f2f5700b720953221b9cc98a58f4678b5c873c2b4c6e37b88eef0c642868ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016400ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a798bd8cb337e2a6c8bed1170503c37bb14a06e3a492166b309aec3bbf12f47871f2bda58f16a06bb420b48b5c4043f2b109de43dc01e0862ebfc55078e53a330c642868ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016500ffffffff0200f2052a01000000160014da92569b04225bc8fb1f95d6f87daa735489ee290000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204488f00bb863cfcb1e038e7e3a5f7b48439a78e55294617d318e89aa1adfad436fe12257d5e7456c01f069ba5c03945cc377c345f7d9efce224ffe37fc03064e0c642868ffff7f200000000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016600ffffffff028df2052a01000000160014db9680a36eba1588d654997b4dfe8367750601560000000000000000266a24aa21a9ede1cda2213558058f747117e749d912456522f34f1d56266b6ebd8b00a9f2643e012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101754da9b9e16d987364f7c82d252ca2f12d18a26e5d23e1eb1d7b1aa19682e1250000000000fdffffff02f36ce7290100000016001406d100d7761da1b04a7c879676b0bd8b8f054b8480841e000000000016001401fad90abcd66697e2592164722de4a95ebee165024730440220393e40c25bdae368e3dba1161b84b4d79f555c75b507c0825c12bb5dc4bd5e33022032527f64e57b3c223c6ceb90f495b9aac804537aec757ed2e826fc0993fd27f3012102ee9864ff8b00633cf9dfdca577142831ccf641d9c066d26cfaf0e3e7e763b48d65000000']
    bitcoind.restore_blocks(blocks)
    l1 = node_factory.get_node(dbfile='channel_htlcs-pre-pagination.sqlite3.xz',
                               options={'database-upgrade': True})

    # l2 is the node l1 thinks it has a channel with.  l2 has no idea, but we allocate it so
    # l3 is a fresh node.
    l2, l3 = node_factory.get_nodes(2)

    # 100 blocks so this bitcoind has funds!
    bitcoind.generate_block(101)
    node_factory.join_nodes([l1, l3])

    # Make some HTLCS
    for amt in (100, 500, 1000, 5000, 10000, 50000, 100000):
        l1.pay(l3, amt)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "STRICT tables are SQLite3 specific")
def test_sqlite_strict_mode(node_factory):
    """Test that STRICT is appended to CREATE TABLE in developer mode."""
    l1 = node_factory.get_node(options={'developer': None})

    tables = l1.db_query("SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")

    strict_tables = [t for t in tables if t['sql'] and 'STRICT' in t['sql']]
    assert len(strict_tables) > 0, f"Expected at least one STRICT table in developer mode, found none out of {len(tables)}"

    known_strict_tables = ['version', 'forwards', 'payments', 'local_anchors', 'addresses']
    for table_name in known_strict_tables:
        table_sql = next((t['sql'] for t in tables if t['name'] == table_name), None)
        if table_sql:
            assert 'STRICT' in table_sql, f"Expected table '{table_name}' to be STRICT in developer mode"


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "SQLite3-specific test")
@unittest.skipIf(not COMPAT, "needs COMPAT to test old database upgrade")
@unittest.skipIf(TEST_NETWORK != 'regtest', "The network must match the DB snapshot")
def test_strict_mode_with_old_database(node_factory, bitcoind):
    """Test old database upgrades work (STRICT not applied during migrations)."""
    bitcoind.generate_block(1)

    l1 = node_factory.get_node(dbfile='oldstyle-scids.sqlite3.xz',
                               options={'database-upgrade': True,
                                        'developer': None})

    assert l1.rpc.getinfo()['id'] is not None

    # Upgraded tables won't be STRICT (only fresh databases get STRICT).
    strict_tables = l1.db_query(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND sql LIKE '%STRICT%'"
    )
    assert len(strict_tables) == 0, "Upgraded database should not have STRICT tables"

    # Verify BLOB->TEXT migration ran for faildetail cleanup.
    result = l1.db_query(
        "SELECT COUNT(*) as count FROM payments "
        "WHERE typeof(faildetail) = 'blob'"
    )
    assert result[0]['count'] == 0, "Found BLOB-typed faildetail after migration"
