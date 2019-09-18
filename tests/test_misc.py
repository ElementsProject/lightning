from bitcoin.rpc import RawProxy
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from flaky import flaky  # noqa: F401
from lightning import RpcError
from threading import Event
from utils import DEVELOPER, TIMEOUT, VALGRIND, sync_blockheight, only_one, wait_for, TailableProc
from ephemeral_port_reserve import reserve

import json
import os
import pytest
import re
import shutil
import signal
import socket
import subprocess
import time
import unittest


@unittest.skipIf(not DEVELOPER, "needs --dev-disconnect")
def test_stop_pending_fundchannel(node_factory, executor):
    """Stop the daemon while waiting for an accept_channel

    This used to crash the node, since we were calling unreserve_utxo while
    freeing the daemon, but that needs a DB transaction to be open.

    """
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We want l2 to stop replying altogether, not disconnect
    os.kill(l2.daemon.proc.pid, signal.SIGSTOP)

    # The fundchannel call will not terminate so run it in a future
    executor.submit(l1.fund_channel, l2, 10**6)
    l1.daemon.wait_for_log('peer_out WIRE_OPEN_CHANNEL')

    l1.rpc.stop()

    # Now allow l2 a clean shutdown
    os.kill(l2.daemon.proc.pid, signal.SIGCONT)
    l2.rpc.stop()


def test_names(node_factory):
    configs = [
        ('0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518', 'JUNIORBEAM', '0266e4'),
        ('022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59', 'SILENTARTIST', '022d22'),
        ('035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d', 'HOPPINGFIRE', '035d2b'),
        ('0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199', 'JUNIORFELONY', '0382ce'),
        ('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'SOMBERFIRE', '032cf1'),
        ('0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6518', 'LOUDPHOTO', '0265b6')
    ]

    for key, alias, color in configs:
        n = node_factory.get_node()
        assert n.daemon.is_in_log(r'public key {}, alias {}.* \(color #{}\)'
                                  .format(key, alias, color))


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This migration is based on a sqlite3 snapshot")
def test_db_upgrade(node_factory):
    l1 = node_factory.get_node()
    l1.stop()

    version = subprocess.check_output(['lightningd/lightningd',
                                       '--version']).decode('utf-8').splitlines()[0]

    upgrades = l1.db_query("SELECT * from db_upgrades;")
    assert len(upgrades) == 1
    assert(upgrades[0]['upgrade_from'] == -1)
    assert(upgrades[0]['lightning_version'] == version)

    # Try resetting to earlier db state.
    os.unlink(os.path.join(l1.daemon.lightning_dir, "lightningd.sqlite3"))
    l1.db_manip("CREATE TABLE version (version INTEGER);")
    l1.db_manip("INSERT INTO version VALUES (1);")

    l1.start()
    upgrades = l1.db_query("SELECT * from db_upgrades;")
    assert len(upgrades) == 1
    assert(upgrades[0]['upgrade_from'] == 1)
    assert(upgrades[0]['lightning_version'] == version)


def test_bitcoin_failure(node_factory, bitcoind):
    l1 = node_factory.get_node()

    # Make sure we're not failing it between getblockhash and getblock.
    sync_blockheight(bitcoind, [l1])

    def crash_bitcoincli(r):
        return {'error': 'go away'}

    # This is not a JSON-RPC response by purpose
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', crash_bitcoincli)
    l1.daemon.rpcproxy.mock_rpc('getblockhash', crash_bitcoincli)

    # This should cause both estimatefee and getblockhash fail
    l1.daemon.wait_for_logs(['estimatesmartfee .* exited with status 1',
                             'getblockhash .* exited with status 1'])

    # And they should retry!
    l1.daemon.wait_for_logs(['estimatesmartfee .* exited with status 1',
                             'getblockhash .* exited with status 1'])

    # Restore, then it should recover and get blockheight.
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', None)
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)

    bitcoind.generate_block(5)
    sync_blockheight(bitcoind, [l1])


def test_bitcoin_ibd(node_factory, bitcoind):
    """Test that we recognize bitcoin in initial download mode"""
    info = bitcoind.rpc.getblockchaininfo()
    info['initialblockdownload'] = True

    l1 = node_factory.get_node(start=False)
    l1.daemon.rpcproxy.mock_rpc('getblockchaininfo', info)

    l1.start(wait_for_bitcoind_sync=False)

    # This happens before the Starting message start() waits for.
    assert l1.daemon.is_in_log('Waiting for initial block download')
    assert 'warning_bitcoind_sync' in l1.rpc.getinfo()

    # "Finish" IDB.
    l1.daemon.rpcproxy.mock_rpc('getblockchaininfo', None)

    l1.daemon.wait_for_log('Bitcoind now synced')
    assert 'warning_bitcoind_sync' not in l1.rpc.getinfo()


def test_lightningd_still_loading(node_factory, bitcoind, executor):
    """Test that we recognize we haven't got all blocks from bitcoind"""

    mock_release = Event()

    # This is slow enough that we're going to notice.
    def mock_getblock(r):
        conf_file = os.path.join(bitcoind.bitcoin_dir, 'bitcoin.conf')
        brpc = RawProxy(btc_conf_file=conf_file)
        if r['params'][0] == slow_blockid:
            mock_release.wait(TIMEOUT)
        return {
            "result": brpc._call(r['method'], *r['params']),
            "error": None,
            "id": r['id']
        }

    # Start it, establish channel, get extra funds.
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True, 'wait_for_bitcoind_sync': False})
    # Extra funds, for second channel attempt.
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], 1.0)
    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l1])

    # Balance l1<->l2 channel
    l1.pay(l2, 10**9 // 2)

    l1.stop()

    # Start extra node.
    l3 = node_factory.get_node()

    # Now make sure it's behind.
    bitcoind.generate_block(2)
    # Make sure l2/l3 are synced
    sync_blockheight(bitcoind, [l2, l3])

    # Make it slow grabbing the final block.
    slow_blockid = bitcoind.rpc.getblockhash(bitcoind.rpc.getblockcount())
    l1.daemon.rpcproxy.mock_rpc('getblock', mock_getblock)

    l1.start(wait_for_bitcoind_sync=False)

    # It will warn about being out-of-sync.
    assert 'warning_bitcoind_sync' not in l1.rpc.getinfo()
    assert 'warning_lightningd_sync' in l1.rpc.getinfo()

    # Payments will fail.  FIXME: More informative msg?
    with pytest.raises(RpcError, match=r'TEMPORARY_CHANNEL_FAILURE'):
        l1.pay(l2, 1000)

    # Can't fund a new channel, either.
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    with pytest.raises(RpcError, match=r'304'):
        l1.rpc.fundchannel(l3.info['id'], 'all')

    # This will work, but will be delayed until synced.
    fut = executor.submit(l2.pay, l1, 1000)
    l1.daemon.wait_for_log("Deferring incoming commit until we sync")

    # Release the mock.
    mock_release.set()
    fut.result()

    assert 'warning_lightningd_sync' not in l1.rpc.getinfo()

    # This will now work normally.
    l1.pay(l2, 1000)


def test_ping(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    def ping_tests(l1, l2):
        # 0-byte pong gives just type + length field.
        ret = l1.rpc.ping(l2.info['id'], 0, 0)
        assert ret['totlen'] == 4

        # 1000-byte ping, 0-byte pong.
        ret = l1.rpc.ping(l2.info['id'], 1000, 0)
        assert ret['totlen'] == 4

        # 1000 byte pong.
        ret = l1.rpc.ping(l2.info['id'], 1000, 1000)
        assert ret['totlen'] == 1004

        # Maximum length pong.
        ret = l1.rpc.ping(l2.info['id'], 1000, 65531)
        assert ret['totlen'] == 65535

        # Overlength -> no reply.
        for s in range(65532, 65536):
            ret = l1.rpc.ping(l2.info['id'], 1000, s)
            assert ret['totlen'] == 0

        # 65535 - type(2 bytes) - num_pong_bytes(2 bytes) - byteslen(2 bytes)
        # = 65529 max.
        with pytest.raises(RpcError, match=r'oversize ping'):
            l1.rpc.ping(l2.info['id'], 65530, 1)

    # Test gossip pinging.
    ping_tests(l1, l2)
    if DEVELOPER:
        l1.daemon.wait_for_log(r'Got pong 1000 bytes \({}\.\.\.\)'
                               .format(l2.info['version']), timeout=1)

    l1.fund_channel(l2, 10**5)

    # channeld pinging
    ping_tests(l1, l2)
    if DEVELOPER:
        l1.daemon.wait_for_log(r'Got pong 1000 bytes \({}\.\.\.\)'
                               .format(l2.info['version']))


@unittest.skipIf(not DEVELOPER, "needs --dev-disconnect")
def test_htlc_sig_persistence(node_factory, bitcoind, executor):
    """Interrupt a payment between two peers, then fail and recover funds using the HTLC sig.
    """
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)
    f = executor.submit(l1.pay, l2, 31337000)
    l1.daemon.wait_for_log(r'HTLC out 0 RCVD_ADD_ACK_COMMIT->SENT_ADD_ACK_REVOCATION')
    l1.stop()

    # `pay` call is lost
    with pytest.raises(RpcError):
        f.result()

    # We should have the HTLC sig
    assert(len(l1.db_query("SELECT * FROM htlc_sigs;")) == 1)

    # This should reload the htlc_sig
    l2.rpc.dev_fail(l1.info['id'])
    # Make sure it broadcasts to chain.
    l2.wait_for_channel_onchain(l1.info['id'])
    l2.stop()
    bitcoind.generate_block(1)
    l1.start()

    assert l1.daemon.is_in_log(r'Loaded 1 HTLC signatures from DB')
    l1.daemon.wait_for_logs([
        r'Peer permanent failure in CHANNELD_NORMAL: Funding transaction spent',
        r'Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US'
    ])
    bitcoind.generate_block(5)
    l1.daemon.wait_for_log("Broadcasting OUR_HTLC_TIMEOUT_TO_US")
    time.sleep(3)
    bitcoind.generate_block(1)
    l1.daemon.wait_for_logs([
        r'Owning output . (\d+)sat .SEGWIT. txid',
    ])

    # We should now have a) the change from funding, b) the
    # unilateral to us, and c) the HTLC respend to us
    assert len(l1.rpc.listfunds()['outputs']) == 3


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_htlc_out_timeout(node_factory, bitcoind, executor):
    """Test that we drop onchain if the peer doesn't time out HTLC"""

    # HTLC 1->2, 1 fails after it's irrevocably committed, can't reconnect
    disconnects = ['@WIRE_REVOKE_AND_ACK']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chanid = l1.fund_channel(l2, 10**6)

    # Wait for route propagation.
    l1.wait_channel_active(chanid)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_htlc_out_timeout', 'desc')['bolt11']
    assert only_one(l2.rpc.listinvoices('test_htlc_out_timeout')['invoices'])['status'] == 'unpaid'

    executor.submit(l1.rpc.pay, inv)

    # l1 will disconnect, and not reconnect.
    l1.daemon.wait_for_log('dev_disconnect: @WIRE_REVOKE_AND_ACK')

    # Takes 6 blocks to timeout (cltv-final + 1), but we also give grace period of 1 block.
    # shadow route can add extra blocks!
    status = only_one(l1.rpc.call('paystatus')['pay'])
    if 'shadow' in status:
        shadowlen = 6 * status['shadow'].count('Added 6 cltv delay for shadow')
    else:
        shadowlen = 0

    bitcoind.generate_block(5 + 1 + shadowlen)
    time.sleep(3)
    assert not l1.daemon.is_in_log('hit deadline')
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log('Offered HTLC 0 SENT_ADD_ACK_REVOCATION cltv .* hit deadline')
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # L1 will timeout HTLC immediately
    l1.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TX .* after 0 blocks',
                             'Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks'])

    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log('Propose handling OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')
    bitcoind.generate_block(4)
    # It should now claim both the to-local and htlc-timeout-tx outputs.
    l1.daemon.wait_for_logs(['Broadcasting OUR_DELAYED_RETURN_TO_WALLET',
                             'Broadcasting OUR_DELAYED_RETURN_TO_WALLET',
                             'sendrawtx exit 0',
                             'sendrawtx exit 0'])

    # Now, 100 blocks it should be done.
    bitcoind.generate_block(100)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_htlc_in_timeout(node_factory, bitcoind, executor):
    """Test that we drop onchain if the peer doesn't accept fulfilled HTLC"""

    # HTLC 1->2, 1 fails after 2 has sent committed the fulfill
    disconnects = ['-WIRE_REVOKE_AND_ACK*2']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chanid = l1.fund_channel(l2, 10**6)

    l1.wait_channel_active(chanid)
    sync_blockheight(bitcoind, [l1, l2])

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_htlc_in_timeout', 'desc')['bolt11']
    assert only_one(l2.rpc.listinvoices('test_htlc_in_timeout')['invoices'])['status'] == 'unpaid'

    executor.submit(l1.rpc.pay, inv)

    # l1 will disconnect and not reconnect.
    l1.daemon.wait_for_log('dev_disconnect: -WIRE_REVOKE_AND_ACK')

    # Deadline HTLC expiry minus 1/2 cltv-expiry delta (rounded up) (== cltv - 3).  cltv is 5+1.
    # shadow route can add extra blocks!
    status = only_one(l1.rpc.call('paystatus')['pay'])
    if 'shadow' in status:
        shadowlen = 6 * status['shadow'].count('Added 6 cltv delay for shadow')
    else:
        shadowlen = 0
    bitcoind.generate_block(2 + shadowlen)
    assert not l2.daemon.is_in_log('hit deadline')
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log('Fulfilled HTLC 0 SENT_REMOVE_COMMIT cltv .* hit deadline')
    l2.daemon.wait_for_log('sendrawtx exit 0')
    l2.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l1.daemon.wait_for_log(' to ONCHAIN')

    # L2 will collect HTLC (iff no shadow route)
    l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* after 0 blocks')
    l2.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')
    bitcoind.generate_block(4)
    l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # Now, 100 blocks it should be both done.
    bitcoind.generate_block(100)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_bech32_funding(node_factory, chainparams):
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)
    l2 = node_factory.get_node(random_hsm=True)

    # connect
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # fund a bech32 address and then open a channel with it
    res = l1.openchannel(l2, 20000, 'bech32')
    address = res['address']
    assert address.startswith(chainparams['bip173_prefix'])

    # probably overly paranoid checking
    wallettxid = res['wallettxid']

    wallettx = l1.bitcoin.rpc.getrawtransaction(wallettxid, True)
    fundingtx = l1.bitcoin.rpc.decoderawtransaction(res['fundingtx']['tx'])

    def is_p2wpkh(output):
        return output['type'] == 'witness_v0_keyhash' and \
            address == only_one(output['addresses'])

    assert any(is_p2wpkh(output['scriptPubKey']) for output in wallettx['vout'])
    assert only_one(fundingtx['vin'])['txid'] == res['wallettxid']


def test_withdraw(node_factory, bitcoind, chainparams):
    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)
    l2 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['bech32']

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

    # Reach around into the db to check that outputs were added
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 10

    waddr = l1.bitcoin.getnewaddress()
    # Now attempt to withdraw some (making sure we collect multiple inputs)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('not an address', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, 'not an amount')
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, -amount)
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
        l1.rpc.withdraw(waddr, amount * 100)

    out = l1.rpc.withdraw(waddr, 2 * amount)

    # Make sure bitcoind received the withdrawal
    unspent = l1.bitcoin.rpc.listunspent(0)
    withdrawal = [u for u in unspent if u['txid'] == out['txid']]

    assert(withdrawal[0]['amount'] == Decimal('0.02'))

    # Now make sure two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 2

    # Now send some money to l2.
    # lightningd uses P2SH-P2WPKH
    waddr = l2.rpc.newaddr('bech32')['bech32']
    l1.rpc.withdraw(waddr, 2 * amount)
    bitcoind.generate_block(1)

    # Make sure l2 received the withdrawal.
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 1)
    outputs = l2.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 2 * amount

    # Now make sure an additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 4

    if chainparams['name'] != 'regtest':
        return

    # Simple test for withdrawal to P2WPKH
    # Address from: https://bc-2.jp/tools/bech32demo/index.html
    waddr = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
    with pytest.raises(RpcError):
        l1.rpc.withdraw('xx1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kdl9fad', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxxxxxx', 2 * amount)
    l1.rpc.withdraw(waddr, 2 * amount)
    bitcoind.generate_block(1)
    # Now make sure additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 6

    # Simple test for withdrawal to P2WSH
    # Address from: https://bc-2.jp/tools/bech32demo/index.html
    waddr = 'bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry'
    with pytest.raises(RpcError):
        l1.rpc.withdraw('xx1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsm03tq', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qxxxxxx', 2 * amount)
    l1.rpc.withdraw(waddr, 2 * amount)
    bitcoind.generate_block(1)
    # Now make sure additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 8

    # failure testing for invalid SegWit addresses, from BIP173
    # HRP character out of range
    with pytest.raises(RpcError):
        l1.rpc.withdraw(' 1nwldj5', 2 * amount)
    # overall max length exceeded
    with pytest.raises(RpcError):
        l1.rpc.withdraw('an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx', 2 * amount)
    # No separator character
    with pytest.raises(RpcError):
        l1.rpc.withdraw('pzry9x0s0muk', 2 * amount)
    # Empty HRP
    with pytest.raises(RpcError):
        l1.rpc.withdraw('1pzry9x0s0muk', 2 * amount)
    # Invalid witness version
    with pytest.raises(RpcError):
        l1.rpc.withdraw('BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2', 2 * amount)
    # Invalid program length for witness version 0 (per BIP141)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 2 * amount)
    # Mixed case
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7', 2 * amount)
    # Non-zero padding in 8-to-5 conversion
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv', 2 * amount)

    # Should have 6 outputs available.
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 6

    # Test withdrawal to self.
    l1.rpc.withdraw(l1.rpc.newaddr('bech32')['bech32'], 'all', minconf=0)
    bitcoind.generate_block(1)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 1

    l1.rpc.withdraw(waddr, 'all', minconf=0)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 0

    # This should fail, can't even afford fee.
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
        l1.rpc.withdraw(waddr, 'all')


def test_minconf_withdraw(node_factory, bitcoind):
    """Issue 2518: ensure that ridiculous confirmation levels don't overflow

    The number of confirmations is used to compute a maximum height that is to
    be accepted. If the current height is smaller than the number of
    confirmations we wrap around and just select everything. The fix is to
    clamp the maxheight parameter to a positive small number.

    """
    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['bech32']

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)
    with pytest.raises(RpcError):
        l1.rpc.withdraw(destination=addr, satoshi=10000, feerate='normal', minconf=9999999)


def test_addfunds_from_block(node_factory, bitcoind):
    """Send funds to the daemon without telling it explicitly
    """
    # Previous runs with same bitcoind can leave funds!
    l1 = node_factory.get_node(random_hsm=True)

    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 0.1)
    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 10000000

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr

    # Send all our money to a P2WPKH address this time.
    addr = l1.rpc.newaddr("bech32")['bech32']
    l1.rpc.withdraw(addr, "all")
    bitcoind.generate_block(1)
    time.sleep(1)

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr


def test_io_logging(node_factory, executor):
    l1 = node_factory.get_node(options={'log-level': 'io'})
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Fundchannel manually so we get channeld pid.
    l1.fundwallet(10**6 + 1000000)
    l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']
    pid1 = l1.subd_pid('channeld')

    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')

    pid2 = l2.subd_pid('channeld')
    l2.daemon.wait_for_log(' to CHANNELD_NORMAL')

    # Send it sigusr1: should turn on logging.
    subprocess.run(['kill', '-USR1', pid1])

    fut = executor.submit(l1.pay, l2, 200000000)

    # WIRE_UPDATE_ADD_HTLC = 128 = 0x0080
    l1.daemon.wait_for_log(r'channeld.*:\[OUT\] 0080')
    # WIRE_UPDATE_FULFILL_HTLC = 130 = 0x0082
    l1.daemon.wait_for_log(r'channeld.*:\[IN\] 0082')
    fut.result(10)

    # Send it sigusr1: should turn off logging.
    subprocess.run(['kill', '-USR1', pid1])

    l1.pay(l2, 200000000)

    assert not l1.daemon.is_in_log(r'channeld.*:\[OUT\] 0080',
                                   start=l1.daemon.logsearch_start)
    assert not l1.daemon.is_in_log(r'channeld.*:\[IN\] 0082',
                                   start=l1.daemon.logsearch_start)

    # IO logs should not appear in peer logs.
    peerlog = only_one(l2.rpc.listpeers(l1.info['id'], "io")['peers'])['log']
    assert not any(l['type'] == 'IO_OUT' or l['type'] == 'IO_IN'
                   for l in peerlog)

    # Turn on in l2 channel logging.
    subprocess.run(['kill', '-USR1', pid2])
    l1.pay(l2, 200000000)

    # Now it should find it.
    peerlog = only_one(l2.rpc.listpeers(l1.info['id'], "io")['peers'])['log']
    assert any(l['type'] == 'IO_OUT' for l in peerlog)
    assert any(l['type'] == 'IO_IN' for l in peerlog)


def test_address(node_factory):
    if DEVELOPER:
        opts = {'dev-allow-localhost': None}
    else:
        opts = None
    l1 = node_factory.get_node(options=opts)
    addr = l1.rpc.getinfo()['address']
    if DEVELOPER:
        assert len(addr) == 1
        assert addr[0]['type'] == 'ipv4'
        assert addr[0]['address'] == '127.0.0.1'
        assert int(addr[0]['port']) == l1.port
    else:
        assert len(addr) == 0

    bind = l1.rpc.getinfo()['binding']
    assert len(bind) == 1
    assert bind[0]['type'] == 'ipv4'
    assert bind[0]['address'] == '127.0.0.1'
    assert int(bind[0]['port']) == l1.port

    # Now test UNIX domain binding.
    l1.stop()
    l1.daemon.opts['bind-addr'] = os.path.join(l1.daemon.lightning_dir, "sock")
    l1.start()

    l2 = node_factory.get_node()
    l2.rpc.connect(l1.info['id'], l1.daemon.opts['bind-addr'])

    # 'addr' with local socket works too.
    l1.stop()
    del l1.daemon.opts['bind-addr']
    l1.daemon.opts['addr'] = os.path.join(l1.daemon.lightning_dir, "sock")
    # start expects a port, so we open-code here.
    l1.daemon.start()

    l2 = node_factory.get_node()
    l2.rpc.connect(l1.info['id'], l1.daemon.opts['addr'])


def test_listconfigs(node_factory, bitcoind, chainparams):
    l1 = node_factory.get_node()

    configs = l1.rpc.listconfigs()
    # See utils.py
    assert configs['allow-deprecated-apis'] is False
    assert configs['network'] == chainparams['name']
    assert configs['ignore-fee-limits'] is False

    # Test one at a time.
    for c in configs.keys():
        if c.startswith('#'):
            continue
        oneconfig = l1.rpc.listconfigs(config=c)
        assert(oneconfig[c] == configs[c])


def test_multirpc(node_factory):
    """Test that we can do multiple RPC without waiting for response"""
    l1 = node_factory.get_node()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(l1.rpc.socket_path)

    commands = [
        b'{"id":1,"jsonrpc":"2.0","method":"listpeers","params":[]}',
        b'{"id":2,"jsonrpc":"2.0","method":"listpeers","params":[]}',
        b'{"id":3,"jsonrpc":"2.0","method":"listpeers","params":[]}',
        b'{"id":4,"jsonrpc":"2.0","method":"listpeers","params":[]}',
        b'{"id":5,"jsonrpc":"2.0","method":"listpeers","params":[]}',
        b'{"id":6,"jsonrpc":"2.0","method":"listpeers","params":[]}',
        b'{"method": "invoice", "params": [100, "foo", "foo"], "jsonrpc": "2.0", "id": 7 }',
        b'{"method": "waitinvoice", "params": ["foo"], "jsonrpc" : "2.0", "id": 8 }',
        b'{"method": "delinvoice", "params": ["foo", "unpaid"], "jsonrpc" : "2.0", "id": 9 }',
    ]

    sock.sendall(b'\n'.join(commands))

    buff = b''
    for i in commands:
        _, buff = l1.rpc._readobj(sock, buff)
    sock.close()


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_multiplexed_rpc(node_factory):
    """Test that we can do multiple RPCs which exit in different orders"""
    l1 = node_factory.get_node()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(l1.rpc.socket_path)

    # Neighbouring ones may be in or out of order.
    commands = [
        b'{"id":1,"jsonrpc":"2.0","method":"dev","params":["slowcmd",2000]}',
        b'{"id":1,"jsonrpc":"2.0","method":"dev","params":["slowcmd",2000]}',
        b'{"id":2,"jsonrpc":"2.0","method":"dev","params":["slowcmd",1500]}',
        b'{"id":2,"jsonrpc":"2.0","method":"dev","params":["slowcmd",1500]}',
        b'{"id":3,"jsonrpc":"2.0","method":"dev","params":["slowcmd",1000]}',
        b'{"id":3,"jsonrpc":"2.0","method":"dev","params":["slowcmd",1000]}',
        b'{"id":4,"jsonrpc":"2.0","method":"dev","params":["slowcmd",500]}',
        b'{"id":4,"jsonrpc":"2.0","method":"dev","params":["slowcmd",500]}'
    ]

    sock.sendall(b'\n'.join(commands))

    buff = b''

    # They will return in the same order, since they start immediately
    # (delaying completion should mean we don't see the other commands intermingled).
    for i in commands:
        obj, buff = l1.rpc._readobj(sock, buff)
        assert obj['id'] == l1.rpc.decoder.decode(i.decode("UTF-8"))['id']
    sock.close()


def test_malformed_rpc(node_factory):
    """Test that we get a correct response to malformed RPC commands"""
    l1 = node_factory.get_node()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(l1.rpc.socket_path)

    # No ID
    sock.sendall(b'{"jsonrpc":"2.0","method":"getinfo","params":[]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['error']['code'] == -32600

    # No method
    sock.sendall(b'{"id":1, "jsonrpc":"2.0","params":[]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['error']['code'] == -32600

    # Complete crap
    sock.sendall(b'[]')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['error']['code'] == -32600

    # Bad ID
    sock.sendall(b'{"id":{}, "jsonrpc":"2.0","method":"getinfo","params":[]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['error']['code'] == -32600

    # Bad method
    sock.sendall(b'{"id":1, "method": 12, "jsonrpc":"2.0","params":[]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['error']['code'] == -32600

    # Unknown method
    sock.sendall(b'{"id":1, "method": "unknown", "jsonrpc":"2.0","params":[]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['error']['code'] == -32601

    sock.close()


def test_cli(node_factory):
    l1 = node_factory.get_node()

    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    # Test some known output.
    assert 'help [command]\n    List available commands, or give verbose help on one {command}' in out

    # Test JSON output.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert j['help'][0]['command'] is not None
    assert j['help'][0]['description'] is not None

    # Test keyword input (autodetect)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help', 'command=help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test keyword input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-k',
                                   'help', 'command=help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test ordered input (autodetect)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test ordered input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-o',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test missing parameters.
    try:
        # This will error due to missing parameters.
        # We want to check if lightningd will crash.
        out = subprocess.check_output(['cli/lightning-cli',
                                       '--lightning-dir={}'
                                       .format(l1.daemon.lightning_dir),
                                       '-J', '-o',
                                       'sendpay']).decode('utf-8')
    except Exception:
        pass

    # Test it escapes JSON completely in both method and params.
    # cli turns " into \", reply turns that into \\\".
    out = subprocess.run(['cli/lightning-cli',
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'x"[]{}'],
                         stdout=subprocess.PIPE)
    assert 'Unknown command \'x\\\\\\"[]{}\'' in out.stdout.decode('utf-8')

    subprocess.check_output(['cli/lightning-cli',
                             '--lightning-dir={}'
                             .format(l1.daemon.lightning_dir),
                             'invoice', '123000', 'l"[]{}', 'd"[]{}']).decode('utf-8')
    # Check label is correct, and also that cli's keyword parsing works.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-k',
                                   'listinvoices', 'label=l"[]{}']).decode('utf-8')
    j = json.loads(out)
    assert only_one(j['invoices'])['label'] == 'l"[]{}'

    # For those using shell scripts (you know who you are Rene), make sure we're maintaining whitespace
    lines = [l for l in out.splitlines() if '"bolt11"' not in l and '"payment_hash"' not in l and '"expires_at"' not in l]
    assert lines == ['{',
                     '   "invoices": [',
                     '      {',
                     r'         "label": "l\"[]{}",',
                     '         "msatoshi": 123000,',
                     '         "amount_msat": "123000msat",',
                     '         "status": "unpaid",',
                     r'         "description": "d\"[]{}",',
                     '      }',
                     '   ]',
                     '}']


def test_daemon_option(node_factory):
    """
    Make sure --daemon at least vaguely works!
    """
    # Lazy way to set up command line and env, plus do VALGRIND checks
    l1 = node_factory.get_node()
    l1.stop()

    os.unlink(l1.rpc.socket_path)
    subprocess.run(l1.daemon.cmd_line + ['--daemon', '--log-file={}/log-daemon'.format(l1.daemon.lightning_dir)], env=l1.daemon.env,
                   check=True)

    # Test some known output (wait for rpc to be ready)
    wait_for(lambda: os.path.exists(l1.rpc.socket_path))
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    assert 'help [command]\n    List available commands, or give verbose help on one {command}' in out

    subprocess.run(['cli/lightning-cli',
                    '--lightning-dir={}'.format(l1.daemon.lightning_dir),
                    'stop'], check=True)

    # It should not complain that subdaemons aren't children.
    with open('{}/log-daemon'.format(l1.daemon.lightning_dir), 'r') as f:
        assert 'No child process' not in f.read()


@flaky
@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_blockchaintrack(node_factory, bitcoind):
    """Check that we track the blockchain correctly across reorgs
    """
    l1 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr(addresstype='all')['p2sh-segwit']

    ######################################################################
    # First failure scenario: rollback on startup doesn't work,
    # and we try to add a block twice when rescanning:
    l1.restart()

    height = bitcoind.rpc.getblockcount()   # 101

    # At height 111 we receive an incoming payment
    hashes = bitcoind.generate_block(9)     # 102-110
    bitcoind.rpc.sendtoaddress(addr, 1)
    time.sleep(1)  # mempool is still unpredictable
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Owning output.* \(P2SH\).* CONFIRMED')
    outputs = l1.rpc.listfunds()['outputs']
    assert len(outputs) == 1

    ######################################################################
    # Second failure scenario: perform a 20 block reorg
    bitcoind.generate_block(10)
    l1.daemon.wait_for_log('Adding block {}: '.format(height + 20))

    # Now reorg out with a longer fork of 21 blocks
    bitcoind.rpc.invalidateblock(hashes[0])
    bitcoind.wait_for_log(r'InvalidChainFound: invalid block=.*  height={}'
                          .format(height + 1))
    hashes = bitcoind.generate_block(30)
    time.sleep(1)

    bitcoind.rpc.getblockcount()
    l1.daemon.wait_for_log('Adding block {}: '.format(height + 30))

    # Our funds got reorged out, we should not have any funds that are confirmed
    # NOTE: sendtoaddress() sets locktime=103 and the reorg at 102 invalidates that tx
    # and deletes it from mempool
    assert [o for o in l1.rpc.listfunds()['outputs'] if o['status'] != "unconfirmed"] == []


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_funding_reorg_private(node_factory, bitcoind):
    """Change funding tx height after lockin, between node restart.
    """
    # Rescan to detect reorg at restart and may_reconnect so channeld
    # will restart.  Reorg can cause bad gossip msg.
    opts = {'funding-confirms': 2, 'rescan': 10, 'may_reconnect': True,
            'allow_bad_gossip': True}
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)
    l1.fundwallet(10000000)
    sync_blockheight(bitcoind, [l1])                # height 102
    bitcoind.generate_block(3)                      # heights 103-105

    l1.rpc.fundchannel(l2.info['id'], "all", announce=False)
    bitcoind.generate_block(1)                      # height 106
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'][0]['channels'])['status']
             == ['CHANNELD_AWAITING_LOCKIN:Funding needs 1 more confirmations for lockin.'])
    bitcoind.generate_block(1)                      # height 107
    l1.wait_channel_active('106x1x0')
    l1.stop()

    # Create a fork that changes short_channel_id from 106x1x0 to 108x1x0
    bitcoind.simple_reorg(106, 2)                   # heights 106-108
    bitcoind.generate_block(1)                      # height 109 (to reach minimum_depth=2 again)
    l1.start()

    # l2 was running, sees last stale block being removed
    l2.daemon.wait_for_logs([r'Removing stale block {}'.format(106),
                             r'Got depth change .->{} for .* REORG'.format(0)])

    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels('106x1x0')['channels']] == [False, False])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels('108x1x0')['channels']] == [True, True])

    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(1, True)
    l1.daemon.wait_for_log(r'Deleting channel')
    l2.daemon.wait_for_log(r'Deleting channel')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_funding_reorg_remote_lags(node_factory, bitcoind):
    """Nodes may disagree about short_channel_id before channel announcement
    """
    # may_reconnect so channeld will restart; bad gossip can happen due to reorg
    opts = {'funding-confirms': 1, 'may_reconnect': True, 'allow_bad_gossip': True}
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)
    l1.fundwallet(10000000)
    sync_blockheight(bitcoind, [l1])                # height 102

    l1.rpc.fundchannel(l2.info['id'], "all")
    bitcoind.generate_block(5)                      # heights 103 - 107
    l1.wait_channel_active('103x1x0')

    # Make l2 temporary blind for blocks > 107
    def no_more_blocks(req):
        return {"result": None,
                "error": {"code": -8, "message": "Block height out of range"}, "id": req['id']}

    l2.daemon.rpcproxy.mock_rpc('getblockhash', no_more_blocks)

    # Reorg changes short_channel_id 103x1x0 to 103x2x0, l1 sees it, restarts channeld
    bitcoind.simple_reorg(102, 1)                   # heights 102 - 108
    l1.daemon.wait_for_log(r'Peer transient failure .* short_channel_id changed to 103x2x0 \(was 103x1x0\)')

    wait_for(lambda: only_one(l2.rpc.listpeers()['peers'][0]['channels'])['status'] == [
        'CHANNELD_NORMAL:Reconnected, and reestablished.',
        'CHANNELD_NORMAL:Funding transaction locked. They need our announcement signatures.'])

    # Unblinding l2 brings it back in sync, restarts channeld and sends its announce sig
    l2.daemon.rpcproxy.mock_rpc('getblockhash', None)

    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels('103x1x0')['channels']] == [False, False])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels('103x2x0')['channels']] == [True, True])

    wait_for(lambda: only_one(l2.rpc.listpeers()['peers'][0]['channels'])['status'] == [
        'CHANNELD_NORMAL:Reconnected, and reestablished.',
        'CHANNELD_NORMAL:Funding transaction locked. Channel announced.'])

    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(1, True)
    l1.daemon.wait_for_log(r'Deleting channel')
    l2.daemon.wait_for_log(r'Deleting channel')


def test_rescan(node_factory, bitcoind):
    """Test the rescan option
    """
    l1 = node_factory.get_node()

    # The first start should start at current_height - 30 = 71, make sure
    # it's not earlier
    l1.daemon.wait_for_log(r'Adding block 101')
    assert not l1.daemon.is_in_log(r'Adding block 70')

    # Restarting with a higher rescan should go back further
    l1.daemon.opts['rescan'] = 50
    l1.restart()
    l1.daemon.wait_for_log(r'Adding block 101')
    assert l1.daemon.is_in_log(r'Adding block 51')
    assert not l1.daemon.is_in_log(r'Adding block 50')

    # Restarting with an absolute rescan should start from there
    l1.daemon.opts['rescan'] = -31
    l1.restart()
    l1.daemon.wait_for_log(r'Adding block 101')
    assert l1.daemon.is_in_log(r'Adding block 31')
    assert not l1.daemon.is_in_log(r'Adding block 30')

    # Restarting with a future absolute blockheight should just start with
    # the current height
    l1.daemon.opts['rescan'] = -500000
    l1.stop()
    bitcoind.generate_block(4)
    l1.start()
    l1.daemon.wait_for_log(r'Adding block 105')
    assert not l1.daemon.is_in_log(r'Adding block 102')


@flaky
def test_reserve_enforcement(node_factory, executor):
    """Channeld should disallow you spending into your reserve"""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})

    # Pay 1000 satoshi to l2.
    l1.pay(l2, 1000000)
    l2.stop()

    # They should both aim for 1%.
    reserves = l2.db.query('SELECT channel_reserve_satoshis FROM channel_configs')
    assert reserves == [{'channel_reserve_satoshis': 10**6 // 100}] * 2

    # Edit db to reduce reserve to 0 so it will try to violate it.
    l2.db.execute('UPDATE channel_configs SET channel_reserve_satoshis=0')

    l2.start()
    wait_for(lambda: only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])

    # This should be impossible to pay entire thing back: l1 should
    # kill us for trying to violate reserve.
    executor.submit(l2.pay, l1, 1000000)
    l1.daemon.wait_for_log(
        'Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: sent '
        'ERROR Bad peer_add_htlc: CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED'
    )


@unittest.skipIf(not DEVELOPER, "needs dev_disconnect")
def test_htlc_send_timeout(node_factory, bitcoind):
    """Test that we don't commit an HTLC to an unreachable node."""
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'log-level': 'io'},
                               feerates=(7500, 7500, 7500))
    # Blackhole it after it sends HTLC_ADD to l3.
    l2 = node_factory.get_node(disconnect=['0WIRE_UPDATE_ADD_HTLC'],
                               options={'log-level': 'io'},
                               feerates=(7500, 7500, 7500))
    l3 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    l1.fund_channel(l2, 10**6)
    chanid2 = l2.fund_channel(l3, 10**6)

    subprocess.run(['kill', '-USR1', l1.subd_pid('channeld')])
    subprocess.run(['kill', '-USR1', l2.subd_pid('channeld')])

    # Make sure channels get announced.
    bitcoind.generate_block(5)

    # Make sure we have 30 seconds without any incoming traffic from l3 to l2
    # so it tries to ping before sending WIRE_COMMITMENT_SIGNED.
    timedout = False
    while not timedout:
        try:
            l2.daemon.wait_for_log(r'channeld-{} chan #[0-9]*:\[IN\] 0101'.format(l3.info['id']), timeout=30)
        except TimeoutError:
            timedout = True

    inv = l3.rpc.invoice(123000, 'test_htlc_send_timeout', 'description')
    with pytest.raises(RpcError, match=r'Ran out of routes to try after 1 attempt: see paystatus') as excinfo:
        l1.rpc.pay(inv['bolt11'])

    err = excinfo.value
    # Complains it stopped after several attempts.
    # FIXME: include in pylightning
    PAY_STOPPED_RETRYING = 210
    assert err.error['code'] == PAY_STOPPED_RETRYING

    status = only_one(l1.rpc.call('paystatus')['pay'])

    # Temporary channel failure
    assert status['attempts'][0]['failure']['data']['failcode'] == 0x1007
    assert status['attempts'][0]['failure']['data']['erring_node'] == l2.info['id']
    assert status['attempts'][0]['failure']['data']['erring_channel'] == chanid2

    # L2 should send ping, but never receive pong so never send commitment.
    l2.daemon.wait_for_log(r'channeld.*:\[OUT\] 0012')
    assert not l2.daemon.is_in_log(r'channeld.*:\[IN\] 0013')
    assert not l2.daemon.is_in_log(r'channeld.*:\[OUT\] 0084')
    # L2 killed the channel with l3 because it was too slow.
    l2.daemon.wait_for_log('channeld-{}.*Adding HTLC too slow: killing connection'.format(l3.info['id']))


def test_ipv4_and_ipv6(node_factory):
    """Test we can bind to both IPv4 and IPv6 addresses (if supported)"""
    port = reserve()
    l1 = node_factory.get_node(options={'addr': ':{}'.format(port)})
    bind = l1.rpc.getinfo()['binding']

    if len(bind) == 2:
        assert bind[0]['type'] == 'ipv6'
        assert bind[0]['address'] == '::'
        assert int(bind[0]['port']) == port
        assert bind[1]['type'] == 'ipv4'
        assert bind[1]['address'] == '0.0.0.0'
        assert int(bind[1]['port']) == port
    else:
        # Assume we're IPv4 only...
        assert len(bind) == 1
        assert bind[0]['type'] == 'ipv4'
        assert bind[0]['address'] == '0.0.0.0'
        assert int(bind[0]['port']) == port


@unittest.skipIf(not DEVELOPER, "Without DEVELOPER=1 we snap to FEERATE_FLOOR on testnets")
def test_feerates(node_factory):
    l1 = node_factory.get_node(options={'log-level': 'io'}, start=False)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    l1.start()

    # Query feerates (shouldn't give any!)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 2)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['warning'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 2**32 - 1
    assert feerates['perkw']['min_acceptable'] == 253

    wait_for(lambda: len(l1.rpc.feerates('perkb')['perkb']) == 2)
    feerates = l1.rpc.feerates('perkb')
    assert feerates['warning'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkw' not in feerates
    assert feerates['perkb']['max_acceptable'] == (2**32 - 1)
    assert feerates['perkb']['min_acceptable'] == 253 * 4

    # Now try setting them, one at a time.
    l1.set_feerates((15000, 0, 0), True)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 3)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['urgent'] == 15000
    assert feerates['warning'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    assert feerates['perkw']['min_acceptable'] == 253

    l1.set_feerates((15000, 6250, 0), True)
    wait_for(lambda: len(l1.rpc.feerates('perkb')['perkb']) == 4)
    feerates = l1.rpc.feerates('perkb')
    assert feerates['perkb']['urgent'] == 15000 * 4
    assert feerates['perkb']['normal'] == 25000
    assert feerates['warning'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkw' not in feerates
    assert feerates['perkb']['max_acceptable'] == 15000 * 4 * 10
    assert feerates['perkb']['min_acceptable'] == 253 * 4

    l1.set_feerates((15000, 6250, 5000), True)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 5)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['urgent'] == 15000
    assert feerates['perkw']['normal'] == 25000 // 4
    assert feerates['perkw']['slow'] == 5000
    assert 'warning' not in feerates
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    assert feerates['perkw']['min_acceptable'] == 5000 // 2

    assert len(feerates['onchain_fee_estimates']) == 3
    assert feerates['onchain_fee_estimates']['opening_channel_satoshis'] == feerates['perkw']['normal'] * 702 // 1000
    assert feerates['onchain_fee_estimates']['mutual_close_satoshis'] == feerates['perkw']['normal'] * 673 // 1000
    assert feerates['onchain_fee_estimates']['unilateral_close_satoshis'] == feerates['perkw']['urgent'] * 598 // 1000


def test_logging(node_factory):
    # Since we redirect, node.start() will fail: do manually.
    l1 = node_factory.get_node(options={'log-file': 'logfile'}, may_fail=True, start=False)
    logpath = os.path.join(l1.daemon.lightning_dir, 'logfile')
    logpath_moved = os.path.join(l1.daemon.lightning_dir, 'logfile_moved')

    l1.daemon.rpcproxy.start()
    l1.daemon.opts['bitcoin-rpcport'] = l1.daemon.rpcproxy.rpcport
    TailableProc.start(l1.daemon)
    wait_for(lambda: os.path.exists(logpath))

    shutil.move(logpath, logpath_moved)
    l1.daemon.proc.send_signal(signal.SIGHUP)
    wait_for(lambda: os.path.exists(logpath_moved))
    wait_for(lambda: os.path.exists(logpath))

    log1 = open(logpath_moved).readlines()
    assert log1[-1].endswith("Ending log due to SIGHUP\n")

    def check_new_log():
        log2 = open(logpath).readlines()
        return len(log2) > 0 and log2[0].endswith("Started log due to SIGHUP\n")
    wait_for(check_new_log)


@unittest.skipIf(VALGRIND,
                 "Valgrind sometimes fails assert on injected SEGV")
def test_crashlog(node_factory):
    l1 = node_factory.get_node(may_fail=True, allow_broken_log=True)

    def has_crash_log(n):
        files = os.listdir(n.daemon.lightning_dir)
        crashfiles = [f for f in files if 'crash.log' in f]
        return len(crashfiles) > 0

    assert not has_crash_log(l1)
    l1.daemon.proc.send_signal(signal.SIGSEGV)
    wait_for(lambda: has_crash_log(l1))


def test_configfile_before_chdir(node_factory):
    """Must read config file before chdir into lightning dir"""
    l1 = node_factory.get_node()
    l1.stop()

    olddir = os.getcwd()
    # as lightning_dir ends in /, basename and dirname don't work as expected.
    os.chdir(os.path.dirname(l1.daemon.lightning_dir[:-1]))
    config = os.path.join(os.path.basename(l1.daemon.lightning_dir[:-1]), "test_configfile")
    # Test both an early arg and a normal arg.
    with open(config, 'wb') as f:
        f.write(b'always-use-proxy=true\n')
        f.write(b'proxy=127.0.0.1:100\n')
    l1.daemon.opts['conf'] = config

    # Update executable to point to right place
    l1.daemon.executable = os.path.join(olddir, l1.daemon.executable)
    l1.start()
    assert l1.rpc.listconfigs()['always-use-proxy']
    assert l1.rpc.listconfigs()['proxy'] == '127.0.0.1:100'
    os.chdir(olddir)


def test_json_error(node_factory):
    """Must return valid json even if it quotes our weirdness"""
    l1 = node_factory.get_node()
    with pytest.raises(RpcError, match=r'Given id is not a channel ID or short channel ID'):
        l1.rpc.close({"tx": "020000000001011490f737edd2ea2175a032b58ea7cd426dfc244c339cd044792096da3349b18a0100000000ffffffff021c900300000000001600140e64868e2f752314bc82a154c8c5bf32f3691bb74da00b00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd0247304402202b2e3195a35dc694bbbc58942dc9ba59cc01d71ba55c9b0ad0610ccd6a65633702201a849254453d160205accc00843efb0ad1fe0e186efa6a7cee1fb6a1d36c736a012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf00000000", "txid": "2128c10f0355354479514f4a23eaa880d94e099406d419bbb0d800143accddbb", "channel_id": "bbddcc3a1400d8b0bb19d40694094ed980a8ea234a4f5179443555030fc12820"})

    # Should not corrupt following RPC
    l1.rpc.getinfo()


def test_check_command(node_factory):
    l1 = node_factory.get_node()

    l1.rpc.check(command_to_check='help')
    l1.rpc.check(command_to_check='help', command='check')
    # Note: this just checks form, not whether it's valid!
    l1.rpc.check(command_to_check='help', command='badcommand')
    with pytest.raises(RpcError, match=r'Unknown command'):
        l1.rpc.check(command_to_check='badcommand')
    with pytest.raises(RpcError, match=r'unknown parameter'):
        l1.rpc.check(command_to_check='help', badarg='x')

    # Ensures we have compulsory parameters.
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.check(command_to_check='connect')
    # Even with optional parameters.
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.check(command_to_check='connect', host='x', port=77)
    # Makes sure parameter types are correct.
    with pytest.raises(RpcError, match=r'should be an integer'):
        l1.rpc.check(command_to_check='connect', id='test', host='x', port="abcd")

    # FIXME: python wrapper doesn't let us test array params.
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(l1.rpc.socket_path)

    sock.sendall(b'{"id":1, "jsonrpc":"2.0","method":"check","params":["help"]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['id'] == 1
    assert 'result' in obj
    assert 'error' not in obj

    sock.sendall(b'{"id":1, "jsonrpc":"2.0","method":"check","params":["help", "check"]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['id'] == 1
    assert 'result' in obj
    assert 'error' not in obj

    sock.sendall(b'{"id":1, "jsonrpc":"2.0","method":"check","params":["help", "a", "b"]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['id'] == 1
    assert 'result' not in obj
    assert 'error' in obj

    sock.sendall(b'{"id":1, "jsonrpc":"2.0","method":"check","params":["badcommand"]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['id'] == 1
    assert 'result' not in obj
    assert 'error' in obj

    sock.sendall(b'{"id":1, "jsonrpc":"2.0","method":"check","params":["connect"]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['id'] == 1
    assert 'result' not in obj
    assert 'error' in obj

    sock.sendall(b'{"id":1, "jsonrpc":"2.0","method":"check","params":["connect", "test", "x", "abcd"]}')
    obj, _ = l1.rpc._readobj(sock, b'')
    assert obj['id'] == 1
    assert 'result' not in obj
    assert 'error' in obj

    sock.close()


@unittest.skipIf(not DEVELOPER, "need log_all_io")
def test_bad_onion(node_factory, bitcoind):
    """Test that we get a reasonable error from sendpay when an onion is bad"""
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True,
                                             opts={'log_all_io': True})

    h = l4.rpc.invoice(123000, 'test_bad_onion', 'description')['payment_hash']
    route = l1.rpc.getroute(l4.info['id'], 123000, 1)['route']

    assert len(route) == 3

    mangled_nodeid = '0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6518'

    # Replace id with a different pubkey, so onion encoded badly at third hop.
    route[2]['id'] = mangled_nodeid
    l1.rpc.sendpay(route, h)
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(h)

    # FIXME: #define PAY_TRY_OTHER_ROUTE		204
    PAY_TRY_OTHER_ROUTE = 204
    assert err.value.error['code'] == PAY_TRY_OTHER_ROUTE
    # FIXME: WIRE_INVALID_ONION_HMAC = BADONION|PERM|5
    WIRE_INVALID_ONION_HMAC = 0x8000 | 0x4000 | 5
    assert err.value.error['data']['failcode'] == WIRE_INVALID_ONION_HMAC
    assert err.value.error['data']['erring_node'] == mangled_nodeid
    assert err.value.error['data']['erring_channel'] == route[2]['channel']

    # We should see a WIRE_UPDATE_FAIL_MALFORMED_HTLC from l4.
    line = l4.daemon.is_in_log(r'\[OUT\] 0087')
    # 008739d3149a5c37e95f9dae718ce46efc60248e110e10117d384870a6762e8e33030000000000000000d7fc52f6c32773aabca55628fe616058aecc44a384e0abfa85c0c48b449dd38dc005
    # type<--------------channelid---------------------------------------><--htlc-id-----><--------------------------------------------- sha_of_onion --->code
    sha = re.search(r' 0087.{64}.{16}(.{64})', line).group(1)

    # Should see same sha in onionreply
    line = l1.daemon.is_in_log(r'failcode .* from onionreply .*')
    assert re.search(r'onionreply .*{}'.format(sha), line)

    # Replace id with a different pubkey, so onion encoded badly at second hop.
    route[1]['id'] = mangled_nodeid
    l1.rpc.sendpay(route, h)
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(h)

    # FIXME: #define PAY_TRY_OTHER_ROUTE		204
    PAY_TRY_OTHER_ROUTE = 204
    assert err.value.error['code'] == PAY_TRY_OTHER_ROUTE
    assert err.value.error['data']['failcode'] == WIRE_INVALID_ONION_HMAC
    assert err.value.error['data']['erring_node'] == mangled_nodeid
    assert err.value.error['data']['erring_channel'] == route[1]['channel']


def test_newaddr(node_factory, chainparams):
    l1 = node_factory.get_node()
    p2sh = l1.rpc.newaddr('p2sh-segwit')
    assert 'bech32' not in p2sh
    assert p2sh['p2sh-segwit'].startswith(chainparams['p2sh_prefix'])
    bech32 = l1.rpc.newaddr('bech32')
    assert 'p2sh-segwit' not in bech32
    assert bech32['bech32'].startswith(chainparams['bip173_prefix'])
    both = l1.rpc.newaddr('all')
    assert both['p2sh-segwit'].startswith(chainparams['p2sh_prefix'])
    assert both['bech32'].startswith(chainparams['bip173_prefix'])


def test_newaddr_deprecated(node_factory, chainparams):
    l1 = node_factory.get_node(options={'allow-deprecated-apis': True})
    p2sh = l1.rpc.newaddr('p2sh-segwit')
    assert p2sh['address'].startswith(chainparams['p2sh_prefix'])
    bech32 = l1.rpc.newaddr('bech32')
    assert bech32['address'].startswith(chainparams['bip173_prefix'])


def test_bitcoind_fail_first(node_factory, bitcoind, executor):
    """Make sure we handle spurious bitcoin-cli failures during startup

    See [#2687](https://github.com/ElementsProject/lightning/issues/2687) for
    details

    """
    # Do not start the lightning node since we need to instrument bitcoind
    # first.
    l1 = node_factory.get_node(start=False)

    # Instrument bitcoind to fail some queries first.
    def mock_fail(*args):
        raise ValueError()

    l1.daemon.rpcproxy.mock_rpc('getblock', mock_fail)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', mock_fail)

    f = executor.submit(l1.start)

    wait_for(lambda: l1.daemon.running)
    # Make sure it fails on the first `getblock` call (need to use `is_in_log`
    # since the `wait_for_log` in `start` sets the offset)
    wait_for(lambda: l1.daemon.is_in_log(
        r'getblock [a-z0-9]* false exited with status 1'))
    wait_for(lambda: l1.daemon.is_in_log(
        r'estimatesmartfee 2 CONSERVATIVE exited with status 1'))

    # Now unset the mock, so calls go through again
    l1.daemon.rpcproxy.mock_rpc('getblock', None)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', None)

    f.result()


@unittest.skipIf(not DEVELOPER, "needs --dev-force-bip32-seed")
@unittest.skipIf(TEST_NETWORK != 'regtest', "Addresses are network specific")
def test_dev_force_bip32_seed(node_factory):
    l1 = node_factory.get_node(options={'dev-force-bip32-seed': '0000000000000000000000000000000000000000000000000000000000000001'})
    # First is m/0/0/1 ..
    bech32 = l1.rpc.newaddr('bech32')['bech32']
    assert bech32 == "bcrt1qsdzqt93xsyewdjvagndw9523m27e52er5ca7hm"
    bech32 = l1.rpc.newaddr('bech32')['bech32']
    assert bech32 == "bcrt1qlkt93775wmf33uacykc49v2j4tayn0yj25msjn"
    bech32 = l1.rpc.newaddr('bech32')['bech32']
    assert bech32 == "bcrt1q2ng546gs0ylfxrvwx0fauzcvhuz655en4kwe2c"
    bech32 = l1.rpc.newaddr('bech32')['bech32']
    assert bech32 == "bcrt1qrdpwrlrmrnvn535l5eldt64lxm8r2nwkv0ruxq"
    bech32 = l1.rpc.newaddr('bech32')['bech32']
    assert bech32 == "bcrt1q622lwmdzxxterumd746eu3d3t40pq53p62zhlz"


@unittest.skipIf(not DEVELOPER, "needs dev command")
def test_dev_demux(node_factory):
    l1 = node_factory.get_node(may_fail=True, allow_broken_log=True)

    # Check should work.
    l1.rpc.check(command_to_check='dev', subcommand='crash')
    l1.rpc.check(command_to_check='dev', subcommand='slowcmd', msec=1000)
    l1.rpc.check(command_to_check='dev', subcommand='rhash', secret='00' * 32)
    with pytest.raises(RpcError, match=r'Unknown subcommand'):
        l1.rpc.check(command_to_check='dev', subcommand='foobar')
    with pytest.raises(RpcError, match=r'unknown parameter'):
        l1.rpc.check(command_to_check='dev', subcommand='crash', unk=1)
    with pytest.raises(RpcError, match=r"'msec' should be an integer"):
        l1.rpc.check(command_to_check='dev', subcommand='slowcmd', msec='aaa')
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.check(command_to_check='dev', subcommand='rhash')
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.check(command_to_check='dev')

    # Non-check failures should fail, in both object and array form.
    with pytest.raises(RpcError, match=r'Unknown subcommand'):
        l1.rpc.call('dev', {'subcommand': 'foobar'})
    with pytest.raises(RpcError, match=r'Unknown subcommand'):
        l1.rpc.call('dev', ['foobar'])
    with pytest.raises(RpcError, match=r'unknown parameter'):
        l1.rpc.call('dev', {'subcommand': 'crash', 'unk': 1})
    with pytest.raises(RpcError, match=r'too many parameters'):
        l1.rpc.call('dev', ['crash', 1])
    with pytest.raises(RpcError, match=r"'msec' should be an integer"):
        l1.rpc.call('dev', {'subcommand': 'slowcmd', 'msec': 'aaa'})
    with pytest.raises(RpcError, match=r"'msec' should be an integer"):
        l1.rpc.call('dev', ['slowcmd', 'aaa'])
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.call('dev', {'subcommand': 'rhash'})
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.call('dev', ['rhash'])
    with pytest.raises(RpcError, match=r'missing required parameter'):
        l1.rpc.call('dev')

    # Help should list them all.
    assert 'subcommand=crash|rhash|slowcmd' in l1.rpc.help('dev')['help'][0]['command']

    # These work
    assert l1.rpc.call('dev', ['slowcmd', '7'])['msec'] == 7
    assert l1.rpc.call('dev', {'subcommand': 'slowcmd', 'msec': '7'})['msec'] == 7
    assert l1.rpc.call('dev', {'subcommand': 'rhash', 'secret': '00' * 32})['rhash'] == '66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925'

    with pytest.raises(RpcError):
        l1.rpc.call('dev', {'subcommand': 'crash'})


def test_list_features_only(node_factory):
    features = subprocess.check_output(['lightningd/lightningd',
                                        '--list-features-only']).decode('utf-8').splitlines()
    expected = ['option_data_loss_protect/odd',
                'option_upfront_shutdown_script/odd',
                'option_gossip_queries/odd',
                'option_gossip_queries_ex/odd',
                'option_static_remotekey/odd']
    assert features == expected
