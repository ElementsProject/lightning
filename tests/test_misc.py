from bitcoin.rpc import RawProxy
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import LightningNode, TEST_NETWORK
from flaky import flaky  # noqa: F401
from pyln.client import RpcError
from threading import Event
from pyln.testing.utils import (
    DEVELOPER, TIMEOUT, VALGRIND, DEPRECATED_APIS, sync_blockheight, only_one,
    wait_for, TailableProc, env
)
from utils import (
    check_coin_moves, account_balance
)
from ephemeral_port_reserve import reserve
from utils import EXPERIMENTAL_FEATURES

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
    # Note:
    # private keys:
    # l1: 41bfd2660762506c9933ade59f1debf7e6495b10c14a92dbcd2d623da2507d3d01,
    # l2: c4a813f81ffdca1da6864db81795ad2d320add274452cafa1fb2ac2d07d062bd01
    # l3: dae24b3853e1443a176daba5544ee04f7db33ebe38e70bdfdb1da34e89512c1001
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
    os.unlink(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3"))
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
    l1.daemon.wait_for_logs(['Unable to estimate .* fee',
                             'getblockhash .* exited with status 1'])

    # And they should retry!
    l1.daemon.wait_for_logs(['Unable to estimate .* fee',
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

    l1.daemon.wait_for_log('Bitcoin backend now synced')
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

    # Make sure it's connected to l2 (otherwise we get TEMPORARY_CHANNEL_FAILURE)
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])

    # Payments will fail.  FIXME: More informative msg?
    with pytest.raises(RpcError, match=r'TEMPORARY_NODE_FAILURE'):
        l1.pay(l2, 1000)

    # Can't fund a new channel.
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    with pytest.raises(RpcError, match=r'304'):
        l1.rpc.fundchannel_start(l3.info['id'], '10000sat')

    # Attempting to fund an extremely large transaction should fail
    # with a 'unsynced' error
    with pytest.raises(RpcError, match=r'304'):
        l1.rpc.txprepare([{l1.rpc.newaddr()['bech32']: '200000000sat'}])

    # This will work, but will be delayed until synced.
    fut = executor.submit(l2.pay, l1, 1000)
    l1.daemon.wait_for_log("Deferring incoming commit until we sync")

    # Release the mock.
    mock_release.set()
    fut.result()

    assert 'warning_lightningd_sync' not in l1.rpc.getinfo()

    # Now we get insufficient funds error
    with pytest.raises(RpcError, match=r'301'):
        l1.rpc.txprepare([{l1.rpc.newaddr()['bech32']: '200000000sat'}])

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
                               feerates=(7500, 7500, 7500, 7500))
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


@unittest.skipIf(not DEVELOPER, "needs to deactivate shadow routing")
def test_htlc_out_timeout(node_factory, bitcoind, executor):
    """Test that we drop onchain if the peer doesn't time out HTLC"""

    # HTLC 1->2, 1 fails after it's irrevocably committed, can't reconnect
    disconnects = ['@WIRE_REVOKE_AND_ACK']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chanid = l1.fund_channel(l2, 10**6)

    # Wait for route propagation.
    l1.wait_channel_active(chanid)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_htlc_out_timeout', 'desc')['bolt11']
    assert only_one(l2.rpc.listinvoices('test_htlc_out_timeout')['invoices'])['status'] == 'unpaid'

    executor.submit(l1.rpc.dev_pay, inv, use_shadow=False)

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


@unittest.skipIf(not DEVELOPER, "needs to deactivate shadow routing")
def test_htlc_in_timeout(node_factory, bitcoind, executor):
    """Test that we drop onchain if the peer doesn't accept fulfilled HTLC"""

    # HTLC 1->2, 1 fails after 2 has sent committed the fulfill
    disconnects = ['-WIRE_REVOKE_AND_ACK*2']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chanid = l1.fund_channel(l2, 10**6)

    l1.wait_channel_active(chanid)
    sync_blockheight(bitcoind, [l1, l2])

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_htlc_in_timeout', 'desc')['bolt11']
    assert only_one(l2.rpc.listinvoices('test_htlc_in_timeout')['invoices'])['status'] == 'unpaid'

    executor.submit(l1.rpc.dev_pay, inv, use_shadow=False)

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


@unittest.skipIf(not TEST_NETWORK == 'regtest', 'must be on bitcoin network')
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


def test_withdraw_misc(node_factory, bitcoind, chainparams):
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True,
                               options={'plugin': coin_mvt_plugin},
                               feerates=(7500, 7500, 7500, 7500))
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

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    assert account_balance(l1, 'wallet') == 0

    wallet_moves = [
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 2000000000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1993745000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 2000000000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 6255000, 'tag': 'chain_fees'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1993745000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 2000000000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 6255000, 'tag': 'chain_fees'},
        {'type': 'chain_mvt', 'credit': 1993745000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 1993745000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1993745000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 2000000000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 6255000, 'tag': 'chain_fees'},
        {'type': 'chain_mvt', 'credit': 1993745000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1993385000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 2000000000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 6615000, 'tag': 'chain_fees'},
        {'type': 'chain_mvt', 'credit': 1993385000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 11961135000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 13485000, 'tag': 'chain_fees'},
        {'type': 'chain_mvt', 'credit': 11961135000, 'debit': 0, 'tag': 'deposit'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 0, 'tag': 'spend_track'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 11957490000, 'tag': 'withdrawal'},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 3645000, 'tag': 'chain_fees'},
    ]
    check_coin_moves(l1, 'wallet', wallet_moves, chainparams)


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

    fut = executor.submit(l1.pay, l2, 200000000)

    # WIRE_UPDATE_ADD_HTLC = 128 = 0x0080
    l1.daemon.wait_for_log(r'channeld.*: \[OUT\] 0080')
    # WIRE_UPDATE_FULFILL_HTLC = 130 = 0x0082
    l1.daemon.wait_for_log(r'channeld.*: \[IN\] 0082')
    fut.result(10)

    # Send it sigusr1: should turn off logging.
    subprocess.run(['kill', '-USR1', pid1])

    l1.pay(l2, 200000000)

    assert not l1.daemon.is_in_log(r'channeld.*: \[OUT\] 0080',
                                   start=l1.daemon.logsearch_start)
    assert not l1.daemon.is_in_log(r'channeld.*: \[IN\] 0082',
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
    l1.daemon.opts['bind-addr'] = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "sock")
    l1.start()

    l2 = node_factory.get_node()
    l2.rpc.connect(l1.info['id'], l1.daemon.opts['bind-addr'])

    # 'addr' with local socket works too.
    l1.stop()
    del l1.daemon.opts['bind-addr']
    l1.daemon.opts['addr'] = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "sock")
    # start expects a port, so we open-code here.
    l1.daemon.start()

    l2 = node_factory.get_node()
    l2.rpc.connect(l1.info['id'], l1.daemon.opts['addr'])


@unittest.skipIf(DEPRECATED_APIS, "Tests the --allow-deprecated-apis config")
def test_listconfigs(node_factory, bitcoind, chainparams):
    # Make extremely long entry, check it works
    l1 = node_factory.get_node(options={'log-prefix': 'lightning1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'})

    configs = l1.rpc.listconfigs()
    # See utils.py
    assert configs['allow-deprecated-apis'] is False
    assert configs['network'] == chainparams['name']
    assert configs['ignore-fee-limits'] is False
    assert configs['ignore-fee-limits'] is False
    assert configs['log-prefix'] == 'lightning1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...'

    # Test one at a time.
    for c in configs.keys():
        if c.startswith('#') or c.startswith('plugins'):
            continue
        oneconfig = l1.rpc.listconfigs(config=c)
        assert(oneconfig[c] == configs[c])


def test_listconfigs_plugins(node_factory, bitcoind, chainparams):
    l1 = node_factory.get_node()

    # assert that we have pay plugin and that plugins have a name and path
    configs = l1.rpc.listconfigs()
    assert configs['plugins']
    assert len([p for p in configs['plugins'] if p['name'] == "pay"]) == 1
    for p in configs['plugins']:
        assert p['name'] and len(p['name']) > 0
        assert p['path'] and len(p['path']) > 0
        assert os.path.isfile(p['path']) and os.access(p['path'], os.X_OK)


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
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    # Test some known output.
    assert 'help [command]\n    List available commands, or give verbose help on one {command}' in out

    # Test JSON output.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert j['help'][0]['command'] is not None
    assert j['help'][0]['description'] is not None

    # Test keyword input (autodetect)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help', 'command=help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test keyword input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-k',
                                   'help', 'command=help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test ordered input (autodetect)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test ordered input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
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
                                       '--network={}'.format(TEST_NETWORK),
                                       '--lightning-dir={}'
                                       .format(l1.daemon.lightning_dir),
                                       '-J', '-o',
                                       'sendpay']).decode('utf-8')
    except Exception:
        pass

    # Test it escapes JSON completely in both method and params.
    # cli turns " into \", reply turns that into \\\".
    out = subprocess.run(['cli/lightning-cli',
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'x"[]{}'],
                         stdout=subprocess.PIPE)
    assert 'Unknown command \'x\\\\\\"[]{}\'' in out.stdout.decode('utf-8')

    subprocess.check_output(['cli/lightning-cli',
                             '--network={}'.format(TEST_NETWORK),
                             '--lightning-dir={}'
                             .format(l1.daemon.lightning_dir),
                             'invoice', '123000', 'l"[]{}', 'd"[]{}']).decode('utf-8')
    # Check label is correct, and also that cli's keyword parsing works.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
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

    # Make sure we omit top-levels and don't include format hint, when -H forced
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-H',
                                   'help']).decode('utf-8')
    lines = out.splitlines()
    assert [l for l in lines if l.startswith('help=')] == []
    assert [l for l in lines if l.startswith('format-hint=')] == []

    # Flat format is great for grep.  LONG LIVE UNIX!
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-F',
                                   'help']).decode('utf-8')
    lines = out.splitlines()
    # Everything is a help[XX]= line, except format-hint.
    assert [l for l in lines if not re.search(r'^help\[[0-9]*\].', l)] == ['format-hint=simple']


def test_daemon_option(node_factory):
    """
    Make sure --daemon at least vaguely works!
    """
    # Lazy way to set up command line and env, plus do VALGRIND checks
    l1 = node_factory.get_node()
    l1.stop()

    os.unlink(l1.rpc.socket_path)
    logfname = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "log-daemon")
    subprocess.run(l1.daemon.cmd_line + ['--daemon', '--log-file={}'.format(logfname)], env=l1.daemon.env,
                   check=True)

    # Test some known output (wait for rpc to be ready)
    wait_for(lambda: os.path.exists(l1.rpc.socket_path))
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    assert 'help [command]\n    List available commands, or give verbose help on one {command}' in out

    subprocess.run(['cli/lightning-cli',
                    '--network={}'.format(TEST_NETWORK),
                    '--lightning-dir={}'.format(l1.daemon.lightning_dir),
                    'stop'], check=True)

    # It should not complain that subdaemons aren't children.
    with open(logfname, 'r') as f:
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

    # Reorg changes short_channel_id 103x1x0 to 104x1x0, l1 sees it, restarts channeld
    bitcoind.simple_reorg(103, 1)                   # heights 103 - 108
    # But now it's height 104, we need another block to make it announcable.
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(r'Peer transient failure .* short_channel_id changed to 104x1x0 \(was 103x1x0\)')

    wait_for(lambda: only_one(l2.rpc.listpeers()['peers'][0]['channels'])['status'] == [
        'CHANNELD_NORMAL:Reconnected, and reestablished.',
        'CHANNELD_NORMAL:Funding transaction locked. They need our announcement signatures.'])

    # Unblinding l2 brings it back in sync, restarts channeld and sends its announce sig
    l2.daemon.rpcproxy.mock_rpc('getblockhash', None)

    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels('103x1x0')['channels']] == [False, False])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels('104x1x0')['channels']] == [True, True])

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

    # Restarting with a future absolute blockheight should *fail* if we
    # can't find that height
    l1.daemon.opts['rescan'] = -500000
    l1.stop()
    bitcoind.generate_block(4)
    with pytest.raises(ValueError):
        l1.start()

    # Restarting with future absolute blockheight is fine if we can find it.
    l1.daemon.opts['rescan'] = -105
    oldneedle = l1.daemon.logsearch_start
    l1.start()
    # This could occur before pubkey msg, so move search needle back.
    l1.daemon.logsearch_start = oldneedle
    l1.daemon.wait_for_log(r'Adding block 105')
    assert not l1.daemon.is_in_log(r'Adding block 102')


def test_bitcoind_goes_backwards(node_factory, bitcoind):
    """Check that we refuse to acknowledge bitcoind giving a shorter chain without explicit rescan"""
    l1 = node_factory.get_node(may_fail=True, allow_broken_log=True)

    bitcoind.generate_block(10)
    sync_blockheight(bitcoind, [l1])
    l1.stop()

    # Now shrink chain (invalidateblock leaves 'headers' field until restart)
    bitcoind.rpc.invalidateblock(bitcoind.rpc.getblockhash(105))
    # Restart without killing proxies
    bitcoind.rpc.stop()
    TailableProc.stop(bitcoind)
    bitcoind.start()

    # Will simply refuse to start.
    with pytest.raises(ValueError):
        l1.start()

    # Nor will it start with if we ask for a reindex of fewer blocks.
    l1.daemon.opts['rescan'] = 3

    with pytest.raises(ValueError):
        l1.start()

    # This will force it, however.
    l1.daemon.opts['rescan'] = -100
    l1.start()

    # Now mess with bitcoind at runtime.
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1])

    l1.daemon.wait_for_log('Adding block 110')

    bitcoind.rpc.invalidateblock(bitcoind.rpc.getblockhash(105))
    bitcoind.rpc.stop()
    TailableProc.stop(bitcoind)
    bitcoind.start()
    bitcoind.generate_block(5)

    # It will ignore bitcoind and keep asking for block 110.
    time.sleep(5)
    assert l1.rpc.getinfo()['blockheight'] == 110
    assert not l1.daemon.is_in_log('Adding block 109',
                                   start=l1.daemon.logsearch_start)

    # Get past that, and it will suddenly read new blocks
    bitcoind.generate_block(2)
    l1.daemon.wait_for_log('Adding block 109')
    l1.daemon.wait_for_log('Adding block 110')
    l1.daemon.wait_for_log('Adding block 111')


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
        'Peer permanent failure in CHANNELD_NORMAL: channeld: sent '
        'ERROR Bad peer_add_htlc: CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED'
    )


@unittest.skipIf(not DEVELOPER, "needs dev_disconnect")
def test_htlc_send_timeout(node_factory, bitcoind, compat):
    """Test that we don't commit an HTLC to an unreachable node."""
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(
        options={'log-level': 'io'},
        feerates=(7500, 7500, 7500, 7500)
    )

    # Blackhole it after it sends HTLC_ADD to l3.
    l2 = node_factory.get_node(disconnect=['0WIRE_UPDATE_ADD_HTLC'],
                               options={'log-level': 'io'},
                               feerates=(7500, 7500, 7500, 7500))
    l3 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    l1.fund_channel(l2, 10**6)
    chanid2 = l2.fund_channel(l3, 10**6)

    # Make sure channels get announced.
    bitcoind.generate_block(5)

    # Make sure we have 30 seconds without any incoming traffic from l3 to l2
    # so it tries to ping before sending WIRE_COMMITMENT_SIGNED.
    timedout = False
    while not timedout:
        try:
            l2.daemon.wait_for_log(r'channeld-chan#[0-9]*: \[IN\] ', timeout=30)
        except TimeoutError:
            timedout = True

    inv = l3.rpc.invoice(123000, 'test_htlc_send_timeout', 'description')
    with pytest.raises(RpcError, match=r'Ran out of routes to try after [0-9]+ attempt[s]?') as excinfo:
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
    l2.daemon.wait_for_log(r'{}-.*channeld.*: \[OUT\] 0012'.format(l3.info['id']))
    assert not l2.daemon.is_in_log(r'{}-.*channeld.*: \[IN\] 0013'.format(l3.info['id']))
    assert not l2.daemon.is_in_log(r'{}-.*channeld.*: \[OUT\] 0084'.format(l3.info['id']))
    # L2 killed the channel with l3 because it was too slow.
    l2.daemon.wait_for_log('{}-.*channeld-.*Adding HTLC too slow: killing connection'.format(l3.info['id']))


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


@unittest.skipIf(
    not DEVELOPER or DEPRECATED_APIS, "Without DEVELOPER=1 we snap to "
    "FEERATE_FLOOR on testnets, and we test the new API."
)
def test_feerates(node_factory):
    l1 = node_factory.get_node(options={'log-level': 'io'}, start=False)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    l1.start()

    # All estimation types
    types = ["opening", "mutual_close", "unilateral_close", "delayed_to_us",
             "htlc_resolution", "penalty"]

    # Query feerates (shouldn't give any!)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 2)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 2**32 - 1
    assert feerates['perkw']['min_acceptable'] == 253
    for t in types:
        assert t not in feerates['perkw']

    wait_for(lambda: len(l1.rpc.feerates('perkb')['perkb']) == 2)
    feerates = l1.rpc.feerates('perkb')
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkw' not in feerates
    assert feerates['perkb']['max_acceptable'] == (2**32 - 1)
    assert feerates['perkb']['min_acceptable'] == 253 * 4
    for t in types:
        assert t not in feerates['perkb']

    # Now try setting them, one at a time.
    # Set CONSERVATIVE/2 feerate, for max and unilateral_close
    l1.set_feerates((15000, 0, 0, 0), True)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 3)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['unilateral_close'] == 15000
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    assert feerates['perkw']['min_acceptable'] == 253

    # Set CONSERVATIVE/3 feerate, for htlc_resolution and penalty
    l1.set_feerates((15000, 11000, 0, 0), True)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 5)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['unilateral_close'] == 15000
    assert feerates['perkw']['htlc_resolution'] == 11000
    assert feerates['perkw']['penalty'] == 11000
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    assert feerates['perkw']['min_acceptable'] == 253

    # Set ECONOMICAL/4 feerate, for all but min
    l1.set_feerates((15000, 11000, 6250, 0), True)
    wait_for(lambda: len(l1.rpc.feerates('perkb')['perkb']) == len(types) + 2)
    feerates = l1.rpc.feerates('perkb')
    assert feerates['perkb']['unilateral_close'] == 15000 * 4
    assert feerates['perkb']['htlc_resolution'] == 11000 * 4
    assert feerates['perkb']['penalty'] == 11000 * 4
    for t in types:
        if t not in ("unilateral_close", "htlc_resolution", "penalty"):
            assert feerates['perkb'][t] == 25000
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkw' not in feerates
    assert feerates['perkb']['max_acceptable'] == 15000 * 4 * 10
    assert feerates['perkb']['min_acceptable'] == 253 * 4

    # Set ECONOMICAL/100 feerate for min
    l1.set_feerates((15000, 11000, 6250, 5000), True)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) >= len(types) + 2)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['unilateral_close'] == 15000
    assert feerates['perkw']['htlc_resolution'] == 11000
    assert feerates['perkw']['penalty'] == 11000
    for t in types:
        if t not in ("unilateral_close", "htlc_resolution", "penalty"):
            assert feerates['perkw'][t] == 25000 // 4
    assert 'warning' not in feerates
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    assert feerates['perkw']['min_acceptable'] == 5000 // 2

    assert len(feerates['onchain_fee_estimates']) == 5
    assert feerates['onchain_fee_estimates']['opening_channel_satoshis'] == feerates['perkw']['opening'] * 702 // 1000
    assert feerates['onchain_fee_estimates']['mutual_close_satoshis'] == feerates['perkw']['mutual_close'] * 673 // 1000
    assert feerates['onchain_fee_estimates']['unilateral_close_satoshis'] == feerates['perkw']['unilateral_close'] * 598 // 1000
    htlc_feerate = feerates["perkw"]["htlc_resolution"]
    htlc_timeout_cost = feerates["onchain_fee_estimates"]["htlc_timeout_satoshis"]
    htlc_success_cost = feerates["onchain_fee_estimates"]["htlc_success_satoshis"]
    assert htlc_timeout_cost == htlc_feerate * 663 // 1000
    assert htlc_success_cost == htlc_feerate * 703 // 1000


def test_logging(node_factory):
    # Since we redirect, node.start() will fail: do manually.
    l1 = node_factory.get_node(options={'log-file': 'logfile'}, start=False)
    logpath = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'logfile')
    logpath_moved = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'logfile_moved')
    l1.daemon.start(wait_for_initialized=False)

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
        files = os.listdir(os.path.join(n.daemon.lightning_dir, TEST_NETWORK))
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
    config = os.path.join(os.path.basename(l1.daemon.lightning_dir[:-1]), TEST_NETWORK, "test_configfile")
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


@unittest.skipIf(not DEVELOPER, "FIXME: without DEVELOPER=1 we timeout")
def test_bad_onion(node_factory, bitcoind):
    """Test that we get a reasonable error from sendpay when an onion is bad"""
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True,
                                             opts={'log-level': 'io'})

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


@unittest.skipIf(not DEVELOPER, "Needs DEVELOPER=1 to force onion fail")
def test_bad_onion_immediate_peer(node_factory, bitcoind):
    """Test that we handle the malformed msg when we're the origin"""
    l1, l2 = node_factory.line_graph(2, opts={'dev-fail-process-onionpacket': None})

    h = l2.rpc.invoice(123000, 'test_bad_onion_immediate_peer', 'description')['payment_hash']
    route = l1.rpc.getroute(l2.info['id'], 123000, 1)['route']
    assert len(route) == 1

    l1.rpc.sendpay(route, h)
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(h)

    # FIXME: #define PAY_UNPARSEABLE_ONION		202
    PAY_UNPARSEABLE_ONION = 202
    assert err.value.error['code'] == PAY_UNPARSEABLE_ONION
    # FIXME: WIRE_INVALID_ONION_HMAC = BADONION|PERM|5
    WIRE_INVALID_ONION_HMAC = 0x8000 | 0x4000 | 5
    assert err.value.error['data']['failcode'] == WIRE_INVALID_ONION_HMAC


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

    l1.daemon.rpcproxy.mock_rpc('getblockhash', mock_fail)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', mock_fail)

    f = executor.submit(l1.start)

    wait_for(lambda: l1.daemon.running)
    # Make sure it fails on the first `getblock` call (need to use `is_in_log`
    # since the `wait_for_log` in `start` sets the offset)
    wait_for(lambda: l1.daemon.is_in_log(
        r'getblockhash [a-z0-9]* exited with status 1'))
    wait_for(lambda: l1.daemon.is_in_log(
        r'Unable to estimate opening fees'))

    # Now unset the mock, so calls go through again
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)
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
                'option_var_onion_optin/odd',
                'option_gossip_queries_ex/odd',
                'option_static_remotekey/odd',
                'option_payment_secret/odd',
                'option_basic_mpp/odd',
                ]
    if EXPERIMENTAL_FEATURES:
        expected += ['option_unknown_102/odd']
    assert features == expected


def test_relative_config_dir(node_factory):
    l1 = node_factory.get_node(start=False)
    initial_dir = os.getcwd()
    lndir = l1.daemon.opts.get("lightning-dir")[:-1]
    *root_dir, l1.daemon.opts["lightning-dir"] = lndir.split('/')
    os.chdir('/'.join(root_dir))
    l1.daemon.executable = os.path.join(initial_dir, l1.daemon.executable)
    l1.start()
    assert os.path.isabs(l1.rpc.listconfigs()["lightning-dir"])
    l1.stop()
    os.chdir(initial_dir)


def test_signmessage(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    corpus = [[None,
               "this is a test!",
               l1.rpc.signmessage("this is a test!")['zbase'],
               l1.info['id']]]

    # Other contributions from LND users!
    corpus += [
        ['@bitconner',
         "is this compatible?",
         'rbgfioj114mh48d8egqx8o9qxqw4fmhe8jbeeabdioxnjk8z3t1ma1hu1fiswpakgucwwzwo6ofycffbsqusqdimugbh41n1g698hr9t',
         '02b80cabdf82638aac86948e4c06e82064f547768dcef977677b9ea931ea75bab5'],
        ['@duck1123',
         'hi',
         'rnrphcjswusbacjnmmmrynh9pqip7sy5cx695h6mfu64iac6qmcmsd8xnsyczwmpqp9shqkth3h4jmkgyqu5z47jfn1q7gpxtaqpx4xg',
         '02de60d194e1ca5947b59fe8e2efd6aadeabfb67f2e89e13ae1a799c1e08e4a43b'],
        ['@jochemin',
         'hi',
         'ry8bbsopmduhxy3dr5d9ekfeabdpimfx95kagdem7914wtca79jwamtbw4rxh69hg7n6x9ty8cqk33knbxaqftgxsfsaeprxkn1k48p3',
         '022b8ece90ee891cbcdac0c1cc6af46b73c47212d8defbce80265ac81a6b794931'],
    ]

    for c in corpus:
        print("Shout out to {}".format(c[0]))
        assert subprocess.check_output(['devtools/lightning-checkmessage',
                                        c[1], c[2]]).decode('utf-8') == "Signature claims to be from key {}\n".format(c[3])

        subprocess.run(['devtools/lightning-checkmessage', c[1], c[2], c[3]], check=True)

        with pytest.raises(subprocess.CalledProcessError):
            subprocess.run(['devtools/lightning-checkmessage',
                            c[1] + "modified", c[2], c[3]], check=True)

        assert l1.rpc.checkmessage(c[1], c[2], c[3])['verified']
        assert not l1.rpc.checkmessage(c[1] + "modified", c[2], c[3])['verified']
        checknokey = l1.rpc.checkmessage(c[1], c[2])
        # Of course, we know our own pubkey
        if c[3] == l1.info['id']:
            assert checknokey['verified']
        else:
            assert not checknokey['verified']
        assert checknokey['pubkey'] == c[3]

    # l2 knows about l1, so it can validate it.
    zm = l1.rpc.signmessage(message="message for you")['zbase']
    checknokey = l2.rpc.checkmessage(message="message for you", zbase=zm)
    assert checknokey['pubkey'] == l1.info['id']
    assert checknokey['verified']


def test_include(node_factory):
    l1 = node_factory.get_node(start=False)

    subdir = os.path.join(l1.daemon.opts.get("lightning-dir"), "subdir")
    os.makedirs(subdir)
    with open(os.path.join(subdir, "conf1"), 'w') as f:
        f.write('include conf2')
    with open(os.path.join(subdir, "conf2"), 'w') as f:
        f.write('alias=conf2')
    l1.daemon.opts['conf'] = os.path.join(subdir, "conf1")
    l1.start()

    assert l1.rpc.listconfigs('alias')['alias'] == 'conf2'


def test_config_in_subdir(node_factory, chainparams):
    l1 = node_factory.get_node(start=False)
    network = chainparams['name']

    subdir = os.path.join(l1.daemon.opts.get("lightning-dir"), network)
    with open(os.path.join(subdir, "config"), 'w') as f:
        f.write('alias=test_config_in_subdir')
    l1.start()

    assert l1.rpc.listconfigs('alias')['alias'] == 'test_config_in_subdir'

    l1.stop()

    # conf is not allowed in any config file.
    with open(os.path.join(l1.daemon.opts.get("lightning-dir"), "config"), 'w') as f:
        f.write('conf={}/conf'.format(network))

    out = subprocess.run(['lightningd/lightningd',
                          '--lightning-dir={}'.format(l1.daemon.opts.get("lightning-dir"))],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert out.returncode == 1
    assert "conf: not permitted in configuration files" in out.stderr.decode('utf-8')

    # network is allowed in root config file.
    with open(os.path.join(l1.daemon.opts.get("lightning-dir"), "config"), 'w') as f:
        f.write('network={}'.format(network))

    l1.start()
    l1.stop()

    # but not in network config file.
    with open(os.path.join(subdir, "config"), 'w') as f:
        f.write('network={}'.format(network))

    out = subprocess.run(['lightningd/lightningd',
                          '--lightning-dir={}'.format(l1.daemon.opts.get("lightning-dir"))],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert out.returncode == 1
    assert "network: not permitted in network-specific configuration files" in out.stderr.decode('utf-8')

    # lightning-dir only allowed if we explicitly use --conf
    os.unlink(os.path.join(subdir, "config"))
    with open(os.path.join(l1.daemon.opts.get("lightning-dir"), "config"), 'w') as f:
        f.write('lightning-dir={}/test'.format(l1.daemon.opts.get("lightning-dir")))

    out = subprocess.run(['lightningd/lightningd',
                          '--lightning-dir={}'.format(l1.daemon.opts.get("lightning-dir"))],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert out.returncode == 1
    assert "lightning-dir: not permitted in implicit configuration files" in out.stderr.decode('utf-8')

    l1.daemon.opts['conf'] = os.path.join(l1.daemon.opts.get("lightning-dir"), "config")
    l1.start()


def restore_valgrind(node, subdir):
    """Move valgrind files back to where fixtures expect them"""
    for f in os.listdir(subdir):
        if f.startswith('valgrind-errors.'):
            shutil.move(os.path.join(subdir, f),
                        node.daemon.opts.get("lightning-dir"))


@unittest.skipIf(env('COMPAT') != 1, "Upgrade code requires COMPAT_V073")
def test_testnet_upgrade(node_factory):
    """Test that we move files correctly on old testnet upgrade (even without specifying the network)"""
    l1 = node_factory.get_node(start=False, may_fail=True)

    basedir = l1.daemon.opts.get("lightning-dir")
    # Make it old-style
    os.rename(os.path.join(basedir, TEST_NETWORK, 'hsm_secret'),
              os.path.join(basedir, 'hsm_secret'))
    shutil.rmtree(os.path.join(basedir, TEST_NETWORK))
    # Add (empty!) config file; it should be left in place.
    with open(os.path.join(basedir, 'config'), 'wb') as f:
        f.write(b"# Test config file")
    with open(os.path.join(basedir, 'another_file'), 'wb') as f:
        pass

    # We need to allow this, otherwise no upgrade!
    del l1.daemon.opts['allow-deprecated-apis']
    # We want to test default network
    del l1.daemon.opts['network']

    # Wrong chain, will fail to start, but that's OK.
    with pytest.raises(ValueError):
        l1.start()

    netdir = os.path.join(basedir, "testnet")
    assert l1.daemon.is_in_log("Moving hsm_secret into {}/".format(netdir))
    assert l1.daemon.is_in_log("Moving another_file into {}/".format(netdir))
    assert not l1.daemon.is_in_log("Moving config into {}/".format(netdir))
    assert not l1.daemon.is_in_log("Moving lightningd-testnet.pid into {}/"
                                   .format(netdir))

    # Should move these
    assert os.path.isfile(os.path.join(netdir, "hsm_secret"))
    assert not os.path.isfile(os.path.join(basedir, "hsm_secret"))
    assert os.path.isfile(os.path.join(netdir, "another_file"))
    assert not os.path.isfile(os.path.join(basedir, "another_file"))

    # Should NOT move these
    assert not os.path.isfile(os.path.join(netdir, "lightningd-testnet.pid"))
    assert os.path.isfile(os.path.join(basedir, "lightningd-testnet.pid"))
    assert not os.path.isfile(os.path.join(netdir, "config"))
    assert os.path.isfile(os.path.join(basedir, "config"))

    restore_valgrind(l1, netdir)


@unittest.skipIf(env('COMPAT') != 1, "Upgrade code requires COMPAT_V073")
def test_regtest_upgrade(node_factory):
    """Test that we move files correctly on regtest upgrade"""
    l1 = node_factory.get_node(start=False)

    basedir = l1.daemon.opts.get("lightning-dir")
    netdir = os.path.join(basedir, TEST_NETWORK)

    # Make it old-style
    os.rename(os.path.join(basedir, TEST_NETWORK, 'hsm_secret'),
              os.path.join(basedir, 'hsm_secret'))
    shutil.rmtree(os.path.join(basedir, TEST_NETWORK))
    # Add config file which tells us it's regtest; it should be left in place.
    with open(os.path.join(basedir, 'config'), 'wb') as f:
        f.write(bytes("network={}".format(TEST_NETWORK), "utf-8"))
    with open(os.path.join(basedir, 'another_file'), 'wb') as f:
        pass

    # We need to allow this, otherwise no upgrade!
    del l1.daemon.opts['allow-deprecated-apis']
    # It should get this from the config file.
    del l1.daemon.opts['network']

    l1.start()

    assert l1.daemon.is_in_log("Moving hsm_secret into {}/".format(netdir))
    assert l1.daemon.is_in_log("Moving another_file into {}/".format(netdir))
    assert not l1.daemon.is_in_log("Moving config into {}/".format(netdir))
    assert not l1.daemon.is_in_log("Moving lightningd-testnet.pid into {}/"
                                   .format(netdir))

    # Should move these
    assert os.path.isfile(os.path.join(netdir, "hsm_secret"))
    assert not os.path.isfile(os.path.join(basedir, "hsm_secret"))
    assert os.path.isfile(os.path.join(netdir, "another_file"))
    assert not os.path.isfile(os.path.join(basedir, "another_file"))

    # Should NOT move these
    assert not os.path.isfile(os.path.join(netdir, "lightningd-{}.pid".format(TEST_NETWORK)))
    assert os.path.isfile(os.path.join(basedir, "lightningd-{}.pid".format(TEST_NETWORK)))
    assert not os.path.isfile(os.path.join(netdir, "config"))
    assert os.path.isfile(os.path.join(basedir, "config"))

    # Should restart fine
    l1.restart()

    restore_valgrind(l1, netdir)


@unittest.skipIf(VALGRIND, "valgrind files can't be written since we rmdir")
@unittest.skipIf(TEST_NETWORK != "regtest", "needs bitcoin mainnet")
def test_new_node_is_mainnet(node_factory):
    """Test that an empty directory causes us to be on mainnet"""
    l1 = node_factory.get_node(start=False, may_fail=True)

    basedir = l1.daemon.opts.get("lightning-dir")
    netdir = os.path.join(basedir, "bitcoin")

    shutil.rmtree(basedir)

    # Don't suppress upgrade (though it shouldn't happen!)
    del l1.daemon.opts['allow-deprecated-apis']
    # We want to test default network
    del l1.daemon.opts['network']

    # Wrong chain, will fail to start, but that's OK.
    with pytest.raises(ValueError):
        l1.start()

    # Should create these
    assert os.path.isfile(os.path.join(netdir, "hsm_secret"))
    assert not os.path.isfile(os.path.join(basedir, "hsm_secret"))
    assert not os.path.isfile(os.path.join(netdir, "lightningd-bitcoin.pid"))
    assert os.path.isfile(os.path.join(basedir, "lightningd-bitcoin.pid"))


def test_unicode_rpc(node_factory, executor, bitcoind):
    node = node_factory.get_node()
    desc = "Some candy 🍬 and a nice glass of milk 🥛."

    node.rpc.invoice(msatoshi=42, label=desc, description=desc)
    invoices = node.rpc.listinvoices()['invoices']
    assert(len(invoices) == 1)
    assert(invoices[0]['description'] == desc)
    assert(invoices[0]['label'] == desc)


@unittest.skipIf(VALGRIND, "Testing pyln doesn't exercise anything interesting in the c code.")
def test_unix_socket_path_length(node_factory, bitcoind, directory, executor, db_provider, test_base_dir):
    lightning_dir = os.path.join(directory, "anode" + "far" * 30 + "away")
    os.makedirs(lightning_dir)
    db = db_provider.get_db(lightning_dir, "test_unix_socket_path_length", 1)

    l1 = LightningNode(1, lightning_dir, bitcoind, executor, db=db, port=node_factory.get_next_port())

    # `LightningNode.start()` internally calls `LightningRpc.getinfo()` which
    # exercises the socket logic, and raises an issue if it fails.
    l1.start()

    # Let's just call it again to make sure it really works.
    l1.rpc.listconfigs()
    l1.stop()


def test_waitblockheight(node_factory, executor, bitcoind):
    node = node_factory.get_node()

    sync_blockheight(bitcoind, [node])

    blockheight = node.rpc.getinfo()['blockheight']

    # Should succeed without waiting.
    node.rpc.waitblockheight(blockheight - 2)
    node.rpc.waitblockheight(blockheight - 1)
    node.rpc.waitblockheight(blockheight)

    # Should not succeed yet.
    fut2 = executor.submit(node.rpc.waitblockheight, blockheight + 2)
    fut1 = executor.submit(node.rpc.waitblockheight, blockheight + 1)
    assert not fut1.done()
    assert not fut2.done()

    # Should take about ~1second and time out.
    with pytest.raises(RpcError):
        node.rpc.waitblockheight(blockheight + 2, 1)

    # Others should still not be done.
    assert not fut1.done()
    assert not fut2.done()

    # Trigger just one more block.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [node])
    fut1.result(5)
    assert not fut2.done()

    # Trigger two blocks.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [node])
    fut2.result(5)


@unittest.skipIf(not DEVELOPER, "Needs dev-sendcustommsg")
def test_sendcustommsg(node_factory):
    """Check that we can send custommsgs to peers in various states.

    `l2` is the node under test. `l1` has a channel with `l2` and should
    therefore be attached to `channeld`. `l4` is just connected, so it should
    be attached to `openingd`. `l3` has a channel open, but is disconnected
    and we can't send to it.

    """
    plugin = os.path.join(os.path.dirname(__file__), "plugins", "custommsg.py")
    opts = {'log-level': 'io', 'plugin': plugin}
    l1, l2, l3 = node_factory.line_graph(3, opts=opts)
    l4 = node_factory.get_node(options=opts)
    l2.connect(l4)
    l3.stop()
    msg = r'ff' * 32
    serialized = r'04070020' + msg

    # This address doesn't exist so we should get an error when we try sending
    # a message to it.
    node_id = '02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f'
    with pytest.raises(RpcError, match=r'No such peer'):
        l1.rpc.dev_sendcustommsg(node_id, msg)

    # `l3` is disconnected and we can't send messages to it
    assert(not l2.rpc.listpeers(l3.info['id'])['peers'][0]['connected'])
    with pytest.raises(RpcError, match=r'Peer is not connected'):
        l2.rpc.dev_sendcustommsg(l3.info['id'], msg)

    # We should not be able to send a bogus `ping` message, since it collides
    # with a message defined in the spec, and could potentially mess up our
    # internal state.
    with pytest.raises(RpcError, match=r'Cannot send messages of type 18 .WIRE_PING.'):
        l2.rpc.dev_sendcustommsg(l2.info['id'], r'0012')

    # The sendcustommsg RPC call is currently limited to odd-typed messages,
    # since they will not result in disconnections or even worse channel
    # failures.
    with pytest.raises(RpcError, match=r'Cannot send even-typed [0-9]+ custom message'):
        l2.rpc.dev_sendcustommsg(l2.info['id'], r'00FE')

    # This should work since the peer is currently owned by `channeld`
    l2.rpc.dev_sendcustommsg(l1.info['id'], msg)
    l2.daemon.wait_for_log(
        r'{peer_id}-{owner}-chan#[0-9]: \[OUT\] {serialized}'.format(
            owner='channeld', serialized=serialized, peer_id=l1.info['id']
        )
    )
    l1.daemon.wait_for_log(r'\[IN\] {}'.format(serialized))
    l1.daemon.wait_for_log(
        r'Got a custom message {serialized} from peer {peer_id}'.format(
            serialized=serialized, peer_id=l2.info['id']))

    # This should work since the peer is currently owned by `openingd`
    l2.rpc.dev_sendcustommsg(l4.info['id'], msg)
    l2.daemon.wait_for_log(
        r'{peer_id}-{owner}-chan#[0-9]: \[OUT\] {serialized}'.format(
            owner='openingd', serialized=serialized, peer_id=l4.info['id']
        )
    )
    l4.daemon.wait_for_log(r'\[IN\] {}'.format(serialized))
    l4.daemon.wait_for_log(
        r'Got a custom message {serialized} from peer {peer_id}'.format(
            serialized=serialized, peer_id=l2.info['id']))


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "Needs sendonionmessage")
def test_sendonionmessage(node_factory):
    l1, l2, l3 = node_factory.line_graph(3)

    blindedpathtool = os.path.join(os.path.dirname(__file__), "..", "devtools", "blindedpath")

    l1.rpc.call('sendonionmessage',
                {'hops':
                 [{'id': l2.info['id']},
                  {'id': l3.info['id']}]})
    assert l3.daemon.wait_for_log('Got onionmsg')

    # Now by SCID.
    l1.rpc.call('sendonionmessage',
                {'hops':
                 [{'id': l2.info['id'],
                   'short_channel_id': l2.get_channel_scid(l3)},
                  {'id': l3.info['id']}]})
    assert l3.daemon.wait_for_log('Got onionmsg')

    # Now test blinded path.
    output = subprocess.check_output(
        [blindedpathtool, '--simple-output', 'create', l2.info['id'], l3.info['id']]
    ).decode('ASCII').strip()

    # First line is blinding, then <peerid> then <encblob>.
    blinding, p1, p1enc, p2 = output.split('\n')
    # First hop can't be blinded!
    assert p1 == l2.info['id']

    l1.rpc.call('sendonionmessage',
                {'hops':
                 [{'id': l2.info['id'],
                   'blinding': blinding,
                   'enctlv': p1enc},
                  {'id': p2}]})
    assert l3.daemon.wait_for_log('Got onionmsg')


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "Needs sendonionmessage")
def test_sendonionmessage_reply(node_factory):
    blindedpathtool = os.path.join(os.path.dirname(__file__), "..", "devtools", "blindedpath")

    plugin = os.path.join(os.path.dirname(__file__), "plugins", "onionmessage-reply.py")
    l1, l2, l3 = node_factory.line_graph(3, opts={'plugin': plugin})

    # Make reply path
    output = subprocess.check_output(
        [blindedpathtool, '--simple-output', 'create', l2.info['id'], l1.info['id']]
    ).decode('ASCII').strip()

    # First line is blinding, then <peerid> then <encblob>.
    blinding, p1, p1enc, p2 = output.split('\n')
    # First hop can't be blinded!
    assert p1 == l2.info['id']

    l1.rpc.call('sendonionmessage',
                {'hops':
                 [{'id': l2.info['id']},
                  {'id': l3.info['id']}],
                 'reply_path':
                 {'blinding': blinding,
                  'path': [{'id': p1, 'enctlv': p1enc}, {'id': p2}]}})

    assert l3.daemon.wait_for_log('Got onionmsg reply_blinding reply_path')
    assert l3.daemon.wait_for_log('Sent reply via')
    assert l1.daemon.wait_for_log('Got onionmsg')


@unittest.skipIf(not DEVELOPER, "needs --dev-force-privkey")
def test_getsharedsecret(node_factory):
    """
    Test getsharedsecret command.
    """
    # From BOLT 8 test vectors.
    options = [
        {"dev-force-privkey": "1212121212121212121212121212121212121212121212121212121212121212"},
        {}
    ]
    l1, l2 = node_factory.get_nodes(2, opts=options)

    # Check BOLT 8 test vectors.
    shared_secret = l1.rpc.getsharedsecret("028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7")['shared_secret']
    assert (shared_secret == "1e2fb3c8fe8fb9f262f649f64d26ecf0f2c0a805a767cf02dc2d77a6ef1fdcc3")

    # Clear the forced privkey of l1.
    del l1.daemon.opts["dev-force-privkey"]
    l1.restart()

    # l1 and l2 can generate the same shared secret
    # knowing only the public key of the other.
    assert (l1.rpc.getsharedsecret(l2.info["id"])["shared_secret"]
            == l2.rpc.getsharedsecret(l1.info["id"])["shared_secret"])


def test_commitfee_option(node_factory):
    """Sanity check for the --commit-fee startup option."""
    l1, l2 = node_factory.get_nodes(2, opts=[{"commit-fee": "200"}, {}])

    mock_wu = 5000
    for l in [l1, l2]:
        l.set_feerates((mock_wu, 0, 0, 0), True)
    l1_commit_fees = l1.rpc.call("estimatefees")["unilateral_close"]
    l2_commit_fees = l2.rpc.call("estimatefees")["unilateral_close"]

    assert l1_commit_fees == 2 * l2_commit_fees == 2 * 4 * mock_wu  # WU->VB


def test_listtransactions(node_factory):
    """Sanity check for the listtransactions RPC command"""
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {}])

    wallettxid = l1.openchannel(l2, 10**4)["wallettxid"]
    txids = [i["txid"] for tx in l1.rpc.listtransactions()["transactions"]
             for i in tx["inputs"]]
    # The txid of the transaction funding the channel is present, and
    # represented as little endian (like bitcoind and explorers).
    assert wallettxid in txids
