from bitcoin.rpc import RawProxy
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import LightningNode, TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from threading import Event
from pyln.testing.utils import (
    TIMEOUT, VALGRIND, sync_blockheight, only_one,
    wait_for, TailableProc, env, mine_funding_to_announce
)
from utils import (
    account_balance, scriptpubkey_addr, check_coin_moves, first_scid
)
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

    nodes = node_factory.get_nodes(len(configs))
    for n, (key, alias, color) in zip(nodes, configs):
        assert n.daemon.is_in_log(r'public key {}, alias {}.* \(color #{}\)'
                                  .format(key, alias, color))


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "This migration is based on a sqlite3 snapshot")
def test_db_upgrade(node_factory):
    l1 = node_factory.get_node(options={'database-upgrade': True})
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
    l1.daemon.wait_for_logs(['Unable to estimate any fees',
                             'getblockhash .* exited with status 1'])

    # And they should retry!
    l1.daemon.wait_for_logs(['Unable to estimate any fees',
                             'getblockhash .* exited with status 1'])

    # Restore, then it should recover and get blockheight.
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', None)
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)

    bitcoind.generate_block(5)
    sync_blockheight(bitcoind, [l1])

    # We refuse to start if bitcoind is in `blocksonly`
    l1.stop()
    bitcoind.stop()
    bitcoind.cmd_line += ["-blocksonly"]
    bitcoind.start()

    # Ignore BROKEN log message about blocksonly mode.
    l2 = node_factory.get_node(start=False, expect_fail=True,
                               allow_broken_log=True)
    l2.daemon.start(wait_for_initialized=False, stderr_redir=True)
    # Will exit with failure code.
    assert l2.daemon.wait() == 1
    assert l2.daemon.is_in_stderr(r".*deactivating transaction relay is not"
                                  " supported.")
    assert l2.daemon.is_in_log('deactivating transaction'
                               ' relay is not supported')


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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
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
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'may_reconnect': True,
                                                  'wait_for_bitcoind_sync': False},
                                                 {'may_reconnect': True,
                                                  'wait_for_bitcoind_sync': False},
                                                 {}])
    node_factory.join_nodes([l1, l2])

    # Balance l1<->l2 channel
    l1.pay(l2, 10**9 // 2)

    l1.stop()

    # Now make sure l2 is behind.
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
        if l1.config('experimental-dual-fund'):
            psbt = l1.rpc.fundpsbt('10000sat', '253perkw', 250)['psbt']
            l1.rpc.openchannel_init(l3.info['id'], '10000sat', psbt)
        else:
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
    l1, l2 = node_factory.line_graph(2)

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

    # channeld pinging
    ping_tests(l1, l2)


def test_htlc_sig_persistence(node_factory, bitcoind, executor):
    """Interrupt a payment between two peers, then fail and recover funds using the HTLC sig.
    """
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)
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

    # Could happen in either order!
    l1.daemon.wait_for_log(r'Peer permanent failure in CHANNELD_NORMAL: Funding transaction spent')

    _, txid, blocks = l1.wait_for_onchaind_tx('OUR_HTLC_TIMEOUT_TO_US',
                                              'THEIR_UNILATERAL/OUR_HTLC')
    assert blocks == 5

    bitcoind.generate_block(5)
    bitcoind.generate_block(1, wait_for_mempool=txid)
    l1.daemon.wait_for_logs([
        r'Owning output . (\d+)sat .SEGWIT. txid',
    ])

    # We should now have 1) the unilateral to us, and b) the HTLC respend to us
    # and maybe (c) change.
    assert 2 <= len(l1.rpc.listfunds()['outputs']) <= 3


def test_htlc_out_timeout(node_factory, bitcoind, executor):
    """Test that we drop onchain if the peer doesn't time out HTLC"""

    # HTLC 1->2, 1 fails after it's irrevocably committed, can't reconnect
    disconnects = ['-WIRE_REVOKE_AND_ACK']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chanid, _ = l1.fundchannel(l2, 10**6)

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_htlc_out_timeout', 'desc')['bolt11']
    assert only_one(l2.rpc.listinvoices('test_htlc_out_timeout')['invoices'])['status'] == 'unpaid'

    executor.submit(l1.dev_pay, inv, dev_use_shadow=False)

    # l1 will disconnect, and not reconnect.
    l1.daemon.wait_for_log('dev_disconnect: -WIRE_REVOKE_AND_ACK')

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
    ((_, _, blocks1), (_, txid, blocks2)) = \
        l1.wait_for_onchaind_txs(('OUR_DELAYED_RETURN_TO_WALLET',
                                  'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US'),
                                 ('OUR_HTLC_TIMEOUT_TX',
                                  'OUR_UNILATERAL/OUR_HTLC'))
    assert blocks1 == 4
    # We hit deadline (we give 1 block grace), then mined another.
    assert blocks2 == -2

    # If we try to reuse the same output as we used for the anchor spend, then
    # bitcoind can reject it.  In that case we'll try again after we get change
    # from anchor spend.
    if txid not in bitcoind.rpc.getrawmempool():
        bitcoind.generate_block(1)
        bitcoind.generate_block(1, wait_for_mempool=1)
    else:
        bitcoind.generate_block(1)

    rawtx, txid, blocks = l1.wait_for_onchaind_tx('OUR_DELAYED_RETURN_TO_WALLET',
                                                  'OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US')
    assert blocks == 4
    bitcoind.generate_block(4)

    # It should now claim both the to-local and htlc-timeout-tx outputs.
    l1.daemon.wait_for_logs(['sendrawtx exit 0.*{}'.format(rawtx),
                             'sendrawtx exit 0'])

    # Now, 100 blocks it should be done.
    bitcoind.generate_block(100, wait_for_mempool=txid)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


def test_htlc_in_timeout(node_factory, bitcoind, executor):
    """Test that we drop onchain if the peer doesn't accept fulfilled HTLC"""

    # HTLC 1->2, 1 fails after 2 has sent committed the fulfill
    disconnects = ['-WIRE_REVOKE_AND_ACK*2']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()
    # Give it some sats for anchor spend!
    l2.fundwallet(25000, mine_block=False)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    chanid, _ = l1.fundchannel(l2, 10**6)

    sync_blockheight(bitcoind, [l1, l2])

    amt = 200000000
    inv = l2.rpc.invoice(amt, 'test_htlc_in_timeout', 'desc')['bolt11']
    assert only_one(l2.rpc.listinvoices('test_htlc_in_timeout')['invoices'])['status'] == 'unpaid'

    executor.submit(l1.dev_pay, inv, dev_use_shadow=False)

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
    _, txid, blocks = l2.wait_for_onchaind_tx('OUR_HTLC_SUCCESS_TX',
                                              'OUR_UNILATERAL/THEIR_HTLC')
    assert blocks == 0

    # If we try to reuse the same output as we used for the anchor spend, then
    # bitcoind can reject it.  In that case we'll try again after we get change
    # from anchor spend.
    if txid not in bitcoind.rpc.getrawmempool():
        bitcoind.generate_block(1)
        bitcoind.generate_block(1, wait_for_mempool=1)
    else:
        bitcoind.generate_block(1)

    rawtx, txid, blocks = l2.wait_for_onchaind_tx('OUR_DELAYED_RETURN_TO_WALLET',
                                                  'OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US')
    assert blocks == 4
    bitcoind.generate_block(4)
    l2.daemon.wait_for_log('sendrawtx exit 0.*{}'.format(rawtx))

    # Now, 100 blocks it should be both done.
    bitcoind.generate_block(100, wait_for_mempool=txid)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', 'must be on bitcoin network')
def test_bech32_funding(node_factory, chainparams):
    # Don't get any funds from previous runs.
    l1, l2 = node_factory.line_graph(2, opts={'random_hsm': True}, fundchannel=False)

    # fund a bech32 address and then open a channel with it
    res = l1.openchannel(l2, 25000, 'bech32')
    address = res['address']
    assert address.startswith(chainparams['bip173_prefix'])

    # probably overly paranoid checking
    wallettxid = res['wallettxid']

    wallettx = l1.bitcoin.rpc.getrawtransaction(wallettxid, True)
    fundingtx = l1.bitcoin.rpc.decoderawtransaction(res['fundingtx'])

    def is_p2wpkh(output):
        return output['type'] == 'witness_v0_keyhash' and \
            address == scriptpubkey_addr(output)

    assert any(is_p2wpkh(output['scriptPubKey']) for output in wallettx['vout'])
    assert only_one(fundingtx['vin'])['txid'] == res['wallettxid']


def test_withdraw_misc(node_factory, bitcoind, chainparams):
    def dont_spend_outputs(n, txid):
        """Reserve both outputs (we assume there are two!) in case any our ours, so we don't spend change: wrecks accounting checks"""
        n.rpc.reserveinputs(bitcoind.rpc.createpsbt([{'txid': txid,
                                                      'vout': 0},
                                                     {'txid': txid,
                                                      'vout': 1}], []))

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    amount = 2000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True,
                               options={'plugin': coin_mvt_plugin},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['bech32']

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

    # Reach around into the db to check that outputs were added
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 10

    waddr = l1.bitcoin.getnewaddress()
    # Now attempt to withdraw some (making sure we collect multiple inputs)
    l1.rpc.check_request_schemas = False
    with pytest.raises(RpcError):
        l1.rpc.withdraw('not an address', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, 'not an amount')
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, -amount)
    with pytest.raises(RpcError, match=r'Could not afford'):
        l1.rpc.withdraw(waddr, amount * 100)
    l1.rpc.check_request_schemas = True

    out = l1.rpc.withdraw(waddr, amount)

    # Make sure bitcoind received the withdrawal
    unspent = l1.bitcoin.rpc.listunspent(0)
    withdrawal = [u for u in unspent if u['txid'] == out['txid']]

    assert(withdrawal[0]['amount'] == Decimal('0.02'))

    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])

    # Now make sure two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 2

    dont_spend_outputs(l1, out['txid'])

    # Now send some money to l2.
    waddr = l2.rpc.newaddr('bech32')['bech32']
    out = l1.rpc.withdraw(waddr, amount)
    bitcoind.generate_block(1)

    # Make sure l2 received the withdrawal.
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 1)
    outputs = l2.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == amount

    # Now make sure an additional two of them were marked as spent
    sync_blockheight(bitcoind, [l1])
    dont_spend_outputs(l1, out['txid'])
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 4

    if chainparams['name'] != 'regtest':
        return

    # Simple test for withdrawal to P2WPKH
    # Address from: https://bc-2.jp/tools/bech32demo/index.html
    waddr = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
    with pytest.raises(RpcError):
        l1.rpc.withdraw('xx1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kdl9fad', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxxxxxx', amount)
    out = l1.rpc.withdraw(waddr, amount)
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])
    dont_spend_outputs(l1, out['txid'])

    # Now make sure additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 6

    # Simple test for withdrawal to P2WSH
    # Address from: https://bc-2.jp/tools/bech32demo/index.html
    waddr = 'bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry'
    with pytest.raises(RpcError):
        l1.rpc.withdraw('xx1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsm03tq', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qxxxxxx', amount)
    out = l1.rpc.withdraw(waddr, amount)
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])
    dont_spend_outputs(l1, out['txid'])
    # Now make sure additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 8

    # failure testing for invalid SegWit addresses, from BIP173
    # HRP character out of range
    with pytest.raises(RpcError):
        l1.rpc.withdraw(' 1nwldj5', amount)
    # overall max length exceeded
    with pytest.raises(RpcError):
        l1.rpc.withdraw('an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx', amount)
    # No separator character
    with pytest.raises(RpcError):
        l1.rpc.withdraw('pzry9x0s0muk', amount)
    # Empty HRP
    with pytest.raises(RpcError):
        l1.rpc.withdraw('1pzry9x0s0muk', amount)
    # Invalid witness version
    with pytest.raises(RpcError):
        l1.rpc.withdraw('BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2', amount)
    # Invalid program length for witness version 0 (per BIP141)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', amount)
    # Mixed case
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7', amount)
    # Non-zero padding in 8-to-5 conversion
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv', amount)

    # Should have 2 outputs available.
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 2

    # Unreserve everything.
    inputs = []
    for out in l1.rpc.listfunds()['outputs']:
        if out['reserved']:
            inputs += [{'txid': out['txid'], 'vout': out['output']}]
            assert out['reserved_to_block'] > bitcoind.rpc.getblockchaininfo()['blocks']
    l1.rpc.unreserveinputs(bitcoind.rpc.createpsbt(inputs, []))

    # Test withdrawal to self.
    l1.rpc.withdraw(l1.rpc.newaddr('bech32')['bech32'], 'all', minconf=0)
    bitcoind.generate_block(1)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 1

    l1.rpc.withdraw(waddr, 'all', minconf=0)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 0

    # This should fail, can't even afford fee.
    with pytest.raises(RpcError, match=r'Could not afford'):
        l1.rpc.withdraw(waddr, 'all')

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    assert account_balance(l1, 'wallet') == 0

    external_moves = [
        {'type': 'chain_mvt', 'credit_msat': 2000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 2000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 2000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 2000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 11956163000, 'debit_msat': 0, 'tags': ['deposit']},
    ]

    check_coin_moves(l1, 'external', external_moves, chainparams)


def test_io_logging(node_factory, executor):
    l1 = node_factory.get_node(options={'log-level': 'io'})
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Fundchannel manually so we get channeld pid.
    l1.fundwallet(10**6 + 1000000)
    l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']

    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(' to CHANNELD_NORMAL')

    fut = executor.submit(l1.pay, l2, 200000000)

    # WIRE_UPDATE_ADD_HTLC = 128 = 0x0080
    l1.daemon.wait_for_log(r'channeld.*: \[OUT\] 0080')
    # WIRE_UPDATE_FULFILL_HTLC = 130 = 0x0082
    l1.daemon.wait_for_log(r'channeld.*: \[IN\] 0082')
    fut.result(10)

    # Send it sigusr1: should turn off logging.
    pid1 = l1.subd_pid('channeld')
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
    pid2 = l2.subd_pid('channeld')
    subprocess.run(['kill', '-USR1', pid2])
    l1.pay(l2, 200000000)

    # Now it should find it.
    peerlog = only_one(l2.rpc.listpeers(l1.info['id'], "io")['peers'])['log']
    assert any(l['type'] == 'IO_OUT' for l in peerlog)
    assert any(l['type'] == 'IO_IN' for l in peerlog)


def test_address(node_factory):
    l1 = node_factory.get_node()
    addr = l1.rpc.getinfo()['address']
    assert len(addr) == 0

    bind = l1.rpc.getinfo()['binding']
    assert len(bind) == 1
    assert bind[0]['type'] == 'ipv4'
    assert bind[0]['address'] == '127.0.0.1'
    assert int(bind[0]['port']) == l1.port

    # Now test UNIX domain binding
    l1.stop()
    l1.daemon.opts['bind-addr'] = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "sock")
    l1.start()

    # Test dev-allow-localhost
    l2 = node_factory.get_node(options={'dev-allow-localhost': None})
    addr = l2.rpc.getinfo()['address']
    assert len(addr) == 1
    assert addr[0]['type'] == 'ipv4'
    assert addr[0]['address'] == '127.0.0.1'
    assert int(addr[0]['port']) == l2.port

    ret = l2.rpc.connect(l1.info['id'], l1.daemon.opts['bind-addr'])
    assert ret['address'] == {'type': 'local socket', 'socket': l1.daemon.opts['bind-addr']}


def test_listconfigs(node_factory, bitcoind, chainparams):
    # Make extremely long entry, check it works
    for deprecated in (True, False):
        l1 = node_factory.get_node(options={'log-prefix': 'lightning1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
                                            'allow-deprecated-apis': deprecated,
                                            'wumbo': None})

        configs = l1.rpc.listconfigs()['configs']
        # See utils.py for these values
        for name, valfield, val in (('allow-deprecated-apis', 'value_bool', deprecated),
                                    ('network', 'value_str', chainparams['name']),
                                    ('ignore-fee-limits', 'value_bool', False),
                                    ('log-prefix', 'value_str', 'lightning1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')):
            c = configs[name]
            assert c['source'] == 'cmdline'
            assert c[valfield] == val
            assert 'plugin' not in c

        # We don't print the (unofficial!) wumbo
        assert 'wumbo' not in configs
        assert configs['large-channels']['set'] is True
        assert configs['large-channels']['source'] == 'cmdline'

        # Test modern ones!
        for c in configs.keys():
            oneconfig = l1.rpc.listconfigs(config=c)['configs']
            assert oneconfig[c] == configs[c]


def test_listconfigs_plugins(node_factory, bitcoind, chainparams):
    l1 = node_factory.get_node(options={'allow-deprecated-apis': True})

    configs = l1.rpc.listconfigs()
    assert configs['important-plugins']
    assert len([p for p in configs['important-plugins'] if p['name'] == "pay"]) == 1
    for p in configs['important-plugins']:
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
        assert obj['id'] == json.loads(i.decode("UTF-8"))['id']
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
    l1 = node_factory.get_node(options={'log-level': 'io'})

    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    # Test some known output.
    assert 'help [command]\n    List available commands, or give verbose help on one {command}' in out

    # Check JSON id is as expected
    l1.daemon.wait_for_log(r'jsonrpc#[0-9]*: "cli:help#[0-9]*"\[IN\]')

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

    # Test filtering
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '--filter={"help":[{"command":true}]}',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert j == {'help': [{'command': 'help [command]'}]}

    # lightningd errors should exit with status 1.
    ret = subprocess.run(['cli/lightning-cli',
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'unknown-command'])
    assert ret.returncode == 1

    # Can't contact will exit with status code 2.
    ret = subprocess.run(['cli/lightning-cli',
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir=xxx',
                          'help'])
    assert ret.returncode == 2

    # Malformed parameter (invalid json) will exit with status code 3.
    ret = subprocess.run(['cli/lightning-cli',
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'listpeers',
                          '[xxx]'])
    assert ret.returncode == 3

    # Bad usage should exit with status 3.
    ret = subprocess.run(['cli/lightning-cli',
                          '--bad-param',
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'help'])
    assert ret.returncode == 3

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
                     '         "amount_msat": 123000,',
                     '         "status": "unpaid",',
                     r'         "description": "d\"[]{}",',
                     '         "created_index": 1',
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


def test_cli_commando(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False,
                                     opts={'log-level': 'io'})
    rune = l2.rpc.commando_rune()['rune']

    # Invalid peer id.
    val = subprocess.run(['cli/lightning-cli',
                          '--commando=00',
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'help'])
    assert val.returncode == 3

    # Valid peer id, but needs rune!
    val = subprocess.run(['cli/lightning-cli',
                          '--commando={}'.format(l2.info['id']),
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'help'])
    assert val.returncode == 1

    # This works!
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--commando={}:{}'.format(l2.info['id'], rune),
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    # Test some known output.
    assert 'help [command]\n    List available commands, or give verbose help on one {command}' in out

    # Check JSON id is as expected
    l1.daemon.wait_for_log(r'jsonrpc#[0-9]*: "cli:help#[0-9]*"\[IN\]')

    # And through l2...
    l2.daemon.wait_for_log(r'jsonrpc#[0-9]*: "cli:help#[0-9]*/cln:commando#[0-9]*/commando:help#[0-9]*"\[IN\]')

    # Test keyword input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--commando={}:{}'.format(l2.info['id'], rune),
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-k',
                                   'help', 'command=help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test ordered input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--commando={}:{}'.format(l2.info['id'], rune),
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-o',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['help'][0]['verbose']

    # Test filtering
    out = subprocess.check_output(['cli/lightning-cli',
                                   '-c', '{}:{}'.format(l2.info['id'], rune),
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '--filter={"help":[{"command":true}]}',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert j == {'help': [{'command': 'help [command]'}]}

    # Test missing parameters.
    try:
        # This will error due to missing parameters.
        # We want to check if lightningd will crash.
        out = subprocess.check_output(['cli/lightning-cli',
                                       '--commando={}:{}'.format(l2.info['id'], rune),
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
                          '--commando={}:{}'.format(l2.info['id'], rune),
                          '--network={}'.format(TEST_NETWORK),
                          '--lightning-dir={}'
                          .format(l1.daemon.lightning_dir),
                          'x"[]{}'],
                         stdout=subprocess.PIPE)
    assert 'Unknown command' in out.stdout.decode('utf-8')

    subprocess.check_output(['cli/lightning-cli',
                             '--commando={}:{}'.format(l2.info['id'], rune),
                             '--network={}'.format(TEST_NETWORK),
                             '--lightning-dir={}'
                             .format(l1.daemon.lightning_dir),
                             'invoice', '123000', 'l"[]{}', 'd"[]{}']).decode('utf-8')
    # Check label is correct, and also that cli's keyword parsing works.
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--commando={}:{}'.format(l2.info['id'], rune),
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-k',
                                   'listinvoices', 'label=l"[]{}']).decode('utf-8')
    j = json.loads(out)
    assert only_one(j['invoices'])['label'] == 'l"[]{}'


def test_daemon_option(node_factory):
    """
    Make sure --daemon at least vaguely works!
    """
    # Lazy way to set up command line and env, plus do VALGRIND checks
    l1 = node_factory.get_node()
    l1.stop()

    os.unlink(l1.rpc.socket_path)
    # Stop it from logging to stdout!
    logfname = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "log-daemon")
    l1.daemon.opts['log-file'] = logfname
    l1.daemon.opts['daemon'] = None
    subprocess.run(l1.daemon.cmd_line, env=l1.daemon.env,
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


def test_cli_no_argument():
    """If no arguments are provided, should display help and exit."""
    out = subprocess.run(['cli/lightning-cli'], stdout=subprocess.PIPE)
    assert out.returncode in [0, 2]  # returns 2 if lightning-rpc not available
    assert "Usage: cli/lightning-cli <command> [<params>...]" in out.stdout.decode()


def test_blockchaintrack(node_factory, bitcoind):
    """Check that we track the blockchain correctly across reorgs
    """
    l1 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr(addresstype='all')['bech32']

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

    l1.daemon.wait_for_log(r'Owning output.* CONFIRMED')
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


@pytest.mark.openchannel('v1')
def test_funding_reorg_private(node_factory, bitcoind):
    """Change funding tx height after lockin, between node restart.
    """
    # Rescan to detect reorg at restart and may_reconnect so channeld
    # will restart.  Reorg can cause bad gossip msg.
    opts = {'funding-confirms': 2, 'rescan': 10, 'may_reconnect': True,
            'allow_bad_gossip': True,
            # gossipd send lightning update for original channel.
            'allow_broken_log': True,
            'allow_warning': True,
            'dev-fast-reconnect': None,
            # if it's not zeroconf, we'll terminate on reorg.
            'plugin': os.path.join(os.getcwd(), 'tests/plugins/zeroconf-selective.py'),
            'zeroconf-allow': 'any'}
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)
    l1.fundwallet(10000000)
    sync_blockheight(bitcoind, [l1])                # height 102
    bitcoind.generate_block(3)                      # heights 103-105

    l1.rpc.fundchannel(l2.info['id'], "all", announce=False)
    bitcoind.generate_block(1)                      # height 106

    daemon = 'DUALOPEND' if l1.config('experimental-dual-fund') else 'CHANNELD'
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['status']
             == ["{}_AWAITING_LOCKIN:They've confirmed channel ready, we haven't yet.".format(daemon)])
    bitcoind.generate_block(1)                      # height 107
    l1.wait_local_channel_active('106x1x0')
    l2.wait_local_channel_active('106x1x0')
    l1.stop()

    # Create a fork that changes short_channel_id from 106x1x0 to 108x1x0
    bitcoind.simple_reorg(106, 2)                   # heights 106-108
    bitcoind.generate_block(1)                      # height 109 (to reach minimum_depth=2 again)
    l1.start()

    # l2 was running, sees last stale block being removed
    l2.daemon.wait_for_logs([r'Removing stale block {}'.format(106),
                             r'Got depth change .->{} for .* REORG'.format(0)])

    # New one should replace old.
    wait_for(lambda: l2.is_local_channel_active('108x1x0'))
    assert [c for c in l2.rpc.listpeerchannels()['channels'] if c['short_channel_id'] == '106x1x0'] == []

    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(1, True)


@pytest.mark.openchannel('v1')
def test_funding_reorg_remote_lags(node_factory, bitcoind):
    """Nodes may disagree about short_channel_id before channel announcement
    """
    # may_reconnect so channeld will restart; bad gossip can happen due to reorg
    opts = {'funding-confirms': 1, 'may_reconnect': True, 'allow_bad_gossip': True,
            'allow_warning': True, 'dev-fast-reconnect': None,
            # if it's not zeroconf, l2 will terminate on reorg.
            'plugin': os.path.join(os.getcwd(), 'tests/plugins/zeroconf-selective.py'),
            'zeroconf-allow': 'any'}
    l1, l2 = node_factory.line_graph(2, fundchannel=False, opts=opts)
    l1.fundwallet(10000000)
    sync_blockheight(bitcoind, [l1])                # height 102

    l1.rpc.fundchannel(l2.info['id'], "all")
    bitcoind.generate_block(5)                      # heights 103 - 107
    l1.wait_local_channel_active('103x1x0')
    l2.wait_local_channel_active('103x1x0')

    # Make l2 temporary blind for blocks > 107
    def no_more_blocks(req):
        return {"result": None,
                "error": {"code": -8, "message": "Block height out of range"}, "id": req['id']}

    l2.daemon.rpcproxy.mock_rpc('getblockhash', no_more_blocks)

    # Reorg changes short_channel_id 103x1x0 to 104x1x0, l1 sees it, restarts channeld
    bitcoind.simple_reorg(103, 1)                   # heights 103 - 108
    # But now it's height 104, we need another block to make it announceable.
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(r'Short channel id changed from 103x1x0->104x1x0')

    # We are OK with this!
    l2.daemon.wait_for_log(r'channel_gossip: received announcement sigs for 104x1x0 \(we have 103x1x0\)')

    # Unblinding l2 brings it back in sync, restarts channeld and sends its announce sig
    l2.daemon.rpcproxy.mock_rpc('getblockhash', None)

    wait_for(lambda: l2.is_local_channel_active('104x1x0'))
    assert [c for c in l2.rpc.listpeerchannels()['channels'] if c['short_channel_id'] == '103x1x0'] == []

    wait_for(lambda: [c['short_channel_id'] for c in l2.rpc.listchannels()['channels']] == ['104x1x0'] * 2)

    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(1, True)
    l1.daemon.wait_for_log(r'Deleting channel')
    l2.daemon.wait_for_log(r'Deleting channel')


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_funding_reorg_get_upset(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, opts=[{}, {'allow_broken_log': True}])
    bitcoind.simple_reorg(103, 1)

    # l1 is ok, as funder.
    l1.daemon.wait_for_log('Funding tx .* reorganized out, but we opened it...')
    assert only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL'
    # l2 is upset!
    l2.daemon.wait_for_log('Funding transaction has been reorged out in state CHANNELD_NORMAL')
    assert only_one(l2.rpc.listpeerchannels()['channels'])['state'] == 'AWAITING_UNILATERAL'


def test_decode(node_factory, bitcoind):
    """Test the decode option to decode the contents of emergency recovery.
    """
    l1 = node_factory.get_node(allow_broken_log=True)
    cmd_line = ["tools/hsmtool", "getemergencyrecover", os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "emergency.recover")]
    out = subprocess.check_output(cmd_line).decode('utf-8')
    bech32_out = out.strip('\n')
    assert bech32_out.startswith('clnemerg1')

    x = l1.rpc.decode(bech32_out)

    assert x["valid"]
    assert x["type"] == "emergency recover"
    assert x["decrypted"].startswith('17')


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "deletes database, which is assumed sqlite3")
def test_recover(node_factory, bitcoind):
    """Test the recover option
    """
    # Start the node with --recovery with valid codex32 secret
    l1 = node_factory.get_node(start=False,
                               options={"recover": "cl10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqjdsjnzedu43ns"})

    os.unlink(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret"))
    l1.daemon.start()

    cmd_line = ["tools/hsmtool", "getcodexsecret", os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")]
    out = subprocess.check_output(cmd_line + ["leet", "0"]).decode('utf-8')
    assert out == "cl10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqjdsjnzedu43ns\n"

    # Check bad ids.
    out = subprocess.run(cmd_line + ["lee", "0"], stderr=subprocess.PIPE, timeout=TIMEOUT)
    assert 'Invalid id: must be 4 characters' in out.stderr.decode('utf-8')
    assert out.returncode == 2

    out = subprocess.run(cmd_line + ["Leet", "0"], stderr=subprocess.PIPE, timeout=TIMEOUT)
    assert 'Invalid id: must be lower-case' in out.stderr.decode('utf-8')
    assert out.returncode == 2

    out = subprocess.run(cmd_line + ["💔", "0"], stderr=subprocess.PIPE, timeout=TIMEOUT)
    assert 'Invalid id: must be ASCII' in out.stderr.decode('utf-8')
    assert out.returncode == 2

    for bad_bech32 in ['b', 'o', 'i', '1']:
        out = subprocess.run(cmd_line + [bad_bech32 + "eet", "0"], stderr=subprocess.PIPE, timeout=TIMEOUT)
        assert 'Invalid id: must be valid bech32 string' in out.stderr.decode('utf-8')
        assert out.returncode == 2

    basedir = l1.daemon.opts.get("lightning-dir")
    with open(os.path.join(basedir, TEST_NETWORK, 'hsm_secret'), 'rb') as f:
        buff = f.read()

    # Check the node secret
    assert buff.hex() == "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
    l1.stop()

    os.unlink(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3"))

    # Node should throw error to recover flag if HSM already exists.
    l1.daemon.opts['recover'] = "cl10leetsllhdmn9m42vcsamx24zrxgs3qrl7ahwvhw4fnzrhve25gvezzyqqjdsjnzedu43ns"
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)

    # Will exit with failure code.
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr(r"hsm_secret already exists!")

    os.unlink(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret"))

    l1.daemon.opts.update({"recover": "CL10LEETSLLHDMN9M42VCSAMX24ZRXGS3QQAT3LTDVAKMT73"})
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr(r"Invalid length: must be 32 bytes")

    # Can do HSM secret in hex, too!
    l1.daemon.opts["recover"] = "6c696768746e696e672d31000000000000000000000000000000000000000000"
    l1.daemon.start()
    l1.stop()

    # And can start without recovery, of course!
    l1.daemon.opts.pop("recover")
    l1.start()


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
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    # Will exit with failure code.
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr(r"bitcoind has gone backwards from 500000 to 105 blocks!")

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
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    # Will exit with failure code.
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr('bitcoind has gone backwards')

    # Nor will it start with if we ask for a reindex of fewer blocks.
    l1.daemon.opts['rescan'] = 3

    # Will simply refuse to start.
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    # Will exit with failure code.
    assert l1.daemon.wait() == 1
    assert l1.daemon.is_in_stderr('bitcoind has gone backwards')

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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_reserve_enforcement(node_factory, executor):
    """Channeld should disallow you spending into your reserve"""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
                                              'dev-no-reconnect': None,
                                              'allow_warning': True})

    # Pay 1000 satoshi to l2.
    l1.pay(l2, 1000000)
    l2.stop()

    # They should both aim for 1%.
    reserves = l2.db.query('SELECT channel_reserve_satoshis FROM channel_configs')
    assert reserves == [{'channel_reserve_satoshis': 10**6 // 100}] * 2

    # Edit db to reduce reserve to 0 so it will try to violate it.
    l2.db.execute('UPDATE channel_configs SET channel_reserve_satoshis=0')

    l2.start()
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)

    # This should be impossible to pay entire thing back: l1 should warn and
    # close connection for trying to violate reserve.
    executor.submit(l2.pay, l1, 1000000)
    l1.daemon.wait_for_log(
        'Peer transient failure in CHANNELD_NORMAL: channeld.*'
        ' CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED'
    )
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'])['connected'] is False)


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


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Fees on elements are different")
@pytest.mark.parametrize("anchors", [False, True])
def test_feerates(node_factory, anchors):
    opts = {'log-level': 'io',
            'dev-no-fake-fees': True}
    if anchors is False:
        opts['dev-force-features'] = "-23"

    l1 = node_factory.get_node(options=opts, start=False)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', {
        'error': {"errors": ["Insufficient data or no feerate found"], "blocks": 0}
    })
    l1.start()

    # All estimation types
    types = ["opening", "mutual_close", "unilateral_close", "penalty"]

    # Try parsing the feerates, won't work because can't estimate
    for t in types:
        with pytest.raises(RpcError, match=r'Cannot estimate fees'):
            feerate = l1.rpc.parsefeerate(t)

    # Query feerates (shouldn't give any!)
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']) == 4)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 2**32 - 1
    assert feerates['perkw']['min_acceptable'] == 253
    assert feerates['perkw']['min_acceptable'] == 253
    assert feerates['perkw']['floor'] == 253
    assert feerates['perkw']['estimates'] == []
    for t in types:
        assert t not in feerates['perkw']

    feerates = l1.rpc.feerates('perkb')
    assert feerates['warning_missing_feerates'] == 'Some fee estimates unavailable: bitcoind startup?'
    assert 'perkw' not in feerates
    assert feerates['perkb']['max_acceptable'] == (2**32 - 1)
    assert feerates['perkb']['min_acceptable'] == 253 * 4
    # Note: This is floored at the FEERATE_FLOOR constant (253)
    assert feerates['perkb']['floor'] == 1012
    assert feerates['perkb']['estimates'] == []
    for t in types:
        assert t not in feerates['perkb']

    # Now try setting them, one at a time.
    # Set CONSERVATIVE/2 feerate, for max
    l1.set_feerates((15000, 0, 0, 0), True)
    # Make sure it's digested the bcli plugin results.
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']['estimates']) == 1)
    feerates = l1.rpc.feerates('perkw')
    # We only get the warning if *no* feerates are avail.
    assert 'warning_missing_feerates' not in feerates
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10

    # With only one data point, this is a terrible guess!
    assert feerates['perkw']['min_acceptable'] == 15000 // 2
    assert feerates['perkw']['estimates'] == [{'blockcount': 2,
                                               'feerate': 15000,
                                               'smoothed_feerate': 15000}]

    # Set ECONOMICAL/6 feerate, for unilateral_close and htlc_resolution
    l1.set_feerates((15000, 11000, 0, 0), True)
    # Make sure it's digested the bcli plugin results.
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']['estimates']) == 2)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['unilateral_close'] == 11000
    assert 'warning_missing_feerates' not in feerates
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    # With only two data points, this is a terrible guess!
    assert feerates['perkw']['min_acceptable'] == 11000 // 2
    assert feerates['perkw']['estimates'] == [{'blockcount': 2,
                                               'feerate': 15000,
                                               'smoothed_feerate': 15000},
                                              {'blockcount': 6,
                                               'feerate': 11000,
                                               'smoothed_feerate': 11000}]

    # Set ECONOMICAL/12 feerate, for all but min (so, no mutual_close feerate)
    l1.set_feerates((15000, 11000, 6250, 0), True)
    # Make sure it's digested the bcli plugin results.
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']['estimates']) == 3)
    feerates = l1.rpc.feerates('perkb')
    assert feerates['perkb']['unilateral_close'] == 11000 * 4
    # We dont' extrapolate, so it uses the same for mutual_close
    assert feerates['perkb']['mutual_close'] == 6250 * 4
    for t in types:
        if t not in ("unilateral_close", "htlc_resolution", "mutual_close"):
            assert feerates['perkb'][t] == 25000
    assert 'warning_missing_feerates' not in feerates
    assert 'perkw' not in feerates
    assert feerates['perkb']['max_acceptable'] == 15000 * 4 * 10
    # With only three data points, this is a terrible guess!
    assert feerates['perkb']['min_acceptable'] == 6250 // 2 * 4
    assert feerates['perkb']['estimates'] == [{'blockcount': 2,
                                               'feerate': 15000 * 4,
                                               'smoothed_feerate': 15000 * 4},
                                              {'blockcount': 6,
                                               'feerate': 11000 * 4,
                                               'smoothed_feerate': 11000 * 4},
                                              {'blockcount': 12,
                                               'feerate': 6250 * 4,
                                               'smoothed_feerate': 6250 * 4}]

    # Set ECONOMICAL/100 feerate for min and mutual_close
    l1.set_feerates((15000, 11000, 6250, 5000), True)
    # Make sure it's digested the bcli plugin results.
    wait_for(lambda: len(l1.rpc.feerates('perkw')['perkw']['estimates']) == 4)
    feerates = l1.rpc.feerates('perkw')
    assert feerates['perkw']['unilateral_close'] == 11000
    assert feerates['perkw']['mutual_close'] == 5000
    for t in types:
        if t not in ("unilateral_close", "htlc_resolution", "mutual_close"):
            assert feerates['perkw'][t] == 25000 // 4
    assert 'warning_missing_feerates' not in feerates
    assert 'perkb' not in feerates
    assert feerates['perkw']['max_acceptable'] == 15000 * 10
    assert feerates['perkw']['min_acceptable'] == 5000 // 2
    assert feerates['perkw']['estimates'] == [{'blockcount': 2,
                                               'feerate': 15000,
                                               'smoothed_feerate': 15000},
                                              {'blockcount': 6,
                                               'feerate': 11000,
                                               'smoothed_feerate': 11000},
                                              {'blockcount': 12,
                                               'feerate': 6250,
                                               'smoothed_feerate': 6250},
                                              {'blockcount': 100,
                                               'feerate': 5000,
                                               'smoothed_feerate': 5000}]

    assert len(feerates['onchain_fee_estimates']) == 6
    assert feerates['onchain_fee_estimates']['opening_channel_satoshis'] == feerates['perkw']['opening'] * 702 // 1000
    assert feerates['onchain_fee_estimates']['mutual_close_satoshis'] == feerates['perkw']['mutual_close'] * 673 // 1000
    if anchors:
        assert feerates['onchain_fee_estimates']['unilateral_close_satoshis'] == feerates['perkw']['unilateral_anchor_close'] * 1112 // 1000
    else:
        assert feerates['onchain_fee_estimates']['unilateral_close_satoshis'] == feerates['perkw']['unilateral_close'] * 598 // 1000
    assert feerates['onchain_fee_estimates']['unilateral_close_nonanchor_satoshis'] == feerates['perkw']['unilateral_close'] * 598 // 1000
    # htlc resolution currently uses 6 block estimate
    htlc_feerate = [f['feerate'] for f in feerates['perkw']['estimates'] if f['blockcount'] == 6][0]
    htlc_timeout_cost = feerates["onchain_fee_estimates"]["htlc_timeout_satoshis"]
    htlc_success_cost = feerates["onchain_fee_estimates"]["htlc_success_satoshis"]

    # Try parsing the feerates, won't work because can't estimate
    for t in types:
        feerate = l1.rpc.parsefeerate(t)
        assert feerate['perkw']
        assert 'perkb' not in feerate

    # These are always the non-zero-fee-anchors values.
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

    # Issue #4240
    # Repeated SIGHUP should just re-open the log file
    # and not terminate the daemon.
    logpath_moved_2 = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'logfile_moved_2')
    shutil.move(logpath, logpath_moved_2)
    l1.daemon.proc.send_signal(signal.SIGHUP)
    wait_for(lambda: os.path.exists(logpath_moved_2))
    wait_for(lambda: os.path.exists(logpath))
    wait_for(check_new_log)

    # Multiple log files
    l2 = node_factory.get_node(options={'log-file': ['logfile1', 'logfile2']}, start=False)
    logpath1 = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'logfile1')
    logpath2 = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'logfile2')
    l2.daemon.start(wait_for_initialized=False)

    wait_for(lambda: os.path.exists(logpath1))
    wait_for(lambda: os.path.exists(logpath2))
    wait_for(lambda: os.path.exists(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "lightning-rpc")))
    lines = subprocess.check_output(['cli/lightning-cli',
                                     '--network={}'.format(TEST_NETWORK),
                                     '--lightning-dir={}'
                                     .format(l2.daemon.lightning_dir),
                                     '-H',
                                     'listconfigs']).decode('utf-8').splitlines()
    # Arrays get split awkwardly by -H!
    assert 'log-file=values_str=logfile1' in lines
    assert 'logfile2' in lines

    # Flat mode is better!
    lines = subprocess.check_output(['cli/lightning-cli',
                                     '--network={}'.format(TEST_NETWORK),
                                     '--lightning-dir={}'
                                     .format(l2.daemon.lightning_dir),
                                     '-F',
                                     'listconfigs']).decode('utf-8').splitlines()
    assert 'configs.log-file.values_str[0]=logfile1' in lines
    assert 'configs.log-file.values_str[1]=logfile2' in lines


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
    assert l1.rpc.listconfigs()['configs']['always-use-proxy'] == {'source': os.path.abspath(config) + ":1", 'value_bool': True}
    assert l1.rpc.listconfigs()['configs']['proxy'] == {'source': os.path.abspath(config) + ":2", 'value_str': '127.0.0.1:100'}
    os.chdir(olddir)


def test_json_error(node_factory):
    """Must return valid json even if it quotes our weirdness"""
    l1 = node_factory.get_node()
    l1.rpc.check_request_schemas = False
    with pytest.raises(RpcError, match=r'id: should be a channel ID or short channel ID: invalid token'):
        l1.rpc.close({"tx": "020000000001011490f737edd2ea2175a032b58ea7cd426dfc244c339cd044792096da3349b18a0100000000ffffffff021c900300000000001600140e64868e2f752314bc82a154c8c5bf32f3691bb74da00b00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd0247304402202b2e3195a35dc694bbbc58942dc9ba59cc01d71ba55c9b0ad0610ccd6a65633702201a849254453d160205accc00843efb0ad1fe0e186efa6a7cee1fb6a1d36c736a012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf00000000", "txid": "2128c10f0355354479514f4a23eaa880d94e099406d419bbb0d800143accddbb", "channel_id": "bbddcc3a1400d8b0bb19d40694094ed980a8ea234a4f5179443555030fc12820"})

    # Should not corrupt following RPC
    l1.rpc.getinfo()


def test_check_command(node_factory):
    l1 = node_factory.get_node()

    l1.rpc.check(command_to_check='help')
    l1.rpc.check(command_to_check='help', command='check')
    # Actually checks that command is there!
    with pytest.raises(RpcError, match=r'Unknown command'):
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
    with pytest.raises(RpcError, match=r'should be a 16-bit integer'):
        l1.rpc.check(command_to_check='connect',
                     id='022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59',
                     host='x', port="abcd")

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


def test_bad_onion(node_factory, bitcoind):
    """Test that we get a reasonable error from sendpay when an onion is bad"""
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True,
                                             opts={'log-level': 'io'})

    inv = l4.rpc.invoice(123000, 'test_bad_onion', 'description')
    route = l1.rpc.getroute(l4.info['id'], 123000, 1)['route']

    assert len(route) == 3

    mangled_nodeid = '0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6518'

    # Replace id with a different pubkey, so onion encoded badly at third hop.
    route[2]['id'] = mangled_nodeid
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(inv['payment_hash'])

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
    l1.daemon.wait_for_log(r'failcode .* from onionreply .*{sha}'.format(sha=sha))

    # Replace id with a different pubkey, so onion encoded badly at second hop.
    route[1]['id'] = mangled_nodeid
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(inv['payment_hash'])

    # FIXME: #define PAY_TRY_OTHER_ROUTE		204
    PAY_TRY_OTHER_ROUTE = 204
    assert err.value.error['code'] == PAY_TRY_OTHER_ROUTE
    assert err.value.error['data']['failcode'] == WIRE_INVALID_ONION_HMAC
    assert err.value.error['data']['erring_node'] == mangled_nodeid
    assert err.value.error['data']['erring_channel'] == route[1]['channel']


def test_bad_onion_immediate_peer(node_factory, bitcoind):
    """Test that we handle the malformed msg when we're the origin"""
    l1, l2 = node_factory.line_graph(2, opts={'dev-fail-process-onionpacket': None})

    inv = l2.rpc.invoice(123000, 'test_bad_onion_immediate_peer', 'description')
    route = l1.rpc.getroute(l2.info['id'], 123000, 1)['route']
    assert len(route) == 1

    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError) as err:
        l1.rpc.waitsendpay(inv['payment_hash'])

    # FIXME: #define PAY_UNPARSEABLE_ONION		202
    PAY_UNPARSEABLE_ONION = 202
    assert err.value.error['code'] == PAY_UNPARSEABLE_ONION
    # FIXME: WIRE_INVALID_ONION_HMAC = BADONION|PERM|5
    WIRE_INVALID_ONION_HMAC = 0x8000 | 0x4000 | 5
    assert err.value.error['data']['failcode'] == WIRE_INVALID_ONION_HMAC


def test_newaddr(node_factory, chainparams):
    l1 = node_factory.get_node()
    bech32 = l1.rpc.newaddr('bech32')
    assert 'p2sh-segwit' not in bech32
    assert bech32['bech32'].startswith(chainparams['bip173_prefix'])
    both = l1.rpc.newaddr('all')
    assert 'p2sh-segwit' not in both
    assert both['bech32'].startswith(chainparams['bip173_prefix'])


def test_bitcoind_fail_first(node_factory, bitcoind):
    """Make sure we handle spurious bitcoin-cli failures during startup

    See [#2687](https://github.com/ElementsProject/lightning/issues/2687) for
    details

    """
    # Do not start the lightning node since we need to instrument bitcoind
    # first.
    timeout = 5 if 5 < TIMEOUT // 3 else TIMEOUT // 3
    l1 = node_factory.get_node(start=False,
                               allow_broken_log=True,
                               may_fail=True,
                               options={'bitcoin-retry-timeout': timeout})

    # Instrument bitcoind to fail some queries first.
    def mock_fail(*args):
        raise ValueError()

    # If any of these succeed, they reset fail timeout.
    l1.daemon.rpcproxy.mock_rpc('getblockhash', mock_fail)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', mock_fail)
    l1.daemon.rpcproxy.mock_rpc('getmempoolinfo', mock_fail)

    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    l1.daemon.wait_for_logs([r'getblockhash [a-z0-9]* exited with status 1',
                             r'Unable to estimate any fees',
                             r'BROKEN.*we have been retrying command for --bitcoin-retry-timeout={} seconds'.format(timeout)])
    # Will exit with failure code.
    assert l1.daemon.wait() == 1

    # Now unset the mock, so calls go through again
    l1.daemon.rpcproxy.mock_rpc('getblockhash', None)
    l1.daemon.rpcproxy.mock_rpc('estimatesmartfee', None)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Fees on elements are different")
@pytest.mark.parametrize("anchors", [False, True])
def test_bitcoind_feerate_floor(node_factory, bitcoind, anchors):
    """Don't return a feerate less than minrelaytxfee/mempoolminfee."""
    opts = {}
    if anchors is False:
        opts['dev-force-features'] = "-23"
    l1 = node_factory.get_node(options=opts)

    assert l1.rpc.feerates('perkb') == {
        "perkb": {
            "opening": 30000,
            "mutual_close": 15000,
            "unilateral_close": 44000,
            'unilateral_anchor_close': 15000,
            "penalty": 30000,
            "min_acceptable": 7500,
            "max_acceptable": 600000,
            "floor": 1012,
            "estimates": [{"blockcount": 2,
                           "feerate": 60000,
                           "smoothed_feerate": 60000},
                          {"blockcount": 6,
                           "feerate": 44000,
                           "smoothed_feerate": 44000},
                          {"blockcount": 12,
                           "feerate": 30000,
                           "smoothed_feerate": 30000},
                          {"blockcount": 100,
                           "feerate": 15000,
                           "smoothed_feerate": 15000}],
        },
        "onchain_fee_estimates": {
            "opening_channel_satoshis": 5265,
            "mutual_close_satoshis": 2523,
            "unilateral_close_satoshis": 4170 if anchors else 6578,
            "unilateral_close_nonanchor_satoshis": 6578,
            # These are always the non-anchor versions!
            "htlc_timeout_satoshis": 7293,
            "htlc_success_satoshis": 7733,
        }
    }

    l1.daemon.rpcproxy.mock_rpc('getmempoolinfo',
                                {
                                    "mempoolminfee": 0.00010001,
                                    "minrelaytxfee": 0.00020001
                                })
    l1.restart()
    assert l1.rpc.feerates('perkb') == {
        "perkb": {
            "opening": 30000,
            # This has increased (rounded up)
            "mutual_close": 20004,
            # This has increased (rounded up)
            "unilateral_anchor_close": 20004,
            # This has increased (rounded up)
            "unilateral_close": 44000,
            "penalty": 30000,
            # This has increased (rounded up)
            "min_acceptable": 20004,
            "max_acceptable": 600000,
            "floor": 20004,
            "estimates": [{"blockcount": 2,
                           "feerate": 60000,
                           "smoothed_feerate": 60000},
                          {"blockcount": 6,
                           "feerate": 44000,
                           "smoothed_feerate": 44000},
                          {"blockcount": 12,
                           "feerate": 30000,
                           "smoothed_feerate": 30000},
                          {"blockcount": 100,
                           "feerate": 20004,
                           "smoothed_feerate": 20004}],
        },
        "onchain_fee_estimates": {
            "opening_channel_satoshis": 5265,
            # This increases too
            "mutual_close_satoshis": 3365,
            "unilateral_close_satoshis": 5561 if anchors else 6578,
            "unilateral_close_nonanchor_satoshis": 6578,
            "htlc_timeout_satoshis": 7293,
            "htlc_success_satoshis": 7733,
        }
    }

    l1.daemon.rpcproxy.mock_rpc('getmempoolinfo',
                                {
                                    "mempoolminfee": 0.00030001,
                                    "minrelaytxfee": 0.00010001
                                })
    l1.restart()
    assert l1.rpc.feerates('perkb') == {
        "perkb": {
            # This has increased (rounded up!)
            "opening": 30004,
            # This has increased (rounded up!)
            "mutual_close": 30004,
            # This has increased (rounded up!)
            "unilateral_anchor_close": 30004,
            "unilateral_close": 44000,
            # This has increased (rounded up!)
            "penalty": 30004,
            # This has increased (rounded up)
            "min_acceptable": 30004,
            "max_acceptable": 600000,
            "floor": 30004,
            "estimates": [{"blockcount": 2,
                           "feerate": 60000,
                           "smoothed_feerate": 60000},
                          {"blockcount": 6,
                           "feerate": 44000,
                           "smoothed_feerate": 44000},
                          # This has increased (rounded up!)
                          {"blockcount": 12,
                           "feerate": 30004,
                           "smoothed_feerate": 30004},
                          # This has increased (rounded up!)
                          {"blockcount": 100,
                           "feerate": 30004,
                           "smoothed_feerate": 30004}],
        },
        "onchain_fee_estimates": {
            "opening_channel_satoshis": 5265,
            # This increases too
            "mutual_close_satoshis": 5048,
            # This increases too (anchors uses min(100blocks,5 sat/vB))
            "unilateral_close_satoshis": 8341 if anchors else 6578,
            "unilateral_close_nonanchor_satoshis": 6578,
            "htlc_timeout_satoshis": 7293,
            "htlc_success_satoshis": 7733,
        }
    }


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
    with pytest.raises(RpcError, match=r"msec: should be an integer: invalid token"):
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
    with pytest.raises(RpcError, match=r"msec: should be an integer: invalid token"):
        l1.rpc.call('dev', {'subcommand': 'slowcmd', 'msec': 'aaa'})
    with pytest.raises(RpcError, match=r"msec: should be an integer: invalid token"):
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


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_list_features_only(node_factory):
    features = subprocess.check_output(['lightningd/lightningd',
                                        '--list-features-only']).decode('utf-8').splitlines()
    expected = ['option_data_loss_protect/even',
                'option_upfront_shutdown_script/odd',
                'option_gossip_queries/even',
                'option_var_onion_optin/even',
                'option_gossip_queries_ex/odd',
                'option_static_remotekey/even',
                'option_payment_secret/even',
                'option_basic_mpp/odd',
                'option_support_large_channel/odd',
                'option_anchors_zero_fee_htlc_tx/odd',
                'option_route_blinding/odd',
                'option_shutdown_anysegwit/odd',
                'option_channel_type/odd',
                'option_scid_alias/odd',
                'option_zeroconf/odd']
    expected += ['supports_open_accept_channel_type']

    assert features == expected


def test_relative_config_dir(node_factory):
    l1 = node_factory.get_node(start=False)
    initial_dir = os.getcwd()
    lndir = l1.daemon.opts.get("lightning-dir")[:-1]
    *root_dir, l1.daemon.opts["lightning-dir"] = lndir.split('/')
    os.chdir('/'.join(root_dir))
    l1.daemon.executable = os.path.join(initial_dir, l1.daemon.executable)
    l1.start()
    assert os.path.isabs(l1.rpc.listconfigs()['configs']["lightning-dir"]['value_str'])
    l1.stop()
    os.chdir(initial_dir)


def test_signmessage(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)
    l1.rpc.jsonschemas = {}

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

        # Of course, we know our own pubkey
        if c[3] == l1.info['id']:
            assert l1.rpc.checkmessage(c[1], c[2])['verified']
        else:
            # It will error, as it can't verify.
            with pytest.raises(RpcError, match="pubkey not found in the graph") as err:
                l1.rpc.checkmessage(c[1], c[2])

            # But error contains the key which it claims.
            assert err.value.error['data']['claimed_key'] == c[3]

    # l2 knows about l1, so it can validate it.
    zm = l1.rpc.signmessage(message="message for you")['zbase']
    checknokey = l2.rpc.checkmessage(message="message for you", zbase=zm)
    assert checknokey['pubkey'] == l1.info['id']
    assert checknokey['verified']
    # check that checkmassage used with a wrong zbase format throws an RPC exception
    with pytest.raises(RpcError, match="zbase is not valid zbase32"):
        l2.rpc.checkmessage(message="wrong zbase format", zbase="wrong zbase format")


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

    assert l1.rpc.listconfigs('alias')['configs']['alias'] == {'source': os.path.join(subdir, "conf2") + ":1", 'value_str': 'conf2'}


def test_config_in_subdir(node_factory, chainparams):
    l1 = node_factory.get_node(start=False)
    network = chainparams['name']

    subdir = os.path.join(l1.daemon.opts.get("lightning-dir"), network)
    with open(os.path.join(subdir, "config"), 'w') as f:
        f.write('alias=test_config_in_subdir')
    l1.start()

    assert l1.rpc.listconfigs('alias')['configs']['alias'] == {'source': os.path.join(subdir, "config") + ":1", 'value_str': 'test_config_in_subdir'}

    l1.stop()

    # conf is not allowed in any config file.
    with open(os.path.join(l1.daemon.opts.get("lightning-dir"), "config"), 'w') as f:
        f.write('conf={}/conf'.format(network))

    out = subprocess.run(['lightningd/lightningd',
                          '--lightning-dir={}'.format(l1.daemon.opts.get("lightning-dir"))],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT)
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
    assert "network={}: not permitted in network-specific configuration files".format(network) in out.stderr.decode('utf-8')

    # lightning-dir only allowed if we explicitly use --conf
    os.unlink(os.path.join(subdir, "config"))
    with open(os.path.join(l1.daemon.opts.get("lightning-dir"), "config"), 'w') as f:
        f.write('lightning-dir={}/test'.format(l1.daemon.opts.get("lightning-dir")))

    out = subprocess.run(['lightningd/lightningd',
                          '--lightning-dir={}'.format(l1.daemon.opts.get("lightning-dir"))],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert out.returncode == 1
    assert "lightning-dir={}/test: not permitted in implicit configuration files".format(l1.daemon.opts.get("lightning-dir")) in out.stderr.decode('utf-8')

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
    l1.daemon.start(wait_for_initialized=False)
    # Will exit with failure code.
    assert l1.daemon.wait() == 1

    # Should create these
    assert os.path.isfile(os.path.join(netdir, "hsm_secret"))
    assert not os.path.isfile(os.path.join(basedir, "hsm_secret"))
    assert not os.path.isfile(os.path.join(netdir, "lightningd-bitcoin.pid"))
    assert os.path.isfile(os.path.join(basedir, "lightningd-bitcoin.pid"))


def test_unicode_rpc(node_factory, executor, bitcoind):
    node = node_factory.get_node()
    desc = "Some candy 🍬 and a nice glass of milk 🥛."

    node.rpc.invoice(amount_msat=42, label=desc, description=desc)
    invoices = node.rpc.listinvoices()['invoices']
    assert(len(invoices) == 1)
    assert(invoices[0]['description'] == desc)
    assert(invoices[0]['label'] == desc)


@unittest.skipIf(VALGRIND, "Testing pyln doesn't exercise anything interesting in the c code.")
def test_unix_socket_path_length(node_factory, bitcoind, directory, executor, db_provider, test_base_dir):
    lightning_dir = os.path.join(directory, "anode" + "far" * 30 + "away")
    os.makedirs(lightning_dir)
    db = db_provider.get_db(lightning_dir, "test_unix_socket_path_length", 1)
    db.provider = db_provider

    l1 = LightningNode(1, lightning_dir, bitcoind, executor, VALGRIND, db=db, port=reserve())

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

    # Developer mode polls bitcoind every second, so 60 seconds is plenty.
    time = 60

    # Should not succeed yet.
    fut2 = executor.submit(node.rpc.waitblockheight, blockheight + 2, time)
    fut1 = executor.submit(node.rpc.waitblockheight, blockheight + 1, time)
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


def test_sendcustommsg(node_factory):
    """Check that we can send custommsgs to peers in various states.

    `l2` is the node under test. `l1` has a channel with `l2` and should
    therefore be attached to `channeld`. `l4` is just connected, so it should
    be attached to `openingd`. `l3` has a channel open, but is disconnected
    and we can't send to it.

    """
    opts = {'log-level': 'io', 'plugin': [
        os.path.join(os.path.dirname(__file__), "plugins", "custommsg_b.py"),
        os.path.join(os.path.dirname(__file__), "plugins", "custommsg_a.py")
    ]}
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)
    node_factory.join_nodes([l1, l2, l3])
    l2.connect(l4)
    l3.stop()
    msg = 'aa' + ('ff' * 30) + 'bb'

    # This address doesn't exist so we should get an error when we try sending
    # a message to it.
    node_id = '02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f'
    with pytest.raises(RpcError, match=r'No such peer'):
        l1.rpc.sendcustommsg(node_id, msg)

    # `l3` is disconnected and we can't send messages to it
    wait_for(lambda: l2.rpc.listpeers(l3.info['id'])['peers'][0]['connected'] is False)
    with pytest.raises(RpcError, match=r'Peer is not connected'):
        l2.rpc.sendcustommsg(l3.info['id'], msg)

    # We should not be able to send a bogus `ping` message, since it collides
    # with a message defined in the spec, and could potentially mess up our
    # internal state.
    with pytest.raises(RpcError, match=r'Cannot send messages of type 18 .WIRE_PING.'):
        l2.rpc.sendcustommsg(l2.info['id'], r'0012')

    # This should work since the peer is currently owned by `channeld`
    l2.rpc.sendcustommsg(l1.info['id'], msg)
    l2.daemon.wait_for_log(
        r'{peer_id}-{owner}: \[OUT\] {msg}'.format(
            owner='connectd', msg=msg, peer_id=l1.info['id']
        )
    )
    l1.daemon.wait_for_log(r'\[IN\] {}'.format(msg))
    l1.daemon.wait_for_logs([
        r'Got custommessage_a {msg} from peer {peer_id}'.format(
            msg=msg, peer_id=l2.info['id']),
        r'Got custommessage_b {msg} from peer {peer_id}'.format(
            msg=msg, peer_id=l2.info['id'])
    ])

    # This should work since the peer is currently owned by `openingd`
    l2.rpc.sendcustommsg(l4.info['id'], msg)
    l2.daemon.wait_for_log(
        r'{peer_id}-{owner}: \[OUT\] {msg}'.format(
            owner='connectd', msg=msg, peer_id=l4.info['id']
        )
    )
    l4.daemon.wait_for_log(r'\[IN\] {}'.format(msg))
    l4.daemon.wait_for_logs([
        r'Got custommessage_a {msg} from peer {peer_id}'.format(
            msg=msg, peer_id=l2.info['id']),
        r'Got custommessage_b {msg} from peer {peer_id}'.format(
            msg=msg, peer_id=l2.info['id']),
    ])


def test_custommsg_triggers_notification(node_factory):
    """Check that a notification is triggered when a node receives
    a custommsg.

    We'll send a message from l2 to l1 and verify that l1 received
    the appropriate notification
    """
    plugin_path = os.path.join(os.path.dirname(__file__), "plugins", "custommsg_notification.py")
    l1: LightningNode = node_factory.get_node(options={"plugin": plugin_path})
    l2: LightningNode = node_factory.get_node()

    # Connect l1 to l2
    l1.connect(l2)
    wait_for(lambda: [p['connected'] for p in l2.rpc.listpeers(l1.info['id'])['peers']] == [True])

    # Send a custommsg from l2 to l1
    # The message id 7777 is chosen to be sufficiently high and shouldn't be used by the
    # lightning spec
    l2.rpc.sendcustommsg(l1.info['id'], "77770012")

    # TODO: Check if the peer_id and payload matches
    peer_id = l2.info["id"]
    l1.daemon.wait_for_log(f"Received a custommsg with data")
    l1.daemon.wait_for_log(f"peer_id={peer_id}")
    l1.daemon.wait_for_log(f"payload=77770012")


def test_makesecret(node_factory):
    """
    Test makesecret command.
    """

    l1 = node_factory.get_node(options={"dev-force-privkey": "1212121212121212121212121212121212121212121212121212121212121212"})
    secret = l1.rpc.makesecret("73636220736563726574")["secret"]

    assert (secret == "a9a2e742405c28f059349132923a99337ae7f71168b7485496e3365f5bc664ed")

    # Same if we do it by parameter name
    assert l1.rpc.makesecret(hex="73636220736563726574")["secret"] == secret

    # Changing seed changes secret!
    assert l1.rpc.makesecret(hex="73636220736563726575")["secret"] != secret
    assert l1.rpc.makesecret(hex="736362207365637265")["secret"] != secret
    assert l1.rpc.makesecret(hex="7363622073656372657401")["secret"] != secret

    # Using string works!
    assert l1.rpc.makesecret(string="scb secret")["secret"] == secret
    assert l1.rpc.makesecret(None, "scb secret")["secret"] == secret


def test_staticbackup(node_factory):
    """
    Test staticbackup
    """
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {}])
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    c12, _ = l1.fundchannel(l2, 10**5)

    # Comparing the channelID, scb_chan has the channel ID starting from the 8th byte
    # and it's own length is 32 byte, hence 16 + 64.
    assert (len(l1.rpc.staticbackup()["scb"]) == 1
            and l1.rpc.staticbackup()["scb"][0][16: 16 + 64] == _["channel_id"])


def test_recoverchannel(node_factory):
    """
    Test recoverchannel
    """
    l1 = node_factory.get_node()
    stubs = l1.rpc.recoverchannel(["0000000000000001c3a7b9d74a174497122bc52d74d6d69836acadc77e0429c6d8b68b48d5c9139a022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d5904017f0000019f0bc3a7b9d74a174497122bc52d74d6d69836acadc77e0429c6d8b68b48d5c9139a0000000000000000000186a000021000"])["stubs"]

    assert len(stubs) == 1
    assert stubs[0] == "c3a7b9d74a174497122bc52d74d6d69836acadc77e0429c6d8b68b48d5c9139a"


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "deletes database, which is assumed sqlite3")
def test_emergencyrecover(node_factory, bitcoind):
    """
    Test emergencyrecover
    """
    l1, l2 = node_factory.get_nodes(2, opts=[{'allow_broken_log': True, 'may_reconnect': True},
                                             {'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    c12, _ = l1.fundchannel(l2, 10**5)
    stubs = l1.rpc.emergencyrecover()["stubs"]
    assert l1.daemon.is_in_log('channel {} already exists!'.format(_['channel_id']))

    l1.stop()

    os.unlink(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3"))

    l1.start()
    assert l1.daemon.is_in_log('Server started with public key')
    stubs = l1.rpc.emergencyrecover()["stubs"]
    assert len(stubs) == 1
    assert stubs[0] == _["channel_id"]
    assert l1.daemon.is_in_log('channel {} already exists!'.format(_['channel_id']))

    listfunds = l1.rpc.listfunds()["channels"][0]
    assert listfunds["short_channel_id"] == "1x1x1"

    l1.daemon.wait_for_log('peer_out WIRE_ERROR')
    l2.daemon.wait_for_log('State changed from CHANNELD_NORMAL to AWAITING_UNILATERAL')

    bitcoind.generate_block(5, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])

    l1.daemon.wait_for_log(r'All outputs resolved.*')
    wait_for(lambda: l1.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN")
    # Check if funds are recovered.
    assert l1.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN"
    assert l2.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN"


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "sqlite3-specific DB rollback")
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_recover_plugin(node_factory, bitcoind):
    l1 = node_factory.get_node(
        may_reconnect=True,
        allow_warning=True,
        feerates=(7500, 7500, 7500, 7500),
        options={
            'log-level': 'info',
            'experimental-peer-storage': None
        },
    )
    l2 = node_factory.get_node(
        may_reconnect=True,
        feerates=(7500, 7500, 7500, 7500),
        allow_broken_log=True,
        allow_bad_gossip=True,
        options={
            'log-level': 'info',
            'experimental-peer-storage': None
        },
    )

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.fundchannel(l1, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2])

    l2.stop()

    # Save copy of the db.
    dbpath = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3")
    orig_db = open(dbpath, "rb").read()

    l2.start()

    assert l2.daemon.is_in_log('Server started with public key')
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)

    # successful payments
    i31 = l1.rpc.invoice(10000, 'i31', 'desc')
    l2.rpc.pay(i31['bolt11'])

    # Now, move l2 back in time.
    l2.stop()

    # Overwrite with OLD db.
    open(dbpath, "wb").write(orig_db)

    l2.start()

    # Force a reconnect, so l2 learns that it went back in time.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Starting the node again causes it to reconnect, and discover
    # that it lost state. This in turn causes the peer to close the
    # channel for us. Here we wait for the close transaction.
    bitcoind.generate_block(5, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])

    l2.daemon.wait_for_log(f"{l1.info['id']}-chan#1: State changed from FUNDING_SPEND_SEEN to ONCHAIN")
    wait_for(lambda: l2.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN")

    # Both channels should go ONCHAIN!
    assert l2.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN"


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "deletes database, which is assumed sqlite3")
def test_restorefrompeer(node_factory, bitcoind):
    """
    Test restorefrompeer
    """
    l1, l2 = node_factory.get_nodes(2, [{'allow_broken_log': True,
                                         'experimental-peer-storage': None,
                                         'may_reconnect': True,
                                         'allow_bad_gossip': True},
                                        {'experimental-peer-storage': None,
                                         'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    c12, _ = l1.fundchannel(l2, 10**5)
    assert l1.daemon.is_in_log('Peer storage sent!')
    assert l2.daemon.is_in_log('Peer storage sent!')

    l1.stop()
    os.unlink(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3"))

    l1.start()
    assert l1.daemon.is_in_log('Server started with public key')

    # If this happens fast enough, connect fails with "disconnected
    # during connection"
    try:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    except RpcError as err:
        assert "disconnected during connection" in err.error['message']

    l1.daemon.wait_for_log('peer_in WIRE_YOUR_PEER_STORAGE')

    assert l1.rpc.restorefrompeer()['stubs'][0] == _['channel_id']

    l1.daemon.wait_for_log('peer_out WIRE_ERROR')
    l2.daemon.wait_for_log('State changed from CHANNELD_NORMAL to AWAITING_UNILATERAL')

    bitcoind.generate_block(5, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])

    l1.daemon.wait_for_log(r'All outputs resolved.*')
    wait_for(lambda: l1.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN")

    # Check if funds are recovered.
    assert l1.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN"
    assert l2.rpc.listfunds()["channels"][0]["state"] == "ONCHAIN"


def test_commitfee_option(node_factory):
    """Sanity check for the --commit-fee startup option."""
    l1, l2 = node_factory.get_nodes(2, opts=[{"commit-fee": "200",
                                              "start": False},
                                             {"start": False}])

    # set_feerates multiplies this by 4 to get perkb; but we divide.
    mock_wu = 5000
    for l in [l1, l2]:
        l.set_feerates((0, mock_wu, 0, 0), False)
        l.start()

    # plugin gives same results:
    assert l1.rpc.call("estimatefees") == l2.rpc.call("estimatefees")

    # But feerates differ.
    l1_commit_fees = l1.rpc.feerates("perkw")['perkw']['unilateral_close']
    l2_commit_fees = l2.rpc.feerates("perkw")['perkw']['unilateral_close']

    assert l1_commit_fees == 2 * l2_commit_fees == 2 * mock_wu


def test_listtransactions(node_factory):
    """Sanity check for the listtransactions RPC command"""
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {}])

    wallettxid = l1.openchannel(l2, 10**5)["wallettxid"]
    txids = [i["txid"] for tx in l1.rpc.listtransactions()["transactions"]
             for i in tx["inputs"]]
    # The txid of the transaction funding the channel is present, and
    # represented as little endian (like bitcoind and explorers).
    assert wallettxid in txids


def test_listfunds(node_factory):
    """Test listfunds command."""
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {}])

    open_txid = l1.openchannel(l2, 10**5)["wallettxid"]

    # unspent outputs
    utxos = l1.rpc.listfunds()["outputs"]

    # only 1 unspent output should be available
    assert len(utxos) == 1

    # both unspent and spent outputs
    all_outputs = l1.rpc.listfunds(spent=True)["outputs"]
    txids = [output['txid'] for output in all_outputs]

    # 1 spent output (channel opening) and 1 unspent output
    assert len(all_outputs) == 2
    assert open_txid in txids


def test_listforwards_and_listhtlcs(node_factory, bitcoind):
    """Test listforwards and listhtlcs commands."""
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=[{}, {}, {}, {}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)

    c12, c12res = l1.fundchannel(l2, 10**5)
    c23, _ = l2.fundchannel(l3, 10**5)
    c24, _ = l2.fundchannel(l4, 10**5)

    # Wait until channels are active
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])
    l1.wait_channel_active(c23)
    l1.wait_channel_active(c24)

    # successful payments
    i31 = l3.rpc.invoice(1000, 'i31', 'desc')
    l1.rpc.pay(i31['bolt11'])

    i41 = l4.rpc.invoice(2000, 'i41', 'desc')
    l1.rpc.pay(i41['bolt11'])

    # failed payment
    failed_inv = l3.rpc.invoice(4000, 'failed', 'desc')
    failed_route = l1.rpc.getroute(l3.info['id'], 4000, 1)['route']

    l2.rpc.close(c23)

    with pytest.raises(RpcError):
        l1.rpc.sendpay(failed_route, failed_inv['payment_hash'], payment_secret=failed_inv['payment_secret'])
        l1.rpc.waitsendpay(failed_inv['payment_hash'])

    all_forwards = l2.rpc.listforwards()['forwards']
    assert len(all_forwards) == 3

    # Not guaranteed to be in chronological order!
    all_forwards.sort(key=lambda f: f['in_htlc_id'])
    assert all_forwards[0]['in_channel'] == c12
    assert all_forwards[0]['out_channel'] == c23
    assert all_forwards[0]['in_htlc_id'] == 0
    assert all_forwards[0]['out_htlc_id'] == 0
    assert all_forwards[1]['in_channel'] == c12
    assert all_forwards[1]['out_channel'] == c24
    assert all_forwards[1]['in_htlc_id'] == 1
    assert all_forwards[1]['out_htlc_id'] == 0
    assert all_forwards[2]['in_channel'] == c12
    assert all_forwards[2]['out_channel'] == c23
    assert all_forwards[2]['in_htlc_id'] == 2
    assert 'out_htlc_id' not in all_forwards[2]

    # status=settled
    settled_forwards = l2.rpc.listforwards(status='settled')['forwards']
    assert len(settled_forwards) == 2
    assert sum(x['out_msat'] for x in settled_forwards) == 3000

    # status=local_failed
    failed_forwards = l2.rpc.listforwards(status='local_failed')['forwards']
    assert len(failed_forwards) == 1

    # in_channel=c23
    c23_forwards = l2.rpc.listforwards(in_channel=c23, status='settled')['forwards']
    assert len(c23_forwards) == 0

    # out_channel=c24
    c24_forwards = l2.rpc.listforwards(out_channel=c24)['forwards']
    assert len(c24_forwards) == 1

    # listhtlcs on l1 is the same with or without id specifiers
    c1htlcs = l1.rpc.listhtlcs()['htlcs']
    assert l1.rpc.listhtlcs(c12)['htlcs'] == c1htlcs
    assert l1.rpc.listhtlcs(c12res['channel_id'])['htlcs'] == c1htlcs
    c1htlcs.sort(key=lambda h: h['id'])
    assert [h['id'] for h in c1htlcs] == [0, 1, 2]
    assert [h['short_channel_id'] for h in c1htlcs] == [c12] * 3
    assert [h['amount_msat'] for h in c1htlcs] == [Millisatoshi(1001),
                                                   Millisatoshi(2001),
                                                   Millisatoshi(4001)]
    assert [h['direction'] for h in c1htlcs] == ['out'] * 3
    assert [h['state'] for h in c1htlcs] == ['RCVD_REMOVE_ACK_REVOCATION'] * 3

    # These should be a mirror!
    c2c1htlcs = l2.rpc.listhtlcs(c12)['htlcs']
    for h in c2c1htlcs:
        assert h['state'] == 'SENT_REMOVE_ACK_REVOCATION'
        assert h['direction'] == 'in'
        h['state'] = 'RCVD_REMOVE_ACK_REVOCATION'
        h['direction'] = 'out'
    assert c2c1htlcs == c1htlcs

    # One channel at a time should result in all htlcs.
    allhtlcs = l2.rpc.listhtlcs()['htlcs']
    parthtlcs = (l2.rpc.listhtlcs(c12)['htlcs']
                 + l2.rpc.listhtlcs(c23)['htlcs']
                 + l2.rpc.listhtlcs(c24)['htlcs'])
    assert len(allhtlcs) == len(parthtlcs)
    for h in allhtlcs:
        assert h in parthtlcs

    # Now, close and forget.
    l2.rpc.close(c24)
    l2.rpc.close(c12)

    bitcoind.generate_block(100, wait_for_mempool=3)

    # Once channels are gone, htlcs are gone.
    for n in (l1, l2, l3, l4):
        # They might reconnect, but still will have no channels
        wait_for(lambda: n.rpc.listpeerchannels()['channels'] == [])
        assert n.rpc.listhtlcs() == {'htlcs': []}

    # But forwards are not forgotten!
    assert l2.rpc.listforwards()['forwards'] == all_forwards

    # Now try delforward!
    with pytest.raises(RpcError, match="Could not find that forward") as exc_info:
        l2.rpc.delforward(in_channel=c12, in_htlc_id=3, status='settled')
    # static const errcode_t DELFORWARD_NOT_FOUND = 1401;
    assert exc_info.value.error['code'] == 1401

    l2.rpc.delforward(in_channel=c12, in_htlc_id=0, status='settled')
    l2.rpc.delforward(in_channel=c12, in_htlc_id=1, status='settled')
    l2.rpc.delforward(in_channel=c12, in_htlc_id=2, status='local_failed')
    assert l2.rpc.listforwards() == {'forwards': []}


def test_listforwards_wait(node_factory, executor):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    scid12 = first_scid(l1, l2)
    scid23 = first_scid(l2, l3)
    waitres = l1.rpc.wait(subsystem='forwards', indexname='created', nextvalue=0)
    assert waitres == {'subsystem': 'forwards',
                       'created': 0}

    # Now ask for 1.
    waitcreate = executor.submit(l2.rpc.wait, subsystem='forwards', indexname='created', nextvalue=1)
    waitupdate = executor.submit(l2.rpc.wait, subsystem='forwards', indexname='updated', nextvalue=1)
    time.sleep(1)

    amt1 = 1000
    inv1 = l3.rpc.invoice(amt1, 'inv1', 'desc')
    l1.rpc.pay(inv1['bolt11'])

    waitres = waitcreate.result(TIMEOUT)
    assert waitres == {'subsystem': 'forwards',
                       'created': 1,
                       'details': {'in_channel': scid12,
                                   'in_htlc_id': 0,
                                   'in_msat': Millisatoshi(amt1 + 1),
                                   'out_channel': scid23,
                                   'status': 'offered'}}
    waitres = waitupdate.result(TIMEOUT)
    assert waitres == {'subsystem': 'forwards',
                       'updated': 1,
                       'details': {'in_channel': scid12,
                                   'in_htlc_id': 0,
                                   'in_msat': Millisatoshi(amt1 + 1),
                                   'out_channel': scid23,
                                   'status': 'settled'}}

    # Now check failure.
    amt2 = 42
    inv2 = l3.rpc.invoice(amt2, 'inv2', 'invdesc2')
    l3.rpc.delinvoice('inv2', 'unpaid')

    waitcreate = executor.submit(l2.rpc.wait, subsystem='forwards', indexname='created', nextvalue=2)
    waitupdate = executor.submit(l2.rpc.wait, subsystem='forwards', indexname='updated', nextvalue=2)
    time.sleep(1)

    with pytest.raises(RpcError, match="WIRE_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS"):
        l1.rpc.pay(inv2['bolt11'])

    waitres = waitcreate.result(TIMEOUT)
    assert waitres == {'subsystem': 'forwards',
                       'created': 2,
                       'details': {'in_channel': scid12,
                                   'in_htlc_id': 1,
                                   'in_msat': Millisatoshi(amt2 + 1),
                                   'out_channel': scid23,
                                   'status': 'offered'}}
    waitres = waitupdate.result(TIMEOUT)
    assert waitres == {'subsystem': 'forwards',
                       'updated': 2,
                       'details': {'in_channel': scid12,
                                   'in_htlc_id': 1,
                                   'in_msat': Millisatoshi(amt2 + 1),
                                   'out_channel': scid23,
                                   'status': 'failed'}}

    # Order and pagination.
    assert [(p['created_index'], p['in_msat'], p['status']) for p in l2.rpc.listforwards(index='created')['forwards']] == [(1, Millisatoshi(amt1 + 1), 'settled'), (2, Millisatoshi(amt2 + 1), 'failed')]
    assert [(p['created_index'], p['in_msat'], p['status']) for p in l2.rpc.listforwards(index='created', start=2)['forwards']] == [(2, Millisatoshi(amt2 + 1), 'failed')]
    assert [(p['created_index'], p['in_msat'], p['status']) for p in l2.rpc.listforwards(index='created', limit=1)['forwards']] == [(1, Millisatoshi(amt1 + 1), 'settled')]

    # We can also filter by status.
    assert [(p['created_index'], p['in_msat'], p['status']) for p in l2.rpc.listforwards(status='failed', index='created', limit=2)['forwards']] == [(2, Millisatoshi(amt2 + 1), 'failed')]

    assert [(p['created_index'], p['in_msat'], p['status']) for p in l2.rpc.listforwards(status='failed', index='updated', limit=2)['forwards']] == [(2, Millisatoshi(amt2 + 1), 'failed')]

    # Finally, check deletion.
    waitfut = executor.submit(l2.rpc.wait, subsystem='forwards', indexname='deleted', nextvalue=1)
    time.sleep(1)

    l2.rpc.delforward(scid12, 1, 'failed')

    waitres = waitfut.result(TIMEOUT)
    assert waitres == {'subsystem': 'forwards',
                       'deleted': 1,
                       'details': {'in_channel': scid12,
                                   'in_htlc_id': 1,
                                   'status': 'failed'}}


@pytest.mark.openchannel('v1')
def test_version_reexec(node_factory, bitcoind):
    badopeningd = os.path.join(os.path.dirname(__file__), "plugins", "badopeningd.sh")
    version = subprocess.check_output(['lightningd/lightningd',
                                       '--version']).decode('utf-8').splitlines()[0]

    l1, l2 = node_factory.get_nodes(2, opts=[{'subdaemon': 'openingd:' + badopeningd,
                                              'start': False,
                                              'allow_broken_log': True},
                                             {}])
    # We use a file to tell our openingd wrapper where the real one is
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "openingd-real"), 'w') as f:
        f.write(os.path.abspath('lightningd/lightning_openingd'))

    l1.start()
    # This is a "version" message
    verfile = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "openingd-version")
    with open(verfile, 'wb') as f:
        f.write(bytes.fromhex('0000000d'        # len
                              'fff6'))          # type
        f.write(bytes('badversion\0', encoding='utf8'))

    # Opening a channel will fire subd.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    try:
        l1.fundchannel(l2)
    except RpcError:
        pass

    l1.daemon.wait_for_log("openingd.*version 'badversion' not '{}': restarting".format(version))

    # Now "fix" it, it should restart.
    os.unlink(verfile)
    l1.daemon.wait_for_log("Server started with public key")


def test_notimestamp_logging(node_factory):
    l1 = node_factory.get_node(start=False)
    # Make sure this is specified *before* other options!
    l1.daemon.early_opts.insert(0, '--log-timestamps=false')
    l1.start()
    assert l1.daemon.logs[0].startswith("lightningd-1 INFO")

    assert l1.rpc.listconfigs()['configs']['log-timestamps']['value_bool'] is False


def test_getlog(node_factory):
    """Test the getlog command"""
    l1 = node_factory.get_node(options={'log-level': 'io'})

    # Default will skip some entries
    logs = l1.rpc.getlog()['log']
    assert [l for l in logs if l['type'] == 'SKIPPED'] != []

    # This should not
    logs = l1.rpc.getlog(level='io')['log']
    assert [l for l in logs if l['type'] == 'SKIPPED'] == []


def test_log_filter(node_factory):
    """Test the log-level option with subsystem filters"""
    # This actually suppresses debug!
    l1 = node_factory.get_node(options={'log-level': ['debug', 'broken:022d223620']})
    l2 = node_factory.get_node(start=False)

    log1 = os.path.join(l2.daemon.lightning_dir, "log")
    log2 = os.path.join(l2.daemon.lightning_dir, "log2")
    # We need to set log file before we set options on it.
    l2.daemon.early_opts += [f'--log-file={l}' for l in [log2] + l2.daemon.opts['log-file']]
    del l2.daemon.opts['log-file']
    l2.daemon.opts['log-level'] = ["broken",  # broken messages go everywhere
                                   f"debug::{log1}",  # debug to normal log
                                   "debug::-",  # debug to stdout
                                   f'io:0266e4598d1d3:{log2}']
    l2.start()
    node_factory.join_nodes([l1, l2])

    # No debug messages in l1's log
    assert not l1.daemon.is_in_log(r'-chan#[0-9]*:')
    # No mention of l2 at all (except spenderp mentions it)
    assert not l1.daemon.is_in_log(l2.info['id'] + '-')

    # Every message in log2 must be about l1...
    with open(log2, "r") as f:
        lines = f.readlines()
    assert all([' {}-'.format(l1.info['id']) in l for l in lines])


def test_log_filter_bug(node_factory):
    """Test the log-level option with overriding to a more verbose setting"""
    log_plugin = os.path.join(os.getcwd(), 'tests/plugins/log.py')
    l1 = node_factory.get_node(options={'plugin': log_plugin,
                                        'log-level': ['info', 'debug:plugin-log']})
    l1.daemon.logsearch_start = 0
    l1.daemon.wait_for_log("printing debug log")
    l1.daemon.wait_for_log("printing info log")


def test_force_feerates(node_factory):
    l1 = node_factory.get_node(options={'force-feerates': 1111})
    assert l1.rpc.listconfigs()['configs']['force-feerates']['value_str'] == '1111'

    # Note that estimates are still valid here, despite "force-feerates"
    estimates = [{"blockcount": 2,
                  "feerate": 15000,
                  "smoothed_feerate": 15000},
                 {"blockcount": 6,
                  "feerate": 11000,
                  "smoothed_feerate": 11000},
                 {"blockcount": 12,
                  "feerate": 7500,
                  "smoothed_feerate": 7500},
                 {"blockcount": 100,
                  "feerate": 3750,
                  "smoothed_feerate": 3750}]

    assert l1.rpc.feerates('perkw')['perkw'] == {
        "opening": 1111,
        "mutual_close": 1111,
        "unilateral_close": 1111,
        "unilateral_anchor_close": 1111,
        "penalty": 1111,
        "min_acceptable": 1875,
        "max_acceptable": 150000,
        "estimates": estimates,
        "floor": 253}

    l1.stop()
    l1.daemon.opts['force-feerates'] = '1111/2222'
    l1.start()

    assert l1.rpc.listconfigs()['configs']['force-feerates']['value_str'] == '1111/2222'
    assert l1.rpc.feerates('perkw')['perkw'] == {
        "opening": 1111,
        "mutual_close": 2222,
        "unilateral_close": 2222,
        "unilateral_anchor_close": 2222,
        "penalty": 2222,
        "min_acceptable": 1875,
        "max_acceptable": 150000,
        "estimates": estimates,
        "floor": 253}

    l1.stop()
    l1.daemon.opts['force-feerates'] = '1111/2222/3333/4444/5555/6666'
    l1.start()

    assert l1.rpc.listconfigs()['configs']['force-feerates']['value_str'] == '1111/2222/3333/4444/5555/6666'
    assert l1.rpc.feerates('perkw')['perkw'] == {
        "opening": 1111,
        "mutual_close": 2222,
        "unilateral_close": 3333,
        "unilateral_anchor_close": 3333,
        "penalty": 6666,
        "min_acceptable": 1875,
        "max_acceptable": 150000,
        "estimates": estimates,
        "floor": 253}


def test_datastore_escapeing(node_factory):
    """ This test demonstrates that there is some character escaping issue
        issue in the datastore API and error messages during startup that
        affect plugins init method. """
    setdata = '{"foo": "bar"}'
    l1 = node_factory.get_node()
    l1.rpc.datastore(key='foo_bar', string=setdata)
    getdata = l1.rpc.listdatastore('foo_bar')['datastore'][0]['string']
    assert not l1.daemon.is_in_log(r".*listdatastore error.*token has no index 0.*")
    assert getdata == setdata


def test_datastore(node_factory):
    l1 = node_factory.get_node()

    # Starts empty
    assert l1.rpc.listdatastore() == {'datastore': []}
    assert l1.rpc.listdatastore('somekey') == {'datastore': []}

    # Fail on empty array
    with pytest.raises(RpcError, match='should not be empty'):
        l1.rpc.listdatastore([])

    # Add entries.
    somedata = b'somedata'.hex()
    somedata_expect = {'key': ['somekey'],
                       'generation': 0,
                       'hex': somedata,
                       'string': 'somedata'}

    # We should fail trying to insert into an empty array
    with pytest.raises(RpcError, match='should not be empty'):
        l1.rpc.datastore(key=[], hex=somedata)

    assert l1.rpc.datastore(key='somekey', hex=somedata) == somedata_expect

    assert l1.rpc.listdatastore() == {'datastore': [somedata_expect]}
    assert l1.rpc.listdatastore('somekey') == {'datastore': [somedata_expect]}
    assert l1.rpc.listdatastore('otherkey') == {'datastore': []}

    # Cannot add by default.
    with pytest.raises(RpcError, match='already exists'):
        l1.rpc.datastore(key='somekey', hex=somedata)

    with pytest.raises(RpcError, match='already exists'):
        l1.rpc.datastore(key='somekey', hex=somedata, mode="must-create")

    # But can insist on replace.
    l1.rpc.datastore(key='somekey', hex=somedata[:-4], mode="must-replace")
    assert only_one(l1.rpc.listdatastore('somekey')['datastore'])['hex'] == somedata[:-4]
    # And append works.
    l1.rpc.datastore(key='somekey', hex=somedata[-4:-2], mode="must-append")
    assert only_one(l1.rpc.listdatastore('somekey')['datastore'])['hex'] == somedata[:-2]
    l1.rpc.datastore(key='somekey', hex=somedata[-2:], mode="create-or-append")
    assert only_one(l1.rpc.listdatastore('somekey')['datastore'])['hex'] == somedata

    # Generation will have increased due to three ops above.
    somedata_expect['generation'] += 3
    assert l1.rpc.listdatastore() == {'datastore': [somedata_expect]}

    # Can't replace or append non-existing records if we say not to
    with pytest.raises(RpcError, match='does not exist'):
        l1.rpc.datastore(key='otherkey', hex=somedata, mode="must-replace")

    with pytest.raises(RpcError, match='does not exist'):
        l1.rpc.datastore(key='otherkey', hex=somedata, mode="must-append")

    otherdata = b'otherdata'.hex()
    otherdata_expect = {'key': ['otherkey'],
                        'generation': 0,
                        'hex': otherdata,
                        'string': 'otherdata'}
    assert l1.rpc.datastore(key='otherkey', string='otherdata', mode="create-or-append") == otherdata_expect

    assert l1.rpc.listdatastore('somekey') == {'datastore': [somedata_expect]}
    assert l1.rpc.listdatastore('otherkey') == {'datastore': [otherdata_expect]}
    assert l1.rpc.listdatastore('badkey') == {'datastore': []}

    # Order is sorted!
    assert l1.rpc.listdatastore() == {'datastore': [otherdata_expect, somedata_expect]}

    assert l1.rpc.deldatastore('somekey') == somedata_expect
    assert l1.rpc.listdatastore() == {'datastore': [otherdata_expect]}
    assert l1.rpc.listdatastore('somekey') == {'datastore': []}
    assert l1.rpc.listdatastore('otherkey') == {'datastore': [otherdata_expect]}
    assert l1.rpc.listdatastore('badkey') == {'datastore': []}
    assert l1.rpc.listdatastore() == {'datastore': [otherdata_expect]}

    # if it's not a string, won't print
    badstring_expect = {'key': ['badstring'],
                        'generation': 0,
                        'hex': '00'}
    assert l1.rpc.datastore(key='badstring', hex='00') == badstring_expect
    assert l1.rpc.listdatastore('badstring') == {'datastore': [badstring_expect]}
    assert l1.rpc.deldatastore('badstring') == badstring_expect

    # It's persistent
    l1.restart()

    assert l1.rpc.listdatastore() == {'datastore': [otherdata_expect]}

    # We can insist generation match on update.
    with pytest.raises(RpcError, match='generation is different'):
        l1.rpc.datastore(key='otherkey', hex='00', mode='must-replace',
                         generation=otherdata_expect['generation'] + 1)

    otherdata_expect['generation'] += 1
    otherdata_expect['string'] += 'a'
    otherdata_expect['hex'] += '61'
    assert (l1.rpc.datastore(key='otherkey', string='otherdataa',
                             mode='must-replace',
                             generation=otherdata_expect['generation'] - 1)
            == otherdata_expect)
    assert l1.rpc.listdatastore() == {'datastore': [otherdata_expect]}

    # We can insist generation match on delete.
    with pytest.raises(RpcError, match='generation is different'):
        l1.rpc.deldatastore(key='otherkey',
                            generation=otherdata_expect['generation'] + 1)

    assert (l1.rpc.deldatastore(key='otherkey',
                                generation=otherdata_expect['generation'])
            == otherdata_expect)
    assert l1.rpc.listdatastore() == {'datastore': []}


def test_datastore_keylist(node_factory):
    l1 = node_factory.get_node()

    # Starts empty
    assert l1.rpc.listdatastore() == {'datastore': []}
    assert l1.rpc.listdatastore(['a']) == {'datastore': []}
    assert l1.rpc.listdatastore(['a', 'b']) == {'datastore': []}

    # Cannot add child to existing!
    l1.rpc.datastore(key='a', string='aval')
    with pytest.raises(RpcError, match=r'1206.*Parent key \[a\] exists'):
        l1.rpc.datastore(key=['a', 'b'], string='abval',
                         mode='create-or-replace')
    # Listing subkey gives DNE.
    assert l1.rpc.listdatastore(['a', 'b']) == {'datastore': []}
    l1.rpc.deldatastore(key=['a'])

    # Create child key.
    l1.rpc.datastore(key=['a', 'b'], string='abval')
    assert l1.rpc.listdatastore() == {'datastore': [{'key': ['a']}]}
    assert l1.rpc.listdatastore(key=['a']) == {'datastore': [{'key': ['a', 'b'],
                                                              'generation': 0,
                                                              'string': 'abval',
                                                              'hex': b'abval'.hex()}]}

    # Cannot create key over that
    with pytest.raises(RpcError, match='has children'):
        l1.rpc.datastore(key='a', string='aval', mode='create-or-replace')

    # Can create another key.
    l1.rpc.datastore(key=['a', 'b2'], string='ab2val')
    assert l1.rpc.listdatastore() == {'datastore': [{'key': ['a']}]}
    assert l1.rpc.listdatastore(key=['a']) == {'datastore': [{'key': ['a', 'b'],
                                                              'string': 'abval',
                                                              'generation': 0,
                                                              'hex': b'abval'.hex()},
                                                             {'key': ['a', 'b2'],
                                                              'string': 'ab2val',
                                                              'generation': 0,
                                                              'hex': b'ab2val'.hex()}]}

    # Can create subkey.
    l1.rpc.datastore(key=['a', 'b3', 'c'], string='ab2val')
    assert l1.rpc.listdatastore() == {'datastore': [{'key': ['a']}]}
    assert l1.rpc.listdatastore(key=['a']) == {'datastore': [{'key': ['a', 'b'],
                                                              'string': 'abval',
                                                              'generation': 0,
                                                              'hex': b'abval'.hex()},
                                                             {'key': ['a', 'b2'],
                                                              'string': 'ab2val',
                                                              'generation': 0,
                                                              'hex': b'ab2val'.hex()},
                                                             {'key': ['a', 'b3']}]}

    # Can update subkey
    l1.rpc.datastore(key=['a', 'b3', 'c'], string='2', mode='must-append')
    assert l1.rpc.listdatastore(key=['a', 'b3', 'c']) == {'datastore': [{'key': ['a', 'b3', 'c'],
                                                                         'string': 'ab2val2',
                                                                         'generation': 1,
                                                                         'hex': b'ab2val2'.hex()}]}


def test_datastoreusage(node_factory):
    l1: LightningNode = node_factory.get_node()
    assert l1.rpc.datastoreusage() == {'datastoreusage': {'key': '[]', 'total_bytes': 0}}

    data = 'somedatatostoreinthedatastore'  # len 29
    l1.rpc.datastore(key=["a", "b"], string=data)
    assert l1.rpc.datastoreusage() == {'datastoreusage': {'key': '[]', 'total_bytes': (29 + 1 + 1 + 1)}}
    assert l1.rpc.datastoreusage(key="a") == {'datastoreusage': {'key': '[a]', 'total_bytes': (29 + 1 + 1 + 1)}}
    assert l1.rpc.datastoreusage(key=["a", "b"]) == {'datastoreusage': {'key': '[a,b]', 'total_bytes': (29 + 1 + 1 + 1)}}

    # add second leaf
    l1.rpc.datastore(key=["a", "c"], string=data)
    assert l1.rpc.datastoreusage() == {'datastoreusage': {'key': '[]', 'total_bytes': (29 + 1 + 1 + 1 + 29 + 1 + 1 + 1)}}
    assert l1.rpc.datastoreusage(key=["a", "b"]) == {'datastoreusage': {'key': '[a,b]', 'total_bytes': (29 + 1 + 1 + 1)}}
    assert l1.rpc.datastoreusage(key=["a", "c"]) == {'datastoreusage': {'key': '[a,c]', 'total_bytes': (29 + 1 + 1 + 1)}}

    # check that the key is also counted as stored data
    l1.rpc.datastore(key=["a", "thisissomelongkeythattriestostore46bytesofdata"], string=data)
    assert l1.rpc.datastoreusage() == {'datastoreusage': {'key': '[]', 'total_bytes': (29 + 1 + 1 + 46 + 64)}}
    assert l1.rpc.datastoreusage(key=["a", "thisissomelongkeythattriestostore46bytesofdata"]) == {'datastoreusage': {'key': '[a,thisissomelongkeythattriestostore46bytesofdata]', 'total_bytes': (29 + 1 + 1 + 46)}}

    # check that the root is also counted
    l1.rpc.datastore(key=["thisissomelongkeythattriestostore46bytesofdata", "a"], string=data)
    assert l1.rpc.datastoreusage(key=["thisissomelongkeythattriestostore46bytesofdata", "a"]) == {'datastoreusage': {'key': '[thisissomelongkeythattriestostore46bytesofdata,a]', 'total_bytes': (29 + 1 + 1 + 46)}}

    # check really deep data
    l1.rpc.datastore(key=["a", "d", "e", "f", "g"], string=data)
    assert l1.rpc.datastoreusage(key=["a", "d", "e", "f", "g"]) == {'datastoreusage': {'key': '[a,d,e,f,g]', 'total_bytes': (29 + 1 + 1 + 1 + 1 + 1 + 4)}}
    assert l1.rpc.datastoreusage() == {'datastoreusage': {'key': '[]', 'total_bytes': (29 + 1 + 1 + 1 + 1 + 1 + 4 + 218)}}


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3',
                 "This test requires sqlite3")
def test_torv2_in_db(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    l1.stop()
    l1.db_manip("UPDATE peers SET address='3fyb44wdhnd2ghhl.onion:1234';")
    l1.start()


def test_field_filter(node_factory, chainparams):
    l1, l2 = node_factory.get_nodes(2)

    addr1 = l1.rpc.newaddr('bech32')['bech32']
    addr2 = '2MxqzNANJNAdMjHQq8ZLkwzooxAFiRzXvEz' if not chainparams['elements'] else 'XGx1E2JSTLZLmqYMAo3CGpsco85aS7so33'
    inv = l1.rpc.invoice(123000, 'label', 'description', 3700, [addr1, addr2])

    # Simple case: single field
    dec = l1.rpc.call('decodepay', {'bolt11': inv['bolt11']}, filter={"currency": True})
    assert dec == {"currency": chainparams['bip173_prefix']}

    # Use context manager:
    with l1.rpc.reply_filter({"currency": True}):
        dec = l1.rpc.decodepay(bolt11=inv['bolt11'])
    assert dec == {"currency": chainparams['bip173_prefix']}

    # Two fields
    dec = l1.rpc.call('decodepay', {'bolt11': inv['bolt11']}, filter={"currency": True, "payment_hash": True})
    assert dec == {"currency": chainparams['bip173_prefix'],
                   "payment_hash": inv['payment_hash']}

    # Nested fields
    dec = l1.rpc.call('decodepay', {'bolt11': inv['bolt11']},
                      filter={"currency": True,
                              "payment_hash": True,
                              "fallbacks": [{"type": True}]})
    assert dec == {"currency": chainparams['bip173_prefix'],
                   "payment_hash": inv['payment_hash'],
                   "fallbacks": [{"type": 'P2WPKH'}, {"type": 'P2SH'}]}

    # Nonexistent fields.
    dec = l1.rpc.call('decodepay', {'bolt11': inv['bolt11']},
                      filter={"foobar": True})
    assert dec == {}

    # Bad filters
    dec = l1.rpc.call('decodepay', {'bolt11': inv['bolt11']},
                      filter={"currency": True,
                              "payment_hash": True,
                              "fallbacks": {'type': True}})
    assert dec['warning_parameter_filter'] == '.fallbacks is an array'

    # C plugins implement filters!
    res = l1.rpc.call('decode', {'string': inv['bolt11']},
                      filter={"currency": True})
    assert res == {"currency": chainparams['bip173_prefix']}


def test_checkmessage_pubkey_not_found(node_factory):
    l1 = node_factory.get_node()

    msg = "testcase to check new rpc error"
    pubkey = "03be3b0e9992153b1d5a6e1623670b6c3663f72ce6cf2e0dd39c0a373a7de5a3b7"
    zbase = "d66bqz3qsku5fxtqsi37j11pci47ydxa95iusphutggz9ezaxt56neh77kxe5hyr41kwgkncgiu94p9ecxiexgpgsz8daoq4tw8kj8yx"

    with pytest.raises(RpcError) as exception:
        l1.rpc.checkmessage(msg, zbase)
    err = exception.value
    assert err.error['message'] == "pubkey not found in the graph"
    assert err.error['data']['claimed_key'] == pubkey

    check_result = l1.rpc.checkmessage(msg, zbase, pubkey=pubkey)
    assert check_result["pubkey"] == pubkey
    assert check_result["verified"] is True


def test_hsm_capabilities(node_factory):
    l1 = node_factory.get_node()
    # This appears before the start message, so it'll already be present.
    assert l1.daemon.is_in_log(r"hsmd: capability \+WIRE_HSMD_CHECK_PUBKEY")


def test_feerate_arg(node_factory):
    """Make sure our variants of feerate argument work!"""
    l1 = node_factory.get_node()

    # These are the get_node() defaults
    by_blocks = {2: 15000,
                 6: 11000,
                 12: 7500,
                 100: 3750}

    # Literal values:
    fees = {"9999perkw": 9999,
            "10000perkb": 10000 // 4,
            10000: 10000 // 4}

    fees["urgent"] = by_blocks[6]
    fees["normal"] = by_blocks[12]
    fees["slow"] = by_blocks[100]

    fees["opening"] = by_blocks[12]
    fees["mutual_close"] = by_blocks[100]
    fees["penalty"] = by_blocks[12]
    fees["unilateral_close"] = by_blocks[6]

    fees["2blocks"] = by_blocks[2]
    fees["6blocks"] = by_blocks[6]
    fees["12blocks"] = by_blocks[12]
    fees["100blocks"] = by_blocks[100]

    # Simple interpolation
    fees["9blocks"] = (by_blocks[6] + by_blocks[12]) // 2

    for fee, expect in fees.items():
        # Put arg in assertion, so it gets printed on failure!
        assert (l1.rpc.parsefeerate(fee), fee) == ({'perkw': expect}, fee)

    # More thorough interpolation
    for block in range(12, 100):
        # y = y1 + (x-x1)(y2-y1)/(x2-x1)
        fee = by_blocks[12] + (block - 12) * (by_blocks[100] - by_blocks[12]) // (100 - 12)
        # Rounding error is a thing!
        assert abs(l1.rpc.parsefeerate(f"{block}blocks")['perkw'] - fee) <= 1


@pytest.mark.skip(reason="Fails by intention for creating test gossip stores")
def test_create_gossip_mesh(node_factory, bitcoind):
    """
    Feel free to modify this test and remove the '@pytest.mark.skip' above.
    Run it to get a customized gossip store. It fails on purpose, see below.

    This builds a small mesh

      l1--l2--l3
      |   |   |
      l4--l5--l6
      |   |   |
      l7--l8--l9
    """
    nodes = node_factory.get_nodes(9)
    nodeids = [n.info['id'] for n in nodes]

    [l1, l2, l3, l4, l5, l6, l7, l8, l9] = nodes
    scid12, _ = l1.fundchannel(l2, wait_for_active=False, connect=True)
    scid14, _ = l1.fundchannel(l4, wait_for_active=False, connect=True)
    scid23, _ = l2.fundchannel(l3, wait_for_active=False, connect=True)
    scid25, _ = l2.fundchannel(l5, wait_for_active=False, connect=True)
    scid36, _ = l3.fundchannel(l6, wait_for_active=False, connect=True)
    scid45, _ = l4.fundchannel(l5, wait_for_active=False, connect=True)
    scid47, _ = l4.fundchannel(l7, wait_for_active=False, connect=True)
    scid56, _ = l5.fundchannel(l6, wait_for_active=False, connect=True)
    scid58, _ = l5.fundchannel(l8, wait_for_active=False, connect=True)
    scid69, _ = l6.fundchannel(l9, wait_for_active=False, connect=True)
    scid78, _ = l7.fundchannel(l8, wait_for_active=False, connect=True)
    scid89, _ = l8.fundchannel(l9, wait_for_active=False, connect=True)
    bitcoind.generate_block(10)

    scids = [scid12, scid14, scid23, scid25, scid36, scid45, scid47, scid56,
             scid58, scid69, scid78, scid89]

    # waits for all nodes to have all scids gossip active
    for n in nodes:
        for scid in scids:
            n.wait_channel_active(scid)

    print("nodeids", nodeids)
    print("scids", scids)
    assert False, "Test failed on purpose, grab the gossip store from /tmp/ltests-..."


def test_fast_shutdown(node_factory):
    l1 = node_factory.get_node(start=False)

    l1.daemon.start(wait_for_initialized=False)

    start_time = time.time()
    # Keep trying until this succeeds (socket may not exist yet!)
    while True:
        if time.time() > start_time + TIMEOUT:
            raise ValueError("Timeout while waiting for stop to work!")
        try:
            l1.rpc.stop()
        except FileNotFoundError:
            continue
        except ConnectionRefusedError:
            continue
        break


def test_setconfig(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)
    configfile = os.path.join(l2.daemon.opts.get("lightning-dir"), TEST_NETWORK, 'config')

    assert (l2.rpc.listconfigs('min-capacity-sat')['configs']
            == {'min-capacity-sat':
                {'source': 'default',
                 'value_int': 10000,
                 'dynamic': True}})

    with pytest.raises(RpcError, match='requires a value'):
        l2.rpc.setconfig('min-capacity-sat')

    with pytest.raises(RpcError, match='requires a value'):
        l2.rpc.setconfig(config='min-capacity-sat')

    with pytest.raises(RpcError, match='is not a number'):
        l2.rpc.setconfig(config='min-capacity-sat', val="abcd")

    # Check will fail the same way.
    with pytest.raises(RpcError, match='requires a value'):
        l2.rpc.check('setconfig', config='min-capacity-sat')

    with pytest.raises(RpcError, match='is not a number'):
        l2.rpc.check('setconfig', config='min-capacity-sat', val="abcd")

    # Check will pass, but NOT change value.
    assert l2.rpc.check(command_to_check='setconfig', config='min-capacity-sat', val=500000) == {'command_to_check': 'setconfig'}

    assert (l2.rpc.listconfigs('min-capacity-sat')['configs']
            == {'min-capacity-sat':
                {'source': 'default',
                 'value_int': 10000,
                 'dynamic': True}})

    ret = l2.rpc.setconfig(config='min-capacity-sat', val=500000)
    assert ret == {'config':
                   {'config': 'min-capacity-sat',
                    'source': '{}:2'.format(configfile),
                    'value_int': 500000,
                    'dynamic': True}}

    with open(configfile, 'r') as f:
        lines = f.read().splitlines()
        timeline = lines[0]
        assert lines[0].startswith('# Inserted by setconfig ')
        assert lines[1] == 'min-capacity-sat=500000'
        assert len(lines) == 2

    # Now we need to meet minumum
    with pytest.raises(RpcError, match='which is below 500000sat'):
        l1.fundchannel(l2, 400000)

    l1.fundchannel(l2, 10**6)
    txid = l1.rpc.close(l2.info['id'])['txid']
    # Make sure we're completely closed!
    bitcoind.generate_block(1, wait_for_mempool=txid)
    sync_blockheight(bitcoind, [l1, l2])

    # It's persistent!
    l2.restart()

    assert (l2.rpc.listconfigs('min-capacity-sat')['configs']
            == {'min-capacity-sat':
                {'source': '{}:2'.format(configfile),
                 'value_int': 500000,
                 'dynamic': True}})

    # Still need to meet minumum
    l1.connect(l2)
    with pytest.raises(RpcError, match='which is below 500000sat'):
        l1.fundchannel(l2, 400000)

    # Now, changing again will comment that one out!
    ret = l2.rpc.setconfig(config='min-capacity-sat', val=400000)
    assert ret == {'config':
                   {'config': 'min-capacity-sat',
                    'source': '{}:2'.format(configfile),
                    'value_int': 400000,
                    'dynamic': True}}

    with open(configfile, 'r') as f:
        lines = f.read().splitlines()
        assert lines[0].startswith('# Inserted by setconfig ')
        # It will have changed timestamp since last time!
        assert lines[0] != timeline
        assert lines[1] == 'min-capacity-sat=400000'
        assert len(lines) == 2

    # If it's not set by setconfig, it will comment it out instead.
    l2.stop()

    with open(configfile, 'w') as f:
        f.write('min-capacity-sat=500000\n')

    l2.start()
    ret = l2.rpc.setconfig(config='min-capacity-sat', val=400000)
    assert ret == {'config':
                   {'config': 'min-capacity-sat',
                    'source': '{}:3'.format(configfile),
                    'value_int': 400000,
                    'dynamic': True}}

    with open(configfile, 'r') as f:
        lines = f.read().splitlines()
        assert lines[0].startswith('# setconfig commented out: min-capacity-sat=500000')
        assert lines[1].startswith('# Inserted by setconfig ')
        assert lines[2] == 'min-capacity-sat=400000'
        assert len(lines) == 3


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "deletes database, which is assumed sqlite3")
def test_recover_command(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2)

    l1oldid = l1.info['id']

    def get_hsm_secret(n):
        """Returns codex32 and hex"""
        hsmfile = os.path.join(n.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
        codex32 = subprocess.check_output(["tools/hsmtool", "getcodexsecret", hsmfile, "leet"]).decode('utf-8').strip()
        with open(hsmfile, "rb") as f:
            hexhsm = f.read().hex()
        return codex32, hexhsm

    l1codex32, l1hex = get_hsm_secret(l1)
    l2codex32, l2hex = get_hsm_secret(l2)

    # Get the PID for later
    with open(os.path.join(l1.daemon.lightning_dir,
                           f"lightningd-{TEST_NETWORK}.pid"), "r") as f:
        pid = f.read().strip()

    assert l1.rpc.check('recover', hsmsecret=l2codex32) == {'command_to_check': 'recover'}
    l1.rpc.recover(hsmsecret=l2codex32)
    l1.daemon.wait_for_log("Server started with public key")
    # l1.info is cached on start, so won't reflect current reality!
    assert l1.rpc.getinfo()['id'] == l2.info['id']

    # Won't work if we issue an address...
    l2.rpc.newaddr()

    with pytest.raises(RpcError, match='Node has already issued bitcoin addresses'):
        l2.rpc.recover(hsmsecret=l1codex32)

    with pytest.raises(RpcError, match='Node has already issued bitcoin addresses'):
        l2.rpc.check('recover', hsmsecret=l1codex32)

    # Now try recovering using hex secret (remove old prerecover!)
    shutil.rmtree(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK,
                               f"lightning.pre-recover.{pid}"))

    # l1 already has --recover in cmdline: recovering again would add it
    # twice!
    with pytest.raises(RpcError, match='Already doing recover'):
        l1.rpc.check('recover', hsmsecret=l1hex)

    with pytest.raises(RpcError, match='Already doing recover'):
        l1.rpc.recover(hsmsecret=l1hex)

    l1.restart()
    assert l1.rpc.check('recover', hsmsecret=l1hex) == {'command_to_check': 'recover'}
    l1.rpc.recover(hsmsecret=l1hex)
    l1.daemon.wait_for_log("Server started with public key")
    assert l1.rpc.getinfo()['id'] == l1oldid


def test_even_sendcustommsg(node_factory):
    l1, l2 = node_factory.get_nodes(2, opts={'log-level': 'io',
                                             'allow_warning': True})
    l1.connect(l2)

    # Even-numbered message
    msg = hex(43690)[2:] + ('ff' * 30) + 'bb'

    # l2 will hang up when it gets this.
    l1.rpc.sendcustommsg(l2.info['id'], msg)
    l2.daemon.wait_for_log(r'\[IN\] {}'.format(msg))
    l1.daemon.wait_for_log('Invalid unknown even msg')
    wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])

    # Now with a plugin which allows it
    l1.connect(l2)
    l2.rpc.plugin_start(os.path.join(os.getcwd(), "tests/plugins/allow_even_msgs.py"))
    l2.daemon.wait_for_log("connectd.*Now allowing 1 custom message types")

    l1.rpc.sendcustommsg(l2.info['id'], msg)
    l2.daemon.wait_for_log(r'\[IN\] {}'.format(msg))
    l2.daemon.wait_for_log(r'allow_even_msgs.*Got message 43690')

    # And nobody gets upset
    assert only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']

    # It does if we remove the plugin though!
    l2.rpc.plugin_stop("allow_even_msgs.py")
    l1.rpc.sendcustommsg(l2.info['id'], msg)
    l2.daemon.wait_for_log(r'\[IN\] {}'.format(msg))
    l1.daemon.wait_for_log('Invalid unknown even msg')
    wait_for(lambda: l1.rpc.listpeers(l2.info['id'])['peers'] == [])


def test_set_feerate_offset(node_factory, bitcoind):
    opts = [{'commit-feerate-offset': 100}, {}]
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    assert l1.daemon.is_in_log('Server started with public key')
    configs = l1.rpc.listconfigs()['configs']
    assert configs['commit-feerate-offset'] == {'source': 'cmdline',
                                                'value_int': 100}
    scid12 = l1.fundchannel(l2)[0]
    # chanid = l1.get_channel_scid(l2)

    # node 1 sets fees.
    l1.set_feerates((14000, 11000, 7500, 3750))

    l1.pay(l2, 200000000)
    # First payment causes fee update, which should reflect the feerate offset.
    if 'anchors_zero_fee_htlc_tx/even' in only_one(l1.rpc.listpeerchannels()['channels'])['channel_type']['names']:
        feerate = 3850
        min_feerate = 253
    else:
        feerate = 11100
        min_feerate = 1875
    l1.daemon.wait_for_log(f'lightningd: update_feerates: feerate = {feerate}, '
                           f'min={min_feerate}, max=150000, penalty=7500')
    l2.daemon.wait_for_log(f'peer updated fee to {feerate}')
    l2.pay(l1, 100000000)

    # Now shutdown cleanly.
    l1.rpc.close(scid12)

    l1.daemon.wait_for_log(' to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log(' to CLOSINGD_COMPLETE')
