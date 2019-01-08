from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from flaky import flaky
from lightning import RpcError
from utils import DEVELOPER, VALGRIND, sync_blockheight, only_one, wait_for, TailableProc
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


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
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
        r'Owning output . (\d+) .SEGWIT. txid',
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
    bitcoind.generate_block(5 + 1)
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
    bitcoind.generate_block(2)
    assert not l2.daemon.is_in_log('hit deadline')
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log('Fulfilled HTLC 0 SENT_REMOVE_COMMIT cltv .* hit deadline')
    l2.daemon.wait_for_log('sendrawtx exit 0')
    l2.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l1.daemon.wait_for_log(' to ONCHAIN')

    # L2 will collect HTLC
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
def test_bech32_funding(node_factory):
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)
    l2 = node_factory.get_node(random_hsm=True)

    # connect
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # fund a bech32 address and then open a channel with it
    res = l1.openchannel(l2, 20000, 'bech32')
    address = res['address']
    assert address[0:4] == "bcrt"

    # probably overly paranoid checking
    wallettxid = res['wallettxid']

    wallettx = l1.bitcoin.rpc.getrawtransaction(wallettxid, True)
    fundingtx = l1.bitcoin.rpc.decoderawtransaction(res['fundingtx']['tx'])

    def is_p2wpkh(output):
        return output['type'] == 'witness_v0_keyhash' and \
            address == only_one(output['addresses'])

    assert any(is_p2wpkh(output['scriptPubKey']) for output in wallettx['vout'])
    assert only_one(fundingtx['vin'])['txid'] == res['wallettxid']


def test_withdraw(node_factory, bitcoind):
    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)
    l2 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['address']

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

    # Reach around into the db to check that outputs were added
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 10

    waddr = l1.bitcoin.rpc.getnewaddress()
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
    waddr = l2.rpc.newaddr('bech32')['address']
    l1.rpc.withdraw(waddr, 2 * amount)
    bitcoind.generate_block(1)

    # Make sure l2 received the withdrawal.
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 1)
    outputs = l2.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 2 * amount

    # Now make sure an additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 4

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
    l1.rpc.withdraw(l1.rpc.newaddr('bech32')['address'], 'all')
    bitcoind.generate_block(1)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 1

    l1.rpc.withdraw(waddr, 'all')
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 0

    # This should fail, can't even afford fee.
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
        l1.rpc.withdraw(waddr, 'all')


def test_addfunds_from_block(node_factory, bitcoind):
    """Send funds to the daemon without telling it explicitly
    """
    # Previous runs with same bitcoind can leave funds!
    l1 = node_factory.get_node(random_hsm=True)

    addr = l1.rpc.newaddr()['address']
    bitcoind.rpc.sendtoaddress(addr, 0.1)
    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 10000000

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr

    # Send all our money to a P2WPKH address this time.
    addr = l1.rpc.newaddr("bech32")['address']
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


def test_listconfigs(node_factory, bitcoind):
    l1 = node_factory.get_node()

    configs = l1.rpc.listconfigs()
    # See utils.py
    assert configs['allow-deprecated-apis'] is False
    assert configs['network'] == 'regtest'
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
        b'{"id":1,"jsonrpc":"2.0","method":"dev-slowcmd","params":[2000]}',
        b'{"id":1,"jsonrpc":"2.0","method":"dev-slowcmd","params":[2000]}',
        b'{"id":2,"jsonrpc":"2.0","method":"dev-slowcmd","params":[1500]}',
        b'{"id":2,"jsonrpc":"2.0","method":"dev-slowcmd","params":[1500]}',
        b'{"id":3,"jsonrpc":"2.0","method":"dev-slowcmd","params":[1000]}',
        b'{"id":3,"jsonrpc":"2.0","method":"dev-slowcmd","params":[1000]}',
        b'{"id":4,"jsonrpc":"2.0","method":"dev-slowcmd","params":[500]}',
        b'{"id":4,"jsonrpc":"2.0","method":"dev-slowcmd","params":[500]}'
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
    assert 'help [command]' in j['verbose']

    # Test keyword input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-k',
                                   'help', 'command=help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['verbose']

    # Test ordered input (autodetect)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['verbose']

    # Test ordered input (forced)
    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   '-J', '-o',
                                   'help', 'help']).decode('utf-8')
    j, _ = json.JSONDecoder().raw_decode(out)
    assert 'help [command]' in j['verbose']

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


@flaky
@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_blockchaintrack(node_factory, bitcoind):
    """Check that we track the blockchain correctly across reorgs
    """
    l1 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['address']

    ######################################################################
    # First failure scenario: rollback on startup doesn't work,
    # and we try to add a block twice when rescanning:
    l1.restart()

    height = bitcoind.rpc.getblockcount()

    # At height 111 we receive an incoming payment
    hashes = bitcoind.generate_block(9)
    bitcoind.rpc.sendtoaddress(addr, 1)
    time.sleep(1)  # mempool is still unpredictable
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Owning')
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
    assert [o for o in l1.rpc.listfunds()['outputs'] if o['status'] != "unconfirmed"] == []


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
    reserves = l2.db_query('SELECT channel_reserve_satoshis FROM channel_configs')
    assert reserves == [{'channel_reserve_satoshis': 10**6 // 100}] * 2

    # Edit db to reduce reserve to 0 so it will try to violate it.
    l2.db_query('UPDATE channel_configs SET channel_reserve_satoshis=0',
                use_copy=False)

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
    with pytest.raises(RpcError) as excinfo:
        l1.rpc.pay(inv['bolt11'])

    err = excinfo.value
    # Complaints it couldn't find route.
    assert err.error['code'] == 205
    # Temporary channel failure
    assert only_one(err.error['data']['failures'])['failcode'] == 0x1007
    assert only_one(err.error['data']['failures'])['erring_node'] == l2.info['id']
    assert only_one(err.error['data']['failures'])['erring_channel'] == chanid2

    # L2 should send ping, but never receive pong so never send commitment.
    l2.daemon.wait_for_log(r'channeld.*:\[OUT\] 0012')
    assert not l2.daemon.is_in_log(r'channeld.*:\[IN\] 0013')
    assert not l2.daemon.is_in_log(r'channeld.*:\[OUT\] 0084')
    # L2 killed the channel with l3 because it was too slow.
    l2.daemon.wait_for_log('channeld-{}.*Adding HTLC too slow: killing channel'.format(l3.info['id']))


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
    l1 = node_factory.get_node(may_fail=True)

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
