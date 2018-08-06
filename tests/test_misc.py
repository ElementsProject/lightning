from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from flaky import flaky
from lightning import RpcError
from utils import DEVELOPER, sync_blockheight, only_one, wait_for


import json
import os
import pytest
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
        assert n.daemon.is_in_log('public key {}, alias {}.* \(color #{}\)'
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
    l1 = node_factory.get_node(fake_bitcoin_cli=True)

    # Make sure we're not failing it between getblockhash and getblock.
    sync_blockheight(bitcoind, [l1])

    l1.fake_bitcoind_fail(1)

    # This should cause both estimatefee and getblockhash fail
    l1.daemon.wait_for_logs(['estimatesmartfee .* exited with status 1',
                             'getblockhash .* exited with status 1'])

    # And they should retry!
    l1.daemon.wait_for_logs(['estimatesmartfee .* exited with status 1',
                             'getblockhash .* exited with status 1'])

    # Restore, then it should recover and get blockheight.
    l1.fake_bitcoind_unfail()
    bitcoind.generate_block(5)
    sync_blockheight(bitcoind, [l1])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_ping(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    def ping_tests(l1, l2):
        # 0-byte pong gives just type + length field.
        ret = l1.rpc.dev_ping(l2.info['id'], 0, 0)
        assert ret['totlen'] == 4

        # 1000-byte ping, 0-byte pong.
        ret = l1.rpc.dev_ping(l2.info['id'], 1000, 0)
        assert ret['totlen'] == 4

        # 1000 byte pong.
        ret = l1.rpc.dev_ping(l2.info['id'], 1000, 1000)
        assert ret['totlen'] == 1004

        # Maximum length pong.
        ret = l1.rpc.dev_ping(l2.info['id'], 1000, 65531)
        assert ret['totlen'] == 65535

        # Overlength -> no reply.
        for s in range(65532, 65536):
            ret = l1.rpc.dev_ping(l2.info['id'], 1000, s)
            assert ret['totlen'] == 0

        # 65535 - type(2 bytes) - num_pong_bytes(2 bytes) - byteslen(2 bytes)
        # = 65529 max.
        with pytest.raises(RpcError, match=r'oversize ping'):
            l1.rpc.dev_ping(l2.info['id'], 65530, 1)

    # Test gossip pinging.
    ping_tests(l1, l2)
    if DEVELOPER:
        l1.daemon.wait_for_log('Got pong 1000 bytes \({}\.\.\.\)'
                               .format(l2.info['version']), timeout=1)

    l1.fund_channel(l2, 10**5)

    # channeld pinging
    ping_tests(l1, l2)
    if DEVELOPER:
        l1.daemon.wait_for_log('Got pong 1000 bytes \({}\.\.\.\)'
                               .format(l2.info['version']))


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
def test_htlc_sig_persistence(node_factory, executor):
    """Interrupt a payment between two peers, then fail and recover funds using the HTLC sig.
    """
    l1 = node_factory.get_node(options={'dev-no-reconnect': None})
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
    l2.daemon.wait_for_log('sendrawtx exit 0')
    l2.stop()
    l1.bitcoin.rpc.generate(1)
    l1.start()

    assert l1.daemon.is_in_log(r'Loaded 1 HTLC signatures from DB')
    l1.daemon.wait_for_logs([
        r'Peer permanent failure in CHANNELD_NORMAL: Funding transaction spent',
        r'Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US'
    ])
    l1.bitcoin.rpc.generate(5)
    l1.daemon.wait_for_log("Broadcasting OUR_HTLC_TIMEOUT_TO_US")
    time.sleep(3)
    l1.bitcoin.rpc.generate(1)
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
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None})
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
    l1 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None})
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

    # Deadline HTLC expiry minus 1/2 cltv-expiry delta (rounded up) (== cltv - 3).  ctlv is 5+1.
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
    l1.bitcoin.rpc.generate(1)

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
    l1.bitcoin.rpc.generate(1)
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
    l1.bitcoin.rpc.generate(1)
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
    bitcoind.rpc.generate(1)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 1

    l1.rpc.withdraw(waddr, 'all')
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 0

    # This should fail, can't even afford fee.
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, 'all')
    l1.daemon.wait_for_log('Cannot afford transaction')


def test_addfunds_from_block(node_factory, bitcoind):
    """Send funds to the daemon without telling it explicitly
    """
    # Previous runs with same bitcoind can leave funds!
    l1 = node_factory.get_node(random_hsm=True)

    addr = l1.rpc.newaddr()['address']
    bitcoind.rpc.sendtoaddress(addr, 0.1)
    bitcoind.rpc.generate(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 10000000

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr

    # Send all our money to a P2WPKH address this time.
    addr = l1.rpc.newaddr("bech32")['address']
    l1.rpc.withdraw(addr, "all")
    bitcoind.rpc.generate(1)
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
    l1 = node_factory.get_node()
    addr = l1.rpc.getinfo()['address']
    if 'dev-allow-localhost' in l1.daemon.opts:
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
    assert configs['bitcoin-datadir'] == bitcoind.bitcoin_dir
    assert configs['lightning-dir'] == l1.daemon.lightning_dir
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

    l1.rpc._readobj(sock)
    sock.close()


def test_cli(node_factory):
    l1 = node_factory.get_node()

    out = subprocess.check_output(['cli/lightning-cli',
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'help']).decode('utf-8')
    # Test some known output.
    assert 'help\n    List available commands, or give verbose help on one command' in out

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
    hashes = bitcoind.rpc.generate(9)
    bitcoind.rpc.sendtoaddress(addr, 1)
    time.sleep(1)  # mempool is still unpredictable
    bitcoind.rpc.generate(1)

    l1.daemon.wait_for_log(r'Owning')
    outputs = l1.rpc.listfunds()['outputs']
    assert len(outputs) == 1

    ######################################################################
    # Second failure scenario: perform a 20 block reorg
    bitcoind.rpc.generate(10)
    l1.daemon.wait_for_log('Adding block {}: '.format(height + 20))

    # Now reorg out with a longer fork of 21 blocks
    bitcoind.rpc.invalidateblock(hashes[0])
    bitcoind.wait_for_log(r'InvalidChainFound: invalid block=.*  height={}'
                          .format(height + 1))
    hashes = bitcoind.rpc.generate(30)
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
    bitcoind.rpc.generate(4)
    l1.start()
    l1.daemon.wait_for_log(r'Adding block 105')
    assert not l1.daemon.is_in_log(r'Adding block 102')


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
