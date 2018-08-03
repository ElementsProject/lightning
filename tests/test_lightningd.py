from concurrent import futures
from decimal import Decimal
from flaky import flaky
from utils import NodeFactory, wait_for, only_one

import copy
import json
import logging
import queue
import os
import random
import re
import shutil
import socket
import sqlite3
import string
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import utils
from lightning import RpcError

with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

bitcoind = None
TEST_DIR = tempfile.mkdtemp(prefix='lightning-')
VALGRIND = os.getenv("VALGRIND", config['VALGRIND']) == "1"
DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"


if TEST_DEBUG:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logging.info("Tests running in '%s'", TEST_DIR)


def to_json(arg):
    return json.loads(json.dumps(arg))


def setupBitcoind(directory):
    global bitcoind
    bitcoind = utils.BitcoinD(bitcoin_dir=directory, rpcport=None)

    try:
        bitcoind.start()
    except Exception:
        teardown_bitcoind()
        raise

    info = bitcoind.rpc.getnetworkinfo()

    if info['version'] < 160000:
        bitcoind.rpc.stop()
        raise ValueError("bitcoind is too old. At least version 16000 (v0.16.0)"
                         " is needed, current version is {}".format(info['version']))

    info = bitcoind.rpc.getblockchaininfo()
    # Make sure we have some spendable funds
    if info['blocks'] < 101:
        bitcoind.generate_block(101 - info['blocks'])
    elif bitcoind.rpc.getwalletinfo()['balance'] < 1:
        logging.debug("Insufficient balance, generating 1 block")
        bitcoind.generate_block(1)


def wait_forget_channels(node):
    """This node is closing all of its channels, check we are forgetting them
    """
    node.daemon.wait_for_log(r'onchaind complete, forgetting peer')
    # May have reconnected, but should merely be gossiping.
    for peer in node.rpc.listpeers()['peers']:
        assert peer['state'] == 'GOSSIPING'
    assert node.db_query("SELECT * FROM channels") == []


def sync_blockheight(nodes):
    target = nodes[0].bitcoin.rpc.getblockcount()
    for n in nodes:
        wait_for(lambda: n.rpc.getinfo()['blockheight'] == target)


def teardown_bitcoind():
    global bitcoind
    try:
        bitcoind.rpc.stop()
    except Exception:
        bitcoind.proc.kill()
    bitcoind.proc.wait()


class BaseLightningDTests(unittest.TestCase):
    def setUp(self):
        bitcoin_dir = os.path.join(TEST_DIR, self._testMethodName, "bitcoind")
        setupBitcoind(bitcoin_dir)
        # Most of the executor threads will be waiting for IO, so
        # let's have a few of them
        self.executor = futures.ThreadPoolExecutor(max_workers=20)
        self.node_factory = NodeFactory(self._testMethodName, bitcoind, self.executor, directory=TEST_DIR)

    def getValgrindErrors(self, node):
        for error_file in os.listdir(node.daemon.lightning_dir):
            if not re.fullmatch("valgrind-errors.\d+", error_file):
                continue
            with open(os.path.join(node.daemon.lightning_dir, error_file), 'r') as f:
                errors = f.read().strip()
                if errors:
                    return errors, error_file
        return None, None

    def printValgrindErrors(self, node):
        errors, fname = self.getValgrindErrors(node)
        if errors:
            print("-" * 31, "Valgrind errors", "-" * 32)
            print("Valgrind error file:", fname)
            print(errors)
            print("-" * 80)
        return 1 if errors else 0

    def getCrashLog(self, node):
        if node.may_fail:
            return None, None
        try:
            crashlog = os.path.join(node.daemon.lightning_dir, 'crash.log')
            with open(crashlog, 'r') as f:
                return f.readlines(), crashlog
        except Exception:
            return None, None

    def printCrashLog(self, node):
        errors, fname = self.getCrashLog(node)
        if errors:
            print("-" * 10, "{} (last 50 lines)".format(fname), "-" * 10)
            for l in errors[-50:]:
                print(l, end='')
            print("-" * 80)
        return 1 if errors else 0

    def checkReconnect(self, node):
        # Without DEVELOPER, we can't suppress reconnection.
        if node.may_reconnect or not DEVELOPER:
            return 0
        if node.daemon.is_in_log('Peer has reconnected'):
            return 1
        return 0

    def checkBadGossipOrder(self, node):
        # We can have a race where we notice a channel deleted and someone
        # sends an update, and we can get unknown channel updates in errors.
        if node.daemon.is_in_log('Bad gossip order from (?!error)') and not node.daemon.is_in_log('Deleting channel'):
            return 1
        return 0

    def tearDown(self):
        ok = self.node_factory.killall([not n.may_fail for n in self.node_factory.nodes])
        self.executor.shutdown(wait=False)

        teardown_bitcoind()
        err_count = 0
        # Do not check for valgrind error files if it is disabled
        if VALGRIND:
            for node in self.node_factory.nodes:
                err_count += self.printValgrindErrors(node)
            if err_count:
                raise ValueError("{} nodes reported valgrind errors".format(err_count))

        for node in self.node_factory.nodes:
            err_count += self.printCrashLog(node)
        if err_count:
            raise ValueError("{} nodes had crash.log files".format(err_count))

        for node in self.node_factory.nodes:
            err_count += self.checkReconnect(node)
        if err_count:
            raise ValueError("{} nodes had unexpected reconnections".format(err_count))

        for node in self.node_factory.nodes:
            err_count += self.checkBadGossipOrder(node)
        if err_count:
            raise ValueError("{} nodes had bad gossip order".format(err_count))

        if not ok:
            raise Exception("At least one lightning exited with unexpected non-zero return code")

        shutil.rmtree(self.node_factory.directory)


class LightningDTests(BaseLightningDTests):
    def connect(self, may_reconnect=False):
        l1, l2 = self.node_factory.get_nodes(2, opts={'may_reconnect': may_reconnect})
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('Handing back peer .* to master')
        l2.daemon.wait_for_log('Handing back peer .* to master')
        return l1, l2

    # Waits until l1 notices funds
    def give_funds(self, l1, satoshi):
        addr = l1.rpc.newaddr()['address']
        bitcoind.rpc.sendtoaddress(addr, satoshi / 10**8)

        numfunds = len(l1.rpc.listfunds()['outputs'])
        bitcoind.generate_block(1)
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > numfunds)

    # Returns the short channel-id: <blocknum>:<txnum>:<outnum>
    def fund_channel(self, l1, l2, amount):
        return l1.fund_channel(l2, amount)

    def pay(self, lsrc, ldst, amt, label=None, async=False):
        if not label:
            label = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))

        rhash = ldst.rpc.invoice(amt, label, label)['payment_hash']
        assert only_one(ldst.rpc.listinvoices(label)['invoices'])['status'] == 'unpaid'

        routestep = {
            'msatoshi': amt,
            'id': ldst.info['id'],
            'delay': 5,
            'channel': '1:1:1'
        }

        def wait_pay():
            # Up to 10 seconds for payment to succeed.
            start_time = time.time()
            while only_one(ldst.rpc.listinvoices(label)['invoices'])['status'] != 'paid':
                if time.time() > start_time + 10:
                    raise TimeoutError('Payment timed out')
                time.sleep(0.1)
        # sendpay is async now
        lsrc.rpc.sendpay(to_json([routestep]), rhash)
        if async:
            return self.executor.submit(wait_pay)
        else:
            # wait for sendpay to comply
            lsrc.rpc.waitsendpay(rhash)

    # This waits until gossipd sees channel_update in both directions
    # (or for local channels, at least a local announcement)
    def wait_for_routes(self, l1, channel_ids):
        bitcoind.generate_block(5)
        # Could happen in any order...
        l1.daemon.wait_for_logs(['Received channel_update for channel {}\\(0\\)'.format(c)
                                 for c in channel_ids] +
                                ['Received channel_update for channel {}\\(1\\)'.format(c)
                                 for c in channel_ids])

    def fake_bitcoind_fail(self, l1, exitcode):
        # Create and rename, for atomicity.
        f = os.path.join(l1.daemon.lightning_dir, "bitcoin-cli-fail.tmp")
        with open(f, "w") as text_file:
            print(exitcode, file=text_file)
        os.rename(f, os.path.join(l1.daemon.lightning_dir, "bitcoin-cli-fail"))

    def fake_bitcoind_unfail(self, l1):
        os.remove(os.path.join(l1.daemon.lightning_dir, "bitcoin-cli-fail"))

    def test_features(self):
        l1, l2 = self.connect()

        # LOCAL_INITIAL_ROUTING_SYNC + LOCAL_GOSSIP_QUERIES
        assert only_one(l1.rpc.listpeers()['peers'])['local_features'] == '88'

    def test_names(self):
        for key, alias, color in [('0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518', 'JUNIORBEAM', '0266e4'),
                                  ('022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59', 'SILENTARTIST', '022d22'),
                                  ('035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d', 'HOPPINGFIRE', '035d2b'),
                                  ('0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199', 'JUNIORFELONY', '0382ce'),
                                  ('032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'SOMBERFIRE', '032cf1'),
                                  ('0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6518', 'LOUDPHOTO', '0265b6')]:
            n = self.node_factory.get_node()
            assert n.daemon.is_in_log('public key {}, alias {}.* \(color #{}\)'
                                      .format(key, alias, color))

    def test_connect(self):
        l1, l2 = self.connect()

        # These should be in gossipd.
        assert l1.rpc.getpeer(l2.info['id'])['state'] == 'GOSSIPING'
        assert l2.rpc.getpeer(l1.info['id'])['state'] == 'GOSSIPING'

        # Both gossipds will have them as new peers once handed back.
        l1.daemon.wait_for_log('hand_back_peer {}: now local again'.format(l2.info['id']))
        l2.daemon.wait_for_log('hand_back_peer {}: now local again'.format(l1.info['id']))

        # Reconnect should be a noop
        ret = l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
        assert ret['id'] == l2.info['id']

        ret = l2.rpc.connect(l1.info['id'], host='localhost', port=l1.port)
        assert ret['id'] == l1.info['id']

        # Should still only have one peer!
        assert len(l1.rpc.listpeers()) == 1
        assert len(l2.rpc.listpeers()) == 1

        # Should get reasonable error if unknown addr for peer.
        self.assertRaisesRegex(RpcError,
                               "No address known",
                               l1.rpc.connect, '032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e')

        # Should get reasonable error if connection refuse.
        self.assertRaisesRegex(RpcError,
                               "Connection establishment: Connection refused",
                               l1.rpc.connect, '032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', 1)

        # Should get reasonable error if wrong key for peer.
        self.assertRaisesRegex(RpcError,
                               "Cryptographic handshake: ",
                               l1.rpc.connect, '032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e', 'localhost', l2.port)

    def test_connect_standard_addr(self):
        """Test standard node@host:port address
        """
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()

        # node@host
        ret = l1.rpc.connect("{}@{}".format(l2.info['id'], 'localhost'), port=l2.port)
        assert ret['id'] == l2.info['id']

        # node@host:port
        ret = l1.rpc.connect("{}@localhost:{}".format(l3.info['id'], l3.port))
        assert ret['id'] == l3.info['id']

        # node@[ipv6]:port --- not supported by our CI
        # ret = l1.rpc.connect("{}@[::1]:{}".format(l3.info['id'], l3.port))
        # assert ret['id'] == l3.info['id']

    def test_reconnect_channel_peers(self):
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.fund_channel(l1, l2, 10**6)
        l2.restart()

        # Should reconnect.
        wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
        wait_for(lambda: only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])
        # Connect command should succeed.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # Stop l2 and wait for l1 to notice.
        l2.stop()
        wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])

        # Now should fail.
        self.assertRaisesRegex(RpcError,
                               "Connection refused",
                               l1.rpc.connect, l2.info['id'], 'localhost', l2.port)

        # Wait for exponential backoff to give us a 2 second window.
        l1.daemon.wait_for_log('...will try again in 2 seconds')

        # It should now succeed when it restarts.
        l2.start()

        # Multiples should be fine!
        fut1 = self.executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
        fut2 = self.executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
        fut3 = self.executor.submit(l1.rpc.connect, l2.info['id'], 'localhost', l2.port)
        fut1.result(10)
        fut2.result(10)
        fut3.result(10)

    def test_balance(self):
        l1, l2 = self.connect()
        self.fund_channel(l1, l2, 10**6)
        p1 = only_one(l1.rpc.getpeer(peer_id=l2.info['id'], level='info')['channels'])
        p2 = only_one(l2.rpc.getpeer(l1.info['id'], 'info')['channels'])
        assert p1['msatoshi_to_us'] == 10**6 * 1000
        assert p1['msatoshi_total'] == 10**6 * 1000
        assert p2['msatoshi_to_us'] == 0
        assert p2['msatoshi_total'] == 10**6 * 1000

    def test_bad_opening(self):
        # l1 asks for a too-long locktime
        l1 = self.node_factory.get_node(options={'watchtime-blocks': 100})
        l2 = self.node_factory.get_node(options={'max-locktime-blocks': 99})
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('Handing back peer .* to master')
        l2.daemon.wait_for_log('Handing back peer .* to master')

        self.give_funds(l1, 10**6 + 1000000)
        self.assertRaises(RpcError, l1.rpc.fundchannel, l2.info['id'], 10**6)

        l2.daemon.wait_for_log('to_self_delay 100 larger than 99')

    def test_db_upgrade(self):
        l1 = self.node_factory.get_node()
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

    def test_bitcoin_failure(self):
        l1 = self.node_factory.get_node(fake_bitcoin_cli=True)

        # Make sure we're not failing it between getblockhash and getblock.
        sync_blockheight([l1])

        self.fake_bitcoind_fail(l1, 1)

        # This should cause both estimatefee and getblockhash fail
        l1.daemon.wait_for_logs(['estimatesmartfee .* exited with status 1',
                                 'getblockhash .* exited with status 1'])

        # And they should retry!
        l1.daemon.wait_for_logs(['estimatesmartfee .* exited with status 1',
                                 'getblockhash .* exited with status 1'])

        # Restore, then it should recover and get blockheight.
        self.fake_bitcoind_unfail(l1)
        bitcoind.generate_block(5)
        sync_blockheight([l1])

    def ping_tests(self, l1, l2):
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
        self.assertRaisesRegex(RpcError, r'oversize ping',
                               l1.rpc.dev_ping, l2.info['id'], 65530, 1)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_ping(self):
        l1, l2 = self.connect()

        # Test gossip pinging.
        self.ping_tests(l1, l2)
        if DEVELOPER:
            l1.daemon.wait_for_log('Got pong 1000 bytes \({}\.\.\.\)'
                                   .format(l2.info['version']), timeout=1)

        self.fund_channel(l1, l2, 10**5)

        # channeld pinging
        self.ping_tests(l1, l2)
        if DEVELOPER:
            l1.daemon.wait_for_log('Got pong 1000 bytes \({}\.\.\.\)'
                                   .format(l2.info['version']))

    def test_second_channel(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l1, l3, 10**6)

    @unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
    def test_forward(self):
        # Connect 1 -> 2 -> 3.
        l1, l2 = self.connect()
        l3 = self.node_factory.get_node()
        ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

        assert ret['id'] == l3.info['id']

        l3.daemon.wait_for_log('Handing back peer .* to master')
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # Allow announce messages.
        l1.bitcoin.generate_block(5)

        # If they're at different block heights we can get spurious errors.
        sync_blockheight([l1, l2, l3])

        chanid1 = only_one(l1.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id']
        chanid2 = only_one(l2.rpc.getpeer(l3.info['id'])['channels'])['short_channel_id']
        assert only_one(l2.rpc.getpeer(l1.info['id'])['channels'])['short_channel_id'] == chanid1
        assert only_one(l3.rpc.getpeer(l2.info['id'])['channels'])['short_channel_id'] == chanid2

        rhash = l3.rpc.invoice(100000000, 'testpayment1', 'desc')['payment_hash']
        assert only_one(l3.rpc.listinvoices('testpayment1')['invoices'])['status'] == 'unpaid'

        # Fee for node2 is 10 millionths, plus 1.
        amt = 100000000
        fee = amt * 10 // 1000000 + 1

        baseroute = [{'msatoshi': amt + fee,
                      'id': l2.info['id'],
                      'delay': 12,
                      'channel': chanid1},
                     {'msatoshi': amt,
                      'id': l3.info['id'],
                      'delay': 6,
                      'channel': chanid2}]

        # Unknown other peer
        route = copy.deepcopy(baseroute)
        route[1]['id'] = '031a8dc444e41bb989653a4501e11175a488a57439b0c4947704fd6e3de5dca607'
        l1.rpc.sendpay(to_json(route), rhash)
        self.assertRaises(RpcError, l1.rpc.waitsendpay, rhash)

        # Delay too short (we always add one internally anyway, so subtract 2 here).
        route = copy.deepcopy(baseroute)
        route[0]['delay'] = 8
        l1.rpc.sendpay(to_json(route), rhash)
        self.assertRaises(RpcError, l1.rpc.waitsendpay, rhash)

        # Final delay too short
        route = copy.deepcopy(baseroute)
        route[1]['delay'] = 3
        l1.rpc.sendpay(to_json(route), rhash)
        self.assertRaises(RpcError, l1.rpc.waitsendpay, rhash)

        # This one works
        route = copy.deepcopy(baseroute)
        l1.rpc.sendpay(to_json(route), rhash)
        l1.rpc.waitsendpay(rhash)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_forward_different_fees_and_cltv(self):
        # FIXME: Check BOLT quotes here too
        # BOLT #7:
        # ```
        #    B
        #   / \
        #  /   \
        # A     C
        #  \   /
        #   \ /
        #    D
        # ```
        #
        # Each advertises the following `cltv_expiry_delta` on its end of every
        # channel:
        #
        # 1. A: 10 blocks
        # 2. B: 20 blocks
        # 3. C: 30 blocks
        # 4. D: 40 blocks
        #
        # C also uses a minimum `cltv_expiry` of 9 (the default) when requesting
        # payments.
        #
        # Also, each node has the same fee scheme which it uses for each of its
        # channels:
        #
        # 1. A: 100 base + 1000 millionths
        # 1. B: 200 base + 2000 millionths
        # 1. C: 300 base + 3000 millionths
        # 1. D: 400 base + 4000 millionths

        # We don't do D yet.
        l1 = self.node_factory.get_node(options={'cltv-delta': 10, 'fee-base': 100, 'fee-per-satoshi': 1000})
        l2 = self.node_factory.get_node(options={'cltv-delta': 20, 'fee-base': 200, 'fee-per-satoshi': 2000})
        l3 = self.node_factory.get_node(options={'cltv-delta': 30, 'cltv-final': 9, 'fee-base': 300, 'fee-per-satoshi': 3000})

        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('Handing back peer .* to master')
        l2.daemon.wait_for_log('Handing back peer .* to master')

        ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
        assert ret['id'] == l3.info['id']

        l2.daemon.wait_for_log('Handing back peer .* to master')
        l3.daemon.wait_for_log('Handing back peer .* to master')

        c1 = self.fund_channel(l1, l2, 10**6)
        c2 = self.fund_channel(l2, l3, 10**6)

        # Make sure l1 has seen announce for all channels.
        self.wait_for_routes(l1, [c1, c2])

        # BOLT #7:
        #
        # If B were to send 4,999,999 millisatoshi directly to C, it wouldn't
        # charge itself a fee nor add its own `cltv_expiry_delta`, so it would
        # use C's requested `cltv_expiry` of 9.  We also assume it adds a
        # "shadow route" to give an extra CLTV of 42.  It could also add extra
        # cltv deltas at other hops, as these values are a minimum, but we don't
        # here for simplicity:

        # FIXME: Add shadow route
        shadow_route = 0
        route = l2.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
        assert len(route) == 1

        # BOLT #7:
        #
        #    * `amount_msat`: 4999999
        #    * `cltv_expiry`: current-block-height + 9 + 42
        #    * `onion_routing_packet`:
        #      * `amt_to_forward` = 4999999
        #      * `outgoing_cltv_value` = current-block-height + 9 + 42
        #
        assert route[0]['msatoshi'] == 4999999
        assert route[0]['delay'] == 9 + shadow_route

        # BOLT #7:
        # If A were to send 4,999,999 millisatoshi to C via B, it needs to
        # pay B the fee it specified in the B->C `channel_update`, calculated as
        # per [HTLC Fees](#htlc_fees):
        #
        # 200 + 4999999 * 2000 / 1000000 = 10199
        #
        # Similarly, it would need to add the `cltv_expiry` from B->C's
        # `channel_update` (20), plus C's requested minimum (9), plus 42 for the
        # "shadow route".  Thus the `update_add_htlc` message from A to B would
        # be:
        #
        #    * `amount_msat`: 5010198
        #    * `cltv_expiry`: current-block-height + 20 + 9 + 42
        #    * `onion_routing_packet`:
        #      * `amt_to_forward` = 4999999
        #      * `outgoing_cltv_value` = current-block-height + 9 + 42
        route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
        assert len(route) == 2

        assert route[0]['msatoshi'] == 5010198
        assert route[0]['delay'] == 20 + 9 + shadow_route
        assert route[1]['msatoshi'] == 4999999
        assert route[1]['delay'] == 9 + shadow_route

        rhash = l3.rpc.invoice(4999999, 'test_forward_different_fees_and_cltv', 'desc')['payment_hash']
        assert only_one(l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'])['status'] == 'unpaid'

        # This should work.
        l1.rpc.sendpay(to_json(route), rhash)
        l1.rpc.waitsendpay(rhash)

        # We add one to the blockcount for a bit of fuzz (FIXME: Shadowroute would fix this!)
        shadow_route = 1
        l1.daemon.wait_for_log("Adding HTLC 0 msat=5010198 cltv={} gave CHANNEL_ERR_ADD_OK"
                               .format(bitcoind.rpc.getblockcount() + 20 + 9 + shadow_route))
        l2.daemon.wait_for_log("Adding HTLC 0 msat=4999999 cltv={} gave CHANNEL_ERR_ADD_OK"
                               .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
        l3.daemon.wait_for_log("test_forward_different_fees_and_cltv: Actual amount 4999999msat, HTLC expiry {}"
                               .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
        assert only_one(l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'])['status'] == 'paid'

        # Check that we see all the channels
        shortids = set(c['short_channel_id'] for c in l2.rpc.listchannels()['channels'])
        for scid in shortids:
            c = l1.rpc.listchannels(scid)['channels']
            # We get one entry for each direction.
            assert len(c) == 2
            assert c[0]['short_channel_id'] == scid
            assert c[1]['short_channel_id'] == scid
            assert c[0]['source'] == c[1]['destination']
            assert c[1]['source'] == c[0]['destination']

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_forward_pad_fees_and_cltv(self):
        """Test that we are allowed extra locktime delta, and fees"""

        l1 = self.node_factory.get_node(options={'cltv-delta': 10, 'fee-base': 100, 'fee-per-satoshi': 1000})
        l2 = self.node_factory.get_node(options={'cltv-delta': 20, 'fee-base': 200, 'fee-per-satoshi': 2000})
        l3 = self.node_factory.get_node(options={'cltv-delta': 30, 'cltv-final': 9, 'fee-base': 300, 'fee-per-satoshi': 3000})

        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('Handing back peer .* to master')
        l2.daemon.wait_for_log('Handing back peer .* to master')

        ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
        assert ret['id'] == l3.info['id']

        l2.daemon.wait_for_log('Handing back peer .* to master')
        l3.daemon.wait_for_log('Handing back peer .* to master')

        c1 = self.fund_channel(l1, l2, 10**6)
        c2 = self.fund_channel(l2, l3, 10**6)

        # Make sure l1 has seen announce for all channels.
        self.wait_for_routes(l1, [c1, c2])

        route = l1.rpc.getroute(l3.info['id'], 4999999, 1)["route"]
        assert len(route) == 2

        assert route[0]['msatoshi'] == 5010198
        assert route[0]['delay'] == 20 + 9
        assert route[1]['msatoshi'] == 4999999
        assert route[1]['delay'] == 9

        # Modify so we overpay, overdo the cltv.
        route[0]['msatoshi'] += 2000
        route[0]['delay'] += 20
        route[1]['msatoshi'] += 1000
        route[1]['delay'] += 10

        # This should work.
        rhash = l3.rpc.invoice(4999999, 'test_forward_pad_fees_and_cltv', 'desc')['payment_hash']
        l1.rpc.sendpay(to_json(route), rhash)
        l1.rpc.waitsendpay(rhash)
        assert only_one(l3.rpc.listinvoices('test_forward_pad_fees_and_cltv')['invoices'])['status'] == 'paid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_htlc_sig_persistence(self):
        """Interrupt a payment between two peers, then fail and recover funds using the HTLC sig.
        """
        l1 = self.node_factory.get_node(options={'dev-no-reconnect': None})
        l2 = self.node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'])

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        self.fund_channel(l1, l2, 10**6)
        f = self.executor.submit(self.pay, l1, l2, 31337000)
        l1.daemon.wait_for_log(r'HTLC out 0 RCVD_ADD_ACK_COMMIT->SENT_ADD_ACK_REVOCATION')
        l1.stop()

        # `pay` call is lost
        self.assertRaises(RpcError, f.result)

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
    def test_htlc_out_timeout(self):
        """Test that we drop onchain if the peer doesn't time out HTLC"""

        # HTLC 1->2, 1 fails after it's irrevocably committed, can't reconnect
        disconnects = ['@WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        options={'dev-no-reconnect': None})
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        chanid = self.fund_channel(l1, l2, 10**6)

        # Wait for route propagation.
        self.wait_for_routes(l1, [chanid])

        amt = 200000000
        inv = l2.rpc.invoice(amt, 'test_htlc_out_timeout', 'desc')['bolt11']
        assert only_one(l2.rpc.listinvoices('test_htlc_out_timeout')['invoices'])['status'] == 'unpaid'

        self.executor.submit(l1.rpc.pay, inv)

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
    def test_htlc_in_timeout(self):
        """Test that we drop onchain if the peer doesn't accept fulfilled HTLC"""

        # HTLC 1->2, 1 fails after 2 has sent committed the fulfill
        disconnects = ['-WIRE_REVOKE_AND_ACK*2']
        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        options={'dev-no-reconnect': None})
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        chanid = self.fund_channel(l1, l2, 10**6)

        self.wait_for_routes(l1, [chanid])
        sync_blockheight([l1, l2])

        amt = 200000000
        inv = l2.rpc.invoice(amt, 'test_htlc_in_timeout', 'desc')['bolt11']
        assert only_one(l2.rpc.listinvoices('test_htlc_in_timeout')['invoices'])['status'] == 'unpaid'

        self.executor.submit(l1.rpc.pay, inv)

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
    def test_disconnect(self):
        # These should all make us fail
        disconnects = ['-WIRE_INIT',
                       '@WIRE_INIT',
                       '+WIRE_INIT']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        self.assertRaises(RpcError, l1.rpc.connect,
                          l2.info['id'], 'localhost', l2.port)
        self.assertRaises(RpcError, l1.rpc.connect,
                          l2.info['id'], 'localhost', l2.port)
        self.assertRaises(RpcError, l1.rpc.connect,
                          l2.info['id'], 'localhost', l2.port)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # Should have 3 connect fails.
        for d in disconnects:
            l1.daemon.wait_for_log('Failed connected out for {}'
                                   .format(l2.info['id']))

        # Should still only have one peer!
        assert len(l1.rpc.listpeers()) == 1
        assert len(l2.rpc.listpeers()) == 1

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_disconnect_funder(self):
        # Now error on funder side duringchannel open.
        disconnects = ['-WIRE_OPEN_CHANNEL',
                       '@WIRE_OPEN_CHANNEL',
                       '+WIRE_OPEN_CHANNEL',
                       '-WIRE_FUNDING_CREATED',
                       '@WIRE_FUNDING_CREATED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        self.give_funds(l1, 2000000)

        for d in disconnects:
            l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
            self.assertRaises(RpcError, l1.rpc.fundchannel, l2.info['id'], 20000)
            assert l1.rpc.getpeer(l2.info['id']) is None

        # This one will succeed.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.fundchannel(l2.info['id'], 20000)

        # Should still only have one peer!
        assert len(l1.rpc.listpeers()) == 1
        assert len(l2.rpc.listpeers()) == 1

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_disconnect_fundee(self):
        # Now error on fundee side during channel open.
        disconnects = ['-WIRE_ACCEPT_CHANNEL',
                       '@WIRE_ACCEPT_CHANNEL',
                       '+WIRE_ACCEPT_CHANNEL']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        self.give_funds(l1, 2000000)

        for d in disconnects:
            l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
            self.assertRaises(RpcError, l1.rpc.fundchannel, l2.info['id'], 20000)
            assert l1.rpc.getpeer(l2.info['id']) is None

        # This one will succeed.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.fundchannel(l2.info['id'], 20000)

        # Should still only have one peer!
        assert len(l1.rpc.listpeers()) == 1
        assert len(l2.rpc.listpeers()) == 1

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_disconnect_half_signed(self):
        # Now, these are the corner cases.  Fundee sends funding_signed,
        # but funder doesn't receive it.
        disconnects = ['@WIRE_FUNDING_SIGNED']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        self.give_funds(l1, 2000000)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        self.assertRaises(RpcError, l1.rpc.fundchannel, l2.info['id'], 20000)

        # Fundee remembers, funder doesn't.
        assert l1.rpc.getpeer(l2.info['id']) is None
        assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_signed(self):
        # This will fail *after* both sides consider channel opening.
        disconnects = ['+WIRE_FUNDING_SIGNED']
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)

        self.give_funds(l1, 2000000)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.fundchannel(l2.info['id'], 20000)

        # They haven't forgotten each other.
        assert l1.rpc.getpeer(l2.info['id'])['id'] == l2.info['id']
        assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

        # Technically, this is async to fundchannel (and could reconnect first)
        l1.daemon.wait_for_logs(['sendrawtx exit 0',
                                 'Peer has reconnected, state CHANNELD_AWAITING_LOCKIN'])

        l1.bitcoin.generate_block(6)

        l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
        l2.daemon.wait_for_log(' to CHANNELD_NORMAL')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_openingd(self):
        # Openingd thinks we're still opening; funder reconnects..
        disconnects = ['0WIRE_ACCEPT_CHANNEL']
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.give_funds(l1, 2000000)

        # l2 closes on l1, l1 forgets.
        self.assertRaises(RpcError, l1.rpc.fundchannel, l2.info['id'], 20000)
        assert l1.rpc.getpeer(l2.info['id']) is None

        # Reconnect.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # We should get a message about reconnecting, but order unsynced.
        l2.daemon.wait_for_logs(['connectd.*reconnect for active peer',
                                 'Killing openingd: Reconnected'])

        # Should work fine.
        l1.rpc.fundchannel(l2.info['id'], 20000)
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # Just to be sure, second openingd hand over to channeld.
        l2.daemon.wait_for_log('lightning_openingd.*REPLY WIRE_OPENING_FUNDEE_REPLY with 2 fds')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_normal(self):
        # Should reconnect fine even if locked message gets lost.
        disconnects = ['-WIRE_FUNDING_LOCKED',
                       '@WIRE_FUNDING_LOCKED',
                       '+WIRE_FUNDING_LOCKED']
        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l2 = self.node_factory.get_node(may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.fund_channel(l1, l2, 10**6)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_sender_add1(self):
        # Fail after add is OK, will cause payment failure though.
        disconnects = ['-WIRE_UPDATE_ADD_HTLC-nocommit',
                       '+WIRE_UPDATE_ADD_HTLC-nocommit',
                       '@WIRE_UPDATE_ADD_HTLC-nocommit']

        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l2 = self.node_factory.get_node(may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'test_reconnect_sender_add1', 'desc')['payment_hash']
        assert only_one(l2.rpc.listinvoices('test_reconnect_sender_add1')['invoices'])['status'] == 'unpaid'

        route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]

        for i in range(0, len(disconnects)):
            l1.rpc.sendpay(to_json(route), rhash)
            self.assertRaises(RpcError, l1.rpc.waitsendpay, rhash)
            # Wait for reconnection.
            l1.daemon.wait_for_log('Already have funding locked in')

        # This will send commit, so will reconnect as required.
        l1.rpc.sendpay(to_json(route), rhash)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_sender_add(self):
        disconnects = ['-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l2 = self.node_factory.get_node(may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment', 'desc')['payment_hash']
        assert only_one(l2.rpc.listinvoices('testpayment')['invoices'])['status'] == 'unpaid'

        route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]

        # This will send commit, so will reconnect as required.
        l1.rpc.sendpay(to_json(route), rhash)
        # Should have printed this for every reconnect.
        for i in range(0, len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_receiver_add(self):
        disconnects = ['-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
        assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'unpaid'

        route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]
        l1.rpc.sendpay(to_json(route), rhash)
        for i in range(len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')
        assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_receiver_fulfill(self):
        # Ordering matters: after +WIRE_UPDATE_FULFILL_HTLC, channeld
        # will continue and try to send WIRE_COMMITMENT_SIGNED: if
        # that's the next failure, it will do two in one run.
        disconnects = ['@WIRE_UPDATE_FULFILL_HTLC',
                       '+WIRE_UPDATE_FULFILL_HTLC',
                       '-WIRE_UPDATE_FULFILL_HTLC',
                       '-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
        assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'unpaid'

        route = [{'msatoshi': amt, 'id': l2.info['id'], 'delay': 5, 'channel': '1:1:1'}]
        l1.rpc.sendpay(to_json(route), rhash)
        for i in range(len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')
        assert only_one(l2.rpc.listinvoices('testpayment2')['invoices'])['status'] == 'paid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_shutdown_reconnect(self):
        disconnects = ['-WIRE_SHUTDOWN',
                       '@WIRE_SHUTDOWN',
                       '+WIRE_SHUTDOWN']
        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        may_reconnect=True)
        l2 = self.node_factory.get_node(may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        chan = self.fund_channel(l1, l2, 10**6)
        self.pay(l1, l2, 200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return with an error, then close.
        self.assertRaisesRegex(RpcError,
                               "Channel close negotiation not finished",
                               l1.rpc.close, chan, False, 0)
        l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool (happens async, so
        # CLOSINGD_COMPLETE may come first).
        l1.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
        l2.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    def test_shutdown_awaiting_lockin(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(options={'funding-confirms': 3})

        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        self.give_funds(l1, 10**6 + 1000000)
        chanid = l1.rpc.fundchannel(l2.info['id'], 10**6)['channel_id']

        # Technically, this is async to fundchannel.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)

        # This should return with an error, then close.
        self.assertRaisesRegex(RpcError,
                               "Channel close negotiation not finished",
                               l1.rpc.close, chanid, False, 0)
        l1.daemon.wait_for_log('CHANNELD_AWAITING_LOCKIN to CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('CHANNELD_AWAITING_LOCKIN to CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('CHANNELD_SHUTTING_DOWN to CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('CHANNELD_SHUTTING_DOWN to CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool (happens async, so
        # CLOSINGD_COMPLETE may come first).
        l1.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
        l2.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
        assert bitcoind.rpc.getmempoolinfo()['size'] == 1

        bitcoind.generate_block(1)
        l1.daemon.wait_for_log(' to ONCHAIN')
        l2.daemon.wait_for_log(' to ONCHAIN')

        bitcoind.generate_block(100)
        wait_forget_channels(l1)
        wait_forget_channels(l2)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_bech32_funding(self):
        # Don't get any funds from previous runs.
        l1 = self.node_factory.get_node(random_hsm=True)
        l2 = self.node_factory.get_node(random_hsm=True)

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

    def test_withdraw(self):
        amount = 1000000
        # Don't get any funds from previous runs.
        l1 = self.node_factory.get_node(random_hsm=True)
        l2 = self.node_factory.get_node(random_hsm=True)
        addr = l1.rpc.newaddr()['address']

        # Add some funds to withdraw later
        for i in range(10):
            l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

        bitcoind.generate_block(1)
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

        # Reach around into the db to check that outputs were added
        db = sqlite3.connect(os.path.join(l1.daemon.lightning_dir, "lightningd.sqlite3"))

        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 10)

        waddr = l1.bitcoin.rpc.getnewaddress()
        # Now attempt to withdraw some (making sure we collect multiple inputs)
        self.assertRaises(RpcError, l1.rpc.withdraw, 'not an address', amount)
        self.assertRaises(RpcError, l1.rpc.withdraw, waddr, 'not an amount')
        self.assertRaises(RpcError, l1.rpc.withdraw, waddr, -amount)

        out = l1.rpc.withdraw(waddr, 2 * amount)

        # Make sure bitcoind received the withdrawal
        unspent = l1.bitcoin.rpc.listunspent(0)
        withdrawal = [u for u in unspent if u['txid'] == out['txid']]

        assert(withdrawal[0]['amount'] == Decimal('0.02'))

        # Now make sure two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 2)

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
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 4)

        # Simple test for withdrawal to P2WPKH
        # Address from: https://bc-2.jp/tools/bech32demo/index.html
        waddr = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
        self.assertRaises(RpcError, l1.rpc.withdraw, 'xx1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 2 * amount)
        self.assertRaises(RpcError, l1.rpc.withdraw, 'tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kdl9fad', 2 * amount)
        self.assertRaises(RpcError, l1.rpc.withdraw, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxxxxxx', 2 * amount)
        l1.rpc.withdraw(waddr, 2 * amount)
        l1.bitcoin.rpc.generate(1)
        # Now make sure additional two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 6)

        # Simple test for withdrawal to P2WSH
        # Address from: https://bc-2.jp/tools/bech32demo/index.html
        waddr = 'bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry'
        self.assertRaises(RpcError, l1.rpc.withdraw, 'xx1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 2 * amount)
        self.assertRaises(RpcError, l1.rpc.withdraw, 'tb1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsm03tq', 2 * amount)
        self.assertRaises(RpcError, l1.rpc.withdraw, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qxxxxxx', 2 * amount)
        l1.rpc.withdraw(waddr, 2 * amount)
        l1.bitcoin.rpc.generate(1)
        # Now make sure additional two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 8)

        # failure testing for invalid SegWit addresses, from BIP173
        # HRP character out of range
        self.assertRaises(RpcError, l1.rpc.withdraw, ' 1nwldj5', 2 * amount)
        # overall max length exceeded
        self.assertRaises(RpcError, l1.rpc.withdraw, 'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx', 2 * amount)
        # No separator character
        self.assertRaises(RpcError, l1.rpc.withdraw, 'pzry9x0s0muk', 2 * amount)
        # Empty HRP
        self.assertRaises(RpcError, l1.rpc.withdraw, '1pzry9x0s0muk', 2 * amount)
        # Invalid witness version
        self.assertRaises(RpcError, l1.rpc.withdraw, 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2', 2 * amount)
        # Invalid program length for witness version 0 (per BIP141)
        self.assertRaises(RpcError, l1.rpc.withdraw, 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 2 * amount)
        # Mixed case
        self.assertRaises(RpcError, l1.rpc.withdraw, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7', 2 * amount)
        # Non-zero padding in 8-to-5 conversion
        self.assertRaises(RpcError, l1.rpc.withdraw, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv', 2 * amount)

        # Should have 6 outputs available.
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 6)

        # Test withdrawal to self.
        l1.rpc.withdraw(l1.rpc.newaddr('bech32')['address'], 'all')
        bitcoind.rpc.generate(1)
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 1)

        l1.rpc.withdraw(waddr, 'all')
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 0)

        # This should fail, can't even afford fee.
        self.assertRaises(RpcError, l1.rpc.withdraw, waddr, 'all')
        l1.daemon.wait_for_log('Cannot afford transaction')

    def test_funding_change(self):
        """Add some funds, fund a channel, and make sure we remember the change
        """
        l1, l2 = self.connect()

        self.give_funds(l1, 0.1 * 10**8)

        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert only_one(outputs)['value'] == 10000000

        l1.rpc.fundchannel(l2.info['id'], 1000000)
        outputs = {r['status']: r['value'] for r in l1.db_query(
            'SELECT status, SUM(value) AS value FROM outputs GROUP BY status;')}

        # The 10m out is spent and we have a change output of 9m-fee
        assert outputs[0] > 8990000
        assert outputs[2] == 10000000

    def test_funding_all(self):
        """Add some funds, fund a channel using all funds, make sure no funds remain
        """
        l1, l2 = self.connect()

        self.give_funds(l1, 0.1 * 10**8)

        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert only_one(outputs)['value'] == 10000000

        l1.rpc.fundchannel(l2.info['id'], "all")

        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert len(outputs) == 0

    def test_funding_all_too_much(self):
        """Add more than max possible funds, fund a channel using all funds we can.
        """
        l1, l2 = self.connect()

        self.give_funds(l1, 2**24 + 10000)
        l1.rpc.fundchannel(l2.info['id'], "all")

        assert only_one(l1.rpc.listfunds()['outputs'])['status'] == 'unconfirmed'
        assert only_one(l1.rpc.listfunds()['channels'])['channel_total_sat'] == 2**24 - 1

    def test_funding_fail(self):
        """Add some funds, fund a channel without enough funds"""
        # Previous runs with same bitcoind can leave funds!
        max_locktime = 5 * 6 * 24
        l1 = self.node_factory.get_node(random_hsm=True, options={'max-locktime-blocks': max_locktime})
        l2 = self.node_factory.get_node(options={'watchtime-blocks': max_locktime + 1})
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        funds = 1000000

        addr = l1.rpc.newaddr()['address']
        l1.bitcoin.rpc.sendtoaddress(addr, funds / 10**8)
        bitcoind.generate_block(1)

        # Wait for it to arrive.
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

        # Fail because l1 dislikes l2's huge locktime.
        self.assertRaisesRegex(RpcError, r'to_self_delay \d+ larger than \d+',
                               l1.rpc.fundchannel, l2.info['id'], int(funds / 10))
        assert only_one(l1.rpc.listpeers()['peers'])['connected']
        assert only_one(l2.rpc.listpeers()['peers'])['connected']

        # Restart l2 without ridiculous locktime.
        del l2.daemon.opts['watchtime-blocks']
        l2.restart()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # We don't have enough left to cover fees if we try to spend it all.
        self.assertRaisesRegex(RpcError, r'Cannot afford transaction',
                               l1.rpc.fundchannel, l2.info['id'], funds)

        # Should still be connected.
        assert only_one(l1.rpc.listpeers()['peers'])['connected']
        assert only_one(l2.rpc.listpeers()['peers'])['connected']

        # This works.
        l1.rpc.fundchannel(l2.info['id'], int(funds / 10))

    def test_funding_toolarge(self):
        """Try to create a giant channel"""
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # Send funds.
        amount = 2**24
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['address'], amount / 10**8 + 0.01)
        bitcoind.generate_block(1)

        # Wait for it to arrive.
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

        # Fail to open (too large)
        try:
            l1.rpc.fundchannel(l2.info['id'], amount)
            self.fail('Expected fundchannel to fail!')
        except RpcError as err:
            assert 'Amount exceeded 16777215' in str(err)

        # This should work.
        amount = amount - 1
        l1.rpc.fundchannel(l2.info['id'], amount)

    def test_lockin_between_restart(self):
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(options={'funding-confirms': 3},
                                        may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        self.give_funds(l1, 10**6 + 1000000)
        l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']

        # l1 goes down.
        l1.stop()

        # Now 120 blocks go by...
        bitcoind.generate_block(120)

        # Restart
        l1.start()

        # All should be good.
        l1.daemon.wait_for_log(' to CHANNELD_NORMAL')
        l2.daemon.wait_for_log(' to CHANNELD_NORMAL')

    def test_funding_while_offline(self):
        l1 = self.node_factory.get_node()
        addr = l1.rpc.newaddr()['address']
        sync_blockheight([l1])

        # l1 goes down.
        l1.stop()

        # We send funds
        bitcoind.rpc.sendtoaddress(addr, (10**6 + 1000000) / 10**8)

        # Now 120 blocks go by...
        bitcoind.generate_block(120)

        # Restart
        l1.start()
        sync_blockheight([l1])

        assert len(l1.rpc.listfunds()['outputs']) == 1

    def test_addfunds_from_block(self):
        """Send funds to the daemon without telling it explicitly
        """
        # Previous runs with same bitcoind can leave funds!
        l1 = self.node_factory.get_node(random_hsm=True)

        addr = l1.rpc.newaddr()['address']
        l1.bitcoin.rpc.sendtoaddress(addr, 0.1)
        l1.bitcoin.rpc.generate(1)

        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert only_one(outputs)['value'] == 10000000

        # The address we detect must match what was paid to.
        output = only_one(l1.rpc.listfunds()['outputs'])
        assert output['address'] == addr

        # Send all our money to a P2WPKH address this time.
        addr = l1.rpc.newaddr("bech32")['address']
        l1.rpc.withdraw(addr, "all")
        l1.bitcoin.rpc.generate(1)
        time.sleep(1)

        # The address we detect must match what was paid to.
        output = only_one(l1.rpc.listfunds()['outputs'])
        assert output['address'] == addr

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_channel_persistence(self):
        # Start two nodes and open a channel (to remember). l2 will
        # mysteriously die while committing the first HTLC so we can
        # check that HTLCs reloaded from the DB work.
        l1 = self.node_factory.get_node(may_reconnect=True)
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'],
                                        may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # Neither node should have a channel open, they are just connected
        for n in (l1, l2):
            assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 0)

        self.fund_channel(l1, l2, 100000)

        peers = l1.rpc.listpeers()['peers']
        assert(only_one(peers[0]['channels'])['state'] == 'CHANNELD_NORMAL')

        # Both nodes should now have exactly one channel in the database
        for n in (l1, l2):
            assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 1)

        # Fire off a sendpay request, it'll get interrupted by a restart
        self.executor.submit(self.pay, l1, l2, 10000)
        # Wait for it to be committed to, i.e., stored in the DB
        l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

        # Stop l2, l1 will reattempt to connect
        print("Killing l2 in mid HTLC")
        l2.daemon.kill()

        # Clear the disconnect and timer stop so we can proceed normally
        del l2.daemon.opts['dev-disconnect']

        # Wait for l1 to notice
        wait_for(lambda: 'connected' not in only_one(l1.rpc.listpeers()['peers'][0]['channels']))

        # Now restart l2 and it should reload peers/channels from the DB
        l2.start()
        wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 1)

        # Wait for the restored HTLC to finish
        wait_for(lambda: only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99990000, interval=1)

        wait_for(lambda: len([p for p in l1.rpc.listpeers()['peers'] if p['connected']]), interval=1)
        wait_for(lambda: len([p for p in l2.rpc.listpeers()['peers'] if p['connected']]), interval=1)

        # Now make sure this is really functional by sending a payment
        self.pay(l1, l2, 10000)

        # L1 doesn't actually update msatoshi_to_us until it receives
        # revoke_and_ack from L2, which can take a little bit.
        wait_for(lambda: only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99980000)
        assert only_one(l2.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 20000

        # Finally restart l1, and make sure it remembers
        l1.restart()
        assert only_one(l1.rpc.listpeers()['peers'][0]['channels'])['msatoshi_to_us'] == 99980000

        # Now make sure l1 is watching for unilateral closes
        l2.rpc.dev_fail(l1.info['id'])
        l2.daemon.wait_for_log('Failing due to dev-fail command')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)

        # L1 must notice.
        l1.daemon.wait_for_log(' to ONCHAIN')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_channel_reenable(self):
        l1, l2 = self.connect(may_reconnect=True)
        self.fund_channel(l1, l2, 10**6)

        l1.bitcoin.generate_block(6)
        l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))
        l2.daemon.wait_for_log('Received node_announcement for node {}'.format(l1.info['id']))

        # Both directions should be active before the restart
        wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])

        # Restart l2, will cause l1 to reconnect
        l2.restart()

        # Now they should sync and re-establish again
        l1.daemon.wait_for_logs(['Received channel_update for channel \\d+:1:1.1.',
                                 'Received channel_update for channel \\d+:1:1.0.'])
        l2.daemon.wait_for_logs(['Received channel_update for channel \\d+:1:1.1.',
                                 'Received channel_update for channel \\d+:1:1.0.'])
        wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_update_fee(self):
        l1, l2 = self.connect()
        chanid = self.fund_channel(l1, l2, 10**6)

        # Make l1 send out feechange.
        l1.rpc.dev_setfees('14000')
        l2.daemon.wait_for_log('peer updated fee to 14000')

        # Now make sure an HTLC works.
        # (First wait for route propagation.)
        self.wait_for_routes(l1, [chanid])
        sync_blockheight([l1, l2])

        # Make payments.
        self.pay(l1, l2, 200000000)
        self.pay(l2, l1, 100000000)

        # Now shutdown cleanly.
        self.assertRaisesRegex(RpcError,
                               "Channel close negotiation not finished",
                               l1.rpc.close, chanid, False, 0)
        l1.daemon.wait_for_log(' to CLOSINGD_COMPLETE')
        l2.daemon.wait_for_log(' to CLOSINGD_COMPLETE')

        # And should put closing into mempool.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        bitcoind.generate_block(1)
        l1.daemon.wait_for_log(' to ONCHAIN')
        l2.daemon.wait_for_log(' to ONCHAIN')

        bitcoind.generate_block(99)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_update_all_fees(self):
        l1, l2 = self.connect()
        chan = self.fund_channel(l1, l2, 10**6)

        # Set all fees as positional parameters.
        l1.rpc.dev_setfees('12345', '6789', '123')
        l1.daemon.wait_for_log('dev-setfees: fees now 12345/6789/123')
        l2.daemon.wait_for_log('peer updated fee to 12345')

        # Call setfees with fees passed as named parameters in different order.
        l1.rpc.dev_setfees(slow='123', normal='4567', immediate='8901')
        l1.daemon.wait_for_log('dev-setfees: fees now 8901/4567/123')
        l2.daemon.wait_for_log('peer updated fee to 8901')

        # Set one value at a time.
        l1.rpc.dev_setfees(slow='321')
        l1.daemon.wait_for_log('dev-setfees: fees now 8901/4567/321')
        l1.rpc.dev_setfees(normal='7654')
        l1.daemon.wait_for_log('dev-setfees: fees now 8901/7654/321')
        l1.rpc.dev_setfees(immediate='21098')
        l1.daemon.wait_for_log('dev-setfees: fees now 21098/7654/321')
        l2.daemon.wait_for_log('peer updated fee to 21098')

        # Verify that all fees are indeed optional in setfees call.
        l1.rpc.dev_setfees()
        l1.daemon.wait_for_log('dev-setfees: fees now 21098/7654/321')

        # This should return finish closing.
        l1.rpc.close(chan)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_fee_limits(self):
        # FIXME: Test case where opening denied.
        l1, l2 = self.node_factory.get_nodes(2, opts={'dev-max-fee-multiplier': 5})
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.fund_channel(l2, 10**6)

        # L1 asks for stupid low fees
        l1.rpc.dev_setfees(15)

        l1.daemon.wait_for_log('Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: received ERROR channel .*: update_fee 15 outside range 1875-75000')
        # Make sure the resolution of this one doesn't interfere with the next!
        # Note: may succeed, may fail with insufficient fee, depending on how
        # bitcoind feels!
        l1.daemon.wait_for_log('sendrawtx exit')

        # Restore to normal.
        l1.rpc.dev_setfees(15000)

        # Try with node which sets --ignore-fee-limits
        l3 = self.node_factory.get_node(options={'ignore-fee-limits': 'true'})
        l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

        chan = self.fund_channel(l1, l3, 10**6)

        # Try stupid high fees
        l1.rpc.dev_setfees(15000 * 10)

        l3.daemon.wait_for_log('peer_in WIRE_UPDATE_FEE')
        l3.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

        # We need to wait until both have committed and revoked the
        # old state, otherwise we'll still try to commit with the old
        # 15sat/byte fee
        l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

        # This should wait for close to complete
        l1.rpc.close(chan)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_update_fee_reconnect(self):
        # Disconnect after first commitsig.
        disconnects = ['+WIRE_COMMITMENT_SIGNED']
        l1 = self.node_factory.get_node(disconnect=disconnects, may_reconnect=True)
        l2 = self.node_factory.get_node(may_reconnect=True)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        chan = self.fund_channel(l1, l2, 10**6)

        # Make l1 send out feechange; triggers disconnect/reconnect.
        l1.rpc.dev_setfees('14000')
        l1.daemon.wait_for_log('Setting REMOTE feerate to 14000')
        l2.daemon.wait_for_log('Setting LOCAL feerate to 14000')
        l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

        # Wait for reconnect....
        l1.daemon.wait_for_log('Applying feerate 14000 to LOCAL')

        self.pay(l1, l2, 200000000)
        self.pay(l2, l1, 100000000)

        # They should both have gotten commits with correct feerate.
        assert l1.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')
        assert l2.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')

        # Now shutdown cleanly.
        l1.rpc.close(chan)

        # And should put closing into mempool.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        bitcoind.generate_block(1)
        l1.daemon.wait_for_log(' to ONCHAIN')
        l2.daemon.wait_for_log(' to ONCHAIN')

        bitcoind.generate_block(99)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_io_logging(self):
        l1 = self.node_factory.get_node(options={'log-level': 'io'})
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # Fundchannel manually so we get channeld pid.
        self.give_funds(l1, 10**6 + 1000000)
        l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']
        pid1 = l1.subd_pid('channeld')

        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log(' to CHANNELD_NORMAL')

        pid2 = l2.subd_pid('channeld')
        l2.daemon.wait_for_log(' to CHANNELD_NORMAL')

        # Send it sigusr1: should turn on logging.
        subprocess.run(['kill', '-USR1', pid1])

        fut = self.pay(l1, l2, 200000000, async=True)

        # WIRE_UPDATE_ADD_HTLC = 128 = 0x0080
        l1.daemon.wait_for_log(r'channeld.*:\[OUT\] 0080')
        # WIRE_UPDATE_FULFILL_HTLC = 130 = 0x0082
        l1.daemon.wait_for_log(r'channeld.*:\[IN\] 0082')
        fut.result(10)

        # Send it sigusr1: should turn off logging.
        subprocess.run(['kill', '-USR1', pid1])

        self.pay(l1, l2, 200000000)

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
        self.pay(l1, l2, 200000000)

        # Now it should find it.
        peerlog = only_one(l2.rpc.listpeers(l1.info['id'], "io")['peers'])['log']
        assert any(l['type'] == 'IO_OUT' for l in peerlog)
        assert any(l['type'] == 'IO_IN' for l in peerlog)

    def test_address(self):
        l1 = self.node_factory.get_node()
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

    def test_listconfigs(self):
        l1 = self.node_factory.get_node()

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

    @unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
    def test_multiple_channels(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()

        for i in range(3):
            # FIXME: we shouldn't disconnect on close?
            ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
            assert ret['id'] == l2.info['id']

            l1.daemon.wait_for_log('Handing back peer .* to master')
            l2.daemon.wait_for_log('Handing back peer .* to master')
            chan = self.fund_channel(l1, l2, 10**6)

            l1.rpc.close(chan)

        channels = only_one(l1.rpc.listpeers()['peers'])['channels']
        assert len(channels) == 3
        # Most in state ONCHAIN, last is CLOSINGD_COMPLETE
        for i in range(len(channels) - 1):
            assert channels[i]['state'] == 'ONCHAIN'
        assert channels[-1]['state'] == 'CLOSINGD_COMPLETE'

    def test_multirpc(self):
        """Test that we can do multiple RPC without waiting for response"""
        l1 = self.node_factory.get_node()

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

    def test_cli(self):
        l1 = self.node_factory.get_node()

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

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_forget_channel(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        self.give_funds(l1, 10**6)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.fundchannel(l2.info['id'], 10**5)

        assert len(l1.rpc.listpeers()['peers']) == 1

        # This should fail, the funding tx is in the mempool and may confirm
        self.assertRaisesRegex(RpcError,
                               "Cowardly refusing to forget channel",
                               l1.rpc.dev_forget_channel, l2.info['id'])
        assert len(l1.rpc.listpeers()['peers']) == 1

        # Forcing should work
        l1.rpc.dev_forget_channel(l2.info['id'], True)
        assert len(l1.rpc.listpeers()['peers']) == 0

        # And restarting should keep that peer forgotten
        l1.restart()
        assert len(l1.rpc.listpeers()['peers']) == 0

    def test_peerinfo(self):
        l1, l2 = self.connect()
        # Gossiping but no node announcement yet
        assert l1.rpc.getpeer(l2.info['id'])['state'] == "GOSSIPING"
        assert l1.rpc.getpeer(l2.info['id'])['local_features'] == '88'
        assert l1.rpc.getpeer(l2.info['id'])['global_features'] == ''

        # Fund a channel to force a node announcement
        chan = self.fund_channel(l1, l2, 10**6)
        # Now proceed to funding-depth and do a full gossip round
        bitcoind.generate_block(5)
        l1.daemon.wait_for_logs(['Received node_announcement for node ' + l2.info['id']])
        l2.daemon.wait_for_logs(['Received node_announcement for node ' + l1.info['id']])

        # Should have announced the same global features as told to peer.
        assert only_one(l1.rpc.listnodes(l2.info['id'])['nodes'])['global_features'] == l1.rpc.getpeer(l2.info['id'])['global_features']
        assert only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['global_features'] == l2.rpc.getpeer(l1.info['id'])['global_features']

        # Close the channel to forget the peer
        self.assertRaisesRegex(RpcError,
                               "Channel close negotiation not finished",
                               l1.rpc.close, chan, False, 0)
        l1.daemon.wait_for_log('Forgetting remote peer')
        bitcoind.generate_block(100)
        l1.daemon.wait_for_log('WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED')
        l2.daemon.wait_for_log('WIRE_ONCHAIN_ALL_IRREVOCABLY_RESOLVED')

        # The only channel was closed, everybody should have forgotten the nodes
        assert l1.rpc.listnodes()['nodes'] == []
        assert l2.rpc.listnodes()['nodes'] == []

    @flaky
    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_blockchaintrack(self):
        """Check that we track the blockchain correctly across reorgs
        """
        l1 = self.node_factory.get_node(random_hsm=True)
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

    def test_disconnectpeer(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.connect(l3.info['id'], 'localhost', l3.port)

        # Gossiping
        assert l1.rpc.getpeer(l2.info['id'])['state'] == "GOSSIPING"
        assert l1.rpc.getpeer(l3.info['id'])['state'] == "GOSSIPING"

        # Disconnect l2 from l1
        l1.rpc.disconnect(l2.info['id'])

        # Make sure listpeers no longer returns the disconnected node
        assert l1.rpc.getpeer(l2.info['id']) is None
        assert l2.rpc.getpeer(l1.info['id']) is None

        # Make sure you cannot disconnect after disconnecting
        self.assertRaisesRegex(RpcError, "Peer not connected",
                               l1.rpc.disconnect, l2.info['id'])
        self.assertRaisesRegex(RpcError, "Peer not connected",
                               l2.rpc.disconnect, l1.info['id'])

        # Fund channel l1 -> l3
        self.fund_channel(l1, l3, 10**6)
        bitcoind.generate_block(5)

        # disconnecting a non gossiping peer results in error
        self.assertRaisesRegex(RpcError, "Peer is not in gossip mode",
                               l1.rpc.disconnect, l3.info['id'])

    def test_rescan(self):
        """Test the rescan option
        """
        l1 = self.node_factory.get_node()

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

    @unittest.skipIf(not DEVELOPER, "needs --dev-max-funding-unconfirmed-blocks")
    def test_fundee_forget_funding_tx_unconfirmed(self):
        """Test that fundee will forget the channel if
        the funding tx has been unconfirmed for too long.
        """
        # Keep this low (default is 2016), since everything
        # is much slower in VALGRIND mode and wait_for_log
        # could time out before lightningd processes all the
        # blocks.
        blocks = 200
        # funder
        l1 = self.node_factory.get_node(fake_bitcoin_cli=True)
        # fundee
        l2 = self.node_factory.get_node(options={"dev-max-funding-unconfirmed-blocks": blocks})
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

        # Give funder some funds.
        self.give_funds(l1, 10**7)
        # Let blocks settle.
        time.sleep(1)

        # Prevent funder from broadcasting funding tx.
        self.fake_bitcoind_fail(l1, 1)
        # Fund the channel.
        # The process will complete, but funder will be unable
        # to broadcast and confirm funding tx.
        l1.rpc.fundchannel(l2.info['id'], 10**6)
        # Prevent l1 from timing out bitcoin-cli.
        self.fake_bitcoind_unfail(l1)
        # Generate blocks until unconfirmed.
        bitcoind.generate_block(blocks)

        # fundee will forget channel!
        l2.daemon.wait_for_log('Forgetting channel: It has been {} blocks'.format(blocks))
        # fundee will also forget and disconnect from peer.
        assert len(l2.rpc.listpeers(l1.info['id'])['peers']) == 0

    def test_reserve_enforcement(self):
        """Channeld should disallow you spending into your reserve"""
        l1, l2 = self.connect(may_reconnect=True)

        self.fund_channel(l1, l2, 10**6)
        # Pay 1000 satoshi to l2.
        self.pay(l1, l2, 1000000)

        l2.stop()

        # They should both aim for 1%.
        assert l2.db_query('SELECT channel_reserve_satoshis FROM channel_configs') == [{'channel_reserve_satoshis': 10**6 // 100}, {'channel_reserve_satoshis': 10**6 // 100}]

        # Edit db to reduce reserve to 0 so it will try to violate it.
        l2.db_query('UPDATE channel_configs SET channel_reserve_satoshis=0',
                    use_copy=False)

        l2.start()
        wait_for(lambda: only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])

        # This should be impossible to pay entire thing back: l1 should
        # kill us for trying to violate reserve.
        self.pay(l2, l1, 1000000, async=True)
        l1.daemon.wait_for_log('Peer permanent failure in CHANNELD_NORMAL: lightning_channeld: sent ERROR Bad peer_add_htlc: CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
