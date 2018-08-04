from concurrent import futures
from decimal import Decimal
from flaky import flaky
from utils import NodeFactory, wait_for, only_one

import copy
import json
import logging
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


if __name__ == '__main__':
    unittest.main(verbosity=2)
