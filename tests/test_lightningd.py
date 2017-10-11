from binascii import hexlify, unhexlify
from concurrent import futures
from decimal import Decimal
from hashlib import sha256
from lightning import LightningRpc

import copy
import json
import logging
import queue
import os
import random
import re
import sqlite3
import string
import sys
import tempfile
import threading
import time
import unittest
import utils

bitcoind = None
TEST_DIR = tempfile.mkdtemp(prefix='lightning-')
VALGRIND = os.getenv("NO_VALGRIND", "0") == "0"
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"

print("Testing results are in {}".format(TEST_DIR))

if TEST_DEBUG:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logging.info("Tests running in '%s'", TEST_DIR)

def to_json(arg):
    return json.loads(json.dumps(arg))

def setupBitcoind():
    global bitcoind
    bitcoind = utils.BitcoinD(rpcport=28332)
    bitcoind.start()
    info = bitcoind.rpc.getinfo()
    # Make sure we have segwit and some funds
    if info['blocks'] < 432:
        logging.debug("SegWit not active, generating some more blocks")
        bitcoind.rpc.generate(432 - info['blocks'])
    elif info['balance'] < 1:
        logging.debug("Insufficient balance, generating 1 block")
        bitcoind.rpc.generate(1)


def wait_for(success, timeout=30, interval=0.1):
    start_time = time.time()
    while not success() and time.time() < start_time + timeout:
        time.sleep(interval)
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)


def sync_blockheight(nodes):
    target = bitcoind.rpc.getblockcount()
    for n in nodes:
        wait_for(lambda: n.rpc.getinfo()['blockheight'] == target)

def tearDownBitcoind():
    global bitcoind
    try:
        bitcoind.rpc.stop()
    except:
        bitcoind.proc.kill()
    bitcoind.proc.wait()


def setUpModule():
    setupBitcoind()


def tearDownModule():
    tearDownBitcoind()

def breakpoint():
    import pdb; pdb.set_trace()

class NodeFactory(object):
    """A factory to setup and start `lightningd` daemons.
    """
    def __init__(self, func, executor):
        self.func = func
        self.next_id = 1
        self.nodes = []
        self.executor = executor

    def get_node(self, disconnect=None, options=None, may_fail=False):
        node_id = self.next_id
        self.next_id += 1

        lightning_dir = os.path.join(
            TEST_DIR, self.func._testMethodName, "lightning-{}/".format(node_id))

        socket_path = os.path.join(lightning_dir, "lightning-rpc").format(node_id)
        port = 16330+node_id
        daemon = utils.LightningD(lightning_dir, bitcoind.bitcoin_dir, port=port)
        # If we have a disconnect string, dump it to a file for daemon.
        if disconnect:
            with open(os.path.join(lightning_dir, "dev_disconnect"), "w") as f:
                f.write("\n".join(disconnect))
            daemon.cmd_line.append("--dev-disconnect=dev_disconnect")
        daemon.cmd_line.append("--dev-fail-on-subdaemon-fail")
        opts = [] if options is None else options
        for opt in opts:
            daemon.cmd_line.append(opt)
        rpc = LightningRpc(socket_path, self.executor)

        node = utils.LightningNode(daemon, rpc, bitcoind, self.executor, may_fail=may_fail)
        self.nodes.append(node)
        if VALGRIND:
            node.daemon.cmd_line = [
                'valgrind',
                '-q',
                '--trace-children=yes',
                '--trace-children-skip=*bitcoin-cli*',
                '--error-exitcode=7',
                '--log-file={}/valgrind-errors.%p'.format(node.daemon.lightning_dir)
            ] + node.daemon.cmd_line

        node.daemon.start()
        # Cache `getinfo`, we'll be using it a lot
        node.info = node.rpc.getinfo()
        return node

    def killall(self):
        rcs = []
        failed = False
        for n in self.nodes:
            try:
                n.stop()
            except:
                failed = True
            rcs.append(n.daemon.proc.returncode)
        if failed:
            raise Exception("At least one lightning exited with non-zero return code: {}".format(rcs))


class BaseLightningDTests(unittest.TestCase):
    def setUp(self):
        # Most of the executor threads will be waiting for IO, so
        # let's have a few of them
        self.executor = futures.ThreadPoolExecutor(max_workers=20)
        self.node_factory = NodeFactory(self, self.executor)

    def getValgrindErrors(self, node):
        for error_file in os.listdir(node.daemon.lightning_dir):
            if not re.match("valgrind-errors.\d+", error_file):
                continue;
            with open(os.path.join(node.daemon.lightning_dir, error_file), 'r') as f:
                errors = f.read().strip()
                if errors:
                    return errors, error_file
        return None, None

    def printValgrindErrors(self, node):
        errors, fname = self.getValgrindErrors(node)
        if errors:
            print("-"*31, "Valgrind errors", "-"*32)
            print("Valgrind error file:", fname)
            print(errors)
            print("-"*80)
        return 1 if errors else 0

    def getCrashLog(self, node):
        if node.may_fail:
            return None, None
        try:
            crashlog = os.path.join(node.daemon.lightning_dir, 'crash.log')
            with open(crashlog, 'r') as f:
                return f.readlines(), crashlog
        except:
            return None, None

    def printCrashLog(self, node):
        errors, fname = self.getCrashLog(node)
        if errors:
            print("-"*10, "{} (last 50 lines)".format(fname), "-"*10)
            for l in errors[-50:]:
                print(l, end='')
            print("-"*80)
        return 1 if errors else 0

    def tearDown(self):
        self.node_factory.killall()
        self.executor.shutdown(wait=False)

        err_count = 0
        # Do not check for valgrind error files if it is disabled
        if VALGRIND:
            for node in self.node_factory.nodes:
                err_count += self.printValgrindErrors(node)
            if err_count:
                raise ValueError(
                    "{} nodes reported valgrind errors".format(err_count))

        for node in self.node_factory.nodes:
            err_count += self.printCrashLog(node)
            if err_count:
                raise ValueError(
                    "{} nodes had crash.log files".format(err_count))

class LightningDTests(BaseLightningDTests):
    def connect(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        return l1,l2

    def fund_channel(self, l1, l2, amount):
        addr = l1.rpc.newaddr()['address']

        txid = l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)

        l1.rpc.addfunds(tx)
        l1.rpc.fundchannel(l2.info['id'], amount)
        # Technically, this is async to fundchannel.
        l1.daemon.wait_for_log('sendrawtx exit 0')

        l1.bitcoin.rpc.generate(1)

        l1.daemon.wait_for_log('-> CHANNELD_NORMAL')
        l2.daemon.wait_for_log('-> CHANNELD_NORMAL')

    def pay(self, lsrc, ldst, amt, label=None, async=False):
        if not label:
            label = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))

        rhash = ldst.rpc.invoice(amt, label)['rhash']
        assert ldst.rpc.listinvoice(label)[0]['complete'] == False

        routestep = {
            'msatoshi' : amt,
            'id' : ldst.info['id'],
            'delay' : 5,
            'channel': '1:1:1'
        }

        def wait_pay():
            # Up to 10 seconds for payment to succeed.
            start_time = time.time()
            while not ldst.rpc.listinvoice(label)[0]['complete']:
                if time.time() > start_time + 10:
                    raise TimeoutError('Payment timed out')
                time.sleep(0.1)

        if async:
            self.executor.submit(lsrc.rpc.sendpay, to_json([routestep]), rhash, async=False)
            return self.executor.submit(wait_pay)
        else:
            lsrc.rpc.sendpay(to_json([routestep]), rhash, async=False)

    def test_shutdown(self):
        l1 = self.node_factory.get_node()
        l1.rpc.stop()

    def test_connect(self):
        l1,l2 = self.connect()

        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')

        assert p1['state'] == 'GOSSIPD'
        assert p2['state'] == 'GOSSIPD'

        # It should have gone through these steps
        assert 'state: UNINITIALIZED -> GOSSIPD' in p1['log']

        # Both should still be owned by gossip
        assert p1['owner'] == 'lightning_gossipd'
        assert p2['owner'] == 'lightning_gossipd'

    def test_balance(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)

        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        assert p1['msatoshi_to_us'] == 10**6 * 1000
        assert p1['msatoshi_total'] == 10**6 * 1000
        assert p2['msatoshi_to_us'] == 0
        assert p2['msatoshi_total'] == 10**6 * 1000

    def test_sendpay(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)

        time.sleep(5)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2')['rhash']
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        routestep = {
            'msatoshi' : amt,
            'id' : l2.info['id'],
            'delay' : 5,
            'channel': '1:1:1'
        }

        # Insufficient funds.
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] - 1
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        # Gross overpayment (more than factor of 2)
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] * 2 + 1
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        # Insufficient delay.
        rs = copy.deepcopy(routestep)
        rs['delay'] = rs['delay'] - 2
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        # Bad ID.
        rs = copy.deepcopy(routestep)
        rs['id'] = '00000000000000000000000000000000'
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        # FIXME: test paying via another node, should fail to pay twice.
        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        assert p1['msatoshi_to_us'] == 10**6 * 1000
        assert p1['msatoshi_total'] == 10**6 * 1000
        assert p2['msatoshi_to_us'] == 0
        assert p2['msatoshi_total'] == 10**6 * 1000

        # This works.
        l1.rpc.sendpay(to_json([routestep]), rhash)
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == True

        # Balances should reflect it.
        time.sleep(1)
        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        assert p1['msatoshi_to_us'] == 10**6 * 1000 - amt
        assert p1['msatoshi_total'] == 10**6 * 1000
        assert p2['msatoshi_to_us'] == amt
        assert p2['msatoshi_total'] == 10**6 * 1000

        # Repeat will "succeed", but won't actually send anything (duplicate)
        assert not l1.daemon.is_in_log('... succeeded')
        l1.rpc.sendpay(to_json([routestep]), rhash)
        l1.daemon.wait_for_log('... succeeded')
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == True

        # Overpaying by "only" a factor of 2 succeeds.
        rhash = l2.rpc.invoice(amt, 'testpayment3')['rhash']
        assert l2.rpc.listinvoice('testpayment3')[0]['complete'] == False
        routestep = { 'msatoshi' : amt * 2, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'}
        l1.rpc.sendpay(to_json([routestep]), rhash)
        assert l2.rpc.listinvoice('testpayment3')[0]['complete'] == True

    def test_sendpay_cant_afford(self):
        l1,l2 = self.connect()

        # Note, this is in SATOSHI, rest are in MILLISATOSHI!
        self.fund_channel(l1, l2, 10**6)

        # Can't pay more than channel capacity.
        self.assertRaises(ValueError, self.pay, l1, l2, 10**9 + 1)

        # This is the fee, which needs to be taken into account for l1.
        available = 10**9 - 13440
        # Reserve is 1%.
        reserve = 10**7

        # Can't pay past reserve.
        self.assertRaises(ValueError, self.pay, l1, l2, available)
        self.assertRaises(ValueError, self.pay, l1, l2, available - reserve + 1)

        # Can pay up to reserve (1%)
        self.pay(l1, l2, available - reserve)

        # And now it can't pay back, due to its own reserve.
        self.assertRaises(ValueError, self.pay, l2, l1, available - reserve)

        # But this should work.
        self.pay(l2, l1, available - reserve*2)

    def test_bad_opening(self):
        # l1 asks for a too-long locktime
        l1 = self.node_factory.get_node(options=['--locktime-blocks=100'])
        l2 = self.node_factory.get_node(options=['--max-locktime-blocks=99'])
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 10**6 / 10**8 + 0.01)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)

        l1.rpc.addfunds(tx)
        self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 10**6)

        l2.daemon.wait_for_log('to_self_delay 100 larger than 99')

    def test_closing(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1,l2,200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return, then close.
        l1.rpc.close(l2.info['id']);
        l1.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    def test_permfail(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1,l2,200000000)

        # Make sure l2 has received sig with 0 htlcs!
        l2.daemon.wait_for_log('Received commit_sig with 0 htlc sigs')

        # Make sure l1 has final revocation.
        l1.daemon.wait_for_log('Sending commit_sig with 0 htlc sigs')
        l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

        # We fail l2, so l1 will reconnect to it.
        l2.rpc.dev_fail(l1.info['id']);
        l2.daemon.wait_for_log('Failing due to dev-fail command')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # "Internal error" in hex
        l1.daemon.wait_for_log('WIRE_ERROR.*496e7465726e616c206572726f72')

        # l2 will send out tx (l1 considers it a transient error)
        bitcoind.rpc.generate(1)

        l1.daemon.wait_for_log('Their unilateral tx, old commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET (.*) in 6 blocks')

        # Now, mine 6 blocks so it sends out the spending tx.
        bitcoind.rpc.generate(6)

        # It should send the to-wallet tx.
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # 100 after l1 sees tx, it should be done.
        bitcoind.rpc.generate(94)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks l2 should be done.
        bitcoind.rpc.generate(6)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_onchain_first_commit(self):
        """Onchain handling where funder immediately drops to chain"""

        # HTLC 1->2, 1 fails just after funding.
        disconnects = ['+WIRE_FUNDING_LOCKED', 'permfail']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        # Like fundchannel, but we'll probably fail before CHANNELD_NORMAL.
        addr = l1.rpc.newaddr()['address']

        txid = l1.bitcoin.rpc.sendtoaddress(addr, 10**6 / 10**8 + 0.01)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)

        l1.rpc.addfunds(tx)
        l1.rpc.fundchannel(l2.info['id'], 10**6)
        l1.daemon.wait_for_log('sendrawtx exit 0')

        l1.bitcoin.rpc.generate(1)

        # l1 will drop to chain.
        l1.daemon.wait_for_log('permfail')
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.rpc.generate(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # 6 later, l1 should collect its to-self payment.
        bitcoind.rpc.generate(6)
        l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # 94 later, l2 is done.
        bitcoind.rpc.generate(94)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks and l1 should be done.
        bitcoind.rpc.generate(6)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_onchain_dust_out(self):
        """Onchain handling of outgoing dust htlcs (they should fail)"""
        # HTLC 1->2, 1 fails after it's irrevocably committed
        disconnects = ['@WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l1, l2, 10**6)

        # Must be dust!
        rhash = l2.rpc.invoice(1, 'onchain_dust_out')['rhash']
        routestep = {
            'msatoshi' : 1,
            'id' : l2.info['id'],
            'delay' : 5,
            'channel': '1:1:1'
        }

        payfuture = self.executor.submit(l1.rpc.sendpay, to_json([routestep]), rhash)

        # l1 will drop to chain.
        l1.daemon.wait_for_log('permfail')
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.rpc.generate(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # We use 3 blocks for "reasonable depth"
        bitcoind.rpc.generate(3)

        # It should fail.
        self.assertRaises(ValueError, payfuture.result, 5)

        l1.daemon.wait_for_log('WIRE_PERMANENT_CHANNEL_FAILURE: missing in commitment tx')

        # 6 later, l1 should collect its to-self payment.
        bitcoind.rpc.generate(6)
        l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # 94 later, l2 is done.
        bitcoind.rpc.generate(94)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks and l1 should be done.
        bitcoind.rpc.generate(6)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Payment failed, BTW
        assert l2.rpc.listinvoice('onchain_dust_out')[0]['complete'] == False

    def test_onchain_timeout(self):
        """Onchain handling of outgoing failed htlcs"""
        # HTLC 1->2, 1 fails just after it's irrevocably committed
        disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l1, l2, 10**6)

        rhash = l2.rpc.invoice(10**8, 'onchain_timeout')['rhash']
        # We underpay, so it fails.
        routestep = {
            'msatoshi' : 10**8 - 1,
            'id' : l2.info['id'],
            'delay' : 5,
            'channel': '1:1:1'
        }

        payfuture = self.executor.submit(l1.rpc.sendpay, to_json([routestep]), rhash)

        # l1 will drop to chain.
        l1.daemon.wait_for_log('permfail')
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.rpc.generate(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # Wait for timeout.
        l1.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 6 blocks')
        bitcoind.rpc.generate(6)

        # (l1 will also collect its to-self payment.)
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # We use 3 blocks for "reasonable depth"
        bitcoind.rpc.generate(3)

        # It should fail.
        self.assertRaises(ValueError, payfuture.result, 5)

        l1.daemon.wait_for_log('WIRE_PERMANENT_CHANNEL_FAILURE: timed out')

        # 91 later, l2 is done.
        bitcoind.rpc.generate(91)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks and l1 should be done.
        bitcoind.rpc.generate(6)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Payment failed, BTW
        assert l2.rpc.listinvoice('onchain_timeout')[0]['complete'] == False

    def test_onchain_middleman(self):
        # HTLC 1->2->3, 1->2 goes down after 2 gets preimage from 3.
        disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        l3 = self.node_factory.get_node()

        # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
        l2.rpc.connect(l1.info['id'], 'localhost:{}'.format(l1.info['port']))
        l2.rpc.connect(l3.info['id'], 'localhost:{}'.format(l3.info['port']))
        self.fund_channel(l2, l1, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # Give l1 some money to play with.
        self.pay(l2, l1, 2 * 10**8)

        # Must be bigger than dust!
        rhash = l3.rpc.invoice(10**8, 'middleman')['rhash']
        # Wait for route propagation.
        l1.bitcoin.rpc.generate(5)
        l1.daemon.wait_for_log('Received node_announcement for node {}'
                               .format(l3.info['id']))

        route = l1.rpc.getroute(l3.info['id'], 10**8, 1)["route"]
        assert len(route) == 2

        q = queue.Queue()

        def try_pay():
            try:
                l1.rpc.sendpay(to_json(route), rhash, async=False)
                q.put(None)
            except Exception as err:
                q.put(err)

        t = threading.Thread(target=try_pay)
        t.daemon = True
        t.start()

        # l2 will drop to chain.
        l2.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.rpc.generate(1)
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('OUR_UNILATERAL/THEIR_HTLC')

        # l2 should fulfill HTLC onchain, and spend to-us (any order)
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* in 0 blocks')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # Payment should succeed.
        l1.bitcoin.rpc.generate(1)
        l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC gave us preimage')
        err = q.get(timeout = 10)
        if err:
            print("Got err from sendpay thread")
            raise err
        t.join(timeout=1)
        assert not t.isAlive()

        # After 4 more blocks, l2 can spend to-us.
        l1.bitcoin.rpc.generate(4)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # One more, HTLC tx is now spentable.
        l1.bitcoin.rpc.generate(1)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # 100 blocks after last spend, l2 should be done.
        l1.bitcoin.rpc.generate(100)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_penalty_inhtlc(self):
        """Test penalty transaction with an incoming HTLC"""
        # We suppress each one after first commit; HTLC gets added not fulfilled.
        l1 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'], may_fail=True)
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'])

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l1, l2, 10**6)

        # Now, this will get stuck due to l1 commit being disabled..
        t = self.pay(l1,l2,100000000,async=True)

        # They should both have commitments blocked now.
        l1.daemon.wait_for_log('=WIRE_COMMITMENT_SIGNED-nocommit')
        l2.daemon.wait_for_log('=WIRE_COMMITMENT_SIGNED-nocommit')

        # Make sure l1 got l2's commitment to the HTLC, and sent to master.
        l1.daemon.wait_for_log('UPDATE WIRE_CHANNEL_GOT_COMMITSIG')

        # Take our snapshot.
        tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

        # Let them continue
        l1.rpc.dev_reenable_commit(l2.info['id'])
        l2.rpc.dev_reenable_commit(l1.info['id'])

        # Should fulfill.
        l1.daemon.wait_for_log('peer_in WIRE_UPDATE_FULFILL_HTLC')
        l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

        l2.daemon.wait_for_log('peer_out WIRE_UPDATE_FULFILL_HTLC')
        l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

        # Payment should now complete.
        t.result(timeout=10)

        # Now we really mess things up!
        bitcoind.rpc.sendrawtransaction(tx)
        bitcoind.rpc.generate(1)

        l2.daemon.wait_for_log('-> ONCHAIND_CHEATED')
        # FIXME: l1 should try to stumble along!

        # l2 should spend all of the outputs (except to-us).
        # Could happen in any order, depending on commitment tx.
        l2.daemon.wait_for_logs(['Propose handling THEIR_REVOKED_UNILATERAL/DELAYED_OUTPUT_TO_THEM by OUR_PENALTY_TX .* in 0 blocks',
                                 'sendrawtx exit 0',
                                 'Propose handling THEIR_REVOKED_UNILATERAL/THEIR_HTLC by OUR_PENALTY_TX .* in 0 blocks',
                                 'sendrawtx exit 0'])

        # FIXME: test HTLC tx race!

        # 100 blocks later, all resolved.
        bitcoind.rpc.generate(100)

        # FIXME: Test wallet balance...
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skip("flaky test causing CI fails too often")
    def test_penalty_outhtlc(self):
        """Test penalty transaction with an outgoing HTLC"""
        # First we need to get funds to l2, so suppress after second.
        l1 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED*3-nocommit'], may_fail=True)
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED*3-nocommit'])

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l1, l2, 10**6)

        # Move some across to l2.
        self.pay(l1,l2,200000000)

        assert not l1.daemon.is_in_log('=WIRE_COMMITMENT_SIGNED')
        assert not l2.daemon.is_in_log('=WIRE_COMMITMENT_SIGNED')

        # Now, this will get stuck due to l1 commit being disabled..
        t = self.pay(l2,l1,100000000,async=True)
        # Make sure we get signature from them.
        l1.daemon.wait_for_log('peer_in WIRE_UPDATE_ADD_HTLC')
        l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

        # They should both have commitments blocked now.
        l1.daemon.wait_for_log('dev_disconnect: =WIRE_COMMITMENT_SIGNED')
        l2.daemon.wait_for_log('dev_disconnect: =WIRE_COMMITMENT_SIGNED')

        # Take our snapshot.
        tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

        # Let the continue
        l1.rpc.dev_reenable_commit(l2.info['id'])
        l2.rpc.dev_reenable_commit(l1.info['id'])

        # Thread should complete.
        t.result(timeout=10)

        # Make sure both sides got revoke_and_ack for final.
        l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')
        l2.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

        # Now we really mess things up!
        bitcoind.rpc.sendrawtransaction(tx)
        bitcoind.rpc.generate(1)

        l2.daemon.wait_for_log('-> ONCHAIND_CHEATED')
        # FIXME: l1 should try to stumble along!

        # l2 should spend all of the outputs (except to-us).
        # Could happen in any order, depending on commitment tx.
        l2.daemon.wait_for_logs(['Ignoring output.*: THEIR_REVOKED_UNILATERAL/OUTPUT_TO_US',
                                 'Propose handling THEIR_REVOKED_UNILATERAL/DELAYED_OUTPUT_TO_THEM by OUR_PENALTY_TX .* in 0 blocks',
                                 'sendrawtx exit 0',
                                 'Propose handling THEIR_REVOKED_UNILATERAL/OUR_HTLC by OUR_PENALTY_TX .* in 0 blocks',
                                 'sendrawtx exit 0'])

        # FIXME: test HTLC tx race!

        # 100 blocks later, all resolved.
        bitcoind.rpc.generate(100)

        # FIXME: Test wallet balance...
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_permfail_new_commit(self):
        # Test case where we have two possible commits: it will use new one.
        disconnects = ['-WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l1, l2, 10**6)

        # This will fail at l2's end.
        t=self.pay(l1,l2,200000000,async=True)

        l2.daemon.wait_for_log('dev_disconnect permfail')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.rpc.generate(1)
        l1.daemon.wait_for_log('Their unilateral tx, new commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) in 5 blocks')
        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US (.*) in 5 blocks')

        # OK, time out HTLC.
        bitcoind.rpc.generate(5)
        l1.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.rpc.generate(1)
        l1.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
        l2.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

        t.cancel()

        # Now, 100 blocks it should be done.
        bitcoind.rpc.generate(100)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_permfail_htlc_in(self):
        # Test case where we fail with unsettled incoming HTLC.
        disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l1, l2, 10**6)

        # This will fail at l2's end.
        t=self.pay(l1, l2, 200000000, async=True)

        l2.daemon.wait_for_log('dev_disconnect permfail')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.rpc.generate(1)
        l1.daemon.wait_for_log('Their unilateral tx, old commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) in 5 blocks')
        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US (.*) in 5 blocks')
        # l2 then gets preimage, uses it instead of ignoring
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* in 0 blocks')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.rpc.generate(1)

        # OK, l1 sees l2 fulfill htlc.
        l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC gave us preimage')
        l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 6 blocks')
        bitcoind.rpc.generate(6)

        l2.daemon.wait_for_log('sendrawtx exit 0')

        t.cancel()

        # Now, 100 blocks it should be done.
        bitcoind.rpc.generate(94)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.rpc.generate(6)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_permfail_htlc_out(self):
        # Test case where we fail with unsettled outgoing HTLC.
        disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.fund_channel(l2, l1, 10**6)

        # This will fail at l2's end.
        t=self.pay(l2,l1,200000000,async=True)

        l2.daemon.wait_for_log('dev_disconnect permfail')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.rpc.generate(1)
        l1.daemon.wait_for_log('Their unilateral tx, old commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US \\(.*\\) in 5 blocks',
                                 'Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 6 blocks'])

        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) in 5 blocks')
        # l1 then gets preimage, uses it instead of ignoring
        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_FULFILL_TO_US .* in 0 blocks')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # l2 sees l1 fulfill tx.
        bitcoind.rpc.generate(1)

        l2.daemon.wait_for_log('OUR_UNILATERAL/OUR_HTLC gave us preimage')
        t.cancel()

        # l2 can send OUR_DELAYED_RETURN_TO_WALLET after 5 more blocks.
        bitcoind.rpc.generate(5)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # Now, 100 blocks they should be done.
        bitcoind.rpc.generate(93)
        assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.rpc.generate(1)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.rpc.generate(5)
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.rpc.generate(1)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    def test_gossip_jsonrpc(self):
        l1,l2 = self.connect()

        self.fund_channel(l1,l2,10**5)

        # Shouldn't send announce signatures until 6 deep.
        assert not l1.daemon.is_in_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')

        l1.bitcoin.rpc.generate(5)
        # Could happen in either order.
        l1.daemon.wait_for_logs(['peer_out WIRE_ANNOUNCEMENT_SIGNATURES',
                                 'peer_in WIRE_ANNOUNCEMENT_SIGNATURES'])

        # Could happen in either order.
        l1.daemon.wait_for_logs(['peer_out WIRE_CHANNEL_ANNOUNCEMENT',
                                 'peer_in WIRE_CHANNEL_ANNOUNCEMENT'])

        nodes = l1.rpc.getnodes()['nodes']
        assert set([n['nodeid'] for n in nodes]) == set([l1.info['id'], l2.info['id']])

        l1.daemon.wait_for_log('peer_in WIRE_CHANNEL_UPDATE')
        l2.daemon.wait_for_log('peer_in WIRE_CHANNEL_UPDATE')

        channels = l1.rpc.getchannels()['channels']
        assert len(channels) == 2
        assert [c['active'] for c in channels] == [True, True]

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

    def test_ping(self):
        l1,l2 = self.connect()

        # Test gossip pinging.
        self.ping_tests(l1, l2)

        self.fund_channel(l1, l2, 10**5)

        # channeld pinging
        self.ping_tests(l1, l2)

    def test_routing_gossip_reconnect(self):
        # Connect two peers, reconnect and then see if we resume the
        # gossip.
        disconnects = ['-WIRE_CHANNEL_ANNOUNCEMENT']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        l1.openchannel(l2, 20000)

        # Now open new channels and everybody should sync
        l2.rpc.connect(l3.info['id'], 'localhost:{}'.format(l3.info['port']))
        l2.openchannel(l3, 20000)

        # Settle the gossip
        for n in [l1, l2, l3]:
            wait_for(lambda: len(n.rpc.getchannels()['channels']) == 4)

    def test_second_channel(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        l1.rpc.connect(l3.info['id'], 'localhost:{}'.format(l3.info['port']))
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l1, l3, 10**6)

    def test_routing_gossip(self):
        nodes = [self.node_factory.get_node() for _ in range(5)]
        l1 = nodes[0]
        l5 = nodes[4]

        for i in range(len(nodes)-1):
            src, dst = nodes[i], nodes[i+1]
            src.rpc.connect(dst.info['id'], 'localhost:{}'.format(dst.info['port']))
            src.openchannel(dst, 20000)

        # Allow announce messages.
        l1.bitcoin.rpc.generate(5)

        def settle_gossip(n):
            """Wait for gossip to settle at the node
            """
            expected_connections = 2*(len(nodes) - 1)
            start_time = time.time()
            # Wait at most 10 seconds, broadcast interval is 1 second
            while time.time() - start_time < 10:
                channels = n.rpc.getchannels()['channels']
                if len(channels) == expected_connections:
                    break
                else:
                    time.sleep(0.1)

        for n in nodes:
            settle_gossip(n)

        # Deep check that all channels are in there
        comb = []
        for i in range(len(nodes) - 1):
            comb.append((nodes[i].info['id'], nodes[i+1].info['id']))
            comb.append((nodes[i+1].info['id'], nodes[i].info['id']))

        for n in nodes:
            seen = []
            channels = n.rpc.getchannels()['channels']
            for c in channels:
                seen.append((c['source'],c['destination']))
            assert set(seen) == set(comb)

    def test_forward(self):
        # Connect 1 -> 2 -> 3.
        l1,l2 = self.connect()
        l3 = self.node_factory.get_node()
        ret = l2.rpc.connect(l3.info['id'], 'localhost:{}'.format(l3.info['port']))

        assert ret['id'] == l3.info['id']

        l3.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # Allow announce messages.
        l1.bitcoin.rpc.generate(5)

        # If they're at different block heights we can get spurious errors.
        sync_blockheight([l1, l2, l3])

        chanid1 = l1.rpc.getpeer(l2.info['id'])['channel']
        chanid2 = l2.rpc.getpeer(l3.info['id'])['channel']
        assert l2.rpc.getpeer(l1.info['id'])['channel'] == chanid1
        assert l3.rpc.getpeer(l2.info['id'])['channel'] == chanid2

        rhash = l3.rpc.invoice(100000000, 'testpayment1')['rhash']
        assert l3.rpc.listinvoice('testpayment1')[0]['complete'] == False

        # Fee for node2 is 10 millionths, plus 1.
        amt = 100000000
        fee = amt * 10 // 1000000 + 1

        baseroute = [ { 'msatoshi' : amt + fee,
                        'id' : l2.info['id'],
                        'delay' : 12,
                        'channel' : chanid1 },
                      { 'msatoshi' : amt,
                        'id' : l3.info['id'],
                        'delay' : 6,
                        'channel' : chanid2 } ]

        # Unknown other peer
        route = copy.deepcopy(baseroute)
        route[1]['id'] = '031a8dc444e41bb989653a4501e11175a488a57439b0c4947704fd6e3de5dca607'
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json(route), rhash)

        # Delay too short (we always add one internally anyway, so subtract 2 here).
        route = copy.deepcopy(baseroute)
        route[0]['delay'] = 8
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json(route), rhash)

        # Final delay too short
        route = copy.deepcopy(baseroute)
        route[1]['delay'] = 3
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json(route), rhash)

        # This one works
        route = copy.deepcopy(baseroute)
        l1.rpc.sendpay(to_json(route), rhash)

    def test_disconnect(self):
        # These should all make us fail.
        disconnects = ['-WIRE_INIT',
                       '@WIRE_INIT',
                       '+WIRE_INIT']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        for d in disconnects:
            self.assertRaises(ValueError, l1.rpc.connect,
                              l2.info['id'], 'localhost:{}'.format(l2.info['port']))
            assert l1.rpc.getpeer(l2.info['id']) == None

        # Now we should connect normally.
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

    def test_disconnect_funder(self):
        # Now error on funder side duringchannel open.
        disconnects = ['-WIRE_OPEN_CHANNEL',
                       '@WIRE_OPEN_CHANNEL',
                       '+WIRE_OPEN_CHANNEL',
                       '-WIRE_FUNDING_CREATED',
                       '@WIRE_FUNDING_CREATED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 20000 / 10**6)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)
        l1.rpc.addfunds(tx)

        for d in disconnects:
            l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
            self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)
            assert l1.rpc.getpeer(l2.info['id']) == None

    def test_disconnect_fundee(self):
        # Now error on fundee side during channel open.
        disconnects = ['-WIRE_ACCEPT_CHANNEL',
                       '@WIRE_ACCEPT_CHANNEL',
                       '+WIRE_ACCEPT_CHANNEL']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 20000 / 10**6)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)
        l1.rpc.addfunds(tx)

        for d in disconnects:
            l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
            self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)
            assert l1.rpc.getpeer(l2.info['id']) == None

    def test_disconnect_half_signed(self):
        # Now, these are the corner cases.  Fundee sends funding_signed,
        # but funder doesn't receive it.
        disconnects = ['@WIRE_FUNDING_SIGNED']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 20000 / 10**6)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)
        l1.rpc.addfunds(tx)

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)

        # Fundee remembers, funder doesn't.
        assert l1.rpc.getpeer(l2.info['id']) == None
        assert l2.rpc.getpeer(l1.info['id'])['peerid'] == l1.info['id']

    def test_reconnect_signed(self):
        # This will fail *after* both sides consider channel opening.
        disconnects = ['+WIRE_FUNDING_SIGNED']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 20000 / 10**6)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)
        l1.rpc.addfunds(tx)

        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))
        l1.rpc.fundchannel(l2.info['id'], 20000)

        # They haven't forgotten each other.
        assert l1.rpc.getpeer(l2.info['id'])['peerid'] == l2.info['id']
        assert l2.rpc.getpeer(l1.info['id'])['peerid'] == l1.info['id']

        # Technically, this is async to fundchannel.
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # Wait for reconnect, awaiting lockin..
        l1.daemon.wait_for_log('Peer has reconnected, state CHANNELD_AWAITING_LOCKIN');

        l1.bitcoin.rpc.generate(6)

        l1.daemon.wait_for_log('-> CHANNELD_NORMAL')
        l2.daemon.wait_for_log('-> CHANNELD_NORMAL')

    def test_reconnect_openingd(self):
        # Openingd thinks we're still opening; funder reconnects..
        disconnects = ['0WIRE_ACCEPT_CHANNEL']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 20000 / 10**6)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)
        l1.rpc.addfunds(tx)

        # l2 closes on l1, l1 forgets.
        self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)
        assert l1.rpc.getpeer(l2.info['id']) == None

        # Reconnect.
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        # We should get a message about old one exiting.
        l2.daemon.wait_for_log('Peer has reconnected, state OPENINGD')
        l2.daemon.wait_for_log('Owning subdaemon lightning_openingd died')

        # Should work fine.
        l1.rpc.fundchannel(l2.info['id'], 20000)
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # Just to be sure, second openingd hand over to channeld.
        l2.daemon.wait_for_log('Subdaemon lightning_openingd died \(0\)')

    def test_reconnect_normal(self):
        # Should reconnect fine even if locked message gets lost.
        disconnects = ['-WIRE_FUNDING_LOCKED',
                       '@WIRE_FUNDING_LOCKED',
                       '+WIRE_FUNDING_LOCKED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)

    def test_reconnect_sender_add1(self):
        # Fail after add is OK, will cause payment failure though.
        disconnects = ['-WIRE_UPDATE_ADD_HTLC-nocommit',
                       '+WIRE_UPDATE_ADD_HTLC-nocommit',
                       '@WIRE_UPDATE_ADD_HTLC-nocommit']

        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'test_reconnect_sender_add1')['rhash']
        assert l2.rpc.listinvoice('test_reconnect_sender_add1')[0]['complete'] == False

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]

        for i in range(0,len(disconnects)):
            self.assertRaises(ValueError, l1.rpc.sendpay, to_json(route), rhash)
            # Wait for reconnection.
            l1.daemon.wait_for_log('Already have funding locked in')

        # This will send commit, so will reconnect as required.
        l1.rpc.sendpay(to_json(route), rhash)

    def test_reconnect_sender_add(self):
        disconnects = ['-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment')['rhash']
        assert l2.rpc.listinvoice('testpayment')[0]['complete'] == False

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]

        # This will send commit, so will reconnect as required.
        l1.rpc.sendpay(to_json(route), rhash)
        # Should have printed this for every reconnect.
        for i in range(0,len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')

    def test_reconnect_receiver_add(self):
        disconnects = ['-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2')['rhash']
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]
        l1.rpc.sendpay(to_json(route), rhash)
        for i in range(len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == True

    def test_reconnect_receiver_fulfill(self):
        disconnects = ['-WIRE_UPDATE_FULFILL_HTLC',
                       '@WIRE_UPDATE_FULFILL_HTLC',
                       '+WIRE_UPDATE_FULFILL_HTLC',
                       '-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        ret = l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2')['rhash']
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == False

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]
        l1.rpc.sendpay(to_json(route), rhash)
        for i in range(len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == True

    def test_shutdown_reconnect(self):
        disconnects = ['-WIRE_SHUTDOWN',
                       '@WIRE_SHUTDOWN',
                       '+WIRE_SHUTDOWN']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1,l2,200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return, then close.
        l1.rpc.close(l2.info['id']);
        l1.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool (happens async, so
        # CLOSINGD_COMPLETE may come first).
        l1.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        l2.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    def test_closing_negotiation_reconnect(self):
        disconnects = ['-WIRE_CLOSING_SIGNED',
                       '@WIRE_CLOSING_SIGNED',
                       '+WIRE_CLOSING_SIGNED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1,l2,200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return, then close.
        l1.rpc.close(l2.info['id']);
        l1.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool (happens async, so
        # CLOSINGD_COMPLETE may come first).
        l1.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        l2.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    def test_json_addfunds(self):
        sat = 10**6
        l1 = self.node_factory.get_node()
        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 0.01)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)

        # The first time should succeed
        assert l1.rpc.addfunds(tx) == { "outputs" : 1, "satoshis" : sat }

        # Second time should fail, we already have those funds
        self.assertRaises(ValueError, l1.rpc.addfunds, tx)

    def test_withdraw(self):
        amount = 1000000
        l1 = self.node_factory.get_node()
        addr = l1.rpc.newaddr()['address']


        # Add some funds to withdraw later
        for i in range(10):
            txid = l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)
            tx = l1.bitcoin.rpc.getrawtransaction(txid)
            l1.rpc.addfunds(tx)

        # Reach around into the db to check that outputs were added
        db = sqlite3.connect(os.path.join(l1.daemon.lightning_dir, "lightningd.sqlite3"))

        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 10)

        waddr = l1.bitcoin.rpc.getnewaddress()
        # Now attempt to withdraw some (making sure we collect multiple inputs)
        self.assertRaises(ValueError, l1.rpc.withdraw, 'not an address', amount)
        self.assertRaises(ValueError, l1.rpc.withdraw, waddr, 'not an amount')
        self.assertRaises(ValueError, l1.rpc.withdraw, waddr, -amount)

        out = l1.rpc.withdraw(waddr, 2*amount)

        # Make sure bitcoind received the withdrawal
        unspent = l1.bitcoin.rpc.listunspent(0)
        withdrawal = [u for u in unspent if u['txid'] == out['txid']]
        assert(len(withdrawal) == 1)

        assert(withdrawal[0]['amount'] == Decimal('0.02'))

        # Now make sure two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 2)

    def test_funding_change(self):
        """Add some funds, fund a channel, and make sure we remember the change
        """
        l1, l2 = self.connect()
        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 0.1)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)
        l1.rpc.addfunds(tx)
        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert len(outputs) == 1 and outputs[0]['value'] == 10000000

        l1.rpc.fundchannel(l2.info['id'], 1000000)
        outputs = {r['status']: r['value'] for r in l1.db_query(
            'SELECT status, SUM(value) AS value FROM outputs GROUP BY status;')}

        # The 10m out is spent and we have a change output of 9m-fee
        assert outputs[0] >   8990000
        assert outputs[2] == 10000000

    def test_channel_persistence(self):
        # Start two nodes and open a channel (to remember). l2 will
        # mysteriously die while committing the first HTLC so we can
        # check that HTLCs reloaded from the DB work.
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'])
        l1.rpc.connect(l2.info['id'], 'localhost:{}'.format(l2.info['port']))

        # Neither node should have a channel open, they are just connected
        for n in (l1, l2):
            assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 0)

        self.fund_channel(l1, l2, 100000)

        peers = l1.rpc.getpeers()['peers']
        assert(len(peers) == 1 and peers[0]['state'] == 'CHANNELD_NORMAL')

        # Both nodes should now have exactly one channel in the database
        for n in (l1, l2):
            assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 1)

        # Fire off a sendpay request, it'll get interrupted by a restart
        fut = self.executor.submit(self.pay, l1, l2, 10000)
        # Wait for it to be committed to, i.e., stored in the DB
        l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

        # Stop l2, l1 will reattempt to connect
        print("Killing l2 in mid HTLC")
        l2.daemon.proc.terminate()

        # Clear the disconnect and timer stop so we can proceed normally
        l2.daemon.cmd_line = [e for e in l2.daemon.cmd_line if 'disconnect' not in e]
        print(" ".join(l2.daemon.cmd_line + ['--dev-debugger=channeld']))

        # Wait for l1 to notice
        wait_for(lambda: not l1.rpc.getpeers()['peers'][0]['connected'])

        # Now restart l1 and it should reload peers/channels from the DB
        l2.daemon.start()
        wait_for(lambda: len(l2.rpc.getpeers()['peers']) == 1)

        # Wait for the restored HTLC to finish
        wait_for(lambda: l1.rpc.getpeers()['peers'][0]['msatoshi_to_us'] == 99990000, interval=1)

        wait_for(lambda: len([p for p in l1.rpc.getpeers()['peers'] if p['connected']]), interval=1)
        wait_for(lambda: len([p for p in l2.rpc.getpeers()['peers'] if p['connected']]), interval=1)

        # Now make sure this is really functional by sending a payment
        self.pay(l1, l2, 10000)
        time.sleep(1)
        assert l1.rpc.getpeers()['peers'][0]['msatoshi_to_us'] == 99980000
        assert l2.rpc.getpeers()['peers'][0]['msatoshi_to_us'] == 20000

        # Finally restart l1, and make sure it remembers
        l1.stop()
        l1.daemon.start()
        assert l1.rpc.getpeers()['peers'][0]['msatoshi_to_us'] == 99980000

    def test_gossip_badsig(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()

        # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
        l2.rpc.connect(l1.info['id'], 'localhost:{}'.format(l1.info['port']))
        l2.rpc.connect(l3.info['id'], 'localhost:{}'.format(l3.info['port']))
        self.fund_channel(l2, l1, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # Wait for route propagation.
        l1.bitcoin.rpc.generate(5)
        l1.daemon.wait_for_log('Received node_announcement for node {}'
                               .format(l3.info['id']))
        assert not l1.daemon.is_in_log('signature verification failed')
        assert not l2.daemon.is_in_log('signature verification failed')
        assert not l3.daemon.is_in_log('signature verification failed')

if __name__ == '__main__':
    unittest.main(verbosity=2)
