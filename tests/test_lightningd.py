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
DEVELOPER = os.getenv("DEVELOPER", "0") == "1"
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"

print("Testing results are in {}".format(TEST_DIR))

if TEST_DEBUG:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logging.info("Tests running in '%s'", TEST_DIR)

def to_json(arg):
    return json.loads(json.dumps(arg))

def setupBitcoind(directory):
    global bitcoind
    bitcoind = utils.BitcoinD(bitcoin_dir=directory, rpcport=28332)
    bitcoind.start()
    info = bitcoind.rpc.getblockchaininfo()
    # Make sure we have segwit and some funds
    if info['blocks'] < 432:
        logging.debug("SegWit not active, generating some more blocks")
        bitcoind.generate_block(432 - info['blocks'])
    elif bitcoind.rpc.getwalletinfo()['balance'] < 1:
        logging.debug("Insufficient balance, generating 1 block")
        bitcoind.generate_block(1)


def wait_for(success, timeout=30, interval=0.1):
    start_time = time.time()
    while not success() and time.time() < start_time + timeout:
        time.sleep(interval)
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)

def wait_forget_channels(node):
    """This node is closing all of its channels, check we are forgetting them
    """
    node.daemon.wait_for_log(r'onchaind complete, forgetting peer')
    assert node.rpc.listpeers()['peers'] == []
    assert node.db_query("SELECT * FROM channels") == []

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

class NodeFactory(object):
    """A factory to setup and start `lightningd` daemons.
    """
    def __init__(self, testname, bitcoind, executor):
        self.testname = testname
        self.next_id = 1
        self.nodes = []
        self.executor = executor
        self.bitcoind = bitcoind

    def get_node(self, disconnect=None, options=None, may_fail=False, random_hsm=False):
        node_id = self.next_id
        self.next_id += 1

        lightning_dir = os.path.join(
            TEST_DIR, self.testname, "lightning-{}/".format(node_id))

        socket_path = os.path.join(lightning_dir, "lightning-rpc").format(node_id)
        port = 16330+node_id
        daemon = utils.LightningD(lightning_dir, self.bitcoind.bitcoin_dir, port=port, random_hsm=random_hsm)
        # If we have a disconnect string, dump it to a file for daemon.
        if disconnect:
            with open(os.path.join(lightning_dir, "dev_disconnect"), "w") as f:
                f.write("\n".join(disconnect))
            daemon.cmd_line.append("--dev-disconnect=dev_disconnect")
        if DEVELOPER:
            daemon.cmd_line.append("--dev-fail-on-subdaemon-fail")
            daemon.env["LIGHTNINGD_DEV_MEMLEAK"] = "1"
            if VALGRIND:
                daemon.env["LIGHTNINGD_DEV_NO_BACKTRACE"] = "1"
        opts = [] if options is None else options
        for opt in opts:
            daemon.cmd_line.append(opt)
        rpc = LightningRpc(socket_path, self.executor)

        node = utils.LightningNode(daemon, rpc, self.bitcoind, self.executor, may_fail=may_fail)
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

    def killall(self, expected_successes):
        """Returns true if every node we expected to succeed actually succeeded"""
        unexpected_fail = False
        for i in range(len(self.nodes)):
            leaks = None
            # leak detection upsets VALGRIND by reading uninitialized mem.
            # If it's dead, we'll catch it below.
            if not VALGRIND:
                try:
                    # This also puts leaks in log.
                    leaks = self.nodes[i].rpc.dev_memleak()['leaks']
                except:
                    pass

            try:
                self.nodes[i].stop()
            except:
                if expected_successes[i]:
                    unexpected_fail = True

            if leaks is not None and len(leaks) != 0:
                raise Exception("Node {} has memory leaks: {}"
                                .format(self.nodes[i].daemon.lightning_dir, leaks))
        return not unexpected_fail


class BaseLightningDTests(unittest.TestCase):
    def setUp(self):
        bitcoin_dir = os.path.join(TEST_DIR, self._testMethodName, "bitcoind")
        setupBitcoind(bitcoin_dir)
        # Most of the executor threads will be waiting for IO, so
        # let's have a few of them
        self.executor = futures.ThreadPoolExecutor(max_workers=20)
        self.node_factory = NodeFactory(self._testMethodName, bitcoind, self.executor)

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
        ok = self.node_factory.killall([not n.may_fail for n in self.node_factory.nodes])
        self.executor.shutdown(wait=False)

        tearDownBitcoind()
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

        if not ok:
            raise Exception("At least one lightning exited with unexpected non-zero return code")

class LightningDTests(BaseLightningDTests):
    def connect(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        return l1,l2

    # Waits until l1 notices funds
    def give_funds(self, l1, satoshi):
        addr = l1.rpc.newaddr()['address']
        bitcoind.rpc.sendtoaddress(addr, satoshi / 10**8)

        numfunds = len(l1.rpc.listfunds()['outputs'])
        bitcoind.generate_block(1)
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > numfunds)

    # Returns the short channel-id: <blocknum>:<txnum>:<outnum>
    def fund_channel(self, l1, l2, amount):
        # Generates a block, so we know next tx will be first in block.
        self.give_funds(l1, amount + 1000000)

        tx = l1.rpc.fundchannel(l2.info['id'], amount)['tx']
        # Technically, this is async to fundchannel.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log('-> CHANNELD_NORMAL')
        l2.daemon.wait_for_log('-> CHANNELD_NORMAL')

        # Hacky way to find our output.
        decoded=bitcoind.rpc.decoderawtransaction(tx)
        for out in decoded['vout']:
            # Sometimes a float?  Sometimes a decimal?  WTF Python?!
            if out['scriptPubKey']['type'] == 'witness_v0_scripthash':
                if out['value'] == Decimal(amount) / 10**8 or out['value'] * 10**8 == amount:
                    return "{}:1:{}".format(bitcoind.rpc.getblockcount(), out['n'])
        # Intermittent decoding failure.  See if it decodes badly twice?
        decoded2=bitcoind.rpc.decoderawtransaction(tx)
        raise ValueError("Can't find {} payment in {} (1={} 2={})".format(amount, tx, decoded, decoded2))

    def line_graph(self, n=2):
        """Build a line graph of the specified length and fund it.
        """
        nodes = [self.node_factory.get_node() for _ in range(n)]

        for i in range(len(nodes)-1):
            nodes[i].rpc.connect(
                nodes[i+1].info['id'],
                'localhost',
                nodes[i+1].info['port']
            )
            self.fund_channel(nodes[i], nodes[i+1], 10**6)

        return nodes

    def pay(self, lsrc, ldst, amt, label=None, async=False):
        if not label:
            label = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))

        rhash = ldst.rpc.invoice(amt, label, label)['payment_hash']
        assert ldst.rpc.listinvoices(label)['invoices'][0]['status'] == 'unpaid'

        routestep = {
            'msatoshi' : amt,
            'id' : ldst.info['id'],
            'delay' : 5,
            'channel': '1:1:1'
        }

        def wait_pay():
            # Up to 10 seconds for payment to succeed.
            start_time = time.time()
            while ldst.rpc.listinvoices(label)['invoices'][0]['status'] != 'paid':
                if time.time() > start_time + 10:
                    raise TimeoutError('Payment timed out')
                time.sleep(0.1)

        if async:
            self.executor.submit(lsrc.rpc.sendpay, to_json([routestep]), rhash, async=False)
            return self.executor.submit(wait_pay)
        else:
            lsrc.rpc.sendpay(to_json([routestep]), rhash, async=False)

    # This waits until gossipd sees channel_update in both directions
    # (or for local channels, at least a local announcement)
    def wait_for_routes(self, l1, channel_ids):
        bitcoind.generate_block(5)
        # Could happen in any order...
        l1.daemon.wait_for_logs(['Channel {}\\(0\\) was updated'.format(c)
                                 for c in channel_ids]
                                + ['Channel {}\\(1\\) was updated'.format(c)
                                 for c in channel_ids])

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_shutdown(self):
        # Fail, in that it will exit before cleanup.
        l1 = self.node_factory.get_node(may_fail=True)
        if not VALGRIND:
            leaks = l1.rpc.dev_memleak()['leaks']
            if len(leaks):
                raise Exception("Node {} has memory leaks: {}"
                                .format(l1.daemon.lightning_dir, leaks))
        l1.rpc.stop()

    def test_invoice(self):
        l1 = self.node_factory.get_node()

        before = int(time.time())
        inv = l1.rpc.invoice(123000, 'label', 'description')
        after = int(time.time())
        b11 = l1.rpc.decodepay(inv['bolt11'])
        assert b11['currency'] == 'tb'
        assert b11['created_at'] >= before
        assert b11['created_at'] <= after
        assert b11['payment_hash'] == inv['payment_hash']
        assert b11['description'] == 'description'
        assert b11['expiry'] == 3600
        assert b11['payee'] == l1.info['id']

        # Check pay_index is null
        outputs = l1.db_query('SELECT pay_index IS NULL AS q FROM invoices WHERE label="label";')
        assert len(outputs) == 1 and outputs[0]['q'] != 0

        # Check any-amount invoice
        inv = l1.rpc.invoice("any", 'label2', 'description2');
        b11 = inv['bolt11']
        # Amount usually comes after currency (tb in our case),
        # but an any-amount invoices will have no amount
        assert b11.startswith("lntb1")
        # By bech32 rules, the last '1' digit is the separator
        # between the human-readable and data parts. We want
        # to match the "lntb1" above with the '1' digit as the
        # separator, and not for example "lntb1m1....".
        assert b11.count('1') == 1

    def test_invoice_expiry(self):
        l1,l2 = self.connect()

        chanid = self.fund_channel(l1, l2, 10**6)

        # Wait for route propagation.
        self.wait_for_routes(l1, [chanid])

        inv = l2.rpc.invoice(123000, 'test_pay', 'description', 1)['bolt11']
        time.sleep(2)
        self.assertRaises(ValueError, l1.rpc.pay, inv)
        assert l2.rpc.listinvoices('test_pay')['invoices'][0]['status'] == 'expired'
        assert l2.rpc.listinvoices('test_pay')['invoices'][0]['expires_at'] < time.time()

        # Try deleting it.
        self.assertRaisesRegex(ValueError,
                               'Invoice status is expired not unpaid',
                               l2.rpc.delinvoice,
                               'test_pay', 'unpaid')
        self.assertRaisesRegex(ValueError,
                               'Invoice status is expired not paid',
                               l2.rpc.delinvoice,
                               'test_pay', 'paid')
        l2.rpc.delinvoice('test_pay', 'expired')

        self.assertRaisesRegex(ValueError,
                               'Unknown invoice',
                               l2.rpc.delinvoice,
                               'test_pay', 'expired')
    def test_connect(self):
        l1,l2 = self.connect()

        # These should be in gossipd.
        assert l1.rpc.getpeer(l2.info['id'])['state'] == 'GOSSIPING'
        assert l2.rpc.getpeer(l1.info['id'])['state'] == 'GOSSIPING'

        # Both gossipds will have them as new peers once handed back.
        l1.daemon.wait_for_log('hand_back_peer {}: now local again'.format(l2.info['id']))
        l2.daemon.wait_for_log('hand_back_peer {}: now local again'.format(l1.info['id']))

        # Reconnect should be a noop
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        assert ret['id'] == l2.info['id']

        ret = l2.rpc.connect(l1.info['id'], 'localhost', l1.info['port'])
        assert ret['id'] == l1.info['id']

        # Should still only have one peer!
        assert len(l1.rpc.listpeers()) == 1
        assert len(l2.rpc.listpeers()) == 1

    def test_balance(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)

        p1 = l1.rpc.getpeer(l2.info['id'], 'info')['channels'][0]
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')['channels'][0]
        assert p1['msatoshi_to_us'] == 10**6 * 1000
        assert p1['msatoshi_total'] == 10**6 * 1000
        assert p2['msatoshi_to_us'] == 0
        assert p2['msatoshi_total'] == 10**6 * 1000

    def test_decodepay(self):
        l1 = self.node_factory.get_node()

        # BOLT #11:
        # > ### Please make a donation of any amount using payment_hash 0001020304050607080900010203040506070809000102030405060708090102 to me @03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad
        # > lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w
        #
        # Breakdown:
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash
        #   * `p5`: `data_length` (`p` = 1, `5` = 20. 1 * 32 + 20 == 52)
        #   * `qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypq`: payment hash 0001020304050607080900010203040506070809000102030405060708090102
        # * `d`: short description
        #   * `pl`: `data_length` (`p` = 1, `l` = 31. 1 * 32 + 31 == 63)
        #   * `2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq`: 'Please consider supporting this project'
        # * `32vjcgqxyuj7nqphl3xmmhls2rkl3t97uan4j0xa87gj5779czc8p0z58zf5wpt9ggem6adl64cvawcxlef9djqwp2jzzfvs272504sp`: signature
        # * `0lkg3c`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq8rkx3yf5tcsyz3d73gafnh3cax9rn449d9p5uxz9ezhhypd0elx87sjle52x86fux2ypatgddc6k63n7erqz25le42c4u4ecky03ylcqca784w')
        assert b11['currency'] == 'bc'
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['description'] == 'Please consider supporting this project'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'

        # BOLT #11:
        # > ### Please send $3 for a cup of coffee to the same peer, within 1 minute
        # > lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp
        #
        # Breakdown:
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `2500u`: amount (2500 micro-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `d`: short description
        #   * `q5`: `data_length` (`q` = 0, `5` = 20. 0 * 32 + 20 == 20)
        #   * `xysxxatsyp3k7enxv4js`: '1 cup coffee'
        # * `x`: expiry time
        #   * `qz`: `data_length` (`q` = 0, `z` = 2. 0 * 32 + 2 == 2)
        #   * `pu`: 60 seconds (`p` = 1, `u` = 28.  1 * 32 + 28 == 60)
        # * `azh8qt5w7qeewkmxtv55khqxvdfs9zzradsvj7rcej9knpzdwjykcq8gv4v2dl705pjadhpsc967zhzdpuwn5qzjm0s4hqm2u0vuhhqq`: signature
        # * `7vc09u`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5se903vruatfhq77w3ls4evs3ch9zw97j25emudupq63nyw24cg27h2rspfj9srp')
        assert b11['currency'] == 'bc'
        assert b11['msatoshi'] == 2500 * 10**11 // 1000000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['description'] == '1 cup coffee'
        assert b11['expiry'] == 60
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'

        # BOLT #11:
        # > ### Now send $24 for an entire list of things (hashed)
        # > lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7
        #
        # Breakdown:
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `20m`: amount (20 milli-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `h`: tagged field: hash of description
        # * `p5`: `data_length` (`p` = 1, `5` = 20. 1 * 32 + 20 == 52)
        # * `8yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs`: SHA256 of 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon'
        # * `vjfls3ljx9e93jkw0kw40yxn4pevgzflf83qh2852esjddv4xk4z70nehrdcxa4fk0t6hlcc6vrxywke6njenk7yzkzw0quqcwxphkcp`: signature
        # * `vam37w`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqscc6gd6ql3jrc5yzme8v4ntcewwz5cnw92tz0pc8qcuufvq7khhr8wpald05e92xw006sq94mg8v2ndf4sefvf9sygkshp5zfem29trqq2yxxz7', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
        assert b11['currency'] == 'bc'
        assert b11['msatoshi'] == 20 * 10**11 // 1000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'

        # > ### The same, on testnet, with a fallback address mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP
        # > lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t
        #
        # Breakdown:
        #
        # * `lntb`: prefix, lightning on bitcoin testnet
        # * `20m`: amount (20 milli-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `f`: tagged field: fallback address
        # * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
        # * `3x9et2e20v6pu37c5d9vax37wxq72un98`: `3` = 17, so P2PKH address
        # * `h`: tagged field: hash of description...
        # * `qh84fmvn2klvglsjxfy0vq2mz6t9kjfzlxfwgljj35w2kwa60qv49k7jlsgx43yhs9nuutllkhhnt090mmenuhp8ue33pv4klmrzlcqp`: signature
        # * `us2s2r`: Bech32 checksum
        b11 = l1.rpc.decodepay('lntb20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un98kmzzhznpurw9sgl2v0nklu2g4d0keph5t7tj9tcqd8rexnd07ux4uv2cjvcqwaxgj7v4uwn5wmypjd5n69z2xm3xgksg28nwht7f6zspwp3f9t', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
        assert b11['currency'] == 'tb'
        assert b11['msatoshi'] == 20 * 10**11 // 1000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
        assert b11['fallback']['type'] == 'P2PKH'
        assert b11['fallback']['addr'] == 'mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP'

        # > ### On mainnet, with fallback address 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T with extra routing info to go via nodes 029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255 then 039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255
        # > lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj
        #
        # Breakdown:
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `20m`: amount (20 milli-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `h`: tagged field: hash of description...
        # * `f`: tagged field: fallback address
        #   * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
        #   * `3` = 17, so P2PKH address
        #   * `qjmp7lwpagxun9pygexvgpjdc4jdj85f`: 160 bit P2PKH address
        # * `r`: tagged field: route information
        #   * `9y`: `data_length` (`9` = 5, `y` = 4.  5 * 32 + 4 = 164)
        #     `q20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqqqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqqqqqqq7qqzq`: pubkey `029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`, `short_channel_id` 0102030405060708, `fee_base_msat` 1 millisatoshi, `fee_proportional_millionths` 20, `cltv_expiry_delta` 3.  pubkey `039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255`, `short_channel_id` 030405060708090a, `fee_base_msat` 2 millisatoshi, `fee_proportional_millionths` 30, `cltv_expiry_delta` 4.
        # * `j9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qq`: signature
        # * `dhhwkj`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc20m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzqj9n4evl6mr5aj9f58zp6fyjzup6ywn3x6sk8akg5v4tgn2q8g4fhx05wf6juaxu9760yp46454gpg5mtzgerlzezqcqvjnhjh8z3g2qqdhhwkj', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
        assert b11['currency'] == 'bc'
        assert b11['msatoshi'] == 20 * 10**11 // 1000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
        assert b11['fallback']['type'] == 'P2PKH'
        assert b11['fallback']['addr'] == '1RustyRX2oai4EYYDpQGWvEL62BBGqN9T'
        assert len(b11['routes']) == 1
        assert len(b11['routes'][0]) == 2
        assert b11['routes'][0][0]['pubkey'] == '029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
        # 0x010203:0x040506:0x0708
        assert b11['routes'][0][0]['short_channel_id'] == '66051:263430:1800'
        assert b11['routes'][0][0]['fee_base_msat'] == 1
        assert b11['routes'][0][0]['fee_proportional_millionths'] == 20
        assert b11['routes'][0][0]['cltv_expiry_delta'] == 3

        assert b11['routes'][0][1]['pubkey'] == '039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255'
        # 0x030405:0x060708:0x090a
        assert b11['routes'][0][1]['short_channel_id'] == '197637:395016:2314'
        assert b11['routes'][0][1]['fee_base_msat'] == 2
        assert b11['routes'][0][1]['fee_proportional_millionths'] == 30
        assert b11['routes'][0][1]['cltv_expiry_delta'] == 4

        # > ### On mainnet, with fallback (P2SH) address 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
        # > lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y
        #
        # Breakdown:
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `20m`: amount (20 milli-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `f`: tagged field: fallback address.
        # * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
        # * `j3a24vwu6r8ejrss3axul8rxldph2q7z9`: `j` = 18, so P2SH address
        # * `h`: tagged field: hash of description...
        # * `2jhz8j78lv2jynuzmz6g8ve53he7pheeype33zlja5azae957585uu7x59w0f2l3rugyva6zpu394y4rh093j6wxze0ldsvk757a9msq`: signature
        # * `mf9swh`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl6qcs9j3tz0469gq5g658y', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
        assert b11['currency'] == 'bc'
        assert b11['msatoshi'] == 20 * 10**11 // 1000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
        assert b11['fallback']['type'] == 'P2SH'
        assert b11['fallback']['addr'] == '3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX'

        # > ### On mainnet, with fallback (P2WPKH) address bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
        # > lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `20m`: amount (20 milli-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `f`: tagged field: fallback address.
        # * `pp`: `data_length` (`p` = 1. 1 * 32 + 1 == 33)
        # * `q`: 0, so witness version 0.
        # * `qw508d6qejxtdg4y5r3zarvary0c5xw7k`: 160 bits = P2WPKH.
        # * `h`: tagged field: hash of description...
        # * `gw6tk8z0p0qdy9ulggx65lvfsg3nxxhqjxuf2fvmkhl9f4jc74gy44d5ua9us509prqz3e7vjxrftn3jnk7nrglvahxf7arye5llphgq`: signature
        # * `qdtpa4`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7kepvrhrm9s57hejg0p662ur5j5cr03890fa7k2pypgttmh4897d3raaq85a293e9jpuqwl0rnfuwzam7yr8e690nd2ypcq9hlkdwdvycqa0qza8', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
        assert b11['currency'] == 'bc'
        assert b11['msatoshi'] == 20 * 10**11 // 1000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
        assert b11['fallback']['type'] == 'P2WPKH'
        assert b11['fallback']['addr'] == 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'

        # > ### On mainnet, with fallback (P2WSH) address bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
        # > lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava
        #
        # * `lnbc`: prefix, lightning on bitcoin mainnet
        # * `20m`: amount (20 milli-bitcoin)
        # * `1`: Bech32 separator
        # * `pvjluez`: timestamp (1496314658)
        # * `p`: payment hash...
        # * `f`: tagged field: fallback address.
        # * `p4`: `data_length` (`p` = 1, `4` = 21. 1 * 32 + 21 == 53)
        # * `q`: 0, so witness version 0.
        # * `rp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q`: 260 bits = P2WSH.
        # * `h`: tagged field: hash of description...
        # * `5yps56lmsvgcrf476flet6js02m93kgasews8q3jhtp7d6cqckmh70650maq4u65tk53ypszy77v9ng9h2z3q3eqhtc3ewgmmv2grasp`: signature
        # * `akvd7y`: Bech32 checksum
        b11 = l1.rpc.decodepay('lnbc20m1pvjluezhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfp4qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q28j0v3rwgy9pvjnd48ee2pl8xrpxysd5g44td63g6xcjcu003j3qe8878hluqlvl3km8rm92f5stamd3jw763n3hck0ct7p8wwj463cql26ava', 'One piece of chocolate cake, one icecream cone, one pickle, one slice of swiss cheese, one slice of salami, one lollypop, one piece of cherry pie, one sausage, one cupcake, and one slice of watermelon')
        assert b11['currency'] == 'bc'
        assert b11['msatoshi'] == 20 * 10**11 // 1000
        assert b11['created_at'] == 1496314658
        assert b11['payment_hash'] == '0001020304050607080900010203040506070809000102030405060708090102'
        assert b11['expiry'] == 3600
        assert b11['payee'] == '03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad'
        assert b11['fallback']['type'] == 'P2WSH'
        assert b11['fallback']['addr'] == 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3'

        self.assertRaises(ValueError, l1.rpc.decodepay, '1111111')

    def test_sendpay(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

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
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

        # Gross overpayment (more than factor of 2)
        rs = copy.deepcopy(routestep)
        rs['msatoshi'] = rs['msatoshi'] * 2 + 1
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

        # Insufficient delay.
        rs = copy.deepcopy(routestep)
        rs['delay'] = rs['delay'] - 2
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

        # Bad ID.
        rs = copy.deepcopy(routestep)
        rs['id'] = '00000000000000000000000000000000'
        self.assertRaises(ValueError, l1.rpc.sendpay, to_json([rs]), rhash)
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

        # FIXME: test paying via another node, should fail to pay twice.
        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        assert p1['channels'][0]['msatoshi_to_us'] == 10**6 * 1000
        assert p1['channels'][0]['msatoshi_total'] == 10**6 * 1000
        assert p2['channels'][0]['msatoshi_to_us'] == 0
        assert p2['channels'][0]['msatoshi_total'] == 10**6 * 1000

        # This works.
        preimage2 = l1.rpc.sendpay(to_json([routestep]), rhash)
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'paid'
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['pay_index'] == 1
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['msatoshi_received'] == rs['msatoshi']

        # Balances should reflect it.
        time.sleep(1)
        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')
        assert p1['channels'][0]['msatoshi_to_us'] == 10**6 * 1000 - amt
        assert p1['channels'][0]['msatoshi_total'] == 10**6 * 1000
        assert p2['channels'][0]['msatoshi_to_us'] == amt
        assert p2['channels'][0]['msatoshi_total'] == 10**6 * 1000

        # Repeat will "succeed", but won't actually send anything (duplicate)
        assert not l1.daemon.is_in_log('... succeeded')
        preimage = l1.rpc.sendpay(to_json([routestep]), rhash)
        assert preimage == preimage2
        l1.daemon.wait_for_log('... succeeded')
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'paid'
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['msatoshi_received'] == rs['msatoshi']

        # Overpaying by "only" a factor of 2 succeeds.
        rhash = l2.rpc.invoice(amt, 'testpayment3', 'desc')['payment_hash']
        assert l2.rpc.listinvoices('testpayment3')['invoices'][0]['status'] == 'unpaid'
        routestep = { 'msatoshi' : amt * 2, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'}
        preimage3 = l1.rpc.sendpay(to_json([routestep]), rhash)
        assert l2.rpc.listinvoices('testpayment3')['invoices'][0]['status'] == 'paid'
        assert l2.rpc.listinvoices('testpayment3')['invoices'][0]['msatoshi_received'] == amt*2

        # Test listpayments
        payments = l1.rpc.listpayments()['payments']
        assert len(payments) == 2

        invoice2 = l2.rpc.listinvoices('testpayment2')['invoices'][0]
        payments = l1.rpc.listpayments(None, invoice2['payment_hash'])['payments']
        assert len(payments) == 1

        assert payments[0]['status'] == 'complete'
        assert payments[0]['payment_preimage'] == preimage2['preimage']

        invoice3 = l2.rpc.listinvoices('testpayment3')['invoices'][0]
        payments = l1.rpc.listpayments(None, invoice3['payment_hash'])['payments']
        assert len(payments) == 1

        assert payments[0]['status'] == 'complete'
        assert payments[0]['payment_preimage'] == preimage3['preimage']

    def test_sendpay_cant_afford(self):
        l1,l2 = self.connect()

        # Note, this is in SATOSHI, rest are in MILLISATOSHI!
        self.fund_channel(l1, l2, 10**6)

        # Can't pay more than channel capacity.
        self.assertRaises(ValueError, self.pay, l1, l2, 10**9 + 1)

        # This is the fee, which needs to be taken into account for l1.
        available = 10**9 - 6720
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

    def test_pay(self):
        l1,l2 = self.connect()

        chanid = self.fund_channel(l1, l2, 10**6)

        # Wait for route propagation.
        self.wait_for_routes(l1, [chanid])

        inv = l2.rpc.invoice(123000, 'test_pay', 'description')['bolt11']
        before = int(time.time())
        preimage = l1.rpc.pay(inv)
        after = int(time.time())
        invoice = l2.rpc.listinvoices('test_pay')['invoices'][0]

        assert invoice['status'] == 'paid'
        assert invoice['paid_at'] >= before
        assert invoice['paid_at'] <= after

        # Repeat payments are NOPs (if valid): we can hand null.
        l1.rpc.pay(inv, None)
        # This won't work: can't provide an amount (even if correct!)
        self.assertRaises(ValueError, l1.rpc.pay, inv, 123000)
        self.assertRaises(ValueError, l1.rpc.pay, inv, 122000)

        # Check pay_index is not null
        outputs = l2.db_query('SELECT pay_index IS NOT NULL AS q FROM invoices WHERE label="label";')
        assert len(outputs) == 1 and outputs[0]['q'] != 0

        # Check payment of any-amount invoice.
        for i in range(5):
            label = "any{}".format(i)
            inv2 = l2.rpc.invoice("any", label, 'description')['bolt11']
            # Must provide an amount!
            self.assertRaises(ValueError, l1.rpc.pay, inv2)
            self.assertRaises(ValueError, l1.rpc.pay, inv2, None)
            # Amount must be nonzero!
            self.assertRaisesRegex(ValueError, 'WIRE_AMOUNT_BELOW_MINIMUM',
                                   l1.rpc.pay, inv2, 0)
            l1.rpc.pay(inv2, random.randint(1000, 999999))

        # Should see 6 completed payments
        assert len(l1.rpc.listpayments()['payments']) == 6

        # Test listpayments indexed by bolt11.
        assert len(l1.rpc.listpayments(inv)['payments']) == 1
        assert l1.rpc.listpayments(inv)['payments'][0]['payment_preimage'] == preimage['preimage']

    def test_bad_opening(self):
        # l1 asks for a too-long locktime
        l1 = self.node_factory.get_node(options=['--locktime-blocks=100'])
        l2 = self.node_factory.get_node(options=['--max-locktime-blocks=99'])
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')

        self.give_funds(l1, 10**6 + 1000000)
        self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 10**6)

        l2.daemon.wait_for_log('to_self_delay 100 larger than 99')

    def test_closing(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1, l2, 200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return, then close.
        l1.rpc.close(l2.info['id'])
        l1.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

        # Now grab the close transaction
        closetxid = l1.bitcoin.rpc.getrawmempool(False)[0]

        l1.bitcoin.rpc.generate(10)

        l1.daemon.wait_for_log(r'Owning output .* txid %s' % closetxid)
        l2.daemon.wait_for_log(r'Owning output .* txid %s' % closetxid)

        # Make sure both nodes have grabbed their close tx funds
        assert closetxid in set([o['txid'] for o in l1.rpc.listfunds()['outputs']])
        assert closetxid in set([o['txid'] for o in l2.rpc.listfunds()['outputs']])

        # Make sure both have forgotten about it
        l1.bitcoin.rpc.generate(100)
        wait_forget_channels(l1)
        wait_forget_channels(l2)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
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
        l2.rpc.dev_fail(l1.info['id'])
        l2.daemon.wait_for_log('Failing due to dev-fail command')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

        # Now grab the close transaction
        closetxid = l1.bitcoin.rpc.getrawmempool(False)[0]

        # "Internal error" in hex
        l1.daemon.wait_for_log('WIRE_ERROR.*496e7465726e616c206572726f72')

        # l2 will send out tx (l1 considers it a transient error)
        bitcoind.generate_block(1)

        l1.daemon.wait_for_log('Their unilateral tx, old commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET (.*) in 5 blocks')

        # Now, mine 5 blocks so it sends out the spending tx.
        bitcoind.generate_block(5)

        # It should send the to-wallet tx.
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # 100 after l1 sees tx, it should be done.
        bitcoind.generate_block(95)
        wait_forget_channels(l1)

        # Now, 100 blocks l2 should be done.
        bitcoind.generate_block(5)
        wait_forget_channels(l2)

        # Only l1 has a direct output since all of l2's outputs are respent (it failed)
        assert closetxid in set([o['txid'] for o in l1.rpc.listfunds()['outputs']])

        addr = l1.bitcoin.rpc.getnewaddress()
        l1.rpc.withdraw(addr, "all")

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_onchain_first_commit(self):
        """Onchain handling where funder immediately drops to chain"""

        # HTLC 1->2, 1 fails just after funding.
        disconnects = ['+WIRE_FUNDING_LOCKED', 'permfail']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        # Make locktime different, as we once had them reversed!
        l2 = self.node_factory.get_node(options=['--locktime-blocks=10'])

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        # Like fundchannel, but we'll probably fail before CHANNELD_NORMAL.
        addr = l1.rpc.newaddr()['address']

        self.give_funds(l1, 10**6 + 1000000)

        l1.rpc.fundchannel(l2.info['id'], 10**6)
        l1.daemon.wait_for_log('sendrawtx exit 0')

        l1.bitcoin.generate_block(1)

        # l1 will drop to chain.
        l1.daemon.wait_for_log('permfail')
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # 10 later, l1 should collect its to-self payment.
        bitcoind.generate_block(10)
        l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # 94 later, l2 is done.
        bitcoind.generate_block(94)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks and l1 should be done.
        bitcoind.generate_block(6)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_onchain_dust_out(self):
        """Onchain handling of outgoing dust htlcs (they should fail)"""
        # HTLC 1->2, 1 fails after it's irrevocably committed
        disconnects = ['@WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        self.fund_channel(l1, l2, 10**6)

        # Must be dust!
        rhash = l2.rpc.invoice(1, 'onchain_dust_out', 'desc')['payment_hash']
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
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # We use 3 blocks for "reasonable depth"
        bitcoind.generate_block(3)

        # It should fail.
        self.assertRaises(ValueError, payfuture.result, 5)

        l1.daemon.wait_for_log('WIRE_PERMANENT_CHANNEL_FAILURE: missing in commitment tx')

        # 6 later, l1 should collect its to-self payment.
        bitcoind.generate_block(6)
        l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # 94 later, l2 is done.
        bitcoind.generate_block(94)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks and l1 should be done.
        bitcoind.generate_block(6)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Payment failed, BTW
        assert l2.rpc.listinvoices('onchain_dust_out')['invoices'][0]['status'] == 'unpaid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_onchain_timeout(self):
        """Onchain handling of outgoing failed htlcs"""
        # HTLC 1->2, 1 fails just after it's irrevocably committed
        disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        self.fund_channel(l1, l2, 10**6)

        rhash = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')['payment_hash']
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
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # Wait for timeout.
        l1.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 5 blocks')
        bitcoind.generate_block(5)

        # (l1 will also collect its to-self payment.)
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # We use 3 blocks for "reasonable depth"
        bitcoind.generate_block(3)

        # It should fail.
        self.assertRaises(ValueError, payfuture.result, 5)

        l1.daemon.wait_for_log('WIRE_PERMANENT_CHANNEL_FAILURE: timed out')

        # 2 later, l1 spends HTLC (5 blocks total).
        bitcoind.generate_block(2)
        l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # 89 later, l2 is done.
        bitcoind.generate_block(89)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Now, 100 blocks and l1 should be done.
        bitcoind.generate_block(10)
        assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')

        # Payment failed, BTW
        assert l2.rpc.listinvoices('onchain_timeout')['invoices'][0]['status'] == 'unpaid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_onchain_middleman(self):
        # HTLC 1->2->3, 1->2 goes down after 2 gets preimage from 3.
        disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        l3 = self.node_factory.get_node()

        # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
        l2.rpc.connect(l1.info['id'], 'localhost', l1.info['port'])
        l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])
        c12 = self.fund_channel(l2, l1, 10**6)
        c23 = self.fund_channel(l2, l3, 10**6)

        # Make sure routes finalized.
        self.wait_for_routes(l1, [c23])

        # Give l1 some money to play with.
        self.pay(l2, l1, 2 * 10**8)

        # Must be bigger than dust!
        rhash = l3.rpc.invoice(10**8, 'middleman', 'desc')['payment_hash']

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
        l1.bitcoin.generate_block(1)
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('OUR_UNILATERAL/THEIR_HTLC')

        # l2 should fulfill HTLC onchain, and spend to-us (any order)
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* in 0 blocks')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # Payment should succeed.
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC gave us preimage')
        err = q.get(timeout = 10)
        if err:
            print("Got err from sendpay thread")
            raise err
        t.join(timeout=1)
        assert not t.isAlive()

        # Three more, l2 can spend to-us.
        bitcoind.generate_block(3)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # One more block, HTLC tx is now spendable.
        l1.bitcoin.generate_block(1)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # 100 blocks after last spend, l2 should be done.
        l1.bitcoin.generate_block(100)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_penalty_inhtlc(self):
        """Test penalty transaction with an incoming HTLC"""
        # We suppress each one after first commit; HTLC gets added not fulfilled.
        l1 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'], may_fail=True)
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'])

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
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
        bitcoind.generate_block(1)

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
        bitcoind.generate_block(100)

        # FIXME: Test wallet balance...
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skip("flaky test causing CI fails too often")
    def test_penalty_outhtlc(self):
        """Test penalty transaction with an outgoing HTLC"""
        # First we need to get funds to l2, so suppress after second.
        l1 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED*3-nocommit'], may_fail=True)
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED*3-nocommit'])

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
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
        bitcoind.generate_block(1)

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
        bitcoind.generate_block(100)

        # FIXME: Test wallet balance...
        wait_forget_channels(l2)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_permfail_new_commit(self):
        # Test case where we have two possible commits: it will use new one.
        disconnects = ['-WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        self.fund_channel(l1, l2, 10**6)

        # This will fail at l2's end.
        t=self.pay(l1,l2,200000000,async=True)

        l2.daemon.wait_for_log('dev_disconnect permfail')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('Their unilateral tx, new commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) in 5 blocks')
        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US (.*) in 5 blocks')

        # OK, time out HTLC.
        bitcoind.generate_block(5)
        l1.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
        l2.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

        t.cancel()

        # Now, 100 blocks it should be done.
        bitcoind.generate_block(100)
        wait_forget_channels(l1)
        wait_forget_channels(l2)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_permfail_htlc_in(self):
        # Test case where we fail with unsettled incoming HTLC.
        disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        self.fund_channel(l1, l2, 10**6)

        # This will fail at l2's end.
        t=self.pay(l1, l2, 200000000, async=True)

        l2.daemon.wait_for_log('dev_disconnect permfail')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('Their unilateral tx, old commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) in 5 blocks')
        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US (.*) in 5 blocks')
        # l2 then gets preimage, uses it instead of ignoring
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* in 0 blocks')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)

        # OK, l1 sees l2 fulfill htlc.
        l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC gave us preimage')
        l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 5 blocks')
        bitcoind.generate_block(5)

        l2.daemon.wait_for_log('sendrawtx exit 0')

        t.cancel()

        # Now, 100 blocks it should be done.
        bitcoind.generate_block(95)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.generate_block(5)
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_permfail_htlc_out(self):
        # Test case where we fail with unsettled outgoing HTLC.
        disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        self.fund_channel(l2, l1, 10**6)

        # This will fail at l2's end.
        t=self.pay(l2,l1,200000000,async=True)

        l2.daemon.wait_for_log('dev_disconnect permfail')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('Their unilateral tx, old commit point')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TX \\(.*\\) in 5 blocks',
                                 'Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 5 blocks'])

        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) in 5 blocks')
        # l1 then gets preimage, uses it instead of ignoring
        l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_FULFILL_TO_US .* in 0 blocks')
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # l2 sees l1 fulfill tx.
        bitcoind.generate_block(1)

        l2.daemon.wait_for_log('OUR_UNILATERAL/OUR_HTLC gave us preimage')
        t.cancel()

        # l2 can send OUR_DELAYED_RETURN_TO_WALLET after 4 more blocks.
        bitcoind.generate_block(4)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # Now, 100 blocks they should be done.
        bitcoind.generate_block(94)
        assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.generate_block(5)
        assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
        bitcoind.generate_block(1)
        wait_forget_channels(l2)

    def test_gossip_jsonrpc(self):
        l1, l2 = self.line_graph(n=2)

        # Shouldn't send announce signatures until 6 deep.
        assert not l1.daemon.is_in_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')

        # Channels should be activated locally
        wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True])

        # Make sure we can route through the channel, will raise on failure
        l1.rpc.getroute(l2.info['id'], 100, 1)

        # Outgoing should be active, but not public.
        channels = l1.rpc.listchannels()['channels']
        assert len(channels) == 1
        assert channels[0]['active'] == True
        assert channels[0]['public'] == False

        channels = l2.rpc.listchannels()['channels']
        assert len(channels) == 1
        assert channels[0]['active'] == True
        assert channels[0]['public'] == False

        # Now proceed to funding-depth and do a full gossip round
        l1.bitcoin.generate_block(5)
        # Could happen in either order.
        l1.daemon.wait_for_logs(['peer_out WIRE_ANNOUNCEMENT_SIGNATURES',
                                 'peer_in WIRE_ANNOUNCEMENT_SIGNATURES'])

        channel_id = channels[0]['short_channel_id']
        # Could happen in any order.
        l1.daemon.wait_for_logs(['peer_out WIRE_CHANNEL_ANNOUNCEMENT',
                                 'peer_in WIRE_CHANNEL_ANNOUNCEMENT',
                                 'Channel {}\\(0\\) was updated.'
                                 .format(channel_id),
                                 'Channel {}\\(1\\) was updated.'
                                 .format(channel_id)])

        l2.daemon.wait_for_logs(['peer_out WIRE_CHANNEL_ANNOUNCEMENT',
                                 'peer_in WIRE_CHANNEL_ANNOUNCEMENT',
                                 'Channel {}\\(0\\) was updated.'
                                 .format(channel_id),
                                 'Channel {}\\(1\\) was updated.'
                                 .format(channel_id)])

        nodes = l1.rpc.listnodes()['nodes']
        assert set([n['nodeid'] for n in nodes]) == set([l1.info['id'], l2.info['id']])

        # Test listnodes with an arg, while we're here.
        n1 = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
        n2 = l1.rpc.listnodes(l2.info['id'])['nodes'][0]
        assert n1['nodeid'] == l1.info['id']
        assert n2['nodeid'] == l2.info['id']

        # Might not have seen other node-announce yet.
        # TODO(cdecker) Can't check these without DEVELOPER=1, re-enable after we get alias and color into getinfo
        if DEVELOPER:
            assert n1['alias'] == 'JUNIORBEAM'
            assert n1['color'] == '0266e4'
            if not 'alias' in n2:
                assert not 'color' in n2
                assert not 'addresses' in n2
            else:
                assert n2['alias'] == 'SILENTARTIST'
                assert n2['color'] == '022d22'

        assert [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True]
        assert [c['public'] for c in l1.rpc.listchannels()['channels']] == [True, True]
        assert [c['active'] for c in l2.rpc.listchannels()['channels']] == [True, True]
        assert [c['public'] for c in l2.rpc.listchannels()['channels']] == [True, True]

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_gossip_pruning(self):
        """ Create channel and see it being updated in time before pruning
        """
        opts = ['--channel-update-interval=5']
        l1 = self.node_factory.get_node(options=opts)
        l2 = self.node_factory.get_node(options=opts)
        l3 = self.node_factory.get_node(options=opts)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])

        scid1 = self.fund_channel(l1, l2, 10**6)
        scid2 = self.fund_channel(l2, l3, 10**6)

        l1.bitcoin.rpc.generate(6)

        # Channels should be activated locally
        wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True]*4)
        wait_for(lambda: [c['active'] for c in l2.rpc.listchannels()['channels']] == [True]*4)
        wait_for(lambda: [c['active'] for c in l3.rpc.listchannels()['channels']] == [True]*4)

        # All of them should send a keepalive message
        l1.daemon.wait_for_logs([
            'Sending keepalive channel_update for {}'.format(scid1),
        ])
        l2.daemon.wait_for_logs([
            'Sending keepalive channel_update for {}'.format(scid1),
            'Sending keepalive channel_update for {}'.format(scid2),
        ])
        l3.daemon.wait_for_logs([
            'Sending keepalive channel_update for {}'.format(scid2),
        ])

        # Now kill l3, so that l2 and l1 can prune it from their view after 10 seconds
        time.sleep(1)
        l3.stop()

        l1.daemon.wait_for_logs([
            "Pruning channel {}/{} from network view".format(scid2, 0),
            "Pruning channel {}/{} from network view".format(scid2, 1),
        ])

        l2.daemon.wait_for_logs([
            "Pruning channel {}/{} from network view".format(scid2, 0),
            "Pruning channel {}/{} from network view".format(scid2, 1),
        ])

        assert scid2 not in [c['short_channel_id'] for c in l1.rpc.listchannels()['channels']]
        assert scid2 not in [c['short_channel_id'] for c in l2.rpc.listchannels()['channels']]
        assert l3.info['id'] not in [n['nodeid'] for n in l1.rpc.listnodes()['nodes']]
        assert l3.info['id'] not in [n['nodeid'] for n in l2.rpc.listnodes()['nodes']]

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

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_ping(self):
        l1,l2 = self.connect()

        # Test gossip pinging.
        self.ping_tests(l1, l2)

        self.fund_channel(l1, l2, 10**5)

        # channeld pinging
        self.ping_tests(l1, l2)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_routing_gossip_reconnect(self):
        # Connect two peers, reconnect and then see if we resume the
        # gossip.
        disconnects = ['-WIRE_CHANNEL_ANNOUNCEMENT']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        l1.openchannel(l2, 20000)

        # Now open new channels and everybody should sync
        l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])
        l2.openchannel(l3, 20000)

        # Settle the gossip
        for n in [l1, l2, l3]:
            wait_for(lambda: len(n.rpc.listchannels()['channels']) == 4)

    def test_second_channel(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        l1.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l1, l3, 10**6)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_routing_gossip(self):
        nodes = [self.node_factory.get_node() for _ in range(5)]
        l1 = nodes[0]
        l5 = nodes[4]

        for i in range(len(nodes)-1):
            src, dst = nodes[i], nodes[i+1]
            src.rpc.connect(dst.info['id'], 'localhost', dst.info['port'])
            src.openchannel(dst, 20000)

        # Allow announce messages.
        l1.bitcoin.generate_block(5)

        def settle_gossip(n):
            """Wait for gossip to settle at the node
            """
            expected_connections = 2*(len(nodes) - 1)
            start_time = time.time()
            # Wait at most 10 seconds, broadcast interval is 1 second
            while time.time() - start_time < 10:
                channels = n.rpc.listchannels()['channels']
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
            channels = n.rpc.listchannels()['channels']
            for c in channels:
                seen.append((c['source'],c['destination']))
            assert set(seen) == set(comb)

    def test_forward(self):
        # Connect 1 -> 2 -> 3.
        l1,l2 = self.connect()
        l3 = self.node_factory.get_node()
        ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])

        assert ret['id'] == l3.info['id']

        l3.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # Allow announce messages.
        l1.bitcoin.generate_block(5)

        # If they're at different block heights we can get spurious errors.
        sync_blockheight([l1, l2, l3])

        chanid1 = l1.rpc.getpeer(l2.info['id'])['channels'][0]['short_channel_id']
        chanid2 = l2.rpc.getpeer(l3.info['id'])['channels'][0]['short_channel_id']
        assert l2.rpc.getpeer(l1.info['id'])['channels'][0]['short_channel_id'] == chanid1
        assert l3.rpc.getpeer(l2.info['id'])['channels'][0]['short_channel_id'] == chanid2

        rhash = l3.rpc.invoice(100000000, 'testpayment1', 'desc')['payment_hash']
        assert l3.rpc.listinvoices('testpayment1')['invoices'][0]['status'] == 'unpaid'

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
        l1 = self.node_factory.get_node(options=['--cltv-delta=10', '--fee-base=100', '--fee-per-satoshi=1000'])
        l2 = self.node_factory.get_node(options=['--cltv-delta=20', '--fee-base=200', '--fee-per-satoshi=2000'])
        l3 = self.node_factory.get_node(options=['--cltv-delta=30', '--cltv-final=9', '--fee-base=300', '--fee-per-satoshi=3000'])

        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')

        ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])
        assert ret['id'] == l3.info['id']

        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        l3.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')

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
        shadow_route=0
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
        # If A were to send an 4,999,999 millisatoshi to C via B, it needs to
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
        assert l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'][0]['status'] == 'unpaid'

        # This should work.
        l1.rpc.sendpay(to_json(route), rhash)

        # We add one to the blockcount for a bit of fuzz (FIXME: Shadowroute would fix this!)
        shadow_route = 1
        l1.daemon.wait_for_log("Adding HTLC 0 msat=5010198 cltv={} gave 0"
                               .format(bitcoind.rpc.getblockcount() + 20 + 9 + shadow_route))
        l2.daemon.wait_for_log("Adding HTLC 0 msat=4999999 cltv={} gave 0"
                               .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
        l3.daemon.wait_for_log("test_forward_different_fees_and_cltv: Actual amount 4999999msat, HTLC expiry {}"
                               .format(bitcoind.rpc.getblockcount() + 9 + shadow_route))
        assert l3.rpc.listinvoices('test_forward_different_fees_and_cltv')['invoices'][0]['status'] == 'paid'

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

        l1 = self.node_factory.get_node(options=['--cltv-delta=10', '--fee-base=100', '--fee-per-satoshi=1000'])
        l2 = self.node_factory.get_node(options=['--cltv-delta=20', '--fee-base=200', '--fee-per-satoshi=2000'])
        l3 = self.node_factory.get_node(options=['--cltv-delta=30', '--cltv-final=9', '--fee-base=300', '--fee-per-satoshi=3000'])

        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')

        ret = l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])
        assert ret['id'] == l3.info['id']

        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')
        l3.daemon.wait_for_log('WIRE_GOSSIPCTL_HAND_BACK_PEER')

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
        assert l3.rpc.listinvoices('test_forward_pad_fees_and_cltv')['invoices'][0]['status'] == 'paid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_htlc_out_timeout(self):
        """Test that we drop onchain if the peer doesn't time out HTLC"""

        # HTLC 1->2, 1 fails after it's irrevocably committed, can't reconnect
        disconnects = ['@WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node(disconnect=disconnects,
                                        options=['--no-reconnect'])
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        chanid = self.fund_channel(l1, l2, 10**6)

        # Wait for route propagation.
        self.wait_for_routes(l1, [chanid])

        amt = 200000000
        inv = l2.rpc.invoice(amt, 'test_htlc_out_timeout', 'desc')['bolt11']
        assert l2.rpc.listinvoices('test_htlc_out_timeout')['invoices'][0]['status'] == 'unpaid'

        payfuture = self.executor.submit(l1.rpc.pay, inv)

        # l1 will disconnect, and not reconnect.
        l1.daemon.wait_for_log('dev_disconnect: @WIRE_REVOKE_AND_ACK')

        # Takes 6 blocks to timeout (cltv-final + 1), but we also give grace period of 1 block.
        bitcoind.generate_block(5 + 1)
        assert not l1.daemon.is_in_log('hit deadline')
        bitcoind.generate_block(1)

        l1.daemon.wait_for_log('Offered HTLC 0 SENT_ADD_ACK_REVOCATION cltv .* hit deadline')
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l1.bitcoin.generate_block(1)
        l1.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l2.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # L1 will timeout HTLC immediately
        l1.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TX .* in 0 blocks',
                                 'Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 5 blocks'])

        l1.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)

        l1.daemon.wait_for_log('Propose handling OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 5 blocks')
        bitcoind.generate_block(5)
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
                                        options=['--no-reconnect'])
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        chanid = self.fund_channel(l1, l2, 10**6)

        self.wait_for_routes(l1, [chanid])

        amt = 200000000
        inv = l2.rpc.invoice(amt, 'test_htlc_in_timeout', 'desc')['bolt11']
        assert l2.rpc.listinvoices('test_htlc_in_timeout')['invoices'][0]['status'] == 'unpaid'

        payfuture = self.executor.submit(l1.rpc.pay, inv)

        # l1 will disconnect and not reconnect.
        l1.daemon.wait_for_log('dev_disconnect: -WIRE_REVOKE_AND_ACK')

        # Deadline HTLC expiry minus 1/2 cltv-expiry delta (rounded up) (== cltv - 3).  ctlv is 5+1.
        bitcoind.generate_block(2)
        assert not l2.daemon.is_in_log('hit deadline')
        bitcoind.generate_block(1)

        l2.daemon.wait_for_log('Fulfilled HTLC 0 SENT_REMOVE_COMMIT cltv .* hit deadline')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        l2.bitcoin.generate_block(1)
        l2.daemon.wait_for_log('-> ONCHAIND_OUR_UNILATERAL')
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

        # L2 will collect HTLC
        l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* in 0 blocks')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)
        l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* in 5 blocks')
        bitcoind.generate_block(5)
        l2.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        # Now, 100 blocks it should be both done.
        bitcoind.generate_block(100)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_disconnect(self):
        # These should all make us fail, and retry.
        # FIXME: Configure short timeout for reconnect!
        disconnects = ['-WIRE_INIT',
                       '@WIRE_INIT',
                       '+WIRE_INIT']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        # Should have 3 connect fails.
        for d in disconnects:
            l1.daemon.wait_for_log('Failed connected out for {}, will try again'
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
            l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
            self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)
            assert l1.rpc.getpeer(l2.info['id']) == None

        # This one will succeed.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
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
            l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
            self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)
            assert l1.rpc.getpeer(l2.info['id']) == None

        # This one will succeed.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
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

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)

        # Fundee remembers, funder doesn't.
        assert l1.rpc.getpeer(l2.info['id']) == None
        assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_signed(self):
        # This will fail *after* both sides consider channel opening.
        disconnects = ['+WIRE_FUNDING_SIGNED']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)

        self.give_funds(l1, 2000000)

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])
        l1.rpc.fundchannel(l2.info['id'], 20000)

        # They haven't forgotten each other.
        assert l1.rpc.getpeer(l2.info['id'])['id'] == l2.info['id']
        assert l2.rpc.getpeer(l1.info['id'])['id'] == l1.info['id']

        # Technically, this is async to fundchannel (and could reconnect first)
        l1.daemon.wait_for_logs(['sendrawtx exit 0',
                                 'Peer has reconnected, state CHANNELD_AWAITING_LOCKIN'])

        l1.bitcoin.generate_block(6)

        l1.daemon.wait_for_log('-> CHANNELD_NORMAL')
        l2.daemon.wait_for_log('-> CHANNELD_NORMAL')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_openingd(self):
        # Openingd thinks we're still opening; funder reconnects..
        disconnects = ['0WIRE_ACCEPT_CHANNEL']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.give_funds(l1, 2000000)

        # l2 closes on l1, l1 forgets.
        self.assertRaises(ValueError, l1.rpc.fundchannel, l2.info['id'], 20000)
        assert l1.rpc.getpeer(l2.info['id']) == None

        # Reconnect.
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        # We should get a message about reconnecting.
        l2.daemon.wait_for_log('Peer has reconnected, state OPENINGD')

        # Should work fine.
        l1.rpc.fundchannel(l2.info['id'], 20000)
        l1.daemon.wait_for_log('sendrawtx exit 0')

        # Just to be sure, second openingd hand over to channeld.
        l2.daemon.wait_for_log('lightning_openingd.*REPLY WIRE_OPENING_FUNDEE_REPLY with 2 fds')

    @unittest.skip("temporarily disabled due to flaky behavior, issue #468")
    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_normal(self):
        # Should reconnect fine even if locked message gets lost.
        disconnects = ['-WIRE_FUNDING_LOCKED',
                       '@WIRE_FUNDING_LOCKED',
                       '+WIRE_FUNDING_LOCKED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_sender_add1(self):
        # Fail after add is OK, will cause payment failure though.
        disconnects = ['-WIRE_UPDATE_ADD_HTLC-nocommit',
                       '+WIRE_UPDATE_ADD_HTLC-nocommit',
                       '@WIRE_UPDATE_ADD_HTLC-nocommit']

        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'test_reconnect_sender_add1', 'desc')['payment_hash']
        assert l2.rpc.listinvoices('test_reconnect_sender_add1')['invoices'][0]['status'] == 'unpaid'

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]

        for i in range(0,len(disconnects)):
            self.assertRaises(ValueError, l1.rpc.sendpay, to_json(route), rhash)
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
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment', 'desc')['payment_hash']
        assert l2.rpc.listinvoices('testpayment')['invoices'][0]['status'] == 'unpaid'

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]

        # This will send commit, so will reconnect as required.
        l1.rpc.sendpay(to_json(route), rhash)
        # Should have printed this for every reconnect.
        for i in range(0,len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_reconnect_receiver_add(self):
        disconnects = ['-WIRE_COMMITMENT_SIGNED',
                       '@WIRE_COMMITMENT_SIGNED',
                       '+WIRE_COMMITMENT_SIGNED',
                       '-WIRE_REVOKE_AND_ACK',
                       '@WIRE_REVOKE_AND_ACK',
                       '+WIRE_REVOKE_AND_ACK']
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]
        l1.rpc.sendpay(to_json(route), rhash)
        for i in range(len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'paid'

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
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=disconnects)
        ret = l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)

        amt = 200000000
        rhash = l2.rpc.invoice(amt, 'testpayment2', 'desc')['payment_hash']
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'unpaid'

        route = [ { 'msatoshi' : amt, 'id' : l2.info['id'], 'delay' : 5, 'channel': '1:1:1'} ]
        l1.rpc.sendpay(to_json(route), rhash)
        for i in range(len(disconnects)):
            l1.daemon.wait_for_log('Already have funding locked in')
        assert l2.rpc.listinvoices('testpayment2')['invoices'][0]['status'] == 'paid'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_shutdown_reconnect(self):
        disconnects = ['-WIRE_SHUTDOWN',
                       '@WIRE_SHUTDOWN',
                       '+WIRE_SHUTDOWN']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1,l2,200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return, then close.
        l1.rpc.close(l2.info['id'])
        l1.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool (happens async, so
        # CLOSINGD_COMPLETE may come first).
        l1.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        l2.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_closing_negotiation_reconnect(self):
        disconnects = ['-WIRE_CLOSING_SIGNED',
                       '@WIRE_CLOSING_SIGNED',
                       '+WIRE_CLOSING_SIGNED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)
        self.pay(l1,l2,200000000)

        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 0

        # This should return, then close.
        l1.rpc.close(l2.info['id'])
        l1.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')
        l2.daemon.wait_for_log('-> CHANNELD_SHUTTING_DOWN')

        l1.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')
        l2.daemon.wait_for_log('-> CLOSINGD_SIGEXCHANGE')

        # And should put closing into mempool (happens async, so
        # CLOSINGD_COMPLETE may come first).
        l1.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        l2.daemon.wait_for_logs(['sendrawtx exit 0', '-> CLOSINGD_COMPLETE'])
        assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    def test_withdraw(self):
        amount = 1000000
        # Don't get any funds from previous runs.
        l1 = self.node_factory.get_node(random_hsm=True)
        l2 = self.node_factory.get_node(random_hsm=True)
        addr = l1.rpc.newaddr()['address']

        # Add some funds to withdraw later
        for i in range(10):
            txid = l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)
            tx = l1.bitcoin.rpc.getrawtransaction(txid)

        bitcoind.generate_block(1)
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

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

        # Now send some money to l2.
        # lightningd uses P2SH-P2WPKH
        waddr = l2.rpc.newaddr()['address']
        out = l1.rpc.withdraw(waddr, 2*amount)
        l1.bitcoin.rpc.generate(1)

        # Make sure l2 received the withdrawal.
        wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 1)
        outputs = l2.db_query('SELECT value FROM outputs WHERE status=0;')
        assert len(outputs) == 1 and outputs[0]['value'] == 2*amount

        # Now make sure an additional two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 4)

        # Simple test for withdrawal to P2WPKH
        # Address from: https://bc-2.jp/tools/bech32demo/index.html
        waddr = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'
        self.assertRaises(ValueError, l1.rpc.withdraw, 'xx1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 2*amount)
        self.assertRaises(ValueError, l1.rpc.withdraw, 'tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kdl9fad', 2*amount)
        self.assertRaises(ValueError, l1.rpc.withdraw, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxxxxxx', 2*amount)
        out = l1.rpc.withdraw(waddr, 2*amount)
        l1.bitcoin.rpc.generate(1)
        # Now make sure additional two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 6)

        # Simple test for withdrawal to P2WSH
        # Address from: https://bc-2.jp/tools/bech32demo/index.html
        waddr = 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'
        self.assertRaises(ValueError, l1.rpc.withdraw, 'xx1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 2*amount)
        self.assertRaises(ValueError, l1.rpc.withdraw, 'tb1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsm03tq', 2*amount)
        self.assertRaises(ValueError, l1.rpc.withdraw, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qxxxxxx', 2*amount)
        out = l1.rpc.withdraw(waddr, 2*amount)
        l1.bitcoin.rpc.generate(1)
        # Now make sure additional two of them were marked as spent
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=2')
        assert(c.fetchone()[0] == 8)

        # failure testing for invalid SegWit addresses, from BIP173
        # HRP character out of range
        self.assertRaises(ValueError, l1.rpc.withdraw, ' 1nwldj5', 2*amount)
        # overall max length exceeded
        self.assertRaises(ValueError, l1.rpc.withdraw, 'an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx', 2*amount)
        # No separator character
        self.assertRaises(ValueError, l1.rpc.withdraw, 'pzry9x0s0muk', 2*amount)
        # Empty HRP
        self.assertRaises(ValueError, l1.rpc.withdraw, '1pzry9x0s0muk', 2*amount)
        # Invalid witness version
        self.assertRaises(ValueError, l1.rpc.withdraw, 'BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2', 2*amount)
        # Invalid program length for witness version 0 (per BIP141)
        self.assertRaises(ValueError, l1.rpc.withdraw, 'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 2*amount)
        # Mixed case
        self.assertRaises(ValueError, l1.rpc.withdraw, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7', 2*amount)
        # Non-zero padding in 8-to-5 conversion
        self.assertRaises(ValueError, l1.rpc.withdraw, 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv', 2*amount)

        # Should have 6 outputs available.
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 6)

        out = l1.rpc.withdraw(waddr, 'all')
        c = db.cursor()
        c.execute('SELECT COUNT(*) FROM outputs WHERE status=0')
        assert(c.fetchone()[0] == 0)

        # This should fail, can't even afford fee.
        self.assertRaises(ValueError, l1.rpc.withdraw, waddr, 'all')
        l1.daemon.wait_for_log('Cannot afford fee')


    def test_funding_change(self):
        """Add some funds, fund a channel, and make sure we remember the change
        """
        l1, l2 = self.connect()

        self.give_funds(l1, 0.1 * 10**8)

        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert len(outputs) == 1 and outputs[0]['value'] == 10000000

        l1.rpc.fundchannel(l2.info['id'], 1000000)
        outputs = {r['status']: r['value'] for r in l1.db_query(
            'SELECT status, SUM(value) AS value FROM outputs GROUP BY status;')}

        # The 10m out is spent and we have a change output of 9m-fee
        assert outputs[0] >   8990000
        assert outputs[2] == 10000000

    def test_funding_fail(self):
        """Add some funds, fund a channel without enough funds"""
        # Previous runs with same bitcoind can leave funds!
        l1 = self.node_factory.get_node(random_hsm=True)
        max_locktime = 3 * 6 * 24
        l2 = self.node_factory.get_node(options=['--locktime-blocks={}'.format(max_locktime + 1)])
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        funds = 1000000

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, funds / 10**8)
        bitcoind.generate_block(1)

        # Wait for it to arrive.
        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

        # Fail because l1 dislikes l2's huge locktime.
        self.assertRaisesRegex(ValueError, r'to_self_delay \d+ larger than \d+',
                               l1.rpc.fundchannel, l2.info['id'], int(funds/10))
        assert l1.rpc.listpeers()['peers'][0]['connected']
        assert l2.rpc.listpeers()['peers'][0]['connected']

        # Restart l2 without ridiculous locktime.
        l2.daemon.cmd_line.remove('--locktime-blocks={}'.format(max_locktime + 1))
        l2.restart()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        # We don't have enough left to cover fees if we try to spend it all.
        self.assertRaisesRegex(ValueError, r'Cannot afford funding transaction',
                               l1.rpc.fundchannel, l2.info['id'], funds)

        # Should still be connected.
        assert l1.rpc.listpeers()['peers'][0]['connected']
        assert l2.rpc.listpeers()['peers'][0]['connected']

        # This works.
        l1.rpc.fundchannel(l2.info['id'], int(funds/10))

    def test_funding_toolarge(self):
        """Try to create a giant channel"""
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

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
        except ValueError as err:
            assert 'Funding satoshi must be <= 16777215' in str(err)

        # This should work.
        amount = amount-1
        l1.rpc.fundchannel(l2.info['id'], amount)

    def test_lockin_between_restart(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(options=['--anchor-confirms=3'])
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.give_funds(l1, 10**6 + 1000000)
        l1.rpc.fundchannel(l2.info['id'], 10**6)['tx']

        # l1 goes down.
        l1.stop()

        # Now 120 blocks go by...
        bitcoind.generate_block(120)

        # Restart
        l1.daemon.start()

        # All should be good.
        l1.daemon.wait_for_log('-> CHANNELD_NORMAL')
        l2.daemon.wait_for_log('-> CHANNELD_NORMAL')
        
    def test_addfunds_from_block(self):
        """Send funds to the daemon without telling it explicitly
        """
        # Previous runs with same bitcoind can leave funds!
        l1 = self.node_factory.get_node(random_hsm=True)

        addr = l1.rpc.newaddr()['address']
        txid = l1.bitcoin.rpc.sendtoaddress(addr, 0.1)
        l1.bitcoin.rpc.generate(1)

        wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

        outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
        assert len(outputs) == 1 and outputs[0]['value'] == 10000000

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_channel_persistence(self):
        # Start two nodes and open a channel (to remember). l2 will
        # mysteriously die while committing the first HTLC so we can
        # check that HTLCs reloaded from the DB work.
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'])
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        # Neither node should have a channel open, they are just connected
        for n in (l1, l2):
            assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 0)

        self.fund_channel(l1, l2, 100000)

        peers = l1.rpc.listpeers()['peers']
        assert(len(peers) == 1 and peers[0]['channels'][0]['state'] == 'CHANNELD_NORMAL')

        # Both nodes should now have exactly one channel in the database
        for n in (l1, l2):
            assert(n.db_query('SELECT COUNT(id) as count FROM channels;')[0]['count'] == 1)

        # Fire off a sendpay request, it'll get interrupted by a restart
        fut = self.executor.submit(self.pay, l1, l2, 10000)
        # Wait for it to be committed to, i.e., stored in the DB
        l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

        # Stop l2, l1 will reattempt to connect
        print("Killing l2 in mid HTLC")
        l2.daemon.kill()

        # Clear the disconnect and timer stop so we can proceed normally
        l2.daemon.cmd_line = [e for e in l2.daemon.cmd_line if 'disconnect' not in e]
        print(" ".join(l2.daemon.cmd_line + ['--dev-debugger=channeld']))

        # Wait for l1 to notice
        wait_for(lambda: not 'connected' in l1.rpc.listpeers()['peers'][0]['channels'][0])

        # Now restart l1 and it should reload peers/channels from the DB
        l2.daemon.start()
        wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 1)

        # Wait for the restored HTLC to finish
        wait_for(lambda: l1.rpc.listpeers()['peers'][0]['channels'][0]['msatoshi_to_us'] == 99990000, interval=1)

        wait_for(lambda: len([p for p in l1.rpc.listpeers()['peers'] if p['connected']]), interval=1)
        wait_for(lambda: len([p for p in l2.rpc.listpeers()['peers'] if p['connected']]), interval=1)

        # Now make sure this is really functional by sending a payment
        self.pay(l1, l2, 10000)
        time.sleep(1)
        assert l1.rpc.listpeers()['peers'][0]['channels'][0]['msatoshi_to_us'] == 99980000
        assert l2.rpc.listpeers()['peers'][0]['channels'][0]['msatoshi_to_us'] == 20000

        # Finally restart l1, and make sure it remembers
        l1.stop()
        l1.daemon.start()
        assert l1.rpc.listpeers()['peers'][0]['channels'][0]['msatoshi_to_us'] == 99980000

        # Now make sure l1 is watching for unilateral closes
        l2.rpc.dev_fail(l1.info['id']);
        l2.daemon.wait_for_log('Failing due to dev-fail command')
        l2.daemon.wait_for_log('sendrawtx exit 0')
        bitcoind.generate_block(1)

        # L1 must notice.
        l1.daemon.wait_for_log('-> ONCHAIND_THEIR_UNILATERAL')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_payment_success_persistence(self):
        # Start two nodes and open a channel.. die during payment.
        l1 = self.node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'],
                                        options=['--no-reconnect'])
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        chanid = self.fund_channel(l1, l2, 100000)

        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')

        # Fire off a pay request, it'll get interrupted by a restart
        fut = self.executor.submit(l1.rpc.pay, inv1['bolt11'])

        l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

        print("Killing l1 in mid HTLC")
        l1.daemon.kill()

        # Restart l1, without disconnect stuff.
        l1.daemon.cmd_line.remove('--no-reconnect')
        l1.daemon.cmd_line.remove('--dev-disconnect=dev_disconnect')

        # Should reconnect, and sort the payment out.
        l1.daemon.start()

        wait_for(lambda: l1.rpc.listpayments()['payments'][0]['status'] != 'pending')

        assert l1.rpc.listpayments()['payments'][0]['status'] == 'complete'
        assert l2.rpc.listinvoices('inv1')['invoices'][0]['status'] == 'paid'

        # FIXME: We should re-add pre-announced routes on startup!
        self.wait_for_routes(l1, [chanid])

        # A duplicate should succeed immediately (nop) and return correct preimage.
        preimage = l1.rpc.pay(inv1['bolt11'])['preimage']
        assert l1.rpc.dev_rhash(preimage)['rhash'] == inv1['payment_hash']


    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_payment_failed_persistence(self):
        # Start two nodes and open a channel.. die during payment.
        l1 = self.node_factory.get_node(disconnect=['+WIRE_COMMITMENT_SIGNED'],
                                        options=['--no-reconnect'])
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 100000)

        # Expires almost immediately, so it will fail.
        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1', 1)

        # Fire off a pay request, it'll get interrupted by a restart
        fut = self.executor.submit(l1.rpc.pay, inv1['bolt11'])

        l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

        print("Killing l1 in mid HTLC")
        l1.daemon.kill()

        # Restart l1, without disconnect stuff.
        l1.daemon.cmd_line.remove('--no-reconnect')
        l1.daemon.cmd_line.remove('--dev-disconnect=dev_disconnect')

        # Make sure invoice has expired.
        time.sleep(2)

        # Should reconnect, and fail the payment
        l1.daemon.start()

        wait_for(lambda: l1.rpc.listpayments()['payments'][0]['status'] != 'pending')

        assert l2.rpc.listinvoices('inv1')['invoices'][0]['status'] == 'expired'
        assert l1.rpc.listpayments()['payments'][0]['status'] == 'failed'

        # Another attempt should also fail.
        self.assertRaises(ValueError, l1.rpc.pay, inv1['bolt11'])

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_payment_duplicate_uncommitted(self):
        # We want to test two payments at the same time, before we send commit
        l1 = self.node_factory.get_node(disconnect=['=WIRE_UPDATE_ADD_HTLC-nocommit'])
        l2 = self.node_factory.get_node()

        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 100000)

        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')

        # Start first payment, but not yet in db.
        fut = self.executor.submit(l1.rpc.pay, inv1['bolt11'])

        # Make sure that's started...
        l1.daemon.wait_for_log('dev_disconnect: =WIRE_UPDATE_ADD_HTLC-nocommit')

        # We should see it in listpayments
        assert l1.rpc.listpayments()['payments'][0]['status'] == 'pending'
        assert l1.rpc.listpayments()['payments'][0]['payment_hash'] == inv1['payment_hash']

        # Second one should fail.
        self.assertRaises(ValueError, l1.rpc.pay, inv1['bolt11'])

        # Now, let it commit.
        l1.rpc.dev_reenable_commit(l2.info['id'])

        # This should succeed.
        fut.result(10)

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_gossip_badsig(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l3 = self.node_factory.get_node()

        # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
        l2.rpc.connect(l1.info['id'], 'localhost', l1.info['port'])
        l2.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])
        self.fund_channel(l2, l1, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # Wait for route propagation.
        l1.bitcoin.generate_block(5)
        l1.daemon.wait_for_log('Received node_announcement for node {}'
                               .format(l3.info['id']))
        assert not l1.daemon.is_in_log('signature verification failed')
        assert not l2.daemon.is_in_log('signature verification failed')
        assert not l3.daemon.is_in_log('signature verification failed')

    def test_waitinvoice(self):
        """Test waiting for one invoice will not return if another invoice
        is paid.
        """
        # Setup
        l1, l2 = self.connect()
        self.fund_channel(l1, l2, 10**6)
        l1.bitcoin.generate_block(6)
        l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))

        # Create invoices
        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
        inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')

        # Start waiting on invoice 1, should block
        f = self.executor.submit(l2.rpc.waitinvoice, 'inv1')
        time.sleep(1)
        assert not f.done()
        # Pay invoice 2
        l1.rpc.pay(inv2['bolt11'])
        # Waiter should stil be blocked
        time.sleep(1)
        assert not f.done()
        # Pay invoice 1
        l1.rpc.pay(inv1['bolt11'])
        # Waiter should now finish
        r = f.result(timeout=5)
        assert r['label'] == 'inv1'

    def test_waitanyinvoice(self):
        """Test various variants of waiting for the next invoice to complete.
        """
        l1, l2 = self.connect()
        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
        inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')
        inv3 = l2.rpc.invoice(1000, 'inv3', 'inv3')

        self.fund_channel(l1, l2, 10**6)

        l1.bitcoin.generate_block(6)
        l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))

        # Attempt to wait for the first invoice
        f = self.executor.submit(l2.rpc.waitanyinvoice)
        time.sleep(1)

        # The call to waitanyinvoice should not have returned just yet
        assert not f.done()

        # Now pay the first two invoices and make sure we notice
        l1.rpc.pay(inv1['bolt11'])
        l1.rpc.pay(inv2['bolt11'])
        r = f.result(timeout=5)
        assert r['label'] == 'inv1'
        pay_index = r['pay_index']

        # This one should return immediately with inv2
        r = self.executor.submit(l2.rpc.waitanyinvoice, pay_index).result(timeout=5)
        assert r['label'] == 'inv2'
        pay_index = r['pay_index']

        # Now spawn the next waiter
        f = self.executor.submit(l2.rpc.waitanyinvoice, pay_index)
        time.sleep(1)
        assert not f.done()
        l1.rpc.pay(inv3['bolt11'])
        r = f.result(timeout=5)
        assert r['label'] == 'inv3'

        self.assertRaises(ValueError, l2.rpc.waitanyinvoice, 'non-number')


    def test_waitanyinvoice_reversed(self):
        """Test waiting for invoices, where they are paid in reverse order
        to when they are created.
        """
        # Setup
        l1, l2 = self.connect()
        self.fund_channel(l1, l2, 10**6)
        l1.bitcoin.generate_block(6)
        l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))

        # Create invoices
        inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
        inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')

        # Pay inv2, wait, pay inv1, wait
        # Pay inv2
        l1.rpc.pay(inv2['bolt11'])
        # Wait - should not block, should return inv2
        r = self.executor.submit(l2.rpc.waitanyinvoice).result(timeout=5)
        assert r['label'] == 'inv2'
        pay_index = r['pay_index']
        # Pay inv1
        l1.rpc.pay(inv1['bolt11'])
        # Wait inv2 - should not block, should return inv1
        r = self.executor.submit(l2.rpc.waitanyinvoice, pay_index).result(timeout=5)
        assert r['label'] == 'inv1'

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for --dev-broadcast-interval")
    def test_channel_reenable(self):
        l1, l2 = self.line_graph(n=2)

        l1.bitcoin.generate_block(6)
        l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))
        l2.daemon.wait_for_log('Received node_announcement for node {}'.format(l1.info['id']))

        # Both directions should be active before the restart
        wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True])

        # Restart l2, will cause l1 to reconnect
        l2.stop()
        l2.daemon.start()

        # Now they should sync and re-establish again
        l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))
        l2.daemon.wait_for_log('Received node_announcement for node {}'.format(l1.info['id']))
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

        # Make payments.
        self.pay(l1,l2,200000000)
        self.pay(l2,l1,100000000)

        # Now shutdown cleanly.
        l1.rpc.close(l2.info['id'])
        l1.daemon.wait_for_log('-> CLOSINGD_COMPLETE')
        l2.daemon.wait_for_log('-> CLOSINGD_COMPLETE')

        # And should put closing into mempool.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('-> ONCHAIND_MUTUAL')
        l2.daemon.wait_for_log('-> ONCHAIND_MUTUAL')

        bitcoind.generate_block(99)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_fee_limits(self):
        # FIXME: Test case where opening denied.
        l1, l2 = self.connect()
        self.fund_channel(l1, l2, 10**6)

        # L1 asks for stupid low fees
        l1.rpc.dev_setfees(15)

        l1.daemon.wait_for_log('STATUS_FAIL_PEER_BAD')

        # Restore to normal.
        l1.rpc.dev_setfees(15000)

        # Try with node which sets --ignore-fee-limits
        l3 = self.node_factory.get_node(options=['--ignore-fee-limits=true'])
        l1.rpc.connect(l3.info['id'], 'localhost', l3.info['port'])

        self.fund_channel(l1, l3, 10**6)

        # Try stupid high fees
        l1.rpc.dev_setfees(15000 * 10)

        l3.daemon.wait_for_log('peer_in WIRE_UPDATE_FEE')
        l3.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

        # We need to wait until both have committed and revoked the
        # old state, otherwise we'll still try to commit with the old
        # 15sat/byte fee
        l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

        # Now shutdown cleanly.
        l1.rpc.close(l3.info['id'])
        l1.daemon.wait_for_log('-> CLOSINGD_COMPLETE')
        l3.daemon.wait_for_log('-> CLOSINGD_COMPLETE')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_update_fee_reconnect(self):
        # Disconnect after first commitsig.
        disconnects = ['+WIRE_COMMITMENT_SIGNED']
        l1 = self.node_factory.get_node(disconnect=disconnects)
        l2 = self.node_factory.get_node()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.info['port'])

        self.fund_channel(l1, l2, 10**6)

        # Make l1 send out feechange; triggers disconnect/reconnect.
        l1.rpc.dev_setfees('14000')
        l1.daemon.wait_for_log('Setting REMOTE feerate to 14000')
        l2.daemon.wait_for_log('Setting LOCAL feerate to 14000')
        l1.daemon.wait_for_log('dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

        # Wait for reconnect....
        l1.daemon.wait_for_log('Applying feerate 14000 to LOCAL')

        self.pay(l1,l2,200000000)
        self.pay(l2,l1,100000000)

        # They should both have gotten commits with correct feerate.
        assert l1.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')
        assert l2.daemon.is_in_log('got commitsig [0-9]*: feerate 14000')

        # Now shutdown cleanly.
        l1.rpc.close(l2.info['id'])
        l1.daemon.wait_for_log('-> CLOSINGD_COMPLETE')
        l2.daemon.wait_for_log('-> CLOSINGD_COMPLETE')

        # And should put closing into mempool.
        l1.daemon.wait_for_log('sendrawtx exit 0')
        l2.daemon.wait_for_log('sendrawtx exit 0')

        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('-> ONCHAIND_MUTUAL')
        l2.daemon.wait_for_log('-> ONCHAIND_MUTUAL')

        bitcoind.generate_block(99)
        l1.daemon.wait_for_log('onchaind complete, forgetting peer')
        l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    @unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
    def test_pay_disconnect(self):
        """If the remote node has disconnected, we fail payment, but can try again when it reconnects"""
        l1,l2 = self.connect()

        chanid = self.fund_channel(l1, l2, 10**6)

        # Wait for route propagation.
        self.wait_for_routes(l1, [chanid])

        inv = l2.rpc.invoice(123000, 'test_pay_disconnect', 'description')['bolt11']

        # Make l2 upset by asking for crazy fee.
        l1.rpc.dev_setfees('150000')

        # Wait for l1 notice
        l1.daemon.wait_for_log('STATUS_FAIL_PEER_BAD')

        # Can't pay while its offline.
        self.assertRaises(ValueError, l1.rpc.pay, inv)
        l1.daemon.wait_for_log('Failing: first peer not ready: WIRE_TEMPORARY_CHANNEL_FAILURE')

        # Should fail due to temporary channel fail
        self.assertRaises(ValueError, l1.rpc.pay, inv)
        l1.daemon.wait_for_log('Failing: first peer not ready: WIRE_TEMPORARY_CHANNEL_FAILURE')
        assert not l1.daemon.is_in_log('Payment is still in progress')

        # After it sees block, someone should close channel.
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('ONCHAIND_.*_UNILATERAL')

        self.assertRaises(ValueError, l1.rpc.pay, inv)
        # Could fail with almost anything, but should fail with WIRE_PERMANENT_CHANNEL_FAILURE or unknown route.  FIXME
        #l1.daemon.wait_for_log('Could not find a route')

if __name__ == '__main__':
    unittest.main(verbosity=2)
