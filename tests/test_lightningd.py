from binascii import hexlify, unhexlify
from concurrent import futures
from hashlib import sha256
from lightning import LightningRpc, LegacyLightningRpc

import copy
import json
import logging
import os
import sys
import tempfile
import time
import unittest
import utils

bitcoind = None
TEST_DIR = tempfile.mkdtemp(prefix='lightning-')
VALGRIND = os.getenv("NOVALGRIND", "0") == "0"
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

def sync_blockheight(*args):
    while True:
        target = bitcoind.rpc.getblockcount()
        all_up_to_date = True
        for l in args:
            if l.rpc.dev_blockheight()['blockheight'] != target:
                all_up_to_date = False

        if all_up_to_date:
            return

        # Sleep before spinning.
        time.sleep(0.1)

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


class NodeFactory(object):
    """A factory to setup and start `lightningd` daemons.
    """
    def __init__(self, func, executor):
        self.func = func
        self.next_id = 1
        self.nodes = []
        self.executor = executor

    def get_node(self, legacy=True):
        node_id = self.next_id
        self.next_id += 1

        lightning_dir = os.path.join(
            TEST_DIR, self.func._testMethodName, "lightning-{}/".format(node_id))

        socket_path = os.path.join(lightning_dir, "lightning-rpc").format(node_id)
        port = 16330+node_id
        if legacy:
            daemon = utils.LegacyLightningD(lightning_dir, bitcoind.bitcoin_dir, port=port)
            rpc = LegacyLightningRpc(socket_path, self.executor)
        else:
            daemon = utils.LightningD(lightning_dir, bitcoind.bitcoin_dir, port=port)
            # TODO(cdecker) Move into LIGHTNINGD_CONFIG once legacy daemon was removed
            daemon.cmd_line.append("--dev-broadcast-interval=1000")
            rpc = LightningRpc(socket_path, self.executor)

        node = utils.LightningNode(daemon, rpc, bitcoind, self.executor)
        self.nodes.append(node)
        if VALGRIND:
            node.daemon.cmd_line = [
                'valgrind',
                '-q',
                '--trace-children=yes',
                '--trace-children-skip=*bitcoin-cli*',
                '--error-exitcode=7',
                '--log-file={}/valgrind-errors'.format(node.daemon.lightning_dir)
            ] + node.daemon.cmd_line

        node.daemon.start()
        # Cache `getinfo`, we'll be using it a lot
        node.info = node.rpc.getinfo()
        return node

    def killall(self):
        for n in self.nodes:
            n.daemon.stop()


class BaseLightningDTests(unittest.TestCase):
    def setUp(self):
        # Most of the executor threads will be waiting for IO, so
        # let's have a few of them
        self.executor = futures.ThreadPoolExecutor(max_workers=20)
        self.node_factory = NodeFactory(self, self.executor)

    def getValgrindErrors(self, node):
        error_file = '{}valgrind-errors'.format(node.daemon.lightning_dir)
        with open(error_file, 'r') as f:
            errors = f.read().strip()
        return errors, error_file

    def printValgrindErrors(self, node):
        errors, fname = self.getValgrindErrors(node)
        if errors:
            print("-"*31, "Valgrind errors", "-"*32)
            print("Valgrind error file:", fname)
            print(errors)
            print("-"*80)
        return 1 if errors else 0

    def tearDown(self):
        self.node_factory.killall()
        self.executor.shutdown(wait=False)

        # Do not check for valgrind error files if it is disabled
        if VALGRIND:
            err_count = 0
            for node in self.node_factory.nodes:
                err_count += self.printValgrindErrors(node)
            if err_count:
                raise ValueError(
                    "{} nodes reported valgrind errors".format(err_count))

class LightningDTests(BaseLightningDTests):
    def connect(self):
        l1 = self.node_factory.get_node(legacy=False)
        l2 = self.node_factory.get_node(legacy=False)
        ret = l1.rpc.connect('localhost', l2.info['port'], l2.info['id'])

        assert ret['id'] == l2.info['id']

        l1.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        l2.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        return l1,l2

    def fund_channel(self,l1,l2,amount):
        addr = l1.rpc.newaddr()['address']

        txid = l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)
        tx = l1.bitcoin.rpc.getrawtransaction(txid)

        l1.rpc.addfunds(tx)
        l1.rpc.fundchannel(l2.info['id'], amount)
        # Technically, this is async to fundchannel.
        l1.daemon.wait_for_log('sendrawtx exit 0')

        l1.bitcoin.rpc.generate(6)

        l1.daemon.wait_for_log('-> NORMAL')
        l2.daemon.wait_for_log('-> NORMAL')

    def test_connect(self):
        l1,l2 = self.connect()

        p1 = l1.rpc.getpeer(l2.info['id'], 'info')
        p2 = l2.rpc.getpeer(l1.info['id'], 'info')

        assert p1['state'] == 'GOSSIPING'
        assert p2['state'] == 'GOSSIPING'

        # It should have gone through these steps
        assert 'state: INITIALIZING -> GOSSIPING' in p1['log']

        # Both should still be owned by gossip
        assert p1['owner'] == 'lightningd_gossip'
        assert p2['owner'] == 'lightningd_gossip'

    def test_htlc(self):
        l1,l2 = self.connect()

        self.fund_channel(l1, l2, 10**6)
        l1.daemon.wait_for_log('-> NORMAL')
        l2.daemon.wait_for_log('-> NORMAL')

        secret = '1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd'
        rhash = l1.rpc.dev_rhash(secret)['rhash']

        # This is actually dust, and uncalled for.
        l1.rpc.dev_newhtlc(l2.info['id'], 100000, l1.bitcoin.rpc.getblockcount() + 10, rhash)
        l1.daemon.wait_for_log('Sending commit_sig with 0 htlc sigs')
        l2.daemon.wait_for_log('their htlc 0 locked')
        l2.daemon.wait_for_log('failed htlc 0 code 0x400f')
        l1.daemon.wait_for_log('htlc 0 failed with code 0x400f')

        # Set up invoice (non-dust, just to test), and pay it.
        # This one isn't dust.
        rhash = l2.rpc.invoice(100000000, 'testpayment1')['rhash']
        assert l2.rpc.listinvoice('testpayment1')[0]['complete'] == False

        l1.rpc.dev_newhtlc(l2.info['id'], 100000000, l1.bitcoin.rpc.getblockcount() + 10, rhash)
        l1.daemon.wait_for_log('Sending commit_sig with 1 htlc sigs')
        l2.daemon.wait_for_log('their htlc 1 locked')
        l2.daemon.wait_for_log("Resolving invoice 'testpayment1' with HTLC 1")
        assert l2.rpc.listinvoice('testpayment1')[0]['complete'] == True
        l1.daemon.wait_for_log('Payment succeeded on HTLC 1')

        # Balances should have changed.
        p1 = l1.rpc.getpeer(l2.info['id'])
        p2 = l2.rpc.getpeer(l1.info['id'])
        assert p1['msatoshi_to_us'] == 900000000
        assert p1['msatoshi_to_them'] == 100000000
        assert p2['msatoshi_to_us'] == 100000000
        assert p2['msatoshi_to_them'] == 900000000

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

        # This works.
        l1.rpc.sendpay(to_json([routestep]), rhash)
        assert l2.rpc.listinvoice('testpayment2')[0]['complete'] == True
        
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

        # FIXME: test paying via another node, should fail to pay twice.

    def test_gossip_jsonrpc(self):
        l1,l2 = self.connect()

        self.fund_channel(l1,l2,10**5)

        l1.daemon.wait_for_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')
        l1.daemon.wait_for_log('peer_in WIRE_ANNOUNCEMENT_SIGNATURES')

        l1.daemon.wait_for_log('peer_out WIRE_CHANNEL_ANNOUNCEMENT')
        l1.daemon.wait_for_log('peer_in WIRE_CHANNEL_ANNOUNCEMENT')

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

    def test_routing_gossip(self):
        nodes = [self.node_factory.get_node(legacy=False) for _ in range(5)]
        l1 = nodes[0]
        l5 = nodes[4]

        for i in range(len(nodes)-1):
            src, dst = nodes[i], nodes[i+1]
            src.rpc.connect('localhost', dst.info['port'], dst.info['id'])
            src.openchannel(dst, 20000)

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
        l3 = self.node_factory.get_node(legacy=False)
        ret = l2.rpc.connect('localhost', l3.info['port'], l3.info['id'])

        assert ret['id'] == l3.info['id']

        l3.daemon.wait_for_log('WIRE_GOSSIPCTL_NEW_PEER')
        self.fund_channel(l1, l2, 10**6)
        self.fund_channel(l2, l3, 10**6)

        # If they're at different block heights we can get spurious errors.
        sync_blockheight(l1, l2, l3)

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
                        'delay' : 10,
                        'channel' : chanid1 },
                      { 'msatoshi' : amt,
                        'id' : l3.info['id'],
                        'delay' : 5,
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

class LegacyLightningDTests(BaseLightningDTests):

    def test_connect(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        l1.connect(l2, 0.01, async=False)

    def test_successful_payment(self):
        l1 = self.node_factory.get_node()
        l2 = self.node_factory.get_node()
        bitcoind = l1.bitcoin

        capacity = 0.01 * 10**8 * 10**3
        htlc_amount = 10000
        l1.connect(l2, 0.01)

        invoice = l2.rpc.invoice(htlc_amount, "successful_payment")

        # TODO(cdecker) Assert that we have an invoice
        rhash = invoice['rhash']
        assert len(rhash) == 64

        route = l1.rpc.getroute(l2.info['id'], htlc_amount, 1)
        assert len(route) == 1
        assert route[0] == {'msatoshi': htlc_amount, 'id': l2.info['id'], 'delay': 6}

        receipt = l1.rpc.sendpay(route, invoice['rhash'])
        assert sha256(unhexlify(receipt['preimage'])).hexdigest() == rhash

        # Now go for the combined RPC call
        invoice = l2.rpc.invoice(100, "one_shot_payment")
        l1.rpc.pay(l2.info['id'], 100, invoice['rhash'])

    def test_multihop_payment(self):
        nodes = [self.node_factory.get_node() for _ in range(5)]
        conn_futures = [nodes[i].connect(nodes[i+1], 0.01, async=True) for i in range(len(nodes)-1)]
        
        htlc_amount = 10000

        # Now wait for all of them
        [f.result() for f in conn_futures]

        time.sleep(1)
        
        # Manually add channel l2 -> l3 to l1 so that it can compute the route
        for i in range(len(nodes)-1):
            nodes[0].rpc.dev_add_route(nodes[i].info['id'], nodes[i+1].info['id'], 1, 1, 6, 6)
        #l1.rpc.dev_add_route(l2.info['id'], l3.info['id'], 1, 1, 6, 6)

        invoice = nodes[-1].rpc.invoice(htlc_amount, "multihop_payment")
        route = nodes[0].rpc.getroute(nodes[-1].info['id'], htlc_amount, 1)
        receipt = nodes[0].rpc.sendpay(route, invoice['rhash'])

        nodes[-1].daemon.wait_for_log("STATE_NORMAL_COMMITTING => STATE_NORMAL")
        nodes[0].daemon.wait_for_log("STATE_NORMAL_COMMITTING => STATE_NORMAL")


if __name__ == '__main__':
    unittest.main(verbosity=2)
