from binascii import hexlify, unhexlify
from concurrent import futures
from hashlib import sha256
from lightning import LightningRpc, LegacyLightningRpc

import logging
import os
import sys
import tempfile
import time
import unittest
import utils

bitcoind = None
TEST_DIR = tempfile.mkdtemp(prefix='lightning-')
VALGRIND = os.getenv("NOVALGRIND", None) == None

if os.getenv("TEST_DEBUG", None) != None:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)
logging.info("Tests running in '%s'", TEST_DIR)


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
            rpc = LightningRpc(socket_path, self.executor)

        node = utils.LightningNode(daemon, rpc, bitcoind, self.executor)
        self.nodes.append(node)
        if VALGRIND:
            node.daemon.cmd_line = [
                'valgrind',
                '-q',
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

    def tearDown(self):
        self.node_factory.killall()
        self.executor.shutdown(wait=False)
        # TODO(cdecker) Check that valgrind didn't find any errors


class LightningDTests(BaseLightningDTests):
    def test_connect(self):
        l1 = self.node_factory.get_node(legacy=False)
        l2 = self.node_factory.get_node(legacy=False)
        ret = l1.rpc.connect('localhost', l2.info['port'], l2.info['id'])

        assert ret['id'] == l2.info['id']

        p1 = l1.rpc.getpeer(l2.info['id'])
        p2 = l2.rpc.getpeer(l1.info['id'])

        l1.daemon.wait_for_log('WIRE_GOSSIPSTATUS_PEER_READY')
        l2.daemon.wait_for_log('WIRE_GOSSIPSTATUS_PEER_READY')

        assert p1['condition'] == 'Exchanging gossip'
        assert p2['condition'] == 'Exchanging gossip'

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

    @unittest.skip('Too damn long')
    def test_routing_gossip(self):
        nodes = [self.node_factory.get_node() for _ in range(20)]
        l1 = nodes[0]
        l5 = nodes[4]

        for i in range(len(nodes)-1):
            nodes[i].connect(nodes[i+1], 0.01)
        start_time = time.time()

        while time.time() - start_time < len(nodes) * 30:
            if sum([c['active'] for c in l1.rpc.getchannels()]) == 2*(len(nodes)-1):
                break
            time.sleep(1)
            l1.bitcoin.rpc.getinfo()

        while time.time() - start_time < len(nodes) * 30:
            if sum([c['active'] for c in l5.rpc.getchannels()]) == 2*(len(nodes)-1):
                break
            time.sleep(1)
            l1.bitcoin.rpc.getinfo()

        # Quick check that things are reasonable
        assert sum([len(l.rpc.getchannels()) for l in nodes]) == 5*2*(len(nodes) - 1)

        # Deep check that all channels are in there
        comb = []
        for i in range(len(nodes) - 1):
            comb.append((nodes[i].info['id'], nodes[i+1].info['id']))
            comb.append((nodes[i+1].info['id'], nodes[i].info['id']))

        for n in nodes:
            seen = []
            for c in n.rpc.getchannels():
                seen.append((c['from'],c['to']))
            assert set(seen) == set(comb)

if __name__ == '__main__':
    unittest.main(verbosity=2)
