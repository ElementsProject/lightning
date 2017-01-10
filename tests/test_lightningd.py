from binascii import hexlify, unhexlify
from hashlib import sha256
from utils import BitcoinD, LightningD, LightningRpc, LightningNode
from concurrent import futures

import logging
import os
import pytest
import sys
import tempfile
import time

TEST_DIR = tempfile.mkdtemp(prefix='lightning-')
VALGRIND = os.getenv("NOVALGRIND", None) == None

if os.getenv("TEST_DEBUG", None) != None:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

@pytest.fixture(scope="module")
def bitcoind():
    bitcoind = BitcoinD(rpcport=28332)
    bitcoind.start()

    info = bitcoind.rpc.getinfo()

    # Make sure we have segwit and some funds
    if info['blocks'] < 432:
        logging.debug("SegWit not active, generating some more blocks")
        bitcoind.rpc.generate(432 - info['blocks'])
    elif info['balance'] < 1:
        logging.debug("Insufficient balance, generating 1 block")
        bitcoind.rpc.generate(1)

    yield bitcoind
    try:
        bitcoind.rpc.stop()
    except:
        bitcoind.proc.kill()
    bitcoind.proc.wait()

def create_node(func_name, bitcoind, node_id):
    lightning_dir = os.path.join(TEST_DIR, func_name, "lightning-{}/".format(node_id))

    l = LightningNode(
        LightningD(lightning_dir, bitcoind.bitcoin_dir, port=16330+node_id),
        LightningRpc(os.path.join(lightning_dir, "lightning-rpc").format(node_id)),
        bitcoind,
    )
    if VALGRIND:
        l.daemon.cmd_line = [
            '/usr/bin/valgrind',
            '-q',
            '--error-exitcode=7',
            '--log-file={}/valgrind-errors'.format(l.daemon.lightning_dir)
        ] + l.daemon.cmd_line

    l.daemon.start()
    l.rpc.connect_rpc()
    # Cache `getinfo`, we'll be using it a lot
    l.info = l.rpc.getinfo()
    return l


@pytest.fixture(scope="function")
def l1(request, bitcoind):
    l = create_node(request.function.__name__, bitcoind, 1)
    yield l
    l.daemon.stop()


@pytest.fixture(scope="function")
def l2(request, bitcoind):
    l = create_node(request.function.__name__, bitcoind, 2)
    yield l
    l.daemon.stop()


@pytest.fixture(scope="function")
def l3(request, bitcoind):
    l = create_node(request.function.__name__, bitcoind, 3)
    yield l
    l.daemon.stop()

@pytest.fixture(scope="function")
def l4(request, bitcoind):
    l = create_node(request.function.__name__, bitcoind, 4)
    yield l
    l.daemon.stop()

@pytest.fixture(scope="function")
def l5(request, bitcoind):
    l = create_node(request.function.__name__, bitcoind, 5)
    yield l
    l.daemon.stop()

@pytest.fixture(scope="function")
def executor():
    ex = futures.ThreadPoolExecutor(max_workers=5)
    yield ex
    ex.shutdown(wait=False)
    
def test_connect(bitcoind, l1, l2):
    l1.connect(l2, 0.01)

def test_successful_payment(bitcoind, l1, l2):
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


def test_multihop_payment(bitcoind, l1, l2, l3):
    htlc_amount = 10000
    l1.connect(l2, 0.01)
    l2.connect(l3, 0.01)

    # Manually add channel l2 -> l3 to l1 so that it can compute the route
    l1.rpc.dev_add_route(l2.info['id'], l3.info['id'], 1, 1, 6, 6)

    invoice = l3.rpc.invoice(htlc_amount, "multihop_payment")
    route = l1.rpc.getroute(l3.info['id'], htlc_amount, 1)
    receipt = l1.rpc.sendpay(route, invoice['rhash'])

    l3.daemon.wait_for_log("STATE_NORMAL_COMMITTING => STATE_NORMAL")
    l1.daemon.wait_for_log("STATE_NORMAL_COMMITTING => STATE_NORMAL")

def test_routing_gossip(l1, l2, l3, l4, l5):
    nodes = [l1,l2,l3,l4,l5]
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

def test_awaitpayment(bitcoind, executor, l1, l2):
    l1.connect(l2, 0.01)

    label = "awaitpayment-test"
    amount = 1000

    try:
        l2.rpc.awaitpayment(label)
        pytest.fail("`awaitpayment` succeeds on unknown invoice.")
    except ValueError as ve:
        # This is expected, the label does not exist
        pass
    
    invoice = l2.rpc.invoice(amount, label)
    
    try:
        f = executor.submit(l2.rpc.awaitpayment, label)
        f.result(timeout=1)
    except ValueError as exc:
        # Should not happen, we registered the invoice...
        pytest.fail("Failing `awaitpayment` despite previous `invoice` call.")
    except Exception as exc:
        # This is ok, it's just the timeout triggering
        pass
    else:
        pytest.fail("`awaitpayment` succeeded despite not paying the invoice.")

    route = l1.rpc.getroute(l2.info['id'], amount, 1)
    receipt = l1.rpc.sendpay(route, invoice['rhash'])

    # Now the future should return
    payment = f.result(timeout=1)
    assert payment['rhash'] == invoice['rhash']
    assert payment['msatoshi'] == amount

    # And checking again should return immediately
    payment2 = executor.submit(l2.rpc.awaitpayment, label).result(timeout=1)
    assert payment == payment2
