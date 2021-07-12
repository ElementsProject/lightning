from concurrent import futures
from fixtures import *  # noqa: F401,F403
from time import time
from tqdm import tqdm


import pytest
import random


num_workers = 480
num_payments = 10000


@pytest.fixture
def executor():
    ex = futures.ThreadPoolExecutor(max_workers=num_workers)
    yield ex
    ex.shutdown(wait=False)


def test_single_hop(node_factory, executor):
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.rpc.getinfo()['id'], 'localhost:%d' % l2.port)
    l1.openchannel(l2, 4000000)

    print("Collecting invoices")
    fs = []
    invoices = []
    for i in tqdm(range(num_payments)):
        inv = l2.rpc.invoice(1000, 'invoice-%d' % (i), 'desc')
        invoices.append((inv['payment_hash'], inv['payment_secret']))

    route = l1.rpc.getroute(l2.rpc.getinfo()['id'], 1000, 1)['route']
    print("Sending payments")
    start_time = time()

    def do_pay(i, s):
        p = l1.rpc.sendpay(route, i, payment_secret=s)
        r = l1.rpc.waitsendpay(p['payment_hash'])
        return r

    for i, s in invoices:
        fs.append(executor.submit(do_pay, i, s))

    for f in tqdm(futures.as_completed(fs), total=len(fs)):
        f.result()

    diff = time() - start_time
    print("Done. %d payments performed in %f seconds (%f payments per second)" % (num_payments, diff, num_payments / diff))


def test_single_payment(node_factory, benchmark):
    l1, l2 = node_factory.line_graph(2)

    def do_pay(l1, l2):
        invoice = l2.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        l1.rpc.pay(invoice)

    benchmark(do_pay, l1, l2)


def test_forward_payment(node_factory, benchmark):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    def do_pay(src, dest):
        invoice = dest.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        src.rpc.pay(invoice)

    benchmark(do_pay, l1, l3)


def test_long_forward_payment(node_factory, benchmark):
    nodes = node_factory.line_graph(21, wait_for_announce=True)

    def do_pay(src, dest):
        invoice = dest.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        src.rpc.pay(invoice)

    benchmark(do_pay, nodes[0], nodes[-1])


def test_invoice(node_factory, benchmark):
    l1 = node_factory.get_node()

    def bench_invoice():
        l1.rpc.invoice(1000, 'invoice-{}'.format(time()), 'desc')

    benchmark(bench_invoice)


def test_pay(node_factory, benchmark):
    l1, l2 = node_factory.line_graph(2)

    invoices = []
    for _ in range(1, 100):
        invoice = l2.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        invoices.append(invoice)

    def do_pay(l1, l2):
        l1.rpc.pay(invoices.pop())

    benchmark(do_pay, l1, l2)


def test_start(node_factory, benchmark):
    benchmark(node_factory.get_node)
