from concurrent import futures
from fixtures import *  # noqa: F401,F403
from tqdm import tqdm
from utils import (wait_for, TIMEOUT)


import os
import pytest
import random
import statistics
import threading
import time


num_workers = 480
num_payments = 10000


def get_bench_node(node_factory, extra_options={}):
    """Get a node which is optimized for benchmarking"""
    options = extra_options.copy()
    # The normal log-level trace makes for a lot of IO.
    options['log-level'] = 'info'
    node = node_factory.get_node(start=False, options=options)
    # Memleak detection here creates significant overhead!
    del node.daemon.env["LIGHTNINGD_DEV_MEMLEAK"]
    # Don't bother recording all our io.
    del node.daemon.opts['dev-save-plugin-io']
    node.start()
    return node


def get_bench_line_graph(node_factory, num_nodes, wait_for_announce=False):
    nodes = [get_bench_node(node_factory) for _ in range(num_nodes)]
    node_factory.join_nodes(nodes, wait_for_announce=wait_for_announce)
    return nodes


@pytest.fixture
def executor():
    ex = futures.ThreadPoolExecutor(max_workers=num_workers)
    yield ex
    ex.shutdown(wait=False)


def test_single_hop(node_factory, executor):
    l1 = get_bench_node(node_factory)
    l2 = get_bench_node(node_factory)

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
    l1, l2 = get_bench_line_graph(node_factory, 2)

    def do_pay(l1, l2):
        invoice = l2.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        l1.rpc.pay(invoice)

    benchmark(do_pay, l1, l2)


def test_forward_payment(node_factory, benchmark):
    l1, l2, l3 = get_bench_line_graph(node_factory, 3, wait_for_announce=True)

    def do_pay(src, dest):
        invoice = dest.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        src.rpc.pay(invoice)

    benchmark(do_pay, l1, l3)


def test_long_forward_payment(node_factory, benchmark):
    nodes = get_bench_line_graph(node_factory, 21, wait_for_announce=True)

    def do_pay(src, dest):
        invoice = dest.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        src.rpc.pay(invoice)

    benchmark(do_pay, nodes[0], nodes[-1])


def test_invoice(node_factory, benchmark):
    l1 = get_bench_node(node_factory)

    def bench_invoice():
        l1.rpc.invoice(1000, 'invoice-{}'.format(time()), 'desc')

    benchmark(bench_invoice)


def test_pay(node_factory, benchmark):
    l1, l2 = get_bench_line_graph(node_factory, 2)

    invoices = []
    for _ in range(1, 100):
        invoice = l2.rpc.invoice(1000, 'invoice-{}'.format(random.random()), 'desc')['bolt11']
        invoices.append(invoice)

    def do_pay(l1, l2):
        l1.rpc.pay(invoices.pop())

    benchmark(do_pay, l1, l2)


def test_start(node_factory, benchmark):
    benchmark(node_factory.get_node)


def test_generate_coinmoves(node_factory, bitcoind, executor, benchmark):
    l1, l2, l3 = get_bench_line_graph(node_factory, 3, wait_for_announce=True)

    # Route some payments
    l1.rpc.xpay(l3.rpc.invoice(1, "test_generate_coinmoves", "test_generate_coinmoves")['bolt11'])
    # Make some payments
    l2.rpc.xpay(l3.rpc.invoice(1, "test_generate_coinmoves3", "test_generate_coinmoves3")['bolt11'])
    # Receive some payments
    l1.rpc.xpay(l2.rpc.invoice(1, "test_generate_coinmoves", "test_generate_coinmoves")['bolt11'])
    wait_for(lambda: all([c['htlcs'] == [] for c in l1.rpc.listpeerchannels()['channels']]))

    l2.stop()
    entries = l2.db.query('SELECT * FROM channel_moves ORDER BY id;')
    assert len(entries) == 4
    next_id = entries[-1]['id'] + 1
    next_timestamp = entries[-1]['timestamp'] + 1

    batch = []
    # Let's make 5 million entries.
    for _ in range(5_000_000 // len(entries)):
        # Random payment_hash
        entries[0]['payment_hash'] = entries[1]['payment_hash'] = random.randbytes(32)
        entries[2]['payment_hash'] = random.randbytes(32)
        entries[3]['payment_hash'] = random.randbytes(32)
        # Incrementing timestamps
        for e in entries:
            e['timestamp'] = next_timestamp
            next_timestamp += 1

        for e in entries:
            batch.append((
                next_id,
                e['account_channel_id'],
                e['account_nonchannel_id'],
                e['tag_bitmap'],
                e['credit_or_debit'],
                e['timestamp'],
                e['payment_hash'],
                e['payment_part_id'],
                e['payment_group_id'],
                e['fees'],
            ))
            next_id += 1

    l2.db.executemany("INSERT INTO channel_moves"
                      " (id, account_channel_id, account_nonchannel_id, tag_bitmap, credit_or_debit,"
                      "  timestamp, payment_hash, payment_part_id, payment_group_id, fees)"
                      " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      batch)
    l2.start()

    def measure_latency(node, stop_event):
        latencies = []

        while not stop_event.is_set():
            time.sleep(0.1)

            start = time.time()
            node.rpc.help()
            end = time.time()

            latencies.append(end - start)

        return latencies

    stopme = threading.Event()
    fut = executor.submit(measure_latency, l2, stopme)

    # This makes bkpr parse it all.
    benchmark(l2.rpc.bkpr_listbalances)

    stopme.set()
    latencies = fut.result(TIMEOUT)

    # FIXME: Print this somewhere!
    benchmark.extra_info = {"title": "Latency details:",
                            "min": min(latencies),
                            "median": statistics.median(latencies),
                            "max": max(latencies)}


def test_spam_commands(node_factory, bitcoind, benchmark):
    plugin = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = get_bench_node(node_factory, extra_options={"plugin": plugin})

    # This calls "batch" 1M times (which doesn't need a transaction)
    benchmark(l1.rpc.spamcommand, 1_000_000)


def test_spam_listcommands(node_factory, bitcoind, benchmark):
    plugin = os.path.join(os.getcwd(), "tests/plugins/test_libplugin")
    l1 = get_bench_node(node_factory, extra_options={"plugin": plugin})

    # This calls "listinvoice" 100,000 times (which doesn't need a transaction commit)
    benchmark(l1.rpc.spamlistcommand, 100_000)
