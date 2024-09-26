#! /usr/bin/env python3
# Script to create huge numbers of forwards/payments/etc for regtest nodes.

# To initialize, use contrib/startup_regtest.sh:
#  $ . contrib/startup_regtest.sh
#  $ start_ln 3
#  $ fund_nodes

import argparse
import random
import string
import sys
import time
import multiprocessing
from pyln.client import LightningRpc, RpcError

parser = argparse.ArgumentParser(
    description='Flood three funded startup_regtest nodes'
)
parser.add_argument('--fail-forward', action="store_true",
                    help='Create failed forward attempts',
                    default=False)
parser.add_argument('--fail-pay', action="store_true",
                    help='Allow some failed pay attempts (faster!)',
                    default=False)
parser.add_argument('--inv-runners', type=int,
                    help='How many invoice-generation processes to run at once',
                    default=1)
parser.add_argument('--pay-runners', type=int,
                    help='How many invoice-paying processes to run at once',
                    default=8)
parser.add_argument('--check-runners', type=int,
                    help='How many pay-checking processes to run at once',
                    default=1)
parser.add_argument('--allow-bookkeeper', action="store_true",
                    help="Don't stop if bookkeeper is running",
                    default=False)
parser.add_argument('num', type=int, nargs='?',
                    help='number to attempt',
                    default=1000000)

args = parser.parse_args()

nodes = (LightningRpc('/tmp/l1/regtest/lightning-rpc'),
         LightningRpc('/tmp/l2/regtest/lightning-rpc'),
         LightningRpc('/tmp/l3/regtest/lightning-rpc'))

# Convenient aliases
l1 = nodes[0]
l2 = nodes[1]
l3 = nodes[2]

if not args.allow_bookkeeper:
    if any([p['name'].endswith('bookkeeper') for p in l1.plugin_list()['plugins']]):
        print("""
Bookkeeper is running on l1, will slow things down!  Run this:

echo 'disable-plugin=bookkeeper' >> /tmp/l1/regtest/config
echo 'disable-plugin=bookkeeper' >> /tmp/l2/regtest/config
echo 'disable-plugin=bookkeeper' >> /tmp/l3/regtest/config
stop_ln
start_ln 3
""")
        sys.exit(1)

route = l1.getroute(l3.getinfo()['id'], 1, 1)['route']
if args.fail_forward:
    route[1]['channel'] = '1x1x1'


def get_invs(inv_q, num, report_q):
    """Runners feed invoices into the queue"""
    prefix = ''.join(random.choice(string.ascii_lowercase) for _ in range(10))
    for i in range(num):
        inv_q.put(l3.invoice(amount_msat=1,
                             label='{}-{}'.format(prefix, i),
                             description='giantnode'))
        report_q.put('i')


def send_pay(inv_q, num, done_q, report_q):
    """Runner to fetch invoices from queue and send"""
    for i in range(num):
        inv = inv_q.get()
        l1.sendpay(route,
                   inv['payment_hash'],
                   payment_secret=inv['payment_secret'])
        report_q.put('p')
        done_q.put(inv)


def checker(num, inv_q, done_q, report_q):
    """Runner which checks that invs didn't fail (TOO_MANY_HTLCS!), and requeues if they did!"""
    for i in range(num):
        inv = done_q.get()
        try:
            res = l1.waitsendpay(inv['payment_hash'])
        except RpcError:
            report_q.put('f')
            if not args.fail_pay and not args.fail_forward:
                inv_q.put(inv)
            continue
        assert res['status'] == 'complete'
        report_q.put('w')


inv_q = multiprocessing.Queue()
done_q = multiprocessing.Queue()
report_q = multiprocessing.Queue()

# In case it doesn't divide
extra_prod = (args.num % args.inv_runners,) + (0,) * (args.inv_runners - 1)
inv_producers = [multiprocessing.Process(target=get_invs, args=(inv_q, args.num // args.inv_runners + extra_prod[i], report_q)) for i in range(args.inv_runners)]
extra_cons = (args.num % args.pay_runners,) + (0,) * (args.pay_runners - 1)
inv_consumers = [multiprocessing.Process(target=send_pay, args=(inv_q, args.num // args.pay_runners + extra_cons[i], done_q, report_q)) for i in range(args.pay_runners)]

extra_checks = (args.num % args.check_runners,) + (0,) * (args.check_runners - 1)
checkers = [multiprocessing.Process(target=checker, args=(args.num // args.check_runners + extra_checks[i], inv_q, done_q, report_q)) for i in range(args.check_runners)]

prev = start = time.time()
for i in inv_producers + inv_consumers + checkers:
    i.start()

num_total = 0
num_successes = 0
num_invs = 0
num_pays = 0
num_retries = 0
prev_total = 0


def timefmt(number, time):
    if time == 0:
        return '?'
    seconds = number / time
    minutes = seconds / 60
    hours = minutes / 60
    if hours > 2:
        return '{} hours'.format(int(hours))
    if minutes > 2:
        return '{} minutes'.format(int(minutes))

    return '{} seconds'.format(int(seconds))


while num_total < args.num:
    letter = report_q.get()
    if letter == 'i':
        num_invs += 1
    elif letter == 'p':
        num_pays += 1
    elif letter == 'f':
        num_retries += 1
    elif letter == 'w':
        num_successes += 1
    else:
        assert False

    if args.fail_pay or args.fail_forward:
        num_total = num_pays
    else:
        num_total = num_successes

    now = time.time()
    if now > prev + 10:
        current_rate = (num_total - prev_total) / (now - prev)
        prev = now
        prev_total = num_total
        total_rate = num_total / (now - start)
        print("{}/{} complete {}/sec ({} invs, {} pays, {} retries) in {} seconds. {}-{} remaining."
              .format(num_total, args.num, format(current_rate, ".2f"),
                      num_invs, num_pays, num_retries, int(now - start),
                      timefmt(args.num - num_total, total_rate),
                      timefmt(args.num - num_total, current_rate)))

for i in inv_producers + inv_consumers + checkers:
    i.join()

print("done")
