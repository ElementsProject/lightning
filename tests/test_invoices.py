from fixtures import *  # noqa: F401,F403
from lightning import RpcError
from utils import only_one, DEVELOPER


import pytest
import time
import unittest


def test_invoice(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    addr1 = l2.rpc.newaddr('bech32')['address']
    addr2 = l2.rpc.newaddr('p2sh-segwit')['address']
    before = int(time.time())
    inv = l1.rpc.invoice(123000, 'label', 'description', '3700', [addr1, addr2])
    after = int(time.time())
    b11 = l1.rpc.decodepay(inv['bolt11'])
    assert b11['currency'] == 'bcrt'
    assert b11['created_at'] >= before
    assert b11['created_at'] <= after
    assert b11['payment_hash'] == inv['payment_hash']
    assert b11['description'] == 'description'
    assert b11['expiry'] == 3700
    assert b11['payee'] == l1.info['id']
    assert len(b11['fallbacks']) == 2
    assert b11['fallbacks'][0]['addr'] == addr1
    assert b11['fallbacks'][0]['type'] == 'P2WPKH'
    assert b11['fallbacks'][1]['addr'] == addr2
    assert b11['fallbacks'][1]['type'] == 'P2SH'

    # Check pay_index is null
    outputs = l1.db_query('SELECT pay_index IS NULL AS q FROM invoices WHERE label="label";')
    assert len(outputs) == 1 and outputs[0]['q'] != 0

    # Check any-amount invoice
    inv = l1.rpc.invoice("any", 'label2', 'description2')
    b11 = inv['bolt11']
    # Amount usually comes after currency (bcrt in our case),
    # but an any-amount invoices will have no amount
    assert b11.startswith("lnbcrt1")
    # By bech32 rules, the last '1' digit is the separator
    # between the human-readable and data parts. We want
    # to match the "lnbcrt1" above with the '1' digit as the
    # separator, and not for example "lnbcrt1m1....".
    assert b11.count('1') == 1


def test_invoice_weirdstring(node_factory):
    l1 = node_factory.get_node()

    weird_label = 'label \\ " \t \n'
    weird_desc = 'description \\ " \t \n'
    l1.rpc.invoice(123000, weird_label, weird_desc)
    # FIXME: invoice RPC should return label!

    # Can find by this label.
    inv = only_one(l1.rpc.listinvoices(weird_label)['invoices'])
    assert inv['label'] == weird_label

    # Can find this in list.
    inv = only_one(l1.rpc.listinvoices()['invoices'])
    assert inv['label'] == weird_label

    b11 = l1.rpc.decodepay(inv['bolt11'])
    assert b11['description'] == weird_desc

    # Can delete by weird label.
    l1.rpc.delinvoice(weird_label, "unpaid")

    # We can also use numbers as labels.
    weird_label = 25
    weird_desc = '"'
    l1.rpc.invoice(123000, weird_label, weird_desc)
    # FIXME: invoice RPC should return label!

    # Can find by this label.
    inv = only_one(l1.rpc.listinvoices(weird_label)['invoices'])
    assert inv['label'] == str(weird_label)

    # Can find this in list.
    inv = only_one(l1.rpc.listinvoices()['invoices'])
    assert inv['label'] == str(weird_label)

    b11 = l1.rpc.decodepay(inv['bolt11'])
    assert b11['description'] == weird_desc

    # Can delete by weird label.
    l1.rpc.delinvoice(weird_label, "unpaid")


def test_invoice_preimage(node_factory):
    """Test explicit invoice 'preimage'.
    """
    l1, l2 = node_factory.line_graph(2, announce=True)

    # I promise the below number is randomly generated
    invoice_preimage = "17b08f669513b7379728fc1abcea5eaf3448bc1eba55a68ca2cd1843409cdc04"

    # Make invoice and pay it
    inv = l2.rpc.invoice(msatoshi=123456, label="inv", description="?", preimage=invoice_preimage)
    payment = l1.rpc.pay(inv['bolt11'])

    # Check preimage was given.
    payment_preimage = payment['payment_preimage']
    assert invoice_preimage == payment_preimage

    # Creating a new invoice with same preimage should error.
    with pytest.raises(RpcError, match=r'preimage already used'):
        l2.rpc.invoice(123456, 'inv2', '?', preimage=invoice_preimage)


def test_invoice_expiry(node_factory, executor):
    l1, l2 = node_factory.line_graph(2, fundchannel=True)

    inv = l2.rpc.invoice(msatoshi=123000, label='test_pay', description='description', expiry=1)['bolt11']
    time.sleep(2)

    with pytest.raises(RpcError):
        l1.rpc.pay(inv)

    invoices = l2.rpc.listinvoices('test_pay')['invoices']
    assert len(invoices) == 1
    assert invoices[0]['status'] == 'expired' and invoices[0]['expires_at'] < time.time()

    # Try deleting it.
    with pytest.raises(RpcError, match=r'Invoice status is expired not unpaid'):
        l2.rpc.delinvoice('test_pay', 'unpaid')

    with pytest.raises(RpcError, match=r'Invoice status is expired not paid'):
        l2.rpc.delinvoice('test_pay', 'paid')

    l2.rpc.delinvoice('test_pay', 'expired')

    with pytest.raises(RpcError, match=r'Unknown invoice'):
        l2.rpc.delinvoice('test_pay', 'expired')

    # Test expiration waiting.
    # The second invoice created expires first.
    l2.rpc.invoice('any', 'inv1', 'description', 10)
    l2.rpc.invoice('any', 'inv2', 'description', 4)
    l2.rpc.invoice('any', 'inv3', 'description', 16)
    creation = int(time.time())

    # Check waitinvoice correctly waits
    w1 = executor.submit(l2.rpc.waitinvoice, 'inv1')
    w2 = executor.submit(l2.rpc.waitinvoice, 'inv2')
    w3 = executor.submit(l2.rpc.waitinvoice, 'inv3')
    time.sleep(2)  # total 2
    assert not w1.done()
    assert not w2.done()
    assert not w3.done()
    time.sleep(4)  # total 6
    assert not w1.done()

    with pytest.raises(RpcError):
        w2.result()
    assert not w3.done()

    time.sleep(6)  # total 12
    with pytest.raises(RpcError):
        w1.result()
    assert not w3.done()

    time.sleep(8)  # total 20
    with pytest.raises(RpcError):
        w3.result()

    # Test delexpiredinvoice
    l2.rpc.delexpiredinvoice(maxexpirytime=creation + 8)
    # only inv2 should have been deleted
    assert len(l2.rpc.listinvoices()['invoices']) == 2
    assert len(l2.rpc.listinvoices('inv2')['invoices']) == 0
    # Test delexpiredinvoice all
    l2.rpc.delexpiredinvoice()
    # all invoices are expired and should be deleted
    assert len(l2.rpc.listinvoices()['invoices']) == 0


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
def test_waitinvoice(node_factory, executor):
    """Test waiting for one invoice will not return if another invoice is paid.
    """
    # Setup
    l1, l2 = node_factory.line_graph(2)

    # Create invoices
    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
    inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')
    l2.rpc.invoice(1000, 'inv3', 'inv3')

    # Start waiting on invoice 3
    f3 = executor.submit(l2.rpc.waitinvoice, 'inv3')
    # Start waiting on invoice 1, should block
    f = executor.submit(l2.rpc.waitinvoice, 'inv1')
    time.sleep(1)
    assert not f.done()
    # Pay invoice 2
    l1.rpc.pay(inv2['bolt11'])
    # Waiter should stil be blocked
    time.sleep(1)
    assert not f.done()
    # Waiting on invoice 2 should return immediately
    r = executor.submit(l2.rpc.waitinvoice, 'inv2').result(timeout=5)
    assert r['label'] == 'inv2'
    # Pay invoice 1
    l1.rpc.pay(inv1['bolt11'])
    # Waiter for invoice 1 should now finish
    r = f.result(timeout=5)
    assert r['label'] == 'inv1'
    # Waiter for invoice 3 should still be waiting
    time.sleep(1)
    assert not f3.done()


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
def test_waitanyinvoice(node_factory, executor):
    """Test various variants of waiting for the next invoice to complete.
    """
    l1, l2 = node_factory.line_graph(2)
    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
    inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')
    inv3 = l2.rpc.invoice(1000, 'inv3', 'inv3')

    # Attempt to wait for the first invoice
    f = executor.submit(l2.rpc.waitanyinvoice)
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
    r = executor.submit(l2.rpc.waitanyinvoice, pay_index).result(timeout=5)
    assert r['label'] == 'inv2'
    pay_index = r['pay_index']

    # Now spawn the next waiter
    f = executor.submit(l2.rpc.waitanyinvoice, pay_index)
    time.sleep(1)
    assert not f.done()
    l1.rpc.pay(inv3['bolt11'])
    r = f.result(timeout=5)
    assert r['label'] == 'inv3'

    with pytest.raises(RpcError):
        l2.rpc.waitanyinvoice('non-number')


def test_waitanyinvoice_reversed(node_factory, executor):
    """Test waiting for invoices, where they are paid in reverse order
    to when they are created.
    """
    # Setup
    l1, l2 = node_factory.line_graph(2)

    # Create invoices
    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
    inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')

    # Pay inv2, wait, pay inv1, wait
    # Pay inv2
    l1.rpc.pay(inv2['bolt11'])
    # Wait - should not block, should return inv2
    r = executor.submit(l2.rpc.waitanyinvoice).result(timeout=5)
    assert r['label'] == 'inv2'
    pay_index = r['pay_index']
    # Pay inv1
    l1.rpc.pay(inv1['bolt11'])
    # Wait inv2 - should not block, should return inv1
    r = executor.submit(l2.rpc.waitanyinvoice, pay_index).result(timeout=5)
    assert r['label'] == 'inv1'


def test_autocleaninvoice(node_factory):
    l1 = node_factory.get_node()

    start_time = time.time()
    l1.rpc.autocleaninvoice(cycle_seconds=8, expired_by=2)

    l1.rpc.invoice(msatoshi=12300, label='inv1', description='description1', expiry=4)
    l1.rpc.invoice(msatoshi=12300, label='inv2', description='description2', expiry=12)

    # time 0
    # Both should still be there.
    assert len(l1.rpc.listinvoices('inv1')['invoices']) == 1
    assert len(l1.rpc.listinvoices('inv2')['invoices']) == 1

    assert l1.rpc.listinvoices('inv1')['invoices'][0]['description'] == 'description1'

    time.sleep(start_time - time.time() + 6)   # total 6
    # Both should still be there - auto clean cycle not started.
    # inv1 should be expired
    assert len(l1.rpc.listinvoices('inv1')['invoices']) == 1
    assert only_one(l1.rpc.listinvoices('inv1')['invoices'])['status'] == 'expired'
    assert len(l1.rpc.listinvoices('inv2')['invoices']) == 1
    assert only_one(l1.rpc.listinvoices('inv2')['invoices'])['status'] != 'expired'

    time.sleep(start_time - time.time() + 10)   # total 10
    # inv1 should have deleted, inv2 still there and unexpired.
    assert len(l1.rpc.listinvoices('inv1')['invoices']) == 0
    assert len(l1.rpc.listinvoices('inv2')['invoices']) == 1
    assert only_one(l1.rpc.listinvoices('inv2')['invoices'])['status'] != 'expired'

    time.sleep(start_time - time.time() + 14)   # total 14
    # inv2 should still be there, but expired
    assert len(l1.rpc.listinvoices('inv1')['invoices']) == 0
    assert len(l1.rpc.listinvoices('inv2')['invoices']) == 1
    assert only_one(l1.rpc.listinvoices('inv2')['invoices'])['status'] == 'expired'

    time.sleep(start_time - time.time() + 18)   # total 18
    # Everything deleted
    assert len(l1.rpc.listinvoices('inv1')['invoices']) == 0
    assert len(l1.rpc.listinvoices('inv2')['invoices']) == 0
