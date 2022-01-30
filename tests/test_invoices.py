from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from utils import only_one, wait_for, wait_channel_quiescent, mine_funding_to_announce


import pytest
import time
import unittest


def test_invoice(node_factory, chainparams):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    addr1 = l2.rpc.newaddr('bech32')['bech32']
    addr2 = l2.rpc.newaddr('p2sh-segwit')['p2sh-segwit']
    before = int(time.time())
    inv = l1.rpc.invoice(123000, 'label', 'description', '3700', [addr1, addr2])
    after = int(time.time())
    b11 = l1.rpc.decodepay(inv['bolt11'])
    assert b11['currency'] == chainparams['bip173_prefix']
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
    assert b11['min_final_cltv_expiry'] == 5
    # There's no incoming channel, so no routeboost
    assert 'routes' not in b11
    assert 'warning_capacity' in inv

    # Check pay_index is null
    outputs = l1.db_query('SELECT pay_index IS NULL AS q FROM invoices WHERE label="label";')
    assert len(outputs) == 1 and outputs[0]['q'] != 0

    # Check any-amount invoice
    inv = l1.rpc.invoice("any", 'label2', 'description2')
    b11 = inv['bolt11']
    # Amount usually comes after currency (bcrt in our case),
    # but an any-amount invoices will have no amount
    assert b11.startswith("ln" + chainparams['bip173_prefix'])
    # By bech32 rules, the last '1' digit is the separator
    # between the human-readable and data parts. We want
    # to match the "lnbcrt1" above with the '1' digit as the
    # separator, and not for example "lnbcrt1m1....".
    assert b11.count('1') == 1
    # There's no incoming channel, so no routeboost
    assert 'routes' not in b11
    assert 'warning_capacity' in inv

    # Test cltv option.
    inv = l1.rpc.invoice(123000, 'label3', 'description', '3700', cltv=99)
    b11 = l1.rpc.decodepay(inv['bolt11'])
    assert b11['min_final_cltv_expiry'] == 99


def test_invoice_zeroval(node_factory):
    """A zero value invoice is unpayable, did you mean 'any'?"""
    l1 = node_factory.get_node()

    with pytest.raises(RpcError, match=r"positive .*: invalid token '0'"):
        l1.rpc.invoice(0, 'inv', '?')

    with pytest.raises(RpcError, match=r"positive .*: invalid token .*0msat"):
        l1.rpc.invoice('0msat', 'inv', '?')

    with pytest.raises(RpcError, match=r"positive .*: invalid token .*0sat"):
        l1.rpc.invoice('0sat', 'inv', '?')

    with pytest.raises(RpcError, match=r"positive .*: invalid token .*0.00000000btc"):
        l1.rpc.invoice('0.00000000btc', 'inv', '?')

    with pytest.raises(RpcError, match=r"positive .*: invalid token .*0.00000000000btc"):
        l1.rpc.invoice('0.00000000000btc', 'inv', '?')


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
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

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


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
@unittest.skipIf(TEST_NETWORK != 'regtest', "Amounts too low, dominated by fees in elements")
def test_invoice_routeboost(node_factory, bitcoind):
    """Test routeboost 'r' hint in bolt11 invoice.
    """
    l0, l1, l2 = node_factory.line_graph(3, fundamount=2 * (10**5), wait_for_announce=True)

    # Check routeboost.
    # Make invoice and pay it
    inv = l2.rpc.invoice(msatoshi=123456, label="inv1", description="?")
    # Check routeboost.
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'][0]['short_channel_id']
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    # Pay it (and make sure it's fully resolved before we take l1 offline!)
    l1.rpc.pay(inv['bolt11'])
    wait_channel_quiescent(l1, l2)

    # Due to reserve & fees, l1 doesn't have capacity to pay this.
    inv = l2.rpc.invoice(msatoshi=2 * (10**8) - 123456, label="inv2", description="?")
    # Check warning
    assert 'warning_capacity' in inv
    assert 'warning_private_unused' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv

    l1.rpc.disconnect(l2.info['id'], True)
    wait_for(lambda: not only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])

    inv = l2.rpc.invoice(123456, label="inv3", description="?")
    # Check warning.
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_offline' in inv
    assert 'warning_mpp' not in inv

    # Close l0, l2 will not use l1 at all.
    l0.rpc.close(l1.info['id'])
    l0.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(100)

    # l2 has to notice channel is gone.
    wait_for(lambda: len(l2.rpc.listchannels()['channels']) == 2)
    inv = l2.rpc.invoice(123456, label="inv4", description="?")
    # Check warning.
    assert 'warning_deadends' in inv
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_mpp' not in inv


@pytest.mark.developer("gossip without DEVELOPER=1 is slow")
def test_invoice_routeboost_private(node_factory, bitcoind):
    """Test routeboost 'r' hint in bolt11 invoice for private channels
    """
    l1, l2, l3 = node_factory.get_nodes(3)
    node_factory.join_nodes([l1, l2], fundamount=16777215, announce_channels=False)

    scid = l1.get_channel_scid(l2)

    # Attach public channel to l1 so it doesn't look like a dead-end.
    l0 = node_factory.get_node()
    l0.rpc.connect(l1.info['id'], 'localhost', l1.port)
    scid_dummy, _ = l0.fundchannel(l1, 2 * (10**5))
    mine_funding_to_announce(bitcoind, [l0, l1, l2, l3])

    # Make sure channel is totally public.
    wait_for(lambda: [c['public'] for c in l2.rpc.listchannels(scid_dummy)['channels']] == [True, True])

    # Since there's only one route, it will reluctantly hint that even
    # though it's private
    inv = l2.rpc.invoice(msatoshi=123456, label="inv0", description="?")
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == l1.rpc.listchannels()['channels'][0]['short_channel_id']
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    # If we explicitly say not to, it won't expose.
    inv = l2.rpc.invoice(msatoshi=123456, label="inv1", description="?", exposeprivatechannels=False)
    assert 'warning_private_unused' in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    assert 'routes' not in l1.rpc.decodepay(inv['bolt11'])

    # If we ask for it, we get it.
    inv = l2.rpc.invoice(msatoshi=123456, label="inv1a", description="?", exposeprivatechannels=scid)
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == l1.rpc.listchannels()['channels'][0]['short_channel_id']
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    # Similarly if we ask for an array.
    inv = l2.rpc.invoice(msatoshi=123456, label="inv1b", description="?", exposeprivatechannels=[scid])
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == l1.rpc.listchannels()['channels'][0]['short_channel_id']
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    # The existence of a public channel, even without capacity, will suppress
    # the exposure of private channels.
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid2, _ = l3.fundchannel(l2, (10**5))
    mine_funding_to_announce(bitcoind, [l0, l1, l2, l3])

    # Make sure channel is totally public.
    wait_for(lambda: [c['public'] for c in l2.rpc.listchannels(scid2)['channels']] == [True, True])

    inv = l2.rpc.invoice(msatoshi=10**7, label="inv2", description="?")
    print(inv)
    assert 'warning_deadends' in inv
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_mpp' not in inv

    # Unless we tell it to include it.
    inv = l2.rpc.invoice(msatoshi=10**7, label="inv3", description="?", exposeprivatechannels=True)
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == l1.rpc.listchannels()['channels'][0]['short_channel_id']
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    inv = l2.rpc.invoice(msatoshi=10**7, label="inv4", description="?", exposeprivatechannels=scid)
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == scid
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    # Ask it explicitly to use a channel it can't (insufficient capacity)
    inv = l2.rpc.invoice(msatoshi=(10**5) * 1000 + 1, label="inv5", description="?", exposeprivatechannels=scid2)
    assert 'warning_private_unused' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_capacity' in inv
    assert 'warning_offline' not in inv
    assert 'warning_mpp' not in inv

    # Give it two options and it will pick one with suff capacity.
    inv = l2.rpc.invoice(msatoshi=(10**5) * 1000 + 1, label="inv6", description="?", exposeprivatechannels=[scid2, scid])
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == scid
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6

    # It will use an explicit exposeprivatechannels even if it thinks its a dead-end
    l0.rpc.close(l1.info['id'])
    l0.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)
    wait_for(lambda: l2.rpc.listchannels(scid_dummy)['channels'] == [])

    inv = l2.rpc.invoice(msatoshi=123456, label="inv7", description="?", exposeprivatechannels=scid)
    assert 'warning_private_unused' not in inv
    assert 'warning_capacity' not in inv
    assert 'warning_offline' not in inv
    assert 'warning_deadends' not in inv
    assert 'warning_mpp' not in inv
    # Route array has single route with single element.
    r = only_one(only_one(l1.rpc.decodepay(inv['bolt11'])['routes']))
    assert r['pubkey'] == l1.info['id']
    assert r['short_channel_id'] == l1.rpc.listchannels()['channels'][0]['short_channel_id']
    assert r['fee_base_msat'] == 1
    assert r['fee_proportional_millionths'] == 10
    assert r['cltv_expiry_delta'] == 6


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

    # Test expiry suffixes.
    start = int(time.time())
    inv = l2.rpc.invoice(msatoshi=123000, label='inv_s', description='description', expiry='1s')['bolt11']
    end = int(time.time())
    expiry = only_one(l2.rpc.listinvoices('inv_s')['invoices'])['expires_at']
    assert expiry >= start + 1 and expiry <= end + 1

    start = int(time.time())
    inv = l2.rpc.invoice(msatoshi=123000, label='inv_m', description='description', expiry='1m')['bolt11']
    end = int(time.time())
    expiry = only_one(l2.rpc.listinvoices('inv_m')['invoices'])['expires_at']
    assert expiry >= start + 60 and expiry <= end + 60

    start = int(time.time())
    inv = l2.rpc.invoice(msatoshi=123000, label='inv_h', description='description', expiry='1h')['bolt11']
    end = int(time.time())
    expiry = only_one(l2.rpc.listinvoices('inv_h')['invoices'])['expires_at']
    assert expiry >= start + 3600 and expiry <= end + 3600

    start = int(time.time())
    inv = l2.rpc.invoice(msatoshi=123000, label='inv_d', description='description', expiry='1d')['bolt11']
    end = int(time.time())
    expiry = only_one(l2.rpc.listinvoices('inv_d')['invoices'])['expires_at']
    assert expiry >= start + 24 * 3600 and expiry <= end + 24 * 3600

    start = int(time.time())
    inv = l2.rpc.invoice(msatoshi=123000, label='inv_w', description='description', expiry='1w')['bolt11']
    end = int(time.time())
    expiry = only_one(l2.rpc.listinvoices('inv_w')['invoices'])['expires_at']
    assert expiry >= start + 7 * 24 * 3600 and expiry <= end + 7 * 24 * 3600


@pytest.mark.developer("Too slow without --dev-fast-gossip")
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


@pytest.mark.developer("Too slow without --dev-fast-gossip")
def test_waitanyinvoice(node_factory, executor):
    """Test various variants of waiting for the next invoice to complete.
    """
    l1, l2 = node_factory.line_graph(2)
    inv1 = l2.rpc.invoice(1000, 'inv1', 'inv1')
    inv2 = l2.rpc.invoice(1000, 'inv2', 'inv2')
    inv3 = l2.rpc.invoice(1000, 'inv3', 'inv3')
    inv4 = l2.rpc.invoice(1000, 'inv4', 'inv4')

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
    pay_index = r['pay_index']

    # If timeout is 0 and a paid invoice is not yet
    # available, it should fail immediately.
    with pytest.raises(RpcError):
        l2.rpc.waitanyinvoice(pay_index, 0)

    # If timeout is 0 but a paid invoice is available
    # anyway, it should return successfully immediately.
    l1.rpc.pay(inv4['bolt11'])
    r = executor.submit(l2.rpc.waitanyinvoice, pay_index, 0).result(timeout=5)
    assert r['label'] == 'inv4'

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

    l1.rpc.invoice(msatoshi=12300, label='inv1', description='description1', expiry=4)
    l1.rpc.invoice(msatoshi=12300, label='inv2', description='description2', expiry=12)
    l1.rpc.autocleaninvoice(cycle_seconds=8, expired_by=2)
    start_time = time.time()

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


def test_decode_unknown(node_factory):
    l1 = node_factory.get_node()

    b11 = l1.rpc.decodepay('lntb30m1pw2f2yspp5s59w4a0kjecw3zyexm7zur8l8n4scw674w8sftjhwec33km882gsdpa2pshjmt9de6zqun9w96k2um5ypmkjargypkh2mr5d9cxzun5ypeh2ursdae8gxqruyqvzddp68gup69uhnzwfj9cejuvf3xshrwde68qcrswf0d46kcarfwpshyaplw3skw0tdw4k8g6tsv9e8gu2etcvsym36pdjpz04wm9nn96f9ntc3t3h5r08pe9d62p3js5wt5rkurqnrl7zkj2fjpvl3rmn7wwazt80letwxlm22hngu8n88g7hsp542qpl')
    assert b11['currency'] == 'tb'
    assert b11['created_at'] == 1554294928
    assert b11['payment_hash'] == '850aeaf5f69670e8889936fc2e0cff3ceb0c3b5eab8f04ae57767118db673a91'
    assert b11['description'] == 'Payment request with multipart support'
    assert b11['expiry'] == 28800
    assert b11['payee'] == '02330d13587b67a85c0a36ea001c4dba14bcd48dda8988f7303275b040bffb6abd'
    assert b11['min_final_cltv_expiry'] == 18
    extra = only_one(b11['extra'])
    assert extra['tag'] == 'v'
    assert extra['data'] == 'dp68gup69uhnzwfj9cejuvf3xshrwde68qcrswf0d46kcarfwpshyaplw3skw0tdw4k8g6tsv9e8g'
    assert b11['signature'] == '3045022100e2b2bc3204dc7416c8227d5db2ce65d24b35e22b8de8379c392b74a0c650a397022041db8304c7ff0ad25264167e23dcfce7744b3bff95b8dfda9579a38799ce8f5e'
    assert 'fallbacks' not in b11
    assert 'routes' not in b11


def test_amountless_invoice(node_factory):
    """The recipient should know how much was received by an amountless invoice.
    """
    l1, l2 = node_factory.line_graph(2)

    inv = l2.rpc.invoice('any', 'lbl', 'desc')['bolt11']
    i = l2.rpc.listinvoices()['invoices']
    assert(len(i) == 1)
    assert('msatoshi_received' not in i[0])
    assert('amount_received_msat' not in i[0])
    assert(i[0]['status'] == 'unpaid')
    details = l1.rpc.decodepay(inv)
    assert('msatoshi' not in details)

    l1.rpc.pay(inv, msatoshi=1337)

    i = l2.rpc.listinvoices()['invoices']
    assert(len(i) == 1)
    assert(i[0]['msatoshi_received'] == 1337)
    assert(i[0]['amount_received_msat'] == Millisatoshi(1337))
    assert(i[0]['status'] == 'paid')


def test_listinvoices_filter(node_factory):
    """ Test the optional query arguments to listinvoices
    """

    l1 = node_factory.get_node()

    invoices = [l1.rpc.invoice(42, 'label{}'.format(i), 'desc') for i in range(10)]

    def match(node, query, invoice):
        r1 = l1.rpc.listinvoices(**query)['invoices']
        assert len(r1) == 1
        assert r1[0]['payment_hash'] == inv['payment_hash']
        assert r1[0]['bolt11'] == inv['bolt11']

    for i, inv in enumerate(invoices):
        match(l1, {'label': "label{}".format(i)}, inv)
        match(l1, {'payment_hash': inv['payment_hash']}, inv)
        match(l1, {'invstring': inv['bolt11']}, inv)

    # Now test for failures

    inv = invoices[0]
    queries = [
        {"payment_hash": inv['payment_hash'], "label": "label0"},
        {"invstring": inv['bolt11'], "label": "label0"},
        {"payment_hash": inv['payment_hash'], "label": "label0"},
    ]

    for q in queries:
        with pytest.raises(
                RpcError,
                match=r'Can only specify one of {label}, {invstring}, {payment_hash} or {offer_id}'
        ):
            l1.rpc.listinvoices(**q)

    # Test querying for non-existent invoices
    queries = [
        {'label': 'doesnt exist'},
        {'payment_hash': 'AA' * 32},
        {'invstring': 'lnbcrt420p1p0lfrl6pp5w4zsagnfqu08s93rd44z93s8tt920hd9jec2yph969wluwkzrwpqdq8v3jhxccxqyjw5qcqp9sp52kw0kp75f6v2jusd8nsg2nfmdr82pqj0gf3jc8tqp7a2j48rzweq9qy9qsqtlu8eslmd4yxqrtrz75v8vmqrwknnk64sm79cj4asxhgndnj22r3g2a6axdvfdkhw966zw63cy3uzzn5hxad9ja8amqpp3wputl3ffcpallm2g'},
        {'offer_id': 'AA' * 32},
    ]

    for q in queries:
        r = l1.rpc.listinvoices(**q)
        assert len(r['invoices']) == 0
