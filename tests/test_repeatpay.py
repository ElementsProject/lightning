import time
from fixtures import *  # noqa: F401,F403
from pyln.client import Millisatoshi, RpcError
from utils import wait_for, only_one, TIMEOUT

import pytest


def make_currency_plugin(state):
    """Return an inline-plugin setup fn whose currencyconvert reads from *state*."""
    def setup(plugin):
        @plugin.method("currencyconvert")
        def currencyconvert(plugin, amount, currency):
            rate = state["rate"]
            return {"msat": Millisatoshi(int(amount * 100_000_000_000 // rate))}
    return setup


def currency_node(node_factory, state, **extra_opts):
    """Get a single node with inline currencyconvert and cln-currencyrate disabled."""
    opts = {'disable-plugin': 'cln-currencyrate', **extra_opts}
    return node_factory.get_node(inline_plugin=make_currency_plugin(state), options=opts)


def test_repeatpay_simple(node_factory):
    """Validate bad offers are rejected, and a valid recurring offer gets paid."""
    l1, l2 = node_factory.line_graph(2)

    # Non-recurring offer is rejected.
    plain = l2.rpc.offer(amount='1msat', description='plain')['bolt12']
    with pytest.raises(RpcError, match='Offer has no recurrence'):
        l1.rpc.repeatpay(bolt12=plain, maxamount='1000msat', label='plain')

    # Offer with no fixed amount is rejected.
    anyamt = l2.rpc.call('offer', {'amount': 'any',
                                   'description': 'any amount',
                                   'recurrence': '10seconds'})['bolt12']
    with pytest.raises(RpcError, match='Offer has no amount specified'):
        l1.rpc.repeatpay(bolt12=anyamt, maxamount='1000msat', label='anyamt')

    # Valid recurring offer with recurrence_limit=1 (two payments, indices 0 and 1).
    offer = l2.rpc.call('offer', {'amount': '1msat',
                                  'description': 'recur',
                                  'recurrence': '10seconds',
                                  'recurrence_limit': 1})['bolt12']

    ret = l1.rpc.repeatpay(bolt12=offer, maxamount='1000msat', label='test_repeatpay_simple')
    assert ret['offer'] == offer
    assert ret['label'] == 'test_repeatpay_simple'
    assert ret['status'] == 'ongoing_making_payment'
    assert ret['payments_made'] == 0
    assert only_one(ret['log']).startswith("Paying #1 1msat ")

    # Duplicate label is rejected.
    with pytest.raises(RpcError, match="Duplicate label 'test_repeatpay_simple'"):
        l1.rpc.repeatpay(bolt12=offer, maxamount='1000msat', label='test_repeatpay_simple')

    # First payment arrives immediately.
    wait_for(lambda: any([i['status'] == 'paid' for i in l2.rpc.listinvoices()['invoices']]))


def test_repeatpay_pays_twice(node_factory):
    """With a 10-second recurrence and recurrence_limit=1, exactly two payments are made."""
    l1, l2 = node_factory.line_graph(2)

    # recurrence_limit=1: period indices 0 and 1 are valid, so exactly 2 payments.
    offer = l2.rpc.call('offer', {'amount': '1msat',
                                  'description': 'twice',
                                  'recurrence': '10seconds',
                                  'recurrence_limit': 1})['bolt12']

    ret = l1.rpc.repeatpay(bolt12=offer, maxamount='1000msat', label='twice')
    assert ret['status'] == 'ongoing_making_payment'

    # Second payment arrives ~10s after the first.
    wait_for(lambda: len([i for i in l2.rpc.listinvoices()['invoices']
                          if i['status'] == 'paid']) == 2,
             timeout=10 + TIMEOUT)


def test_repeatpay_currency(node_factory):
    """When both nodes agree on the rate, a currency-denominated payment succeeds.

    rate=100_000_000 → 1 USD = 100B/100M = 1000 msat.
    offer "1USD" → invoice 1000 msat; maxamount "2USD" → 2000 msat limit → OK.
    """
    state = {"rate": 100_000_000}
    l1 = currency_node(node_factory, state)
    l2 = currency_node(node_factory, state)
    node_factory.join_nodes([l1, l2])

    # recurrence_limit=1: periods 0 and 1 valid; we just need period 0 to succeed.
    offer = l2.rpc.call('offer', {'amount': '1USD',
                                  'description': 'currency',
                                  'recurrence': '10seconds',
                                  'recurrence_limit': 1})['bolt12']

    ret = l1.rpc.repeatpay(bolt12=offer, maxamount='2USD', label='currency')
    assert ret['status'] in ('ongoing', 'ongoing_making_payment')
    assert 'maxamount_currency' in ret

    # Wait for first payment: payments_made transitions from 0 to 1.
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='currency')['repeatpays'])['payments_made'] >= 1,
             timeout=TIMEOUT)
    assert len([i for i in l2.rpc.listinvoices()['invoices']
                if i['status'] == 'paid']) >= 1


def test_repeatpay_currency_budget(node_factory):
    """When l2's rate makes the invoice exceed l1's maxamount, payment fails.

    l1 rate=100_000_000 → maxamount "1USD" = 1000 msat.
    l2 rate=50_000_000  → offer "1USD" invoices for 2000 msat.
    2000 > 1000 → failing_amount.
    """
    state_l1 = {"rate": 100_000_000}
    state_l2 = {"rate": 50_000_000}
    l1 = currency_node(node_factory, state_l1)
    l2 = currency_node(node_factory, state_l2)
    node_factory.join_nodes([l1, l2])

    offer = l2.rpc.call('offer', {'amount': '1USD',
                                  'description': 'budget',
                                  'recurrence': '10seconds',
                                  'recurrence_limit': 1})['bolt12']

    ret = l1.rpc.repeatpay(bolt12=offer, maxamount='1USD', label='budget')
    assert ret['status'] == 'ongoing_failing_amount'
    assert ret['log'] == ["Invoice #1 amount 2000msat exceeds maximum 1000msat"]

    # Fails eventually.
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='budget')['repeatpays'])['status']
             == 'complete_failed',
             timeout=10 + TIMEOUT)
    assert only_one(l1.rpc.listrepeatpays(label='budget')['repeatpays'])['payments_made'] == 0
    assert not any([i['status'] == 'paid' for i in l2.rpc.listinvoices()['invoices']])


def test_recurring_currency_invoice_refresh(node_factory):
    """After currency-expiry seconds, a new invoice request gets a fresh invoice at
    the current rate; a request within that window returns the cached invoice."""
    state = {"rate": 100_000_000}
    l1 = currency_node(node_factory, state)
    # l2 hosts the offer with a 2-second currency expiry (normally 600s).
    l2 = currency_node(node_factory, state, **{'dev-currency-expiry': 2})
    node_factory.join_nodes([l1, l2])

    # Period is much longer than the currency expiry so we stay in period 0.
    offer = l2.rpc.call('offer', {'amount': '1USD',
                                  'description': 'refresh',
                                  'recurrence': '1000seconds'})['bolt12']

    # First fetch: server creates a fresh invoice (1 USD = 1000 msat).
    inv1 = l1.rpc.call('fetchinvoice', {'offer': offer,
                                        'recurrence_counter': 0,
                                        'recurrence_label': 'refresh'})['invoice']

    # Second fetch within the 2-second window: server returns the same invoice.
    inv2 = l1.rpc.call('fetchinvoice', {'offer': offer,
                                        'recurrence_counter': 0,
                                        'recurrence_label': 'refresh'})['invoice']
    assert inv1 == inv2, "Expected identical invoice within currency-expiry window"

    # Change the rate and wait for the 2-second currency expiry to lapse.
    state["rate"] = 200_000_000  # 1 USD = 500 msat now
    time.sleep(3)

    # Third fetch after expiry: server should delete the old invoice and
    # issue a fresh one at the new rate.
    inv3 = l1.rpc.call('fetchinvoice', {'offer': offer,
                                        'recurrence_counter': 0,
                                        'recurrence_label': 'refresh'})['invoice']
    assert inv3 != inv1, "Expected a fresh invoice after currency-expiry elapsed"

    dec1 = l1.rpc.decode(inv1)
    dec3 = l1.rpc.decode(inv3)
    assert dec1['invoice_amount_msat'] == 1000
    assert dec3['invoice_amount_msat'] == 500


def test_repeatpay_currency_recovery(node_factory):
    """Rates diverge initially (budget exceeded), then re-converge: payment succeeds.

    l1 rate=100_000_000 → maxamount "1USD" = 1000 msat throughout.
    l2 starts at 50_000_000  → invoice 2000 msat > 1000 msat → fails.
    l2 changes to 200_000_000 → invoice 500 msat < 1000 msat → succeeds.
    """
    state_l1 = {"rate": 100_000_000}
    state_l2 = {"rate": 50_000_000}
    l1 = currency_node(node_factory, state_l1)
    l2 = currency_node(node_factory, state_l2)
    node_factory.join_nodes([l1, l2])
    l2.rpc.setconfig('dev-currency-expiry', 10)

    # Long period so there is time to change the rate and retry within period 0.
    offer = l2.rpc.call('offer', {'amount': '1USD',
                                  'description': 'recovery',
                                  'recurrence': '30seconds'})['bolt12']

    ret = l1.rpc.repeatpay(bolt12=offer, maxamount='1USD', label='recovery')
    assert ret['status'] == 'ongoing_failing_amount'
    assert ret['log'] == ["Invoice #1 amount 2000msat exceeds maximum 1000msat"]

    # Now make l2's invoice within l1's budget; next retry will succeed.
    state_l2["rate"] = 100_000_000

    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='recovery')['repeatpays'])['status'] == 'ongoing',
             timeout=TIMEOUT + 30)
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='recovery')['repeatpays'])['payments_made'] >= 1)
    assert any([i['status'] == 'paid' for i in l2.rpc.listinvoices()['invoices']])
