import os
import time
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import Millisatoshi, RpcError
from utils import wait_for, only_one, TIMEOUT

import pytest


HOLD_INVOICE_PLUGIN = os.path.join(os.path.dirname(__file__), 'plugins', 'hold_invoice.py')
HOLD_HTLCS_PLUGIN = os.path.join(os.path.dirname(__file__), 'plugins', 'hold_htlcs.py')


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


def test_repeatpay_amend(node_factory):
    """amendrepeatpay raises a too-low limit and allows a blocked payment through.

    offer=100msat; start with maxamount=50msat → ongoing_failing_amount immediately.
    Amend to 200msat → payment succeeds.  Also covers error cases.
    """
    l1, l2 = node_factory.line_graph(2)

    offer = l2.rpc.call('offer', {'amount': '100msat',
                                  'description': 'amend',
                                  'recurrence': '10seconds',
                                  'recurrence_limit': 1})['bolt12']

    l1.rpc.repeatpay(bolt12=offer, maxamount='50msat', label='amend')

    # Should immediately hit failing_amount (invoice=100 > max=50).
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='amend')['repeatpays'])['status']
             == 'ongoing_failing_amount', timeout=TIMEOUT)

    # Unknown label is rejected.
    with pytest.raises(RpcError, match='Unknown label'):
        l1.rpc.amendrepeatpay(label='no-such', maxamount='1000msat')

    # Raise the limit; next retry should pay successfully.
    ret = l1.rpc.amendrepeatpay(label='amend', maxamount='200msat')
    assert ret['maxamount_msat'] == 200
    assert ret['label'] == 'amend'

    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='amend')['repeatpays'])['payments_made'] >= 1,
             timeout=TIMEOUT)

    # Wait for the offer limit to be reached (finished) then verify amend is rejected.
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='amend')['repeatpays'])['status']
             == 'complete_finished', timeout=10 + TIMEOUT)
    with pytest.raises(RpcError, match='Payment already finished'):
        l1.rpc.amendrepeatpay(label='amend', maxamount='9000msat')


def test_repeatpay_cancel(node_factory):
    """cancelrepeatpay marks a payment cancel_pending then transitions to cancelled.

    Also verifies the cancel_reason field appears in listrepeatpays and that
    cancelling a finished/already-cancelling payment is rejected.
    """
    l1, l2 = node_factory.line_graph(2)

    offer = l2.rpc.call('offer', {'amount': '1msat',
                                  'description': 'cancel',
                                  'recurrence': '10seconds'})['bolt12']

    l1.rpc.repeatpay(bolt12=offer, maxamount='1000msat', label='cancel')

    # Wait for period 2 to complete; cancel before the period-1 timer fires.
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='cancel')['repeatpays'])['payments_made'] == 2)

    ret = l1.rpc.cancelrepeatpay(label='cancel', reason='test done')
    assert ret['status'] == 'complete_cancel_pending'
    assert ret['cancel_reason'] == 'test done'

    # A second cancel is rejected while cancel is pending.
    with pytest.raises(RpcError, match='already being cancelled'):
        l1.rpc.cancelrepeatpay(label='cancel')

    # The period-1 timer fires (≤10 s), cancel message is sent, status → cancelled.
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='cancel')['repeatpays'])['status']
             == 'complete_cancelled', timeout=10 + TIMEOUT)

    # No further payments after cancel.
    final = only_one(l1.rpc.listrepeatpays(label='cancel')['repeatpays'])
    assert final['payments_made'] == 2

    # Cancelling a terminated payment is rejected.
    with pytest.raises(RpcError, match='Payment already finished'):
        l1.rpc.cancelrepeatpay(label='cancel')

    # Unknown label.
    with pytest.raises(RpcError, match='Unknown label'):
        l1.rpc.cancelrepeatpay(label='no-such')


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


def test_repeatpay_persistence(node_factory):
    """Verify that repeatpay state survives a node restart and payments continue."""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})

    # 30-second recurrence so period 0 completes long before period 1 triggers,
    # giving a clean restart window between the two payments.
    offer = l2.rpc.call('offer', {'amount': '1msat',
                                  'description': 'persist',
                                  'recurrence': '30seconds',
                                  'recurrence_limit': 4})['bolt12']

    l1.rpc.repeatpay(bolt12=offer, maxamount='1000msat', label='persist')

    # Wait for at least one payment AND status=ongoing (timer running, no payment
    # in-flight).  Restarting during making_payment would replay the in-flight
    # period after reload (the FIXME double-pay case).
    def ready_to_restart():
        r = only_one(l1.rpc.listrepeatpays(label='persist')['repeatpays'])
        return r['payments_made'] >= 1 and r['status'] == 'ongoing'
    wait_for(ready_to_restart, timeout=TIMEOUT)

    before = only_one(l1.rpc.listrepeatpays(label='persist')['repeatpays'])
    l1.restart()
    # Reconnect so onion-message-based fetchinvoice can reach the offer node.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # After restart the entry must be present with stable fields intact.
    after = only_one(l1.rpc.listrepeatpays(label='persist')['repeatpays'])
    assert after['offer'] == before['offer']
    assert after['label'] == before['label']
    assert after['maxamount_msat'] == before['maxamount_msat']
    assert after['payments_made'] >= before['payments_made']

    # Payments must continue: wait for at least one more payment beyond pre-restart count.
    wait_for(lambda: only_one(l1.rpc.listrepeatpays(label='persist')['repeatpays'])['payments_made']
             > before['payments_made'],
             timeout=30 + TIMEOUT)


def test_repeatpay_restart_making_payment(node_factory):
    """Restart while status is making_payment; no double-pay and recovery."""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})

    # Long period keeps the deadline ahead so a retry after restart still
    # lands inside the window.  recurrence_limit=1 gives two valid periods.
    offer = l2.rpc.call('offer', {'amount': '1msat',
                                  'description': 'mid-pay',
                                  'recurrence': '30seconds',
                                  'recurrence_limit': 1})['bolt12']

    l1.rpc.repeatpay(bolt12=offer, maxamount='1000msat', label='mid-pay')

    # Wait for the plugin to log the transition into making_payment for period 0.
    l1.daemon.wait_for_log(r'plugin-cln-repeatpay: payment mid-pay #1: status.*->ongoing_making_payment')

    # Restart while the payment is in-flight or has just completed.
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Entry must survive with stable fields intact.
    r = only_one(l1.rpc.listrepeatpays(label='mid-pay')['repeatpays'])
    assert r['offer'] == offer
    assert r['label'] == 'mid-pay'

    # Wait until l1's counter and l2's paid-invoice count are both >=1 and
    # equal each other: this is the no-double-pay / no-phantom-credit invariant.
    def consistent_and_nonzero():
        rr = only_one(l1.rpc.listrepeatpays(label='mid-pay')['repeatpays'])
        paid = len([i for i in l2.rpc.listinvoices()['invoices']
                    if i['status'] == 'paid'])
        return rr['payments_made'] >= 1 and paid == rr['payments_made']
    wait_for(consistent_and_nonzero)


def test_repeatpay_restart_payment_pending_success(node_factory):
    """Payment HTLC held in-flight during restart; an unrelated payment exercises
    the wrong-hash re-arm in pending_wait_done; releasing the hold results in
    the payment being counted exactly once (no double-pay)."""
    # l3 holds every incoming invoice payment until 'unhold' file appears.
    l1, l2, l3 = node_factory.line_graph(
        3,
        wait_for_announce=True,
        opts=[{'may_reconnect': True},
              {'may_reconnect': True},
              {'may_reconnect': True, 'plugin': HOLD_INVOICE_PLUGIN}],
    )

    # Long period so the deadline is safely ahead of the test duration.
    offer = l3.rpc.call('offer', {'amount': '1msat',
                                  'description': 'holdpay',
                                  'recurrence': '120seconds',
                                  'recurrence_limit': 1})['bolt12']

    l1.rpc.repeatpay(bolt12=offer, maxamount='10msat', label='holdpay')

    # Wait until making_payment is logged and the HTLC has reached l3.
    l1.daemon.wait_for_log(r'plugin-cln-repeatpay: payment holdpay #1: status.*->ongoing_making_payment')
    wait_for(lambda: len(l3.rpc.listpeerchannels()['channels'][0]['htlcs']) > 0)

    # Restart l1 while the payment is pending.
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Pay l2's own invoice directly (l1→l2 only, not through l3).  When this
    # completes it fires sendpays/updated with a *different* payment_hash,
    # exercising the wrong-hash re-arm path in pending_wait_done before our
    # real payment resolves.
    l1.rpc.xpay(l2.rpc.invoice(1000, 'other', 'other')['bolt11'])

    # Release the hold; l3 settles the HTLC and our payment becomes complete.
    open(os.path.join(l3.daemon.lightning_dir, TEST_NETWORK, 'unhold'), 'w').close()

    # The wait subscription should now fire with the correct hash, call
    # pending_listpays_done, and increment the counter.
    # Note that l1 will immediately pay second invoice!
    wait_for(
        lambda: only_one(l1.rpc.listrepeatpays(label='holdpay')['repeatpays'])['payments_made'] == 2,
        timeout=TIMEOUT,
    )

    # No double-pay: paid invoices on l3 must equal what l1 has counted.
    r = only_one(l1.rpc.listrepeatpays(label='holdpay')['repeatpays'])
    paid = len([i for i in l3.rpc.listinvoices()['invoices'] if i['status'] == 'paid'])
    assert paid == r['payments_made']


def test_repeatpay_restart_payment_pending_failure(node_factory):
    """Payment HTLC held in-flight during restart; an unrelated payment exercises
    the wrong-hash re-arm; when the hold expires l3 rejects the HTLC;
    plugin records offline failure and payments_made stays zero."""
    # l3 holds every HTLC for 20 s then rejects it.
    l1, l2, l3 = node_factory.line_graph(
        3,
        wait_for_announce=True,
        opts=[{'may_reconnect': True},
              {'may_reconnect': True},
              {'may_reconnect': True,
               'plugin': HOLD_HTLCS_PLUGIN,
               'hold-time': 20,
               'hold-result': 'fail'}],
    )

    # Long period so the payment deadline is not hit during the test.
    offer = l3.rpc.call('offer', {'amount': '1msat',
                                  'description': 'failpay',
                                  'recurrence': '600seconds',
                                  'recurrence_limit': 1})['bolt12']

    l1.rpc.repeatpay(bolt12=offer, maxamount='10msat', label='failpay')

    # Wait until making_payment is logged and the HTLC has reached l3.
    l1.daemon.wait_for_log(r'plugin-cln-repeatpay: payment failpay #1: status.*->ongoing_making_payment')
    wait_for(lambda: len(l3.rpc.listpeerchannels()['channels'][0]['htlcs']) > 0)

    # Restart l1 while the HTLC is still being held (not yet failed).
    l1.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Unrelated l1→l2 payment fires sendpays/updated with a different hash,
    # exercising the wrong-hash re-arm path before the failure arrives.
    l1.rpc.xpay(l2.rpc.invoice(1000, 'other', 'other')['bolt11'])

    # After 20 s the hold expires and l3 rejects the HTLC.  The wait
    # subscription fires; pending_listpays_done sees "failed" and calls
    # payment_offline_failure, logging the status transition.
    l1.daemon.wait_for_log(
        r'plugin-cln-repeatpay: payment failpay.*->ongoing_failing_payment.*restarting',
        timeout=25 + TIMEOUT,
    )

    # payment_offline_failure must not have credited any payment.
    assert only_one(l1.rpc.listrepeatpays(label='failpay')['repeatpays'])['payments_made'] == 0
    assert len([i for i in l3.rpc.listinvoices()['invoices'] if i['status'] == 'paid']) == 0


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
