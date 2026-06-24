from fixtures import *  # noqa: F401,F403
import pytest
import unittest
import time
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND
from utils import (
    TEST_NETWORK
)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_disconnect_sig(node_factory, bitcoind):
    # Dual open and splicing both use tx_sig messages. If we have dual enabled, ignore the first one.
    disconnect = ['-WIRE_TX_SIGNATURES']
    if EXPERIMENTAL_DUAL_FUND:
        disconnect = ['=WIRE_TX_SIGNATURES'] + disconnect

    l1 = node_factory.get_node(disconnect=disconnect,
                               options={'dev-no-reconnect': None},
                               may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.openchannel(l2, 1000000)

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("107527sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l1.daemon.wait_for_log(r'dev_disconnect: \-WIRE_TX_SIGNATURES')
    time.sleep(.2)

    print("Killing l1 without sending WIRE_TX_SIGNATURES")
    l1.daemon.kill()

    # Restart l1, without disconnect stuff.
    del l1.daemon.opts['dev-no-reconnect']
    del l1.daemon.opts['dev-disconnect']

    # Should reconnect, and reestablish the splice.
    l1.start()

    # Wait until nodes are reconnected
    l1.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')
    l2.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')

    bitcoind.generate_block(6, wait_for_mempool=1)

    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.xpay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.xfail(strict=True, reason="channel_ready wrongly retransmitted after splice until funding_tx_index detection")
def test_splice_reconnect_after_lock_no_channel_ready(node_factory, bitcoind):
    # Once a splice locks, channel funding txid is updated to the splice txid.
    # On reconnect we must still recognise the peer's `my_current_funding_locked`
    # as a splice (funding_tx_index > 0) and NOT retransmit `channel_ready`.
    # channeld used to compare the txid against the (already-updated) channel
    # funding txid, which is wrong once a splice completes.  This drives a full
    # splice + restart + reestablish to exercise the funding_tx_index path end
    # to end (DB columns, inflight wire, and the reestablish detection).
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.openchannel(l2, 1000000)

    chan_id = l1.get_channel_id(l2)

    l1.rpc.splicein(chan_id, "100000")

    # Confirm and lock the splice on both sides.
    bitcoind.generate_block(6, wait_for_mempool=1)
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    # Restart l1 so it reloads channel + inflight state from the DB (exercising
    # the new funding_tx_index columns) and reconnects/reestablishes.
    l1.restart()

    # Force the reconnect rather than waiting on auto-reconnect backoff.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')
    l2.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')

    # The locked splice must have been persisted with funding_tx_index == 1...
    rows = l1.db_query("SELECT funding_tx_index FROM channels;")
    assert max(r['funding_tx_index'] for r in rows) == 1

    # Drive a payment so both peers finish reestablish; this guarantees any
    # erroneous channel_ready retransmit is already logged before we assert it
    # did not happen.
    inv = l2.rpc.invoice(10**2, 'lbl', 'desc')
    l1.rpc.xpay(inv['bolt11'])

    # ...and the splice was recognised on reestablish, so channel_ready is NOT
    # retransmitted.
    assert not l1.daemon.is_in_log(r'Retransmitting channel_ready')
    assert not l2.daemon.is_in_log(r'Retransmitting channel_ready')


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_disconnect_commit(node_factory, bitcoind, executor):
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               may_reconnect=True)
    # Note: for dual-fund, there's a COMMITMENT_SIGNED for the initial tx, before splicing!
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['+WIRE_COMMITMENT_SIGNED*2']
    else:
        disconnects = ['+WIRE_COMMITMENT_SIGNED']
    l2 = node_factory.get_node(disconnect=disconnects,
                               options={'dev-no-reconnect': None},
                               may_reconnect=True)
    l1.openchannel(l2, 1000000)

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("107527sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)

    executor.submit(l1.rpc.splice_update, chan_id, result['psbt'])

    print("l2 waiting for dev_disconnect msg")

    l2.daemon.wait_for_log(r'dev_disconnect: \+WIRE_COMMITMENT_SIGNED')

    l1.daemon.kill()

    # Restart l1, should reconnect
    del l1.daemon.opts['dev-no-reconnect']

    # Should reconnect, and reestablish the splice.
    l1.start()

    # Splice should be abandoned via tx_abort

    # Wait until nodes are reconnected
    l1.daemon.wait_for_log(r'billboard: Channel ready for use.')
    l2.daemon.wait_for_log(r'billboard: Channel ready for use.')

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_funding_tx_index_increments(node_factory, bitcoind):
    # funding_tx_index is 0 for the original funding and increments by 1 per
    # splice.  Two sequential splices must reach index 2 on the persisted
    # channel (exercises the parent + 1 assignment).
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.openchannel(l2, 1000000)
    chan_id = l1.get_channel_id(l2)

    def do_splice(amount):
        l1.rpc.splicein(chan_id, str(amount))
        bitcoind.generate_block(6, wait_for_mempool=1)
        l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
        l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    def channel_funding_tx_index():
        rows = l1.db_query("SELECT funding_tx_index FROM channels;")
        return max(r['funding_tx_index'] for r in rows)

    # First splice: 0 -> 1
    do_splice(100000)
    assert channel_funding_tx_index() == 1

    # Second splice: 1 -> 2
    do_splice(50000)
    assert channel_funding_tx_index() == 2


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_inflight_funding_tx_index(node_factory, bitcoind):
    # A pending (not-yet-locked) splice inflight carries funding_tx_index == 1
    # (the open was index 0), and the value must survive a restart so the
    # reestablish detection still has it.
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.openchannel(l2, 1000000)
    chan_id = l1.get_channel_id(l2)

    l1.rpc.splicein(chan_id, "100000")

    # The pending splice inflight is index 1.
    inflights = l1.db_query("SELECT funding_tx_index FROM"
                            " channel_funding_inflights;")
    assert [r['funding_tx_index'] for r in inflights] == [1]

    # Restart l1: the inflight (and its index) must reload from the DB.
    l1.restart()
    l1.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')
    inflights = l1.db_query("SELECT funding_tx_index FROM"
                            " channel_funding_inflights;")
    assert [r['funding_tx_index'] for r in inflights] == [1]

    # And the splice still completes after the restart.
    bitcoind.generate_block(6, wait_for_mempool=1)
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
