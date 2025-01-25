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
                               options={'experimental-splicing': None, 'dev-no-reconnect': None},
                               may_reconnect=True)
    l2 = node_factory.get_node(options={'experimental-splicing': None}, may_reconnect=True)
    l1.openchannel(l2, 1000000)

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

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
    l1.rpc.pay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_disconnect_commit(node_factory, bitcoind, executor):
    l1 = node_factory.get_node(options={'experimental-splicing': None, 'dev-no-reconnect': None},
                               may_reconnect=True)
    # Note: for dual-fund, there's a COMMITMENT_SIGNED for the initial tx, before splicing!
    if EXPERIMENTAL_DUAL_FUND:
        disconnects = ['+WIRE_COMMITMENT_SIGNED*2']
    else:
        disconnects = ['+WIRE_COMMITMENT_SIGNED']
    l2 = node_factory.get_node(disconnect=disconnects,
                               options={'experimental-splicing': None, 'dev-no-reconnect': None},
                               may_reconnect=True)
    l1.openchannel(l2, 1000000)

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

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
