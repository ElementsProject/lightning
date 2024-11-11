from fixtures import *  # noqa: F401,F403
from utils import TEST_NETWORK
import pytest
import unittest


def make_pending_splice(node_factory):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None, 'may_reconnect': True})

    chan_id = l1.get_channel_id(l2)

    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    return [l1, l2]


def wait_for_confirm(l1, l2):
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')


def confirm(bitcoind):
    bitcoind.generate_block(6, wait_for_mempool=1)


def confirm_and_wait(l1, l2, bitcoind):
    confirm(bitcoind)
    wait_for_confirm(l1, l2)


def confirm_funding_not_spent(nodes):
    for node in nodes:
        assert not node.daemon.is_in_log("Funding transaction spent")
        assert node.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


def wait_for_restart(l1, l2):
    l1.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')
    l2.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_insane(node_factory, bitcoind):
    nodes = []

    l1, l2 = make_pending_splice(node_factory)
    l2.restart()
    wait_for_restart(l1, l2)
    confirm_and_wait(l1, l2, bitcoind)
    nodes.append(l1)
    nodes.append(l2)

    l1, l2 = make_pending_splice(node_factory)
    l1.restart()
    wait_for_restart(l1, l2)
    confirm_and_wait(l1, l2, bitcoind)
    nodes.append(l1)
    nodes.append(l2)

    l1, l2 = make_pending_splice(node_factory)
    l1.restart()
    wait_for_restart(l1, l2)
    confirm_and_wait(l1, l2, bitcoind)
    nodes.append(l1)
    nodes.append(l2)

    l1, l2 = make_pending_splice(node_factory)
    l2.restart()
    wait_for_restart(l1, l2)
    confirm_and_wait(l1, l2, bitcoind)
    nodes.append(l1)
    nodes.append(l2)

    l1, l2 = make_pending_splice(node_factory)
    confirm_and_wait(l1, l2, bitcoind)
    l1.restart()
    wait_for_restart(l1, l2)
    nodes.append(l1)
    nodes.append(l2)

    l1, l2 = make_pending_splice(node_factory)
    confirm_and_wait(l1, l2, bitcoind)
    l2.restart()
    wait_for_restart(l1, l2)
    nodes.append(l1)
    nodes.append(l2)

    confirm_funding_not_spent(nodes)
