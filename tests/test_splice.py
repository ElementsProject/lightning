from fixtures import *  # noqa: F401,F403
import pytest
import unittest
from utils import (
    TEST_NETWORK, only_one, wait_for
)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_splice_out(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})
    # Splice out 100k from first channel, explicitly putting result less fees into onchain wallet
    l1.rpc.splice("*:? -> 100000; 100%-fee -> wallet", force_feerate=True, debug_log=True)
    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['inflight'][0]['splice_amount'] == -100000
    assert p1['inflight'][0]['total_funding_msat'] == 900000000
    assert p1['inflight'][0]['our_funding_msat'] == 1000000000
    assert p2['inflight'][0]['splice_amount'] == 0
    assert p2['inflight'][0]['total_funding_msat'] == 900000000
    assert p2['inflight'][0]['our_funding_msat'] == 0
    bitcoind.generate_block(6, wait_for_mempool=1)
    l2.daemon.wait_for_log(r'lightningd, splice_locked clearing inflights')

    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['to_us_msat'] == 900000000
    assert p1['total_msat'] == 900000000
    assert p2['to_us_msat'] == 0
    assert p2['total_msat'] == 900000000
    assert 'inflight' not in p1
    assert 'inflight' not in p2

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)
    wait_for(lambda: len(l1.rpc.listfunds()['channels']) == 1)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_splice_in(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})
    # Splice in 100k sats into first channel, explicitly taking out 200k sats from wallet
    # and letting change go automatically back to wallet (100k less onchain fees)
    l1.rpc.splice("wallet -> 200000; 100000 -> *:?", force_feerate=True, debug_log=True)
    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['inflight'][0]['splice_amount'] == 100000
    assert p1['inflight'][0]['total_funding_msat'] == 1100000000
    assert p1['inflight'][0]['our_funding_msat'] == 1000000000
    assert p2['inflight'][0]['splice_amount'] == 0
    assert p2['inflight'][0]['total_funding_msat'] == 1100000000
    assert p2['inflight'][0]['our_funding_msat'] == 0
    bitcoind.generate_block(6, wait_for_mempool=1)
    l2.daemon.wait_for_log(r'lightningd, splice_locked clearing inflights')

    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['to_us_msat'] == 1100000000
    assert p1['total_msat'] == 1100000000
    assert p2['to_us_msat'] == 0
    assert p2['total_msat'] == 1100000000
    assert 'inflight' not in p1
    assert 'inflight' not in p2

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    wait_for(lambda: len(l1.rpc.listfunds()['channels']) == 1)
