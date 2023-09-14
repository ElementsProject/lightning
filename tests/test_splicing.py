from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
import pytest
import unittest
import time
from utils import (
    wait_for, TEST_NETWORK, first_scid, only_one
)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert result['txid'] in list(mempool.keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_gossip(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)
    pre_splice_scid = first_scid(l1, l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['state'] == 'CHANNELD_AWAITING_SPLICE')
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_AWAITING_SPLICE')

    bitcoind.generate_block(6, wait_for_mempool=result['txid'])

    # l3 will see channel dying, but still consider it OK for 12 blocks.
    l3.daemon.wait_for_log(f'gossipd: channel {pre_splice_scid} closing soon due to the funding outpoint being spent')
    assert len(l3.rpc.listchannels(short_channel_id=pre_splice_scid)['channels']) == 2
    assert len(l3.rpc.listchannels(source=l1.info['id'])['channels']) == 1

    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    post_splice_scid = first_scid(l1, l2)
    assert post_splice_scid != pre_splice_scid

    # l3 should see the new channel now.
    wait_for(lambda: l3.rpc.listchannels(short_channel_id=post_splice_scid)['channels'] != [])
    assert len(l3.rpc.listchannels(short_channel_id=pre_splice_scid)['channels']) == 2

    bitcoind.generate_block(7)

    # The old channel should fall off l3's perspective
    wait_for(lambda: l3.rpc.listchannels(short_channel_id=pre_splice_scid)['channels'] == [])
    assert len(l3.rpc.listchannels(short_channel_id=post_splice_scid)['channels']) == 2

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0

    # Still looks normal from both sides
    assert only_one(l1.rpc.listpeerchannels()['channels'])['short_channel_id'] == post_splice_scid
    assert only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL'
    assert only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['short_channel_id'] == post_splice_scid
    assert only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL'

    # Check for channel announcement failure
    assert not l1.daemon.is_in_log("invalid local_channel_announcement")
    assert not l2.daemon.is_in_log("invalid local_channel_announcement")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_listnodes(node_factory, bitcoind):
    # Here we do a splice but underfund it purposefully
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    assert len(l1.rpc.listnodes()['nodes']) == 2
    assert len(l2.rpc.listnodes()['nodes']) == 2

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    bitcoind.generate_block(7)

    assert len(l1.rpc.listnodes()['nodes']) == 2
    assert len(l2.rpc.listnodes()['nodes']) == 2


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_out(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    funds_result = l1.rpc.addpsbtoutput(100000)

    # Pay with fee by subjtracting 5000 from channel balance
    result = l1.rpc.splice_init(chan_id, -105000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert result['txid'] in list(mempool.keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_invalid_splice(node_factory, bitcoind):
    # Here we do a splice but underfund it purposefully
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None,
                                                                                          'may_reconnect': True,
                                                                                          'allow_warning': True})

    chan_id = l1.get_channel_id(l2)

    # We claim to add 100000 but in fact add nothing
    result = l1.rpc.splice_init(chan_id, 100000)

    with pytest.raises(RpcError) as rpc_error:
        result = l1.rpc.splice_update(chan_id, result['psbt'])

    assert rpc_error.value.error["code"] == 357
    assert rpc_error.value.error["message"] == "You provided 1000000000msat but committed to 1100000000msat."

    # The splicing inflight should not have been left pending in the DB
    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 0

    l1.daemon.wait_for_log(r'Peer has reconnected, state CHANNELD_NORMAL')

    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 0

    # Now we do a real splice to confirm everything works after restart
    funds_result = l1.rpc.fundpsbt("109000sat", "slow", 166, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert result['txid'] in list(mempool.keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_commit_crash_splice(node_factory, bitcoind):
    # Here we do a normal splice out but force a restart after commiting.
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None,
                                                                                          'may_reconnect': True})

    chan_id = l1.get_channel_id(l2)

    result = l1.rpc.splice_init(chan_id, -105000, l1.rpc.addpsbtoutput(100000)['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])

    l1.daemon.wait_for_log(r"Splice initiator: we commit")

    l1.restart()

    # The splicing inflight should have been left pending in the DB
    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 1

    l1.daemon.wait_for_log(r'Peer has reconnected, state CHANNELD_NORMAL')

    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 1

    result = l1.rpc.splice_init(chan_id, -105000, l1.rpc.addpsbtoutput(100000)['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert result['txid'] in list(mempool.keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    time.sleep(1)

    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 0

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0
