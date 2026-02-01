from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
import pytest
import unittest
import time
from utils import (
    sync_blockheight, wait_for, TEST_NETWORK, first_scid, only_one
)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    mempool = bitcoind.rpc.getrawmempool(True)
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
def test_two_chan_splice_in(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    # l2 will splice funds into the channels with l1 and l3 at the same time

    chan_id1 = l2.get_channel_id(l1)
    chan_id2 = l2.get_channel_id(l3)

    # add extra sats to pay fee
    funds_result = l2.rpc.fundpsbt("205790sat", 0, 0, excess_as_change=True)

    # Intiate splices to both channels
    result = l2.rpc.splice_init(chan_id1, 100000, funds_result['psbt'])
    result = l2.rpc.splice_init(chan_id2, 100000, result['psbt'])  # start with psbt from first channel

    done1 = False
    done2 = False
    sigs1 = False
    sigs2 = False

    while not done1 or not done2:
        if not done1:
            result = l2.rpc.splice_update(chan_id1, result['psbt'])
            done1 = result['commitments_secured']
            sigs1 = result['signatures_secured']
            print("chan 1 " + result['psbt'])
        if not done2:
            result = l2.rpc.splice_update(chan_id2, result['psbt'])
            done2 = result['commitments_secured']
            sigs2 = result['signatures_secured']
            print("chan 2 " + result['psbt'])

    # Due to splice signing order, we may or may not have signatures
    # from all peers, but we must have them from one.
    print("Sigs1 " + str(sigs1) + ", Sigs2 " + str(sigs2))
    assert(sigs1 or sigs2)

    # Sign the inputs provided by `fundpsbt`
    result = l2.rpc.signpsbt(result['psbt'])
    result['psbt'] = result['signed_psbt']

    if sigs2:
        # If chan2 gave us sigs, start with chan1
        result = l2.rpc.splice_signed(chan_id1, result['psbt'])
        result = l2.rpc.splice_signed(chan_id2, result['psbt'])
    else:
        # If chan1 gave us sigs, start with chan2
        result = l2.rpc.splice_signed(chan_id2, result['psbt'])
        result = l2.rpc.splice_signed(chan_id1, result['psbt'])

    l3.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    assert result['txid'] in list(bitcoind.rpc.getrawmempool(True).keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l3.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    inv = l3.rpc.invoice(10**2, '2', 'no_2')
    l2.rpc.pay(inv['bolt11'])


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_rbf(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    funds_result = l1.rpc.addpsbtoutput(100000)

    # Pay with fee by subtracting 5000 from channel balance
    result = l1.rpc.splice_init(chan_id, -105000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.splice_signed(chan_id, result['psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    mempool = bitcoind.rpc.getrawmempool(True)
    assert result['txid'] in list(mempool.keys())

    inv = l2.rpc.invoice(10**2, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    funds_result = l1.rpc.addpsbtoutput(100000)

    # Pay with fee by subtracting 5790 from channel balance
    result = l1.rpc.splice_init(chan_id, -105790, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.splice_signed(chan_id, result['psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_AWAITING_SPLICE')

    inv = l2.rpc.invoice(10**2, '2', 'no_2')
    l1.rpc.pay(inv['bolt11'])

    # Make sure l1 doesn't unilateral close if HTLC hasn't completely settled before deadline.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

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
def test_splice_nosign(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    try:
        l1.rpc.splice_signed(chan_id, result['psbt'])
        assert(False)
    except RpcError as e:
        assert(e.error['code'] == 358)
        assert(e.error['message'] == "The PSBT is missing a signature. Have you signed it with `signpsbt`?")


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_gossip(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)
    pre_splice_scid = first_scid(l1, l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['state'] == 'CHANNELD_AWAITING_SPLICE')
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_AWAITING_SPLICE')

    bitcoind.generate_block(5, wait_for_mempool=result['txid'])

    # l3 will see channel dying, but still consider it OK for 12 blocks.
    l3.daemon.wait_for_log(f'gossipd: channel {pre_splice_scid} closing soon due to the funding outpoint being spent')
    assert len(l3.rpc.listchannels(short_channel_id=pre_splice_scid)['channels']) == 2
    assert len(l3.rpc.listchannels(source=l1.info['id'])['channels']) == 1

    # Final one will allow splice announcement to proceed.
    bitcoind.generate_block(1)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    post_splice_scid = first_scid(l1, l2)
    assert post_splice_scid != pre_splice_scid

    # l3 should see the new channel now.
    wait_for(lambda: len(l3.rpc.listchannels(short_channel_id=post_splice_scid)['channels']) == 2)
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
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
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

    wait_for(lambda: len(l1.rpc.listnodes()['nodes']) == 2)
    wait_for(lambda: len(l2.rpc.listnodes()['nodes']) == 2)


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
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.splice_signed(chan_id, result['psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    mempool = bitcoind.rpc.getrawmempool(True)
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
        assert(result['commitments_secured'] is False)
        result = l1.rpc.splice_update(chan_id, result['psbt'])
        assert(result['commitments_secured'] is True)

    assert rpc_error.value.error["code"] == 357
    assert rpc_error.value.error["message"] == "You provided 1000000000msat but committed to 1100000000msat."

    # The splicing inflight should not have been left pending in the DB
    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 0

    l1.daemon.wait_for_log(r'Restarting channeld after tx_abort on CHANNELD_NORMAL channel')

    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 0

    # Now we do a real splice to confirm everything works after restart
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    mempool = bitcoind.rpc.getrawmempool(True)
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
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)

    l1.daemon.wait_for_log(r"Splice initiator: we commit")

    l1.restart()

    # The splicing inflight should have been left pending in the DB
    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 1

    l1.daemon.wait_for_log(r'peer_out WIRE_CHANNEL_REESTABLISH')
    l1.daemon.wait_for_log(r'Got reestablish commit=1 revoke=0 inflights: 1, active splices: 1')
    l1.daemon.wait_for_log(r'Splice resume check with local_next_funding: sent, remote_next_funding: received, inflights: 1')
    l1.daemon.wait_for_log(r'Splice negotation, will not send commit, not recv commit, send signature, recv signature as initiator')

    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 1

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)

    bitcoind.generate_block(6, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    time.sleep(5)

    assert l1.db_query("SELECT count(*) as c FROM channel_funding_inflights;")[0]['c'] == 0

    inv = l2.rpc.invoice(10**2, '3', 'no_3')
    l1.rpc.pay(inv['bolt11'])

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_splice_stuck_htlc(node_factory, bitcoind, executor):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True, opts={'experimental-splicing': None})

    l3.rpc.dev_ignore_htlcs(id=l2.info['id'], ignore=True)

    inv = l3.rpc.invoice(10000000, '1', 'no_1')
    executor.submit(l1.rpc.pay, inv['bolt11'])
    l3.daemon.wait_for_log('their htlc 0 dev_ignore_htlcs')

    # Now we should have a stuck invoice between l1 -> l2

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)

    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    mempool = bitcoind.rpc.getrawmempool(True)
    assert result['txid'] in list(mempool.keys())

    bitcoind.generate_block(1, wait_for_mempool=1)
    # Don't have l2, l3 reject channel_announcement as too far in future.
    sync_blockheight(bitcoind, [l1, l2, l3])
    bitcoind.generate_block(5)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    # Check that the splice doesn't generate a unilateral close transaction
    time.sleep(5)
    assert l1.db_query("SELECT count(*) as c FROM channeltxs;")[0]['c'] == 0


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_route_by_old_scid(node_factory, bitcoind):
    opts = {'experimental-splicing': None, 'may_reconnect': True}
    # l1 sometimes talks about pre-splice channels.  l2 (being part of the splice) immediately forgets
    # the old scid and uses the new one, then complains when l1 talks about it.  Which is fine, but
    # breaks CI.
    l1opts = opts.copy()
    l1opts['allow_warning'] = True
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True, opts=[l1opts, opts, opts])

    # Get pre-splice route.
    inv = l3.rpc.invoice(10000000, 'test_route_by_old_scid', 'test_route_by_old_scid')
    inv2 = l3.rpc.invoice(10000000, 'test_route_by_old_scid2', 'test_route_by_old_scid2')
    route = l1.rpc.getroute(l3.info['id'], 10000000, 1, cltv=16)['route']

    # Do a splice
    funds_result = l2.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)
    chan_id = l2.get_channel_id(l3)
    result = l2.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l2.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l2.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l2.rpc.signpsbt(result['psbt'])
    result = l2.rpc.splice_signed(chan_id, result['signed_psbt'])

    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['state'] == 'CHANNELD_AWAITING_SPLICE')
    bitcoind.generate_block(6, wait_for_mempool=1)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    # Now l1 tries to send using old scid: should work
    l1.rpc.sendpay(route, inv['payment_hash'], payment_secret=inv['payment_secret'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    # Let's splice again, so the original scid is two behind the times.
    l3.fundwallet(200000)
    funds_result = l3.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)
    chan_id = l3.get_channel_id(l2)
    result = l3.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l3.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l3.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l3.rpc.signpsbt(result['psbt'])
    result = l3.rpc.splice_signed(chan_id, result['signed_psbt'])

    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['state'] == 'CHANNELD_AWAITING_SPLICE')
    bitcoind.generate_block(6, wait_for_mempool=1)
    wait_for(lambda: only_one(l2.rpc.listpeerchannels(l3.info['id'])['channels'])['state'] == 'CHANNELD_NORMAL')

    # Now restart l2, make sure it remembers the original!
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'])['connected'] is True)
    l1.rpc.sendpay(route, inv2['payment_hash'], payment_secret=inv2['payment_secret'])
    l1.rpc.waitsendpay(inv2['payment_hash'])


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_splice_unannounced(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=False, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    # add extra sats to pay fee
    funds_result = l1.rpc.fundpsbt("105790sat", 0, 0, excess_as_change=True)
    result = l1.rpc.splice_init(chan_id, 100000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.signpsbt(result['psbt'])
    result = l1.rpc.splice_signed(chan_id, result['signed_psbt'])

    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    bitcoind.generate_block(1, wait_for_mempool=1)

    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2])
