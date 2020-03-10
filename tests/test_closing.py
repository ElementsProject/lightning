from fixtures import *  # noqa: F401,F403
from flaky import flaky
from pyln.client import RpcError
from utils import (
    only_one, sync_blockheight, wait_for, DEVELOPER, TIMEOUT, VALGRIND,
    SLOW_MACHINE
)

import os
import queue
import pytest
import re
import threading
import unittest


@unittest.skipIf(not DEVELOPER, "Too slow without --dev-bitcoind-poll")
def test_closing(node_factory, bitcoind, chainparams):
    l1, l2 = node_factory.line_graph(2)
    chan = l1.get_channel_scid(l2)
    fee = 5430 if not chainparams['elements'] else 8955

    l1.pay(l2, 200000000)

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    billboard = only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status']
    assert billboard == ['CHANNELD_NORMAL:Funding transaction locked.']
    billboard = only_one(l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'])['status']
    assert billboard == ['CHANNELD_NORMAL:Funding transaction locked.']

    bitcoind.generate_block(5)

    # Only wait for the channels to activate with DEVELOPER=1,
    # otherwise it's going to take too long because of the missing
    # --dev-fast-gossip
    if DEVELOPER:
        wait_for(lambda: len(l1.getactivechannels()) == 2)
        wait_for(lambda: len(l2.getactivechannels()) == 2)
        billboard = only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status']
        # This may either be from a local_update or an announce, so just
        # check for the substring
        assert 'CHANNELD_NORMAL:Funding transaction locked.' in billboard[0]

    l1.rpc.close(chan)

    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
    l2.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')

    l1.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')
    l2.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')

    # And should put closing into mempool.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # Both nodes should have disabled the channel in their view
    wait_for(lambda: len(l1.getactivechannels()) == 0)
    wait_for(lambda: len(l2.getactivechannels()) == 0)

    assert bitcoind.rpc.getmempoolinfo()['size'] == 1

    # Now grab the close transaction
    closetxid = only_one(bitcoind.rpc.getrawmempool(False))

    billboard = only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status']
    assert billboard == [
        'CLOSINGD_SIGEXCHANGE:We agreed on a closing fee of {} satoshi for tx:{}'.format(fee, closetxid),
    ]
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Owning output.* \(SEGWIT\).* txid %s.* CONFIRMED' % closetxid)
    l2.daemon.wait_for_log(r'Owning output.* \(SEGWIT\).* txid %s.* CONFIRMED' % closetxid)

    # Make sure both nodes have grabbed their close tx funds
    assert closetxid in set([o['txid'] for o in l1.rpc.listfunds()['outputs']])
    assert closetxid in set([o['txid'] for o in l2.rpc.listfunds()['outputs']])

    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status'] == [
        'CLOSINGD_SIGEXCHANGE:We agreed on a closing fee of {} satoshi for tx:{}'.format(fee, closetxid),
        'ONCHAIN:Tracking mutual close transaction',
        'ONCHAIN:All outputs resolved: waiting 99 more blocks before forgetting channel'
    ])

    bitcoind.generate_block(9)
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status'] == [
        'CLOSINGD_SIGEXCHANGE:We agreed on a closing fee of {} satoshi for tx:{}'.format(fee, closetxid),
        'ONCHAIN:Tracking mutual close transaction',
        'ONCHAIN:All outputs resolved: waiting 90 more blocks before forgetting channel'
    ])

    # Make sure both have forgotten about it
    bitcoind.generate_block(90)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 0)
    wait_for(lambda: len(l2.rpc.listchannels()['channels']) == 0)

    # The entry in the channels table should still be there
    assert l1.db_query("SELECT count(*) as c FROM channels;")[0]['c'] == 1
    assert l2.db_query("SELECT count(*) as c FROM channels;")[0]['c'] == 1


def test_closing_while_disconnected(node_factory, bitcoind, executor):
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True})
    chan = l1.get_channel_scid(l2)

    l1.pay(l2, 200000000)
    l2.stop()

    # The close should still be triggered afterwards.
    fut = executor.submit(l1.rpc.close, chan, 0)
    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')

    l2.start()
    fut.result(TIMEOUT)

    l1.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')
    l2.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')

    # And should put closing into mempool.
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    bitcoind.generate_block(101)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 0)
    wait_for(lambda: len(l2.rpc.listchannels()['channels']) == 0)


def test_closing_id(node_factory):
    """Test closing using peer ID and full channel ID
    """
    l1, l2 = node_factory.get_nodes(2)

    # Close by full channel ID.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)
    cid = l2.rpc.listpeers()['peers'][0]['channels'][0]['channel_id']
    l2.rpc.close(cid)
    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    wait_for(lambda: not only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])

    # Close by peer ID.
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l1.daemon.wait_for_log("Handed peer, entering loop")
    l2.fund_channel(l1, 10**6)
    pid = l1.info['id']
    l2.rpc.close(pid)
    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    wait_for(lambda: not only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])


@unittest.skipIf(VALGRIND, "Flaky under valgrind")
def test_closing_torture(node_factory, executor, bitcoind):
    # We set up a fully-connected mesh of N nodes, then try
    # closing them all at once.
    amount = 10**6

    num_nodes = 10  # => 45 channels (36 seconds on my laptop)
    if VALGRIND:
        num_nodes -= 4  # => 15 (135 seconds)
    if SLOW_MACHINE:
        num_nodes -= 1  # => 36/10 (37/95 seconds)

    nodes = node_factory.get_nodes(num_nodes)

    # Make sure bitcoind has plenty of utxos
    bitcoind.generate_block(num_nodes)

    # Give them all plenty of UTXOs, make sure they see them
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            addr = nodes[i].rpc.newaddr()['bech32']
            bitcoind.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, nodes)

    txs = []
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            nodes[i].rpc.connect(nodes[j].info['id'], 'localhost', nodes[j].port)
            txs.append(nodes[i].rpc.fundchannel(nodes[j].info['id'], amount)['txid'])

    # Make sure they're all in, then lock them in.
    bitcoind.generate_block(1, wait_for_mempool=txs)

    # Wait for them all to be CHANNELD_NORMAL
    for n in nodes:
        wait_for(lambda: all(p['channels'][0]['state'] == 'CHANNELD_NORMAL' for p in n.rpc.listpeers()['peers']))

    # Start closers: can take a long time under valgrind!
    futures = []
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            futures.append(executor.submit(nodes[i].rpc.close, nodes[j].info['id']))
            futures.append(executor.submit(nodes[j].rpc.close, nodes[i].info['id']))

    # Wait for close to finish
    close_txs = set()
    for f in futures:
        # If one side completes closing, we'll get an error here 'Peer has no active channel'
        try:
            close_txs.add(f.result(TIMEOUT)['txid'])
        except RpcError as err:
            assert err.error['message'] == 'Peer has no active channel'

    # Should have one close for each open.
    assert len(close_txs) == len(txs)
    # Get closes confirmed
    bitcoind.generate_block(100, wait_for_mempool=list(close_txs))

    # And make sure they hangup.
    for n in nodes:
        wait_for(lambda: n.rpc.listpeers()['peers'] == [])


@unittest.skipIf(SLOW_MACHINE and VALGRIND, "slow test")
def test_closing_different_fees(node_factory, bitcoind, executor):
    l1 = node_factory.get_node()

    # Default feerate = 15000/11000/7500/1000
    # It will start at the second number, accepting anything above the first.
    feerates = [[20000, 11000, 15000, 7400], [8000, 6000, 1001, 100]]
    amounts = [0, 545999, 546000]
    num_peers = len(feerates) * len(amounts)

    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 1)
    numfunds = len(l1.rpc.listfunds()['outputs'])
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > numfunds)

    # Create them in a batch, for speed!
    peers = []
    for feerate in feerates:
        for amount in amounts:
            p = node_factory.get_node(feerates=feerate)
            p.feerate = feerate
            p.amount = amount
            l1.rpc.connect(p.info['id'], 'localhost', p.port)
            peers.append(p)

    for p in peers:
        p.channel = l1.rpc.fundchannel(p.info['id'], 10**6, minconf=0)['channel_id']
        # Technically, this is async to fundchannel returning.
        l1.daemon.wait_for_log('sendrawtx exit 0')

    bitcoind.generate_block(6)

    # Now wait for them all to hit normal state, do payments
    l1.daemon.wait_for_logs(['update for channel .* now ACTIVE'] * num_peers
                            + ['to CHANNELD_NORMAL'] * num_peers)
    for p in peers:
        if p.amount != 0:
            l1.pay(p, 100000000)

    # Now close all channels (not unilaterally!)
    closes = [executor.submit(l1.rpc.close, p.channel, 0) for p in peers]

    for c in closes:
        c.result(90)

    # close does *not* wait for the sendrawtransaction, so do that!
    # Note that since they disagree on the ideal fee, they may conflict
    # (first one in will win), so we cannot look at logs, we need to
    # wait for mempool.
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == num_peers)

    bitcoind.generate_block(1)
    for p in peers:
        p.daemon.wait_for_log(' to ONCHAIN')
        wait_for(lambda: 'ONCHAIN:Tracking mutual close transaction' in only_one(p.rpc.listpeers(l1.info['id'])['peers'][0]['channels'])['status'])

    l1.daemon.wait_for_logs([' to ONCHAIN'] * num_peers)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_closing_negotiation_reconnect(node_factory, bitcoind):
    disconnects = ['-WIRE_CLOSING_SIGNED',
                   '@WIRE_CLOSING_SIGNED',
                   '+WIRE_CLOSING_SIGNED']
    l1 = node_factory.get_node(disconnect=disconnects, may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    chan = l1.fund_channel(l2, 10**6)
    l1.pay(l2, 200000000)

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    l1.rpc.close(chan)

    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
    l2.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')

    l1.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')
    l2.daemon.wait_for_log(' to CLOSINGD_SIGEXCHANGE')

    # And should put closing into mempool (happens async, so
    # CLOSINGD_COMPLETE may come first).
    l1.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    l2.daemon.wait_for_logs(['sendrawtx exit 0', ' to CLOSINGD_COMPLETE'])
    assert bitcoind.rpc.getmempoolinfo()['size'] == 1


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_closing_specified_destination(node_factory, bitcoind, chainparams):
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)

    chan12 = l1.fund_channel(l2, 10**6)
    chan13 = l1.fund_channel(l3, 10**6)
    chan14 = l1.fund_channel(l4, 10**6)

    l1.pay(l2, 100000000)
    l1.pay(l3, 100000000)
    l1.pay(l4, 100000000)

    bitcoind.generate_block(5)
    addr = chainparams['example_addr']
    l1.rpc.close(chan12, None, addr)
    l1.rpc.call('close', {'id': chan13, 'destination': addr})
    l1.rpc.call('close', [chan14, None, addr])

    l1.daemon.wait_for_logs([' to CLOSINGD_SIGEXCHANGE'] * 3)

    # Both nodes should have disabled the channel in their view
    wait_for(lambda: len(l1.getactivechannels()) == 0)

    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == 3)

    # Now grab the close transaction
    closetxs = {}
    for i, n in enumerate([l2, l3, l4]):
        billboard = only_one(l1.rpc.listpeers(n.info['id'])['peers'][0]['channels'])['status'][0]
        m = re.search(r'CLOSINGD_SIGEXCHANGE.* tx:([a-f0-9]{64})', billboard)
        closetxs[n] = m.group(1)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3, l4])

    # l1 can't spent the output to addr.
    for txid in closetxs.values():
        assert not l1.daemon.is_in_log(r'Owning output.* \(SEGWIT\).* txid {}.* CONFIRMED'.format(txid))

    # Check the txid has at least 1 confirmation
    for n, txid in closetxs.items():
        n.daemon.wait_for_log(r'Owning output.* \(SEGWIT\).* txid {}.* CONFIRMED'.format(txid))

    for n in [l2, l3, l4]:
        # Make sure both nodes have grabbed their close tx funds
        closetx = closetxs[n]
        outputs = n.rpc.listfunds()['outputs']
        assert closetx in set([o['txid'] for o in outputs])
        output_num2 = [o for o in outputs if o['txid'] == closetx][0]['output']
        output_num1 = 0 if output_num2 == 1 else 1
        # Check the another address is addr
        assert addr == bitcoind.rpc.gettxout(closetx, output_num1)['scriptPubKey']['addresses'][0]
        assert 1 == bitcoind.rpc.gettxout(closetx, output_num1)['confirmations']


def closing_fee(node_factory, bitcoind, chainparams, opts):
    rate = opts['funder_feerate_per_kw']
    funder = node_factory.get_node(feerates=(rate, rate, rate, rate))

    rate = opts['fundee_feerate_per_kw']
    fundee = node_factory.get_node(feerates=(rate, rate, rate, rate))

    funder_id = funder.info['id']
    fundee_id = fundee.info['id']

    fund_amount = 10**6

    funder.rpc.connect(fundee_id, 'localhost', fundee.port)
    funder.fund_channel(fundee, fund_amount)

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    if opts['close_initiated_by'] == 'funder':
        funder.rpc.close(peer_id=fundee_id)
    else:
        assert opts['close_initiated_by'] == 'fundee'
        fundee.rpc.close(peer_id=funder_id)

    # Get the closing transaction from the bitcoind mempool and get its fee

    mempool = None
    mempool_tx_ids = None

    def get_mempool_when_size_1():
        nonlocal mempool, mempool_tx_ids
        mempool = bitcoind.rpc.getrawmempool(True)
        mempool_tx_ids = list(mempool.keys())
        return len(mempool_tx_ids) == 1

    wait_for(get_mempool_when_size_1)

    close_tx_id = mempool_tx_ids[0]
    fee_mempool = round(mempool[close_tx_id]['fee'] * 10**8)

    # Get the proclaimed closing fee from the two nodes' statuses

    status_agreed_regex = re.compile("agreed on a closing fee of ([0-9]+) satoshi")

    # [fee_from_funder_status, fee_from_fundee_status]
    fees_from_status = [None, None]

    def get_fee_from_status(node, peer_id, i):
        nonlocal fees_from_status
        status = only_one(only_one(node.rpc.listpeers(peer_id)['peers'][0]['channels'])['status'])
        m = status_agreed_regex.search(status)
        if not m:
            return False
        fees_from_status[i] = int(m.group(1))
        return True

    wait_for(lambda: get_fee_from_status(funder, fundee_id, 0))
    wait_for(lambda: get_fee_from_status(fundee, funder_id, 1))

    assert fee_mempool == fees_from_status[0]
    assert fee_mempool == fees_from_status[1]
    assert fee_mempool == opts['expected_close_fee']


def test_closing_fee(node_factory, bitcoind, chainparams):
    """Test that the closing negotiation strategy works"""
    # feerate 27625 -> closing fee negotiation starts at 20000
    # feerate 29006 -> closing fee negotiation starts at 21000

    opts = {
        'funder_feerate_per_kw': 29006,
        'fundee_feerate_per_kw': 27625,
        'close_initiated_by': 'funder',
        'expected_close_fee': 33533 if chainparams['elements'] else 20333
    }

    closing_fee(node_factory, bitcoind, chainparams, opts)

    opts['close_initiated_by'] = 'fundee'
    closing_fee(node_factory, bitcoind, chainparams, opts)


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_penalty_inhtlc(node_factory, bitcoind, executor, chainparams):
    """Test penalty transaction with an incoming HTLC"""
    # We suppress each one after first commit; HTLC gets added not fulfilled.
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'],
                               may_fail=True, feerates=(7500, 7500, 7500, 7500),
                               allow_broken_log=True)
    l2 = node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED-nocommit'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    # Now, this will get stuck due to l1 commit being disabled..
    t = executor.submit(l1.pay, l2, 100000000)

    assert len(l1.getactivechannels()) == 2
    assert len(l2.getactivechannels()) == 2

    # They should both have commitments blocked now.
    l1.daemon.wait_for_log('=WIRE_COMMITMENT_SIGNED-nocommit')
    l2.daemon.wait_for_log('=WIRE_COMMITMENT_SIGNED-nocommit')

    # Make sure l1 got l2's commitment to the HTLC, and sent to master.
    l1.daemon.wait_for_log('got commitsig')

    # Take our snapshot.
    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    # Let them continue
    l1.rpc.dev_reenable_commit(l2.info['id'])
    l2.rpc.dev_reenable_commit(l1.info['id'])

    # Should fulfill.
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_FULFILL_HTLC')
    l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

    l2.daemon.wait_for_log('peer_out WIRE_UPDATE_FULFILL_HTLC')
    l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # Payment should now complete.
    t.result(timeout=10)

    # Now we really mess things up!
    bitcoind.rpc.sendrawtransaction(tx)
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log(' to ONCHAIN')

    # FIXME: l1 should try to stumble along!
    wait_for(lambda: len(l2.getactivechannels()) == 0)

    # l2 should spend all of the outputs (except to-us).
    # Could happen in any order, depending on commitment tx.
    needle = l2.daemon.logsearch_start
    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_OUTPUT_TO_THEM')
    l2.daemon.logsearch_start = needle
    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/THEIR_HTLC')

    # FIXME: test HTLC tx race!

    # 100 blocks later, all resolved.
    bitcoind.generate_block(100)

    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    outputs = l2.rpc.listfunds()['outputs']
    assert [o['status'] for o in outputs] == ['confirmed'] * 2
    # Allow some lossage for fees.
    slack = 30000 if chainparams['elements'] else 20000
    assert sum(o['value'] for o in outputs) < 10**6
    assert sum(o['value'] for o in outputs) > 10**6 - slack


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_penalty_outhtlc(node_factory, bitcoind, executor, chainparams):
    """Test penalty transaction with an outgoing HTLC"""
    # First we need to get funds to l2, so suppress after second.
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED*3-nocommit'],
                               may_fail=True, feerates=(7500, 7500, 7500, 7500),
                               allow_broken_log=True)
    l2 = node_factory.get_node(disconnect=['=WIRE_COMMITMENT_SIGNED*3-nocommit'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    # Move some across to l2.
    l1.pay(l2, 200000000)

    assert not l1.daemon.is_in_log('=WIRE_COMMITMENT_SIGNED')
    assert not l2.daemon.is_in_log('=WIRE_COMMITMENT_SIGNED')

    # Now, this will get stuck due to l1 commit being disabled..
    t = executor.submit(l2.pay, l1, 100000000)

    # Make sure we get signature from them.
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_ADD_HTLC')
    l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # They should both have commitments blocked now.
    l1.daemon.wait_for_log('dev_disconnect: =WIRE_COMMITMENT_SIGNED')
    l2.daemon.wait_for_log('dev_disconnect: =WIRE_COMMITMENT_SIGNED')

    # Make sure both sides got revoke_and_ack for that commitment.
    l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')
    l2.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # Take our snapshot.
    tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    # Let them continue
    l1.rpc.dev_reenable_commit(l2.info['id'])
    l2.rpc.dev_reenable_commit(l1.info['id'])

    # Thread should complete.
    t.result(timeout=10)

    # Make sure both sides got revoke_and_ack for final.
    l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')
    l2.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # Now we really mess things up!
    bitcoind.rpc.sendrawtransaction(tx)
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log(' to ONCHAIN')
    # FIXME: l1 should try to stumble along!

    # l2 should spend all of the outputs (except to-us).
    # Could happen in any order, depending on commitment tx.
    needle = l2.daemon.logsearch_start
    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_OUTPUT_TO_THEM')
    l2.daemon.logsearch_start = needle
    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/OUR_HTLC')

    l2.daemon.logsearch_start = needle
    l2.daemon.wait_for_log('Ignoring output.*: THEIR_REVOKED_UNILATERAL/OUTPUT_TO_US')

    # FIXME: test HTLC tx race!

    # 100 blocks later, all resolved.
    bitcoind.generate_block(100)

    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    outputs = l2.rpc.listfunds()['outputs']
    assert [o['status'] for o in outputs] == ['confirmed'] * 3
    # Allow some lossage for fees.
    slack = 30000 if chainparams['elements'] else 20000
    assert sum(o['value'] for o in outputs) < 10**6
    assert sum(o['value'] for o in outputs) > 10**6 - slack


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchain_first_commit(node_factory, bitcoind):
    """Onchain handling where funder immediately drops to chain"""

    # HTLC 1->2, 1 fails just after funding.
    disconnects = ['+WIRE_FUNDING_LOCKED', 'permfail']
    l1 = node_factory.get_node(disconnect=disconnects)
    # Make locktime different, as we once had them reversed!
    l2 = node_factory.get_node(options={'watchtime-blocks': 10})
    l1.fundwallet(10**7)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.rpc.fundchannel(l2.info['id'], 10**6)
    l1.daemon.wait_for_log('sendrawtx exit 0')

    l1.bitcoin.generate_block(1)

    # l1 will drop to chain.
    l1.daemon.wait_for_log('permfail')
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # 10 later, l1 should collect its to-self payment.
    bitcoind.generate_block(10)
    l1.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # 94 later, l2 is done.
    bitcoind.generate_block(94)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Now, 100 blocks and l1 should be done.
    bitcoind.generate_block(6)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchain_unwatch(node_factory, bitcoind):
    """Onchaind should not watch random spends"""
    l1, l2 = node_factory.line_graph(2)

    l1.pay(l2, 200000000)

    l1.rpc.dev_fail(l2.info['id'])
    l1.daemon.wait_for_log('Failing due to dev-fail command')
    l1.wait_for_channel_onchain(l2.info['id'])

    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # 10 later, l1 should collect its to-self payment.
    bitcoind.generate_block(10)
    l1.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # First time it sees it, onchaind cares.
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Resolved OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by our proposal '
                           'OUR_DELAYED_RETURN_TO_WALLET')

    # Now test unrelated onchain churn.
    # Daemon gets told about wallet; says it doesn't care.
    l1.rpc.withdraw(l1.rpc.newaddr()['bech32'], 'all')
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log("but we don't care")

    # And lightningd should respect that!
    assert not l1.daemon.is_in_log("Can't unwatch txid")

    # So these should not generate further messages
    for i in range(5):
        l1.rpc.withdraw(l1.rpc.newaddr()['bech32'], 'all')
        bitcoind.generate_block(1)
        # Make sure it digests the block
        sync_blockheight(bitcoind, [l1])

    # We won't see this again.
    assert not l1.daemon.is_in_log("but we don't care",
                                   start=l1.daemon.logsearch_start)

    # Note: for this test we leave onchaind running, so we can detect
    # any leaks!


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchaind_replay(node_factory, bitcoind):
    disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
    options = {'watchtime-blocks': 201, 'cltv-delta': 101}
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options=options, disconnect=disconnects,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(options=options)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    rhash = l2.rpc.invoice(10**8, 'onchaind_replay', 'desc')['payment_hash']
    routestep = {
        'msatoshi': 10**8 - 1,
        'id': l2.info['id'],
        'delay': 101,
        'channel': '1x1x1'
    }
    l1.rpc.sendpay([routestep], rhash)
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)

    # Wait for nodes to notice the failure, this seach needle is after the
    # DB commit so we're sure the tx entries in onchaindtxs have been added
    l1.daemon.wait_for_log("Deleting channel .* due to the funding outpoint being spent")
    l2.daemon.wait_for_log("Deleting channel .* due to the funding outpoint being spent")

    # We should at least have the init tx now
    assert len(l1.db_query("SELECT * FROM channeltxs;")) > 0
    assert len(l2.db_query("SELECT * FROM channeltxs;")) > 0

    # Generate some blocks so we restart the onchaind from DB (we rescan
    # last_height - 100)
    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l1, l2])

    # l1 should still have a running onchaind
    assert len(l1.db_query("SELECT * FROM channeltxs;")) > 0

    l2.rpc.stop()
    l1.restart()

    # Can't wait for it, it's after the "Server started" wait in restart()
    assert l1.daemon.is_in_log(r'Restarting onchaind for channel')

    # l1 should still notice that the funding was spent and that we should react to it
    l1.daemon.wait_for_log("Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET")
    sync_blockheight(bitcoind, [l1])
    bitcoind.generate_block(10)
    sync_blockheight(bitcoind, [l1])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchain_dust_out(node_factory, bitcoind, executor):
    """Onchain handling of outgoing dust htlcs (they should fail)"""
    # HTLC 1->2, 1 fails after it's irrevocably committed
    disconnects = ['@WIRE_REVOKE_AND_ACK', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    # Must be dust!
    rhash = l2.rpc.invoice(1, 'onchain_dust_out', 'desc')['payment_hash']
    routestep = {
        'msatoshi': 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    l1.rpc.sendpay([routestep], rhash)
    payfuture = executor.submit(l1.rpc.waitsendpay, rhash)

    # l1 will drop to chain.
    l1.daemon.wait_for_log('permfail')
    l1.wait_for_channel_onchain(l2.info['id'])
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # We use 3 blocks for "reasonable depth"
    bitcoind.generate_block(3)

    # It should fail.
    with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE: missing in commitment tx'):
        payfuture.result(5)

    # Retry payment, this should fail (and, as a side-effect, tickle a
    # bug).
    with pytest.raises(RpcError, match=r'WIRE_UNKNOWN_NEXT_PEER'):
        l1.rpc.sendpay([routestep], rhash)

    # 6 later, l1 should collect its to-self payment.
    bitcoind.generate_block(6)
    l1.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # 94 later, l2 is done.
    bitcoind.generate_block(94)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Restart l1, it should not crash!
    l1.restart()

    # Now, 100 blocks and l1 should be done.
    bitcoind.generate_block(6)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Payment failed, BTW
    assert only_one(l2.rpc.listinvoices('onchain_dust_out')['invoices'])['status'] == 'unpaid'


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchain_timeout(node_factory, bitcoind, executor):
    """Onchain handling of outgoing failed htlcs"""
    # HTLC 1->2, 1 fails just after it's irrevocably committed
    disconnects = ['+WIRE_REVOKE_AND_ACK*3', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(disconnect=disconnects,
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    rhash = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')['payment_hash']
    # We underpay, so it fails.
    routestep = {
        'msatoshi': 10**8 - 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    l1.rpc.sendpay([routestep], rhash)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # Make sure CLTVs are different, in case it confuses onchaind.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    # Second one will cause drop to chain.
    l1.rpc.sendpay([routestep], rhash)
    payfuture = executor.submit(l1.rpc.waitsendpay, rhash)

    # l1 will drop to chain.
    l1.daemon.wait_for_log('permfail')
    l1.wait_for_channel_onchain(l2.info['id'])
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # Wait for timeout.
    l1.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks',
                             'Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TX .* after 6 blocks'])
    bitcoind.generate_block(4)

    l1.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    bitcoind.generate_block(1)
    l1.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                   'OUR_UNILATERAL/OUR_HTLC')

    # We use 3 blocks for "reasonable depth"
    bitcoind.generate_block(3)

    # It should fail.
    with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE: timed out'):
        payfuture.result(5)

    # 2 later, l1 spends HTLC (5 blocks total).
    bitcoind.generate_block(2)
    l1.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US')

    # 89 later, l2 is done.
    bitcoind.generate_block(89)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Now, 100 blocks and l1 should be done.
    bitcoind.generate_block(10)
    sync_blockheight(bitcoind, [l1])
    assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Payment failed, BTW
    assert only_one(l2.rpc.listinvoices('onchain_timeout')['invoices'])['status'] == 'unpaid'


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchain_middleman(node_factory, bitcoind):
    # HTLC 1->2->3, 1->2 goes down after 2 gets preimage from 3.
    disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(disconnect=disconnects)
    l3 = node_factory.get_node()

    # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.fund_channel(l1, 10**6)
    c23 = l2.fund_channel(l3, 10**6)

    # Make sure routes finalized.
    bitcoind.generate_block(5)
    l1.wait_channel_active(c23)

    # Give l1 some money to play with.
    l2.pay(l1, 2 * 10**8)

    # Must be bigger than dust!
    rhash = l3.rpc.invoice(10**8, 'middleman', 'desc')['payment_hash']

    route = l1.rpc.getroute(l3.info['id'], 10**8, 1)["route"]
    assert len(route) == 2

    q = queue.Queue()

    def try_pay():
        try:
            l1.rpc.sendpay(route, rhash)
            l1.rpc.waitsendpay(rhash)
            q.put(None)
        except Exception as err:
            q.put(err)

    t = threading.Thread(target=try_pay)
    t.daemon = True
    t.start()

    # l2 will drop to chain.
    l2.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log('OUR_UNILATERAL/THEIR_HTLC')

    # l2 should fulfill HTLC onchain, and spend to-us (any order)
    l2.wait_for_onchaind_broadcast('OUR_HTLC_SUCCESS_TX',
                                   'OUR_UNILATERAL/THEIR_HTLC')

    # Payment should succeed.
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC gave us preimage')
    err = q.get(timeout=10)
    if err:
        print("Got err from sendpay thread")
        raise err
    t.join(timeout=1)
    assert not t.is_alive()

    # Three more, l2 can spend to-us.
    bitcoind.generate_block(3)
    l2.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # One more block, HTLC tx is now spendable.
    l1.bitcoin.generate_block(1)
    l2.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US')

    # 100 blocks after last spend, l2 should be done.
    l1.bitcoin.generate_block(100)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_onchain_feechange(node_factory, bitcoind, executor):
    """Onchain handling when we restart with different fees"""
    # HTLC 1->2, 2 fails just after they're both irrevocably committed
    # We need 2 to drop to chain, because then 1's HTLC timeout tx
    # is generated on-the-fly, and is thus feerate sensitive.
    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']
    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(disconnect=disconnects,
                               may_reconnect=True)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    rhash = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')['payment_hash']
    # We underpay, so it fails.
    routestep = {
        'msatoshi': 10**8 - 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    executor.submit(l1.rpc.sendpay, [routestep], rhash)

    # l2 will drop to chain.
    l2.daemon.wait_for_log('permfail')
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # Wait for timeout.
    l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US .* after 6 blocks')
    bitcoind.generate_block(6)

    l1.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                   'THEIR_UNILATERAL/OUR_HTLC')

    # Make sure that gets included.

    bitcoind.generate_block(1)
    # Now we restart with different feerates.
    l1.stop()

    l1.daemon.cmd_line.append('--override-fee-rates=20000/9000/2000')
    l1.start()

    # We recognize different proposal as ours.
    l1.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')

    # We use 3 blocks for "reasonable depth", so add two more
    bitcoind.generate_block(2)

    # Note that the very similar test_onchain_timeout looks for a
    # different string: that's because it sees the JSONRPC response,
    # and due to the l1 restart, there is none here.
    l1.daemon.wait_for_log('WIRE_PERMANENT_CHANNEL_FAILURE')

    # 90 later, l2 is done
    bitcoind.generate_block(89)
    sync_blockheight(bitcoind, [l2])
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Now, 7 blocks and l1 should be done.
    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1])
    assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Payment failed, BTW
    assert only_one(l2.rpc.listinvoices('onchain_timeout')['invoices'])['status'] == 'unpaid'


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for dev-set-fees")
def test_onchain_all_dust(node_factory, bitcoind, executor):
    """Onchain handling when we reduce output to all dust"""
    # HTLC 1->2, 2 fails just after they're both irrevocably committed
    # We need 2 to drop to chain, because then 1's HTLC timeout tx
    # is generated on-the-fly, and is thus feerate sensitive.
    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    rhash = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')['payment_hash']
    # We underpay, so it fails.
    routestep = {
        'msatoshi': 10**7 - 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    executor.submit(l1.rpc.sendpay, [routestep], rhash)

    # l2 will drop to chain.
    l2.daemon.wait_for_log('permfail')
    l2.wait_for_channel_onchain(l1.info['id'])

    # Make l1's fees really high (and wait for it to exceed 50000)
    l1.set_feerates((100000, 100000, 100000, 100000))
    l1.daemon.wait_for_log('Feerate estimate for unilateral_close set to [56789][0-9]{4}')

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # Wait for timeout.
    l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by IGNORING_TINY_PAYMENT .* after 6 blocks')
    bitcoind.generate_block(5)

    l1.wait_for_onchaind_broadcast('IGNORING_TINY_PAYMENT',
                                   'THEIR_UNILATERAL/OUR_HTLC')
    l1.daemon.wait_for_log('Ignoring output 0 of .*: THEIR_UNILATERAL/OUR_HTLC')

    # 100 deep and l2 forgets.
    bitcoind.generate_block(93)
    sync_blockheight(bitcoind, [l1, l2])
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # l1 does not wait for ignored payment.
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for dev_fail")
def test_onchain_different_fees(node_factory, bitcoind, executor):
    """Onchain handling when we've had a range of fees"""
    l1, l2 = node_factory.line_graph(2, fundchannel=True, fundamount=10**7,
                                     opts={'may_reconnect': True})

    l2.rpc.dev_ignore_htlcs(id=l1.info['id'], ignore=True)
    p1 = executor.submit(l1.pay, l2, 1000000000)
    l1.daemon.wait_for_log('htlc 0: RCVD_ADD_ACK_COMMIT->SENT_ADD_ACK_REVOCATION')

    l1.set_feerates((16000, 11000, 7500, 3750))
    p2 = executor.submit(l1.pay, l2, 900000000)
    l1.daemon.wait_for_log('htlc 1: RCVD_ADD_ACK_COMMIT->SENT_ADD_ACK_REVOCATION')

    # Restart with different feerate for second HTLC.
    l1.set_feerates((5000, 5000, 5000, 3750))
    l1.restart()
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE')

    p3 = executor.submit(l1.pay, l2, 800000000)
    l1.daemon.wait_for_log('htlc 2: RCVD_ADD_ACK_COMMIT->SENT_ADD_ACK_REVOCATION')

    # Drop to chain
    l1.rpc.dev_fail(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # Both sides should have correct feerate
    assert l1.db_query('SELECT min_possible_feerate, max_possible_feerate FROM channels;') == [{
        'min_possible_feerate': 5000,
        'max_possible_feerate': 16000
    }]
    assert l2.db_query('SELECT min_possible_feerate, max_possible_feerate FROM channels;') == [{
        'min_possible_feerate': 5000,
        'max_possible_feerate': 16000
    }]

    bitcoind.generate_block(5)
    # Three HTLCs, and one for the to-us output.
    l1.daemon.wait_for_logs(['sendrawtx exit 0'] * 4)

    # We use 3 blocks for "reasonable depth"
    bitcoind.generate_block(3)

    with pytest.raises(Exception):
        p1.result(10)
    with pytest.raises(Exception):
        p2.result(10)
    with pytest.raises(Exception):
        p3.result(10)

    # Two more for HTLC timeout tx to be spent.
    bitcoind.generate_block(2)
    l1.daemon.wait_for_logs(['sendrawtx exit 0'] * 3)

    # Now, 100 blocks it should be done.
    bitcoind.generate_block(100)
    wait_for(lambda: l1.rpc.listpeers()['peers'] == [])
    wait_for(lambda: l2.rpc.listpeers()['peers'] == [])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_permfail_new_commit(node_factory, bitcoind, executor):
    # Test case where we have two possible commits: it will use new one.
    disconnects = ['-WIRE_REVOKE_AND_ACK', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    # This will fail at l2's end.
    t = executor.submit(l1.pay, l2, 200000000)

    l2.daemon.wait_for_log('dev_disconnect permfail')
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Their unilateral tx, new commit point')
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) after 6 blocks')
    l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US (.*) after 6 blocks')

    # OK, time out HTLC.
    bitcoind.generate_block(5)
    l1.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                   'THEIR_UNILATERAL/OUR_HTLC')

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Resolved THEIR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TO_US')
    l2.daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')

    t.cancel()

    # Now, 100 blocks it should be done.
    bitcoind.generate_block(100)
    wait_for(lambda: l1.rpc.listpeers()['peers'] == [])
    wait_for(lambda: l2.rpc.listpeers()['peers'] == [])


def setup_multihtlc_test(node_factory, bitcoind):
    # l1 -> l2 -> l3 -> l4 -> l5 -> l6 -> l7
    # l1 and l7 ignore and HTLCs they're sent.
    # For each direction, we create these HTLCs with same payment_hash:
    #   1 failed (CLTV1)
    #   1 failed (CLTV2)
    #   2 live (CLTV2)
    #   1 live (CLTV3)
    nodes = node_factory.line_graph(7, wait_for_announce=True,
                                    opts={'dev-no-reconnect': None,
                                          'may_reconnect': True})

    # Balance by pushing half the funds.
    b11 = nodes[-1].rpc.invoice(10**9 // 2, '1', 'balancer')['bolt11']
    nodes[0].rpc.pay(b11)

    nodes[0].rpc.dev_ignore_htlcs(id=nodes[1].info['id'], ignore=True)
    nodes[-1].rpc.dev_ignore_htlcs(id=nodes[-2].info['id'], ignore=True)

    preimage = "0" * 64
    h = nodes[0].rpc.invoice(msatoshi=10**8, label='x', description='desc',
                             preimage=preimage)['payment_hash']
    nodes[-1].rpc.invoice(msatoshi=10**8, label='x', description='desc',
                          preimage=preimage)['payment_hash']

    # First, the failed attempts (paying wrong node).  CLTV1
    r = nodes[0].rpc.getroute(nodes[-2].info['id'], 10**8, 1)["route"]
    nodes[0].rpc.sendpay(r, h)
    with pytest.raises(RpcError, match=r'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        nodes[0].rpc.waitsendpay(h)

    r = nodes[-1].rpc.getroute(nodes[1].info['id'], 10**8, 1)["route"]
    nodes[-1].rpc.sendpay(r, h)
    with pytest.raises(RpcError, match=r'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        nodes[-1].rpc.waitsendpay(h)

    # Now increment CLTV -> CLTV2
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, nodes)

    # Now, the live attempts with CLTV2 (blackholed by end nodes)
    r = nodes[0].rpc.getroute(nodes[-1].info['id'], 10**8, 1)["route"]
    nodes[0].rpc.sendpay(r, h)
    r = nodes[-1].rpc.getroute(nodes[0].info['id'], 10**8, 1)["route"]
    nodes[-1].rpc.sendpay(r, h)

    # We send second HTLC from different node, since they refuse to send
    # multiple with same hash.
    r = nodes[1].rpc.getroute(nodes[-1].info['id'], 10**8, 1)["route"]
    nodes[1].rpc.sendpay(r, h)
    r = nodes[-2].rpc.getroute(nodes[0].info['id'], 10**8, 1)["route"]
    nodes[-2].rpc.sendpay(r, h)

    # Now increment CLTV -> CLTV3.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, nodes)

    r = nodes[2].rpc.getroute(nodes[-1].info['id'], 10**8, 1)["route"]
    nodes[2].rpc.sendpay(r, h)
    r = nodes[-3].rpc.getroute(nodes[0].info['id'], 10**8, 1)["route"]
    nodes[-3].rpc.sendpay(r, h)

    # Make sure HTLCs have reached the end.
    nodes[0].daemon.wait_for_logs(['peer_in WIRE_UPDATE_ADD_HTLC'] * 3)
    nodes[-1].daemon.wait_for_logs(['peer_in WIRE_UPDATE_ADD_HTLC'] * 3)

    return h, nodes


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for dev_ignore_htlcs")
@unittest.skipIf(SLOW_MACHINE and VALGRIND, "slow test")
def test_onchain_multihtlc_our_unilateral(node_factory, bitcoind):
    """Node pushes a channel onchain with multiple HTLCs with same payment_hash """
    h, nodes = setup_multihtlc_test(node_factory, bitcoind)

    mid = len(nodes) // 2

    for i in range(len(nodes) - 1):
        assert only_one(nodes[i].rpc.listpeers(nodes[i + 1].info['id'])['peers'])['connected']

    # Now midnode goes onchain with n+1 channel.
    nodes[mid].rpc.dev_fail(nodes[mid + 1].info['id'])
    nodes[mid].wait_for_channel_onchain(nodes[mid + 1].info['id'])

    bitcoind.generate_block(1)
    nodes[mid].daemon.wait_for_log(' to ONCHAIN')
    nodes[mid + 1].daemon.wait_for_log(' to ONCHAIN')

    # Now, restart and manually reconnect end nodes (so they don't ignore HTLCs)
    # In fact, they'll fail them with WIRE_TEMPORARY_NODE_FAILURE.
    # TODO Remove our reliance on HTLCs failing on startup and the need for
    #      this plugin
    nodes[0].daemon.opts['plugin'] = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')
    nodes[-1].daemon.opts['plugin'] = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')
    nodes[0].restart()
    nodes[-1].restart()

    # We disabled auto-reconnect so we'd detect breakage, so manually reconnect.
    nodes[0].rpc.connect(nodes[1].info['id'], 'localhost', nodes[1].port)
    nodes[-1].rpc.connect(nodes[-2].info['id'], 'localhost', nodes[-2].port)

    # Wait for HTLCs to stabilize.
    nodes[0].daemon.wait_for_logs(['peer_out WIRE_UPDATE_FAIL_HTLC'] * 3)
    nodes[0].daemon.wait_for_log('peer_out WIRE_COMMITMENT_SIGNED')
    nodes[0].daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')
    nodes[-1].daemon.wait_for_logs(['peer_out WIRE_UPDATE_FAIL_HTLC'] * 3)
    nodes[-1].daemon.wait_for_log('peer_out WIRE_COMMITMENT_SIGNED')
    nodes[-1].daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

    # After at depth 5, midnode will spend its own to-self output.
    bitcoind.generate_block(4)
    nodes[mid].wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                           'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # The three outgoing HTLCs time out at 21, 21 and 22 blocks.
    bitcoind.generate_block(16)
    nodes[mid].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                           'OUR_UNILATERAL/OUR_HTLC')
    nodes[mid].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                           'OUR_UNILATERAL/OUR_HTLC')
    bitcoind.generate_block(1)
    nodes[mid].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                           'OUR_UNILATERAL/OUR_HTLC')

    # And three more for us to consider them all settled.
    bitcoind.generate_block(3)

    # Now, those nodes should have correctly failed the HTLCs
    for n in nodes[:mid - 1]:
        with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE'):
            n.rpc.waitsendpay(h, TIMEOUT)

    # Other timeouts are 27,27,28 blocks.
    bitcoind.generate_block(2)
    nodes[mid].daemon.wait_for_logs(['Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC'] * 2)
    for _ in range(2):
        nodes[mid + 1].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                                   'THEIR_UNILATERAL/OUR_HTLC')
    bitcoind.generate_block(1)
    nodes[mid].daemon.wait_for_log('Ignoring output.*: OUR_UNILATERAL/THEIR_HTLC')
    nodes[mid + 1].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                               'THEIR_UNILATERAL/OUR_HTLC')

    # Depth 3 to consider it settled.
    bitcoind.generate_block(3)

    for n in nodes[mid + 1:]:
        with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE'):
            n.rpc.waitsendpay(h, TIMEOUT)

    # At depth 100 it's all done (we didn't bother waiting for mid+1's
    # spends, so that might still be going)
    bitcoind.generate_block(97)
    nodes[mid].daemon.wait_for_logs(['onchaind complete, forgetting peer'])

    # No other channels should have failed.
    for i in range(len(nodes) - 1):
        if i != mid:
            assert only_one(nodes[i].rpc.listpeers(nodes[i + 1].info['id'])['peers'])['connected']


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1 for dev_ignore_htlcs")
@unittest.skipIf(SLOW_MACHINE and VALGRIND, "slow test")
def test_onchain_multihtlc_their_unilateral(node_factory, bitcoind):
    """Node pushes a channel onchain with multiple HTLCs with same payment_hash """
    h, nodes = setup_multihtlc_test(node_factory, bitcoind)

    mid = len(nodes) // 2

    for i in range(len(nodes) - 1):
        assert only_one(nodes[i].rpc.listpeers(nodes[i + 1].info['id'])['peers'])['connected']

    # Now midnode+1 goes onchain with midnode channel.
    nodes[mid + 1].rpc.dev_fail(nodes[mid].info['id'])
    nodes[mid + 1].wait_for_channel_onchain(nodes[mid].info['id'])

    bitcoind.generate_block(1)
    nodes[mid].daemon.wait_for_log(' to ONCHAIN')
    nodes[mid + 1].daemon.wait_for_log(' to ONCHAIN')

    # Now, restart and manually reconnect end nodes (so they don't ignore HTLCs)
    # In fact, they'll fail them with WIRE_TEMPORARY_NODE_FAILURE.
    # TODO Remove our reliance on HTLCs failing on startup and the need for
    #      this plugin
    nodes[0].daemon.opts['plugin'] = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')
    nodes[-1].daemon.opts['plugin'] = os.path.join(os.getcwd(), 'tests/plugins/fail_htlcs.py')
    nodes[0].restart()
    nodes[-1].restart()

    # We disabled auto-reconnect so we'd detect breakage, so manually reconnect.
    nodes[0].rpc.connect(nodes[1].info['id'], 'localhost', nodes[1].port)
    nodes[-1].rpc.connect(nodes[-2].info['id'], 'localhost', nodes[-2].port)

    # Wait for HTLCs to stabilize.
    nodes[0].daemon.wait_for_logs(['peer_out WIRE_UPDATE_FAIL_HTLC'] * 3)
    nodes[0].daemon.wait_for_log('peer_out WIRE_COMMITMENT_SIGNED')
    nodes[0].daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')
    nodes[-1].daemon.wait_for_logs(['peer_out WIRE_UPDATE_FAIL_HTLC'] * 3)
    nodes[-1].daemon.wait_for_log('peer_out WIRE_COMMITMENT_SIGNED')
    nodes[-1].daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')

    # At depth 5, midnode+1 will spend its own to-self output.
    bitcoind.generate_block(4)
    nodes[mid + 1].wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET')

    # The three outgoing HTLCs time out at depth 21, 21 and 22 blocks.
    bitcoind.generate_block(16)
    nodes[mid].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                           'THEIR_UNILATERAL/OUR_HTLC')
    nodes[mid].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                           'THEIR_UNILATERAL/OUR_HTLC')
    bitcoind.generate_block(1)
    nodes[mid].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                           'THEIR_UNILATERAL/OUR_HTLC')

    # At depth 3 we consider them all settled.
    bitcoind.generate_block(3)

    # Now, those nodes should have correctly failed the HTLCs
    for n in nodes[:mid - 1]:
        with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE'):
            n.rpc.waitsendpay(h, TIMEOUT)

    # Other timeouts are at depths 27,27,28 blocks.
    bitcoind.generate_block(2)
    nodes[mid].daemon.wait_for_logs(['Ignoring output.*: THEIR_UNILATERAL/THEIR_HTLC'] * 2)
    for _ in range(2):
        nodes[mid + 1].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                                   'OUR_UNILATERAL/OUR_HTLC')
    bitcoind.generate_block(1)
    nodes[mid].daemon.wait_for_log('Ignoring output.*: THEIR_UNILATERAL/THEIR_HTLC')
    nodes[mid + 1].wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                               'OUR_UNILATERAL/OUR_HTLC')

    # At depth 3 we consider them all settled.
    bitcoind.generate_block(3)

    for n in nodes[mid + 1:]:
        with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE'):
            n.rpc.waitsendpay(h, TIMEOUT)

    # At depth 5, mid+1 can spend HTLC_TIMEOUT_TX output.
    bitcoind.generate_block(1)
    for _ in range(2):
        nodes[mid + 1].wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                                   'OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US')
    bitcoind.generate_block(1)
    nodes[mid + 1].wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                               'OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US')

    # At depth 100 they're all done.
    bitcoind.generate_block(100)
    nodes[mid].daemon.wait_for_logs(['onchaind complete, forgetting peer'])
    nodes[mid + 1].daemon.wait_for_logs(['onchaind complete, forgetting peer'])

    # No other channels should have failed.
    for i in range(len(nodes) - 1):
        if i != mid:
            assert only_one(nodes[i].rpc.listpeers(nodes[i + 1].info['id'])['peers'])['connected']


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_permfail_htlc_in(node_factory, bitcoind, executor):
    # Test case where we fail with unsettled incoming HTLC.
    disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 10**6)

    # This will fail at l2's end.
    t = executor.submit(l1.pay, l2, 200000000)

    l2.daemon.wait_for_log('dev_disconnect permfail')
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Their unilateral tx, old commit point')
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) after 6 blocks')
    l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TO_US (.*) after 6 blocks')
    # l2 then gets preimage, uses it instead of ignoring
    l2.wait_for_onchaind_broadcast('OUR_HTLC_SUCCESS_TX',
                                   'OUR_UNILATERAL/THEIR_HTLC')
    bitcoind.generate_block(1)

    # OK, l1 sees l2 fulfill htlc.
    l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC gave us preimage')
    l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')
    bitcoind.generate_block(5)

    l2.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US')

    t.cancel()

    # Now, 100 blocks it should be done.
    bitcoind.generate_block(95)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(5)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_permfail_htlc_out(node_factory, bitcoind, executor):
    # Test case where we fail with unsettled outgoing HTLC.
    disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
    l1 = node_factory.get_node(options={'dev-no-reconnect': None})
    # Feerates identical so we don't get gratuitous commit to update them
    l2 = node_factory.get_node(disconnect=disconnects,
                               feerates=(7500, 7500, 7500, 7500))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('openingd-chan#1: Handed peer, entering loop'.format(l1.info['id']))
    l2.fund_channel(l1, 10**6)

    # This will fail at l2's end.
    t = executor.submit(l2.pay, l1, 200000000)

    l2.daemon.wait_for_log('dev_disconnect permfail')
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Their unilateral tx, old commit point')
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_logs([
        'Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TX \\(.*\\) after 6 blocks',
        'Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks'
    ])

    l1.daemon.wait_for_log('Propose handling THEIR_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM \\(IGNORING\\) after 6 blocks')
    # l1 then gets preimage, uses it instead of ignoring
    l1.wait_for_onchaind_broadcast('THEIR_HTLC_FULFILL_TO_US',
                                   'THEIR_UNILATERAL/THEIR_HTLC')

    # l2 sees l1 fulfill tx.
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log('OUR_UNILATERAL/OUR_HTLC gave us preimage')
    t.cancel()

    # l2 can send OUR_DELAYED_RETURN_TO_WALLET after 3 more blocks.
    bitcoind.generate_block(3)
    l2.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # Now, 100 blocks they should be done.
    bitcoind.generate_block(95)
    sync_blockheight(bitcoind, [l1, l2])
    assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    sync_blockheight(bitcoind, [l2])
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(3)
    sync_blockheight(bitcoind, [l2])
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    wait_for(lambda: l2.rpc.listpeers()['peers'] == [])


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_permfail(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2)

    # The funding change should be confirmed and our only output
    assert [o['status'] for o in l1.rpc.listfunds()['outputs']] == ['confirmed']
    l1.pay(l2, 200000000)

    # Make sure l2 has received sig with 0 htlcs!
    l2.daemon.wait_for_log('Received commit_sig with 1 htlc sigs')
    l2.daemon.wait_for_log('Received commit_sig with 0 htlc sigs')

    # Make sure l1 has final revocation.
    l1.daemon.wait_for_log('Sending commit_sig with 1 htlc sigs')
    l1.daemon.wait_for_log('Sending commit_sig with 0 htlc sigs')
    l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # We fail l2, so l1 will reconnect to it.
    l2.rpc.dev_fail(l1.info['id'])
    l2.daemon.wait_for_log('Failing due to dev-fail command')
    l2.wait_for_channel_onchain(l1.info['id'])

    assert l1.bitcoin.rpc.getmempoolinfo()['size'] == 1

    # Now grab the close transaction
    closetxid = only_one(l1.bitcoin.rpc.getrawmempool(False))

    # l2 will send out tx (l1 considers it a transient error)
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log('Their unilateral tx, old commit point')
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log('Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET (.*) after 5 blocks')

    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status']
             == ['ONCHAIN:Tracking their unilateral close',
                 'ONCHAIN:All outputs resolved: waiting 99 more blocks before forgetting channel'])

    def check_billboard():
        billboard = only_one(l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'])['status']
        return (
            len(billboard) == 2
            and billboard[0] == 'ONCHAIN:Tracking our own unilateral close'
            and re.fullmatch(r'ONCHAIN:.* outputs unresolved: in 4 blocks will spend DELAYED_OUTPUT_TO_US \(.*:0\) using OUR_DELAYED_RETURN_TO_WALLET', billboard[1])
        )
    wait_for(check_billboard)

    # Now, mine 4 blocks so it sends out the spending tx.
    bitcoind.generate_block(4)

    # onchaind notes to-local payment immediately.
    assert (closetxid, "confirmed") in set([(o['txid'], o['status']) for o in l1.rpc.listfunds()['outputs']])

    # Restart, should still be confirmed (fails: unwinding blocks erases
    # the confirmation, and we don't re-make it).
    l1.restart()
    wait_for(lambda: (closetxid, "confirmed") in set([(o['txid'], o['status']) for o in l1.rpc.listfunds()['outputs']]))

    # It should send the to-wallet tx.
    l2.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # 100 after l1 sees tx, it should be done.
    bitcoind.generate_block(95)
    wait_for(lambda: l1.rpc.listpeers()['peers'] == [])

    wait_for(lambda: only_one(l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'])['status'] == [
        'ONCHAIN:Tracking our own unilateral close',
        'ONCHAIN:All outputs resolved: waiting 5 more blocks before forgetting channel'
    ])

    # Now, 100 blocks l2 should be done.
    bitcoind.generate_block(5)
    wait_for(lambda: l2.rpc.listpeers()['peers'] == [])

    # Only l1 has a direct output since all of l2's outputs are respent (it
    # failed). Also the output should now be listed as confirmed since we
    # generated some more blocks.
    assert (closetxid, "confirmed") in set([(o['txid'], o['status']) for o in l1.rpc.listfunds()['outputs']])

    # Check that the all the addresses match what we generated ourselves:
    for o in l1.rpc.listfunds()['outputs']:
        txout = bitcoind.rpc.gettxout(o['txid'], o['output'])
        addr = txout['scriptPubKey']['addresses'][0]
        assert(addr == o['address'])

    addr = l1.bitcoin.getnewaddress()
    l1.rpc.withdraw(addr, "all")


@unittest.skipIf(not DEVELOPER, "needs DEVELOPER=1")
def test_shutdown(node_factory):
    # Fail, in that it will exit before cleanup.
    l1 = node_factory.get_node(may_fail=True)
    if not VALGRIND:
        leaks = l1.rpc.dev_memleak()['leaks']
        if len(leaks):
            raise Exception("Node {} has memory leaks: {}"
                            .format(l1.daemon.lightning_dir, leaks))
    l1.rpc.stop()


@flaky
@unittest.skipIf(not DEVELOPER, "needs to set upfront_shutdown_script")
def test_option_upfront_shutdown_script(node_factory, bitcoind, executor):
    l1 = node_factory.get_node(start=False)
    # Insist on upfront script we're not going to match.
    l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = "76a91404b61f7dc1ea0dc99424464cc4064dc564d91e8988ac"
    l1.start()

    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 1000000, False)

    # This will block, as l12 will send an error but l2 will retry.
    fut = executor.submit(l1.rpc.close, l2.info['id'])

    # l2 will close unilaterally when it dislikes shutdown script.
    l1.daemon.wait_for_log(r'scriptpubkey .* is not as agreed upfront \(76a91404b61f7dc1ea0dc99424464cc4064dc564d91e8988ac\)')

    # Clear channel.
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) != 0)
    bitcoind.generate_block(1)
    fut.result(TIMEOUT)
    wait_for(lambda: [c['state'] for c in only_one(l1.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN'])
    wait_for(lambda: [c['state'] for c in only_one(l2.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN'])

    # Works when l2 closes channel, too.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fund_channel(l2, 1000000, False)

    l2.rpc.close(l1.info['id'])

    # l2 will close unilaterally when it dislikes shutdown script.
    l1.daemon.wait_for_log(r'scriptpubkey .* is not as agreed upfront \(76a91404b61f7dc1ea0dc99424464cc4064dc564d91e8988ac\)')

    # Clear channel.
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) != 0)
    bitcoind.generate_block(1)
    wait_for(lambda: [c['state'] for c in only_one(l1.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN', 'ONCHAIN'])
    wait_for(lambda: [c['state'] for c in only_one(l2.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN', 'ONCHAIN'])

    # Figure out what address it will try to use.
    keyidx = int(l1.db_query("SELECT intval FROM vars WHERE name='bip32_max_index';")[0]['intval'])

    # Expect 1 for change address, 1 for the channel final address,
    # which are discarded as the 'scratch' tx that the fundchannel
    # plugin makes, plus 1 for the funding address of the actual
    # funding tx.
    addr = l1.rpc.call('dev-listaddrs', [keyidx + 3])['addresses'][-1]

    # Now, if we specify upfront and it's OK, all good.
    l1.stop()
    # We need to prepend the segwit version (0) and push opcode (14).
    l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = '0014' + addr['bech32_redeemscript']
    l1.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 1000000)
    l1.rpc.close(l2.info['id'])
    wait_for(lambda: sorted([c['state'] for c in only_one(l1.rpc.listpeers()['peers'])['channels']]) == ['CLOSINGD_COMPLETE', 'ONCHAIN', 'ONCHAIN'])
