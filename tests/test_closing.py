from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError, Millisatoshi
from shutil import copyfile
from pyln.testing.utils import SLOW_MACHINE
from utils import (
    only_one, sync_blockheight, wait_for, TIMEOUT,
    account_balance, first_channel_id, closing_fee, TEST_NETWORK,
    scriptpubkey_addr, calc_lease_fee, EXPERIMENTAL_FEATURES,
    check_utxos_channel, anchor_expected, check_coin_moves,
    check_balance_snaps, mine_funding_to_announce
)

import os
import queue
import pytest
import re
import subprocess
import threading
import unittest


@pytest.mark.developer("Too slow without --dev-bitcoind-poll")
def test_closing_simple(node_factory, bitcoind, chainparams):
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1, l2 = node_factory.line_graph(2, opts={'plugin': coin_mvt_plugin})
    chan = l1.get_channel_scid(l2)
    channel_id = first_channel_id(l1, l2)
    fee = closing_fee(3750, 2) if not chainparams['elements'] else 4263

    l1.pay(l2, 200000000)

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    billboard = only_one(l1.rpc.listpeers(l2.info['id'])['peers'][0]['channels'])['status']
    assert billboard == ['CHANNELD_NORMAL:Funding transaction locked.']
    billboard = only_one(l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'])['status']
    assert billboard == ['CHANNELD_NORMAL:Funding transaction locked.']

    bitcoind.generate_block(5)

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

    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    expected_1 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('external', ['to_them'], None, None)],
    }

    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('external', ['to_them'], None, None)],
    }
    tags = check_utxos_channel(l1, [channel_id], expected_1)
    check_utxos_channel(l2, [channel_id], expected_2, tags)


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


def test_closing_disconnected_notify(node_factory, bitcoind, executor):
    l1, l2 = node_factory.line_graph(2)

    l1.pay(l2, 200000000)
    l2.stop()
    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])

    out = subprocess.check_output(['cli/lightning-cli',
                                   '--network={}'.format(TEST_NETWORK),
                                   '--lightning-dir={}'
                                   .format(l1.daemon.lightning_dir),
                                   'close',
                                   l2.info['id'],
                                   '5']).decode('utf-8').splitlines()
    assert out[0] == '# peer is offline, will negotiate once they reconnect (5 seconds before unilateral close).'
    assert out[1] == '# Timed out, forcing close.'
    assert not any([line.startswith('#') for line in out[2:]])


def test_closing_id(node_factory):
    """Test closing using peer ID and full channel ID
    """
    l1, l2 = node_factory.get_nodes(2)

    # Close by full channel ID.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)
    cid = l2.rpc.listpeers()['peers'][0]['channels'][0]['channel_id']
    l2.rpc.close(cid)
    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    wait_for(lambda: not only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])

    # Close by peer ID.
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l1.daemon.wait_for_log("Handed peer, entering loop")
    l2.fundchannel(l1, 10**6)
    pid = l1.info['id']
    l2.rpc.close(pid)
    wait_for(lambda: not only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'])
    wait_for(lambda: not only_one(l2.rpc.listpeers(l1.info['id'])['peers'])['connected'])


@unittest.skipIf(TEST_NETWORK != 'regtest', 'FIXME: broken under elements')
@pytest.mark.slow_test
def test_closing_different_fees(node_factory, bitcoind, executor):
    l1 = node_factory.get_node()

    # Default feerate = 15000/11000/7500/1000
    # It will start at the second number, accepting anything above the first.
    feerates = [[20000, 11000, 15000, 7400], [8000, 6000, 1001, 100]]
    balance = [False, True]
    num_peers = len(feerates) * len(balance)

    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 1)
    numfunds = len(l1.rpc.listfunds()['outputs'])
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > numfunds)

    # Create them in a batch, for speed!
    peers = []
    for feerate in feerates:
        for b in balance:
            p = node_factory.get_node(feerates=feerate)
            p.feerate = feerate
            p.balance = balance
            l1.rpc.connect(p.info['id'], 'localhost', p.port)
            peers.append(p)

    for p in peers:
        p.channel = l1.rpc.fundchannel(p.info['id'], 10**6, minconf=0)['channel_id']
        # Technically, this is async to fundchannel returning.
        l1.daemon.wait_for_log('sendrawtx exit 0')

    mine_funding_to_announce(bitcoind, peers, num_blocks=6)

    # Now wait for them all to hit normal state, do payments
    l1.daemon.wait_for_logs(['update for channel .* now ACTIVE'] * num_peers
                            + ['to CHANNELD_NORMAL'] * num_peers)
    for p in peers:
        if p.balance:
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


@pytest.mark.developer("needs DEVELOPER=1")
def test_closing_negotiation_reconnect(node_factory, bitcoind):
    disconnects = ['-WIRE_CLOSING_SIGNED',
                   '+WIRE_CLOSING_SIGNED']
    l1, l2 = node_factory.line_graph(2, opts=[{'disconnect': disconnects,
                                               'may_reconnect': True},
                                              {'may_reconnect': True}])
    l1.pay(l2, 200000000)

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    l1.rpc.close(l2.info['id'])
    l1.daemon.wait_for_log(r'State changed from CHANNELD_NORMAL to CHANNELD_SHUTTING_DOWN')
    l2.daemon.wait_for_log(r'State changed from CHANNELD_NORMAL to CHANNELD_SHUTTING_DOWN')

    # Now verify that the closing tx is in the mempool.
    bitcoind.generate_block(6, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])
    for n in [l1, l2]:
        # Ensure we actually got a mutual close.
        n.daemon.wait_for_log(r'Resolved FUNDING_TRANSACTION/FUNDING_OUTPUT by MUTUAL_CLOSE')


@pytest.mark.developer("needs DEVELOPER=1")
def test_closing_specified_destination(node_factory, bitcoind, chainparams):
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)

    chan12, _ = l1.fundchannel(l2, 10**6)
    chan13, _ = l1.fundchannel(l3, 10**6)
    chan14, _ = l1.fundchannel(l4, 10**6)

    l1.pay(l2, 100000000)
    l1.pay(l3, 100000000)
    l1.pay(l4, 100000000)

    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])

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
        assert addr == scriptpubkey_addr(bitcoind.rpc.gettxout(closetx, output_num1)['scriptPubKey'])
        assert 1 == bitcoind.rpc.gettxout(closetx, output_num1)['confirmations']


def closing_negotiation_step(node_factory, bitcoind, chainparams, opts):
    def feerate_for(target, minimum=0, maximum=10000000):
        """Binary search to find feerate"""
        assert minimum != maximum
        mid = (minimum + maximum) // 2
        mid_fee = closing_fee(mid, 1)
        if mid_fee > target:
            return feerate_for(target, minimum, mid)
        elif mid_fee < target:
            return feerate_for(target, mid, maximum)
        else:
            return mid

    orate = feerate_for(21000)  # closing fee negotiation starts at 21000
    prate = feerate_for(20000)  # closing fee negotiation starts at 20000
    opener, peer = node_factory.line_graph(2, opts=[{'feerates': (orate, orate, orate, orate)},
                                                    {'feerates': (prate, prate, prate, prate)}])

    opener_id = opener.info['id']
    peer_id = peer.info['id']

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    if opts['close_initiated_by'] == 'opener':
        opener.rpc.close(peer_id=peer_id, fee_negotiation_step=opts['fee_negotiation_step'])
    else:
        assert opts['close_initiated_by'] == 'peer'
        peer.rpc.close(peer_id=opener_id, fee_negotiation_step=opts['fee_negotiation_step'])

    # Get the proclaimed closing fee from the two nodes' statuses

    status_agreed_regex = re.compile("agreed on a closing fee of ([0-9]+) satoshi")

    # [fee_from_opener_status, fee_from_peer_status]
    fees_from_status = [None, None]

    def get_fee_from_status(node, peer_id, i):
        nonlocal fees_from_status
        peer = only_one(node.rpc.listpeers(peer_id)['peers'])
        channel = only_one(peer['channels'])
        status = channel['status'][0]

        m = status_agreed_regex.search(status)
        if not m:
            return False

        fees_from_status[i] = int(m.group(1))
        return True

    wait_for(lambda: get_fee_from_status(opener, peer_id, 0))
    wait_for(lambda: get_fee_from_status(peer, opener_id, 1))

    assert opts['expected_close_fee'] == fees_from_status[0]
    assert opts['expected_close_fee'] == fees_from_status[1]

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
    # v22.99.0-8fe6f5a6fbcd at least doesn't have 'fee', it has 'fees'.
    if 'fees' in mempool[close_tx_id]:
        fee_mempool = round(mempool[close_tx_id]['fees']['base'] * 10**8)
    else:
        fee_mempool = round(mempool[close_tx_id]['fee'] * 10**8)

    assert opts['expected_close_fee'] == fee_mempool


@unittest.skipIf(EXPERIMENTAL_FEATURES, "anchors uses quick-close, not negotiation")
@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Different closing fees")
def test_closing_negotiation_step_30pct(node_factory, bitcoind, chainparams):
    """Test that the closing fee negotiation step works, 30%"""
    opts = {}
    opts['fee_negotiation_step'] = '30%'

    opts['close_initiated_by'] = 'opener'
    opts['expected_close_fee'] = 20537
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)

    opts['close_initiated_by'] = 'peer'
    opts['expected_close_fee'] = 20233
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)


@unittest.skipIf(EXPERIMENTAL_FEATURES, "anchors uses quick-close, not negotiation")
@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Different closing fees")
def test_closing_negotiation_step_100pct(node_factory, bitcoind, chainparams):
    """Test that the closing fee negotiation step works, 100%"""
    opts = {}
    opts['fee_negotiation_step'] = '100%'

    opts['close_initiated_by'] = 'opener'
    opts['expected_close_fee'] = 20001
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)

    # The close fee of 20499 looks strange in this case - one would expect
    # to have a number close to 21000. This is because
    # * the range is initially set to [20000 (peer), 21000 (opener)]
    # * the opener is always first to propose, he uses 50% step, so he proposes 20500
    # * the range is narrowed to [20001, 20499] and the peer proposes 20499
    opts['close_initiated_by'] = 'peer'
    opts['expected_close_fee'] = 20499
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)


@unittest.skipIf(EXPERIMENTAL_FEATURES, "anchors uses quick-close, not negotiation")
@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Different closing fees")
def test_closing_negotiation_step_1sat(node_factory, bitcoind, chainparams):
    """Test that the closing fee negotiation step works, 1sat"""
    opts = {}
    opts['fee_negotiation_step'] = '1'

    opts['close_initiated_by'] = 'opener'
    opts['expected_close_fee'] = 20989
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)

    opts['close_initiated_by'] = 'peer'
    opts['expected_close_fee'] = 20010
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)


@unittest.skipIf(EXPERIMENTAL_FEATURES, "anchors uses quick-close, not negotiation")
@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Different closing fees")
def test_closing_negotiation_step_700sat(node_factory, bitcoind, chainparams):
    """Test that the closing fee negotiation step works, 700sat"""
    opts = {}
    opts['fee_negotiation_step'] = '700'

    opts['close_initiated_by'] = 'opener'
    opts['expected_close_fee'] = 20151
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)

    opts['close_initiated_by'] = 'peer'
    opts['expected_close_fee'] = 20499
    closing_negotiation_step(node_factory, bitcoind, chainparams, opts)


@pytest.mark.developer("needs dev-disable-commit-after")
def test_penalty_inhtlc(node_factory, bitcoind, executor, chainparams):
    """Test penalty transaction with an incoming HTLC"""

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    # We suppress each one after first commit; HTLC gets added not fulfilled.
    # Feerates identical so we don't get gratuitous commit to update them
    l1, l2 = node_factory.line_graph(2, opts=[{'dev-disable-commit-after': 1,
                                               'may_fail': True,
                                               'feerates': (7500, 7500, 7500, 7500),
                                               'allow_broken_log': True,
                                               'plugin': coin_mvt_plugin},
                                              {'dev-disable-commit-after': 1,
                                               'plugin': coin_mvt_plugin}])

    channel_id = first_channel_id(l1, l2)

    # Now, this will get stuck due to l1 commit being disabled..
    t = executor.submit(l1.pay, l2, 100000000)

    assert len(l1.getactivechannels()) == 2
    assert len(l2.getactivechannels()) == 2

    # They should both have commitments blocked now.
    l1.daemon.wait_for_log('dev-disable-commit-after: disabling')
    l2.daemon.wait_for_log('dev-disable-commit-after: disabling')

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
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM')
    l2.daemon.logsearch_start = needle
    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/THEIR_HTLC')

    # FIXME: test HTLC tx race!

    bitcoind.generate_block(100)

    sync_blockheight(bitcoind, [l1, l2])
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # Do one last pass over the logs to extract the reactions l2 sent
    l2.daemon.logsearch_start = needle
    needles = [
        # The first needle will match, but since we don't have a direct output
        # for l2 it won't result in an output, hence the comment:
        # r'Resolved FUNDING_TRANSACTION/FUNDING_OUTPUT by THEIR_REVOKED_UNILATERAL .([a-f0-9]{64}).',
        r'Resolved THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM by our proposal OUR_PENALTY_TX .([a-f0-9]{64}).',
        r'Resolved THEIR_REVOKED_UNILATERAL/THEIR_HTLC by our proposal OUR_PENALTY_TX .([a-f0-9]{64}).',
    ]
    matches = list(map(l2.daemon.is_in_log, needles))

    # Now extract the txids for these responses
    txids = set([re.search(r'\(([0-9a-f]{64})\)', m).group(1) for m in matches])

    # We should have one confirmed output for each of the above reactions in
    # the list of funds we own.
    outputs = l2.rpc.listfunds()['outputs']

    assert [o['status'] for o in outputs] == ['confirmed'] * 2
    assert set([o['txid'] for o in outputs]) == txids
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    # l1 loses all of their channel balance to the peer, as penalties
    expected_1 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('external', ['penalty'], None, None), ('external', ['penalty'], None, None)],
    }

    # l2 sweeps all of l1's closing outputs
    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('cid1', ['penalty'], ['to_wallet'], 'C'), ('cid1', ['penalty'], ['to_wallet'], 'D')],
        'C': [('wallet', ['deposit'], None, None)],
        'D': [('wallet', ['deposit'], None, None)]
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    # We use a subset of tags in expected_2 that are used in expected_1
    tags = check_utxos_channel(l1, [channel_id], expected_1)
    check_utxos_channel(l2, [channel_id], expected_2, tags)


@pytest.mark.developer("needs dev-disable-commit-after")
def test_penalty_outhtlc(node_factory, bitcoind, executor, chainparams):
    """Test penalty transaction with an outgoing HTLC"""

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    # First we need to get funds to l2, so suppress after second.
    # Feerates identical so we don't get gratuitous commit to update them
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'dev-disable-commit-after': 3,
                                            'may_fail': True,
                                            'feerates': (7500, 7500, 7500, 7500),
                                            'allow_broken_log': True,
                                            'plugin': coin_mvt_plugin},
                                           {'dev-disable-commit-after': 3,
                                            'plugin': coin_mvt_plugin}])
    channel_id = first_channel_id(l1, l2)

    # Move some across to l2.
    l1.pay(l2, 200000000)

    assert not l1.daemon.is_in_log('dev-disable-commit-after: disabling')
    assert not l2.daemon.is_in_log('dev-disable-commit-after: disabling')

    # Now, this will get stuck due to l1 commit being disabled..
    t = executor.submit(l2.pay, l1, 100000000)

    # Make sure we get signature from them.
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_ADD_HTLC')
    l1.daemon.wait_for_log('peer_in WIRE_COMMITMENT_SIGNED')

    # They should both have commitments blocked now.
    l1.daemon.wait_for_log('dev-disable-commit-after: disabling')
    l2.daemon.wait_for_log('dev-disable-commit-after: disabling')

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
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM')
    l2.daemon.logsearch_start = needle
    l2.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/OUR_HTLC')

    l2.daemon.logsearch_start = needle
    l2.daemon.wait_for_log('Ignoring output.*: THEIR_REVOKED_UNILATERAL/OUTPUT_TO_US')

    # FIXME: test HTLC tx race!

    # 100 blocks later, all resolved.
    bitcoind.generate_block(100)

    sync_blockheight(bitcoind, [l1, l2])
    wait_for(lambda: len(l2.rpc.listpeers()['peers']) == 0)

    # Do one last pass over the logs to extract the reactions l2 sent
    l2.daemon.logsearch_start = needle
    needles = [
        r'Resolved FUNDING_TRANSACTION/FUNDING_OUTPUT by THEIR_REVOKED_UNILATERAL .([a-f0-9]{64}).',
        r'Resolved THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM by our proposal OUR_PENALTY_TX .([a-f0-9]{64}).',
        r'Resolved THEIR_REVOKED_UNILATERAL/OUR_HTLC by our proposal OUR_PENALTY_TX .([a-f0-9]{64}).',
    ]
    matches = list(map(l2.daemon.is_in_log, needles))

    # Now extract the txids for these responses
    txids = set([re.search(r'\(([0-9a-f]{64})\)', m).group(1) for m in matches])

    # We should have one confirmed output for each of the above reactions in
    # the list of funds we own.
    outputs = l2.rpc.listfunds()['outputs']

    assert [o['status'] for o in outputs] == ['confirmed'] * 3
    assert set([o['txid'] for o in outputs]) == txids
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    # l1 loses all of their channel balance to the peer, as penalties
    expected_1 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('external', ['penalty'], None, None), ('external', ['penalty'], None, None), ('external', ['penalty'], None, None)],
    }

    # l2 sweeps all of l1's closing outputs
    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('cid1', ['penalty'], ['to_wallet'], 'C'), ('cid1', ['penalty'], ['to_wallet'], 'D')],
        'C': [('wallet', ['deposit'], None, None)],
        'D': [('wallet', ['deposit'], None, None)]
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    # We use a subset of tags in expected_2 that are used in expected_1
    tags = check_utxos_channel(l1, [channel_id], expected_1)
    check_utxos_channel(l2, [channel_id], expected_2, tags)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
@pytest.mark.slow_test
@pytest.mark.developer("requres 'dev-queryrates'")
def test_channel_lease_falls_behind(node_factory, bitcoind):
    '''
    If our peer falls too far behind/doesn't send us an update for
    their blockheight, the lessor fails the channel
    '''
    opts = [{'funder-policy': 'match', 'funder-policy-mod': 100,
             'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100},
            {'funder-policy': 'match', 'funder-policy-mod': 100,
             'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100}]
    l1, l2, = node_factory.get_nodes(2, opts=opts)
    amount = 500000
    feerate = 2000
    l1.fundwallet(20000000)
    l2.fundwallet(20000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    rates = l1.rpc.dev_queryrates(l2.info['id'], amount, amount)
    wait_for(lambda: len(l1.rpc.listpeers(l2.info['id'])['peers']) == 0)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l1 leases a channel from l2
    l1.rpc.fundchannel(l2.info['id'], amount, request_amt=amount,
                       feerate='{}perkw'.format(feerate),
                       compact_lease=rates['compact_lease'])

    # sink the funding transaction
    bitcoind.generate_block(1, wait_for_mempool=1)

    # stop l1
    l1.stop()

    # advance blockchain 1008 blocks, the lessor should drop to chain
    bitcoind.generate_block(1008)
    sync_blockheight(bitcoind, [l2])

    l2.daemon.wait_for_log('Offline peer is too far behind, terminating')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
@pytest.mark.developer("requres 'dev-queryrates'")
@pytest.mark.slow_test
def test_channel_lease_post_expiry(node_factory, bitcoind, chainparams):

    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    opts = {'funder-policy': 'match', 'funder-policy-mod': 100,
            'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
            'may_reconnect': True, 'plugin': coin_mvt_plugin}

    l1, l2, = node_factory.get_nodes(2, opts=opts)

    feerate = 2000
    amount = 500000
    l1.fundwallet(20000000)
    l2.fundwallet(20000000)

    # l1 leases a channel from l2
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    rates = l1.rpc.dev_queryrates(l2.info['id'], amount, amount)
    wait_for(lambda: len(l1.rpc.listpeers(l2.info['id'])['peers']) == 0)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], amount, request_amt=amount,
                       feerate='{}perkw'.format(feerate),
                       compact_lease=rates['compact_lease'])

    est_fees = calc_lease_fee(amount, feerate, rates)

    # This should be the accepter's amount
    fundings = only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['funding']
    assert Millisatoshi(est_fees + amount * 1000) == Millisatoshi(fundings['remote_msat'])

    bitcoind.generate_block(6)
    l1.daemon.wait_for_log('to CHANNELD_NORMAL')
    channel_id = first_channel_id(l1, l2)

    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(l1.get_channel_scid(l2))['channels']] == [True, True])

    # send some payments, mine a block or two
    inv = l2.rpc.invoice(10**4, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    # l2 attempts to close a channel that it leased, should fail
    with pytest.raises(RpcError, match=r'Peer leased this channel from us'):
        l2.rpc.close(l1.get_channel_scid(l2))

    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1, l2])
    # make sure we're at the right place for the csv lock
    l2.daemon.wait_for_log('Blockheight: SENT_ADD_ACK_COMMIT->RCVD_ADD_ACK_REVOCATION LOCAL now 115')

    # We need to give l1-l2 time to update their blockheights
    bitcoind.generate_block(1000)
    sync_blockheight(bitcoind, [l1, l2])
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_BLOCKHEIGHT')

    bitcoind.generate_block(1000)
    sync_blockheight(bitcoind, [l1, l2])
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_BLOCKHEIGHT')

    bitcoind.generate_block(1000)
    sync_blockheight(bitcoind, [l1, l2])
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_BLOCKHEIGHT')

    bitcoind.generate_block(1000)
    sync_blockheight(bitcoind, [l1, l2])
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_BLOCKHEIGHT')

    bitcoind.generate_block(32)
    sync_blockheight(bitcoind, [l1, l2])
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_BLOCKHEIGHT')

    # l1<->l2 mutual close should work
    chan = l1.get_channel_scid(l2)
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l1.rpc.close(chan)
    l2.daemon.wait_for_log('State changed from CLOSINGD_SIGEXCHANGE to CLOSINGD_COMPLETE')

    bitcoind.generate_block(2)
    sync_blockheight(bitcoind, [l1, l2])
    l1.daemon.wait_for_log('Resolved FUNDING_TRANSACTION/FUNDING_OUTPUT by MUTUAL_CLOSE')
    l2.daemon.wait_for_log('Resolved FUNDING_TRANSACTION/FUNDING_OUTPUT by MUTUAL_CLOSE')

    channel_mvts_1 = [
        {'type': 'chain_mvt', 'credit_msat': 506432000, 'debit_msat': 0, 'tags': ['channel_open', 'opener', 'leased']},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 6432000, 'tags': ['lease_fee'], 'fees_msat': '0msat'},
        {'type': 'channel_mvt', 'credit_msat': 0, 'debit_msat': 10000, 'tags': ['invoice'], 'fees_msat': '0msat'},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 499990000, 'tags': ['channel_close']},
    ]

    channel_mvts_2 = [
        {'type': 'chain_mvt', 'credit_msat': 500000000, 'debit_msat': 0, 'tags': ['channel_open', 'leased']},
        {'type': 'channel_mvt', 'credit_msat': 6432000, 'debit_msat': 0, 'tags': ['lease_fee'], 'fees_msat': '0msat'},
        {'type': 'channel_mvt', 'credit_msat': 10000, 'debit_msat': 0, 'tags': ['invoice'], 'fees_msat': '0msat'},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 506442000, 'tags': ['channel_close']},
    ]

    check_coin_moves(l1, channel_id, channel_mvts_1, chainparams)
    check_coin_moves(l2, channel_id, channel_mvts_2, chainparams)
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
@pytest.mark.slow_test
@pytest.mark.developer("requres 'dev-queryrates'")
def test_channel_lease_unilat_closes(node_factory, bitcoind):
    '''
    Check that channel leases work

    l1-l2: l1 leases funds from l2; l1 goes to chain unilaterally
    l2-l3: l2 leases funds from l3; l3 goes to chain unilaterally
    '''
    opts = {'funder-policy': 'match', 'funder-policy-mod': 100,
            'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
            'funder-lease-requests-only': False}

    l1, l2, l3 = node_factory.get_nodes(3, opts=opts)
    # Allow l2 some warnings
    l2.allow_warning = True

    feerate = 2000
    amount = 500000
    l1.fundwallet(20000000)
    l2.fundwallet(20000000)
    l3.fundwallet(20000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    rates = l1.rpc.dev_queryrates(l2.info['id'], amount, amount)
    wait_for(lambda: len(l1.rpc.listpeers(l2.info['id'])['peers']) == 0)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l1 leases a channel from l2
    l1.rpc.fundchannel(l2.info['id'], amount, request_amt=amount,
                       feerate='{}perkw'.format(feerate),
                       compact_lease=rates['compact_lease'])

    # l2 leases a channel from l3
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    rates = l2.rpc.dev_queryrates(l3.info['id'], amount, amount)
    wait_for(lambda: len(l2.rpc.listpeers(l3.info['id'])['peers']) == 0)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.rpc.fundchannel(l3.info['id'], amount, request_amt=amount,
                       feerate='{}perkw'.format(feerate), minconf=0,
                       compact_lease=rates['compact_lease'])

    est_fees = calc_lease_fee(amount, feerate, rates)

    # This should be the accepter's amount
    fundings = only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['funding']
    assert Millisatoshi(est_fees + amount * 1000) == Millisatoshi(fundings['remote_msat'])

    bitcoind.generate_block(6)
    l1.daemon.wait_for_log('to CHANNELD_NORMAL')
    l3.daemon.wait_for_log('to CHANNELD_NORMAL')

    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(l1.get_channel_scid(l2))['channels']] == [True, True])
    wait_for(lambda: [c['active'] for c in l3.rpc.listchannels(l3.get_channel_scid(l2))['channels']] == [True, True])

    # send some payments, mine a block or two
    inv = l2.rpc.invoice(10**4, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])
    inv = l2.rpc.invoice(10**4, '3', 'no_3')
    l3.rpc.pay(inv['bolt11'])

    bitcoind.generate_block(6)
    sync_blockheight(bitcoind, [l1, l2, l3])
    # make sure we're at the right place for the csv lock
    l2.daemon.wait_for_log('Blockheight: SENT_ADD_ACK_COMMIT->RCVD_ADD_ACK_REVOCATION LOCAL now 110')
    l2.stop()

    # unilateral close channels l1<->l2 & l3<->l2
    l1.rpc.close(l2.info['id'], 1)
    l3.rpc.close(l2.info['id'], 1, force_lease_closed=True)

    # Wait til to_self_delay expires, l1 should claim to_local back
    bitcoind.generate_block(10, wait_for_mempool=2)
    l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
    bitcoind.generate_block(1, wait_for_mempool=1)
    l1.daemon.wait_for_log('Resolved OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by our proposal OUR_DELAYED_RETURN_TO_WALLET')
    assert len(l1.rpc.listfunds()['outputs']) == 2

    l2.start()
    search_start = l2.daemon.logsearch_start
    log = l2.daemon.wait_for_log('adding utxo to watch .* csv 40.*')
    utxo1 = re.match('.* adding utxo to watch (.*), csv .*', log).group(1)

    l2.daemon.logsearch_start = search_start
    log = l2.daemon.wait_for_log('adding utxo to watch .* csv 1')
    utxo3 = re.match('.* adding utxo to watch (.*), csv 1', log).group(1)

    # we *shouldn't* be able to spend it, there's a lock on it
    with pytest.raises(RpcError, match='UTXO .* is csv locked'):
        l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], "all", utxos=[utxo1])

    # we *can* spend the 1csv lock one
    l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], "all", utxos=[utxo3])

    # This can timeout, so do it in four easy stages.
    for i in range(4):
        bitcoind.generate_block(4032 // 4)
        sync_blockheight(bitcoind, [l2, l3])

    l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], "all", utxos=[utxo1])

    # l3 cleans up their to-self after their lease expires
    assert l3.daemon.is_in_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@pytest.mark.developer("requres 'dev-queryrates'")
def test_channel_lease_lessor_cheat(node_factory, bitcoind, chainparams):
    '''
    Check that lessee can recover funds if lessor cheats
    '''
    balance_snaps = os.path.join(os.getcwd(), 'tests/plugins/balance_snaps.py')
    opts = [{'funder-policy': 'match', 'funder-policy-mod': 100,
             'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
             'may_reconnect': True, 'allow_warning': True,
             'plugin': balance_snaps},
            {'funder-policy': 'match', 'funder-policy-mod': 100,
             'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
             'may_reconnect': True, 'allow_broken_log': True,
             'plugin': balance_snaps}]
    l1, l2, = node_factory.get_nodes(2, opts=opts)
    amount = 500000
    feerate = 2000
    l1.fundwallet(20000000)
    l2.fundwallet(20000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    rates = l1.rpc.dev_queryrates(l2.info['id'], amount, amount)
    wait_for(lambda: len(l1.rpc.listpeers(l2.info['id'])['peers']) == 0)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l1 leases a channel from l2
    l1.rpc.fundchannel(l2.info['id'], amount, request_amt=amount,
                       feerate='{}perkw'.format(feerate),
                       compact_lease=rates['compact_lease'])

    bitcoind.generate_block(6)
    l1.daemon.wait_for_log('to CHANNELD_NORMAL')
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(l1.get_channel_scid(l2))['channels']] == [True, True])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels(l2.get_channel_scid(l1))['channels']] == [True, True])
    # send some payments, mine a block or two
    inv = l2.rpc.invoice(10**4, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    bitcoind.generate_block(1)

    # make database snapshot of l2
    l2.stop()
    l2_db_path = os.path.join(l2.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3')
    l2_db_path_bak = os.path.join(l2.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3.bak')
    copyfile(l2_db_path, l2_db_path_bak)
    l2.start(wait_for_bitcoind_sync=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    sync_blockheight(bitcoind, [l2])

    # push some money from l2->l1, so the commit counter advances
    inv = l1.rpc.invoice(10**5, '2', 'no_2')
    l2.rpc.pay(inv['bolt11'])

    # stop both nodes, roll back l2's database
    l2.stop()
    l1.stop()
    copyfile(l2_db_path_bak, l2_db_path)

    # start l2 and force close channel with l1 while l1 is still offline
    l2.start()
    sync_blockheight(bitcoind, [l2])
    l2.rpc.close(l1.info['id'], 1, force_lease_closed=True)
    bitcoind.generate_block(1, wait_for_mempool=1)

    l1.start()
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_logs(['Broadcasting OUR_PENALTY_TX',
                             ' Propose handling THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM by OUR_PENALTY_TX'])

    bitcoind.generate_block(1, wait_for_mempool=1)
    # l2 sees that l1 has spent their coins!
    l2.daemon.wait_for_log('Unknown spend of OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@pytest.mark.developer("requres 'dev-queryrates'")
def test_channel_lease_lessee_cheat(node_factory, bitcoind, chainparams):
    '''
    Check that lessor can recover funds if lessee cheats
    '''
    opts = [{'funder-policy': 'match', 'funder-policy-mod': 100,
             'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
             'may_reconnect': True, 'allow_broken_log': True},
            {'funder-policy': 'match', 'funder-policy-mod': 100,
             'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
             'may_reconnect': True}]
    l1, l2, = node_factory.get_nodes(2, opts=opts)
    amount = 500000
    feerate = 2000
    l1.fundwallet(20000000)
    l2.fundwallet(20000000)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    rates = l1.rpc.dev_queryrates(l2.info['id'], amount, amount)
    wait_for(lambda: len(l1.rpc.listpeers(l2.info['id'])['peers']) == 0)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # l1 leases a channel from l2
    l1.rpc.fundchannel(l2.info['id'], amount, request_amt=amount,
                       feerate='{}perkw'.format(feerate),
                       compact_lease=rates['compact_lease'])

    bitcoind.generate_block(6)
    l1.daemon.wait_for_log('to CHANNELD_NORMAL')
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels(l1.get_channel_scid(l2))['channels']] == [True, True])
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels(l2.get_channel_scid(l1))['channels']] == [True, True])
    # send some payments, mine a block or two
    inv = l2.rpc.invoice(10**4, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    bitcoind.generate_block(1)

    # make database snapshot of l1
    l1.stop()
    l1_db_path = os.path.join(l1.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3')
    l1_db_path_bak = os.path.join(l1.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3.bak')
    copyfile(l1_db_path, l1_db_path_bak)
    l1.start()
    l1.rpc.connect(l1.info['id'], 'localhost', l1.port)
    sync_blockheight(bitcoind, [l1])

    # push some money from l2->l1, so the commit counter advances
    inv = l1.rpc.invoice(10**5, '2', 'no_2')
    l2.rpc.pay(inv['bolt11'])

    # stop both nodes, roll back l1's database
    l1.stop()
    l2.stop()
    copyfile(l1_db_path_bak, l1_db_path)

    # start l1 and force close channel with l2 while l2 is still offline
    l1.start()
    sync_blockheight(bitcoind, [l1])
    l1.rpc.close(l2.info['id'], 1, force_lease_closed=True)
    bitcoind.generate_block(1, wait_for_mempool=1)

    l2.start()
    sync_blockheight(bitcoind, [l2])
    l2.daemon.wait_for_logs(['Broadcasting OUR_PENALTY_TX',
                             ' Propose handling THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM by OUR_PENALTY_TX'])

    bitcoind.generate_block(1, wait_for_mempool=1)
    # l2 sees that l1 has spent their coins!
    l1.daemon.wait_for_logs(['Grinding for to_remote',
                             'Unknown spend of OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by'])


@pytest.mark.developer("needs DEVELOPER=1")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@pytest.mark.slow_test
def test_penalty_htlc_tx_fulfill(node_factory, bitcoind, chainparams):
    """ Test that the penalizing node claims any published
        HTLC transactions

      Node topology:
      l1 <-> l2 <-> l3 <-> l4

      l4 pushes money to l1, who doesn't fulfill (freezing htlc across l2-l3)
      we snapshot l2
      l2 pushes money to l3 (updating state)
      l2 + l3 go offline; l2 is backed up from snapshot
      l1 fails the channel with l2, fulfilling the stranded htlc onchain
      l2 comes back online, force closes channel with l3

      block chain advances, l2 broadcasts their htlc fulfill tx
      l3 comes back online, sees l2's cheat. takes funds from htlc fulfill tx.
      some blocks are mined. the dust settles.

      we check the accounting.
      """

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    balance_snaps = os.path.join(os.getcwd(), 'tests/plugins/balance_snaps.py')

    l1, l2, l3, l4 = node_factory.line_graph(4,
                                             opts=[{'disconnect': ['-WIRE_UPDATE_FULFILL_HTLC'],
                                                    'may_reconnect': True,
                                                    'dev-no-reconnect': None},
                                                   {'plugin': [coin_mvt_plugin, balance_snaps],
                                                    'disable-mpp': None,
                                                    'dev-no-reconnect': None,
                                                    'may_reconnect': True,
                                                    'allow_broken_log': True},
                                                   {'plugin': [coin_mvt_plugin, balance_snaps],
                                                    'dev-no-reconnect': None,
                                                    'may_reconnect': True,
                                                    'allow_broken_log': True},
                                                   {'dev-no-reconnect': None,
                                                    'may_reconnect': True}],
                                             wait_for_announce=True)

    channel_id = first_channel_id(l2, l3)

    # push some money so that 1 + 4 can both send htlcs
    inv = l2.rpc.invoice(10**9 // 2, '1', 'balancer')
    l1.rpc.pay(inv['bolt11'])
    l1.rpc.waitsendpay(inv['payment_hash'])

    inv = l4.rpc.invoice(10**9 // 2, '1', 'balancer')
    l2.rpc.pay(inv['bolt11'])
    l2.rpc.waitsendpay(inv['payment_hash'])

    # now we send one 'sticky' htlc: l4->l1
    amt = 10**8 // 2
    sticky_inv = l1.rpc.invoice(amt, '2', 'sticky')
    route = l4.rpc.getroute(l1.info['id'], amt, 1)['route']
    l4.rpc.sendpay(route, sticky_inv['payment_hash'], payment_secret=sticky_inv['payment_secret'])
    l1.daemon.wait_for_log('dev_disconnect: -WIRE_UPDATE_FULFILL_HTLC')

    wait_for(lambda: len(l2.rpc.listpeers(l3.info['id'])['peers'][0]['channels'][0]['htlcs']) == 1)

    # make database snapshot of l2
    l2.stop()
    l2_db_path = os.path.join(l2.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3')
    l2_db_path_bak = os.path.join(l2.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3.bak')
    copyfile(l2_db_path, l2_db_path_bak)
    l2.start()
    sync_blockheight(bitcoind, [l2])

    # push some money from l3->l2, so that the commit counter advances
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    inv = l3.rpc.invoice(10**4, '1', 'push')
    # Make sure gossipd in l2 knows it's active
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels(l2.get_channel_scid(l3))['channels']] == [True, True])
    l2.rpc.pay(inv['bolt11'])

    # stop both nodes, roll back l2's database
    l2.stop()
    l3.stop()
    copyfile(l2_db_path_bak, l2_db_path)

    # start l2 and force close channel with l3 while l3 is still offline
    l2.start()
    sync_blockheight(bitcoind, [l2])
    l2.rpc.close(l3.info['id'], 1)
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # reconnect with l1, which will fulfill the payment
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log('got commitsig .*: feerate 11000, blockheight: 0, 0 added, 1 fulfilled, 0 failed, 0 changed')

    # l2 moves on for closed l3
    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('to ONCHAIN')
    l2.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks',
                             'Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* after 0 blocks'])

    l2.wait_for_onchaind_broadcast('OUR_HTLC_SUCCESS_TX',
                                   'OUR_UNILATERAL/THEIR_HTLC')

    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')

    # l3 comes back up, sees cheat, penalizes l2 (revokes the htlc they've offered;
    # notes that they've successfully claimed to_local and the fulfilled htlc)
    l3.start()
    sync_blockheight(bitcoind, [l3])
    l3.daemon.wait_for_logs(['Propose handling THEIR_REVOKED_UNILATERAL/OUR_HTLC by OUR_PENALTY_TX',
                             'Propose handling THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM '
                             'by OUR_PENALTY_TX',
                             'Resolved THEIR_REVOKED_UNILATERAL/OUR_HTLC by OUR_HTLC_FULFILL_TO_THEM',
                             'Propose handling OUR_HTLC_FULFILL_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM'
                             ' by OUR_PENALTY_TX'])
    l3.wait_for_onchaind_broadcast('OUR_PENALTY_TX',
                                   'OUR_HTLC_FULFILL_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM')
    bitcoind.generate_block(1)
    l3.daemon.wait_for_log('Resolved OUR_HTLC_FULFILL_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM '
                           'by our proposal OUR_PENALTY_TX')
    l2.daemon.wait_for_log('Unknown spend of OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US')

    # 100 blocks later, l3+l2 are both done
    bitcoind.generate_block(100)
    l3.daemon.wait_for_log('{}.*: onchaind complete, forgetting peer'.format(l2.info['id']))
    l2.daemon.wait_for_log('{}.*: onchaind complete, forgetting peer'.format(l3.info['id']))

    assert account_balance(l3, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    expected_2 = {
        'A': [('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('cid1', ['htlc_fulfill'], ['htlc_fulfill'], 'C'), ('external', ['penalized'], None, None)],
        'C': [('external', ['penalized'], None, None)],
    }

    expected_3 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('external', ['htlc_fulfill'], ['htlc_fulfill'], 'C'), ('cid1', ['penalty'], ['to_wallet'], 'E')],
        'C': [('cid1', ['penalty'], ['to_wallet'], 'D')],
        'D': [('wallet', ['deposit'], None, None)],
        'E': [('wallet', ['deposit'], None, None)]
    }

    if anchor_expected():
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_3['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))
        expected_3['B'].append(('wallet', ['anchor'], None, None))

    tags = check_utxos_channel(l2, [channel_id], expected_2, filter_channel=channel_id)
    check_utxos_channel(l3, [channel_id], expected_3, tags, filter_channel=channel_id)

    if not chainparams['elements']:
        # Also check snapshots
        expected_bals_2 = [
            {'blockheight': 101, 'accounts': [{'balance_msat': '0msat'}]},
            {'blockheight': 108, 'accounts': [{'balance_msat': '995433000msat'}, {'balance_msat': '500000000msat'}, {'balance_msat': '499994999msat'}]},
            # There's a duplicate because we stop and restart l2 twice
            # (both times at block 108)
            {'blockheight': 108, 'accounts': [{'balance_msat': '995433000msat'}, {'balance_msat': '500000000msat'}, {'balance_msat': '499994999msat'}]},
        ]
        check_balance_snaps(l2, expected_bals_2)


@pytest.mark.developer("needs DEVELOPER=1")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@pytest.mark.slow_test
def test_penalty_htlc_tx_timeout(node_factory, bitcoind, chainparams):
    """ Test that the penalizing node claims any published
        HTLC transactions

      Node topology:
      l1 <-> l2 <-> l3 <-> l4
                     ^---> l5

      l1 pushes money to l5, who doesn't fulfill (freezing htlc across l2-l3)
      l4 pushes money to l1, who doesn't fulfill (freezing htlc across l2-l3)
      we snapshot l2
      l2 pushes money to l3 (updating state)
      l2 + l3 go offline; l2 is backed up from snapshot
      l1 fails the channel with l2, fulfilling the stranded htlc onchain
      l2 comes back online, force closes channel with l3

      block chain advances, l2 broadcasts the timeout htlc_tx + fulfill htlc_tx
        both of which have a delay. l2 goes ahead and 'steals back' their
        output + the htlc they fulfill

      l3 comes back online, sees l2's cheat. takes funds from htlc timeout tx
      some blocks are mined. the dust settles.

      we check the accounting.
      """

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    l1, l2, l3, l4, l5 = node_factory.get_nodes(
        5,
        opts=[
            {
                'disconnect': ['-WIRE_UPDATE_FULFILL_HTLC'],
                'may_reconnect': True,
                'dev-no-reconnect': None,
            }, {
                'plugin': coin_mvt_plugin,
                'dev-no-reconnect': None,
                'may_reconnect': True,
                'allow_broken_log': True,
            }, {
                'plugin': coin_mvt_plugin,
                'dev-no-reconnect': None,
                'may_reconnect': True,
                'allow_broken_log': True,
            }, {
                'dev-no-reconnect': None,
            }, {
                'disconnect': ['-WIRE_UPDATE_FULFILL_HTLC'],
                'may_reconnect': True,
                'dev-no-reconnect': None,
                'allow_broken_log': True,
            }
        ]
    )

    node_factory.join_nodes([l1, l2, l3, l4], wait_for_announce=True)
    node_factory.join_nodes([l3, l5], wait_for_announce=True)

    channel_id = first_channel_id(l2, l3)

    # push some money so that 1 + 4 can both send htlcs
    inv = l2.rpc.invoice(10**9 // 2, '1', 'balancer')
    l1.rpc.pay(inv['bolt11'])

    inv = l4.rpc.invoice(10**9 // 2, '1', 'balancer')
    l2.rpc.pay(inv['bolt11'])

    # now we send two 'sticky' htlcs, l1->l5 + l4->l1
    amt = 10**8 // 2
    sticky_inv_1 = l5.rpc.invoice(amt, '2', 'sticky')
    route = l1.rpc.getroute(l5.info['id'], amt, 1)['route']
    l1.rpc.sendpay(route, sticky_inv_1['payment_hash'], payment_secret=sticky_inv_1['payment_secret'])
    l5.daemon.wait_for_log('dev_disconnect: -WIRE_UPDATE_FULFILL_HTLC')

    sticky_inv_2 = l1.rpc.invoice(amt, '2', 'sticky')
    route = l4.rpc.getroute(l1.info['id'], amt, 1)['route']
    l4.rpc.sendpay(route, sticky_inv_2['payment_hash'], payment_secret=sticky_inv_2['payment_secret'])
    l1.daemon.wait_for_log('dev_disconnect: -WIRE_UPDATE_FULFILL_HTLC')

    wait_for(lambda: len(l2.rpc.listpeers(l3.info['id'])['peers'][0]['channels'][0]['htlcs']) == 2)

    # make database snapshot of l2
    l2.stop()
    l2_db_path = os.path.join(l2.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3')
    l2_db_path_bak = os.path.join(l2.daemon.lightning_dir, chainparams['name'], 'lightningd.sqlite3.bak')
    copyfile(l2_db_path, l2_db_path_bak)
    l2.start()
    sync_blockheight(bitcoind, [l2])

    # push some money from l3->l2, so that the commit counter advances
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    inv = l3.rpc.invoice(10**4, '1', 'push')
    # Make sure gossipd in l2 knows it's active
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels(l2.get_channel_scid(l3))['channels']] == [True, True])
    l2.rpc.pay(inv['bolt11'])

    # stop both nodes, roll back l2's database
    l2.stop()
    l3.stop()
    copyfile(l2_db_path_bak, l2_db_path)

    # start l2, now back a bit. force close channel with l3 while l3 is still offline
    l2.start()
    sync_blockheight(bitcoind, [l2])
    l2.rpc.close(l3.info['id'], 1)
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # reconnect with l1, which will fulfill the payment
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.daemon.wait_for_log('got commitsig .*: feerate 11000, blockheight: 0, 0 added, 1 fulfilled, 0 failed, 0 changed')

    # l2 moves on for closed l3
    bitcoind.generate_block(1, wait_for_mempool=1)
    l2.daemon.wait_for_log('to ONCHAIN')
    l2.daemon.wait_for_logs(['Propose handling OUR_UNILATERAL/OUR_HTLC by OUR_HTLC_TIMEOUT_TX .* after 16 blocks',
                             'Propose handling OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks',
                             'Propose handling OUR_UNILATERAL/THEIR_HTLC by OUR_HTLC_SUCCESS_TX .* after 0 blocks'])

    l2.wait_for_onchaind_broadcast('OUR_HTLC_SUCCESS_TX',
                                   'OUR_UNILATERAL/THEIR_HTLC')

    bitcoind.generate_block(1, wait_for_mempool=1)
    l2.daemon.wait_for_log('Propose handling OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')

    # after 5 blocks, l2 reclaims both their DELAYED_OUTPUT_TO_US and their delayed output
    bitcoind.generate_block(5, wait_for_mempool=0)
    sync_blockheight(bitcoind, [l2])
    l2.daemon.wait_for_logs(['Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_HTLC_SUCCESS_TX/DELAYED_OUTPUT_TO_US',
                             'Broadcasting OUR_DELAYED_RETURN_TO_WALLET .* to resolve OUR_UNILATERAL/DELAYED_OUTPUT_TO_US'])

    bitcoind.generate_block(10, wait_for_mempool=2)
    l2.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TX',
                                   'OUR_UNILATERAL/OUR_HTLC')

    bitcoind.generate_block(1, wait_for_mempool=1)
    l2.daemon.wait_for_log('Propose handling OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US by OUR_DELAYED_RETURN_TO_WALLET .* after 5 blocks')

    # l3 comes back up, sees cheat, penalizes l2 (revokes the htlc they've offered;
    # notes that they've successfully claimed to_local and the fulfilled htlc)
    l3.start()
    sync_blockheight(bitcoind, [l3])
    l3.daemon.wait_for_logs(['Propose handling THEIR_REVOKED_UNILATERAL/OUR_HTLC by OUR_PENALTY_TX',
                             'Propose handling THEIR_REVOKED_UNILATERAL/THEIR_HTLC by OUR_PENALTY_TX',
                             'Propose handling THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM '
                             'by OUR_PENALTY_TX',
                             'Resolved THEIR_REVOKED_UNILATERAL/OUR_HTLC by OUR_HTLC_FULFILL_TO_THEM',
                             'Propose handling OUR_HTLC_FULFILL_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM'
                             ' by OUR_PENALTY_TX',
                             'Resolved OUR_HTLC_FULFILL_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM '
                             'by THEIR_DELAYED_CHEAT',
                             'Resolved THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM '
                             'by THEIR_DELAYED_CHEAT',
                             'Resolved THEIR_REVOKED_UNILATERAL/THEIR_HTLC by THEIR_HTLC_TIMEOUT_TO_THEM',
                             'Propose handling THEIR_HTLC_TIMEOUT_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM by OUR_PENALTY_TX'])

    # Make sure we've broadcast the tx we expect (other channels shutting down can create
    # unrelated txs!)

    # In theory this could have occurred before all the previous loglines appeared.
    l3.daemon.logsearch_start = 0
    line = l3.daemon.wait_for_log(r'Broadcasting OUR_PENALTY_TX \([0-9a-f]*\) to resolve THEIR_HTLC_TIMEOUT_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM')
    tx = re.search(r'\(([0-9a-f]*)\)', line).group(1)
    txid = bitcoind.rpc.decoderawtransaction(tx)['txid']
    bitcoind.generate_block(1, wait_for_mempool=[txid])
    l3.daemon.wait_for_log('Resolved THEIR_HTLC_TIMEOUT_TO_THEM/DELAYED_CHEAT_OUTPUT_TO_THEM '
                           'by our proposal OUR_PENALTY_TX')
    l2.daemon.wait_for_log('Unknown spend of OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US')

    # 100 blocks later, l3+l2 are both done
    bitcoind.generate_block(100)
    l3.daemon.wait_for_log('{}.*: onchaind complete, forgetting peer'.format(l2.info['id']))
    l2.daemon.wait_for_log('{}.*: onchaind complete, forgetting peer'.format(l3.info['id']))

    assert account_balance(l3, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    expected_2 = {
        'A': [('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('cid1', ['htlc_fulfill'], ['htlc_fulfill'], 'E'), ('cid1', ['delayed_to_us'], ['to_wallet'], 'F'), ('cid1', ['htlc_timeout'], ['htlc_timeout'], 'C')],
        'C': [('external', ['penalized'], None, None)],
        'E': [('cid1', ['htlc_tx'], ['to_wallet'], 'G')],
        'F': [('wallet', ['deposit'], None, None)],
        'G': [('wallet', ['deposit'], None, None)]
    }

    expected_3 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('external', ['htlc_fulfill'], ['htlc_fulfill'], 'E'), ('external', ['stolen'], None, None), ('external', ['htlc_timeout'], ['htlc_timeout'], 'C')],
        'C': [('cid1', ['penalty'], ['to_wallet'], 'D')],
        'D': [('wallet', ['deposit'], None, None)],
        'E': [('external', ['stolen'], None, None)]
    }

    if anchor_expected():
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_3['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))
        expected_3['B'].append(('wallet', ['anchor'], None, None))

    tags = check_utxos_channel(l2, [channel_id], expected_2, filter_channel=channel_id)
    check_utxos_channel(l3, [channel_id], expected_3, tags, filter_channel=channel_id)


@pytest.mark.developer("uses dev_sign_last_tx")
def test_penalty_rbf_normal(node_factory, bitcoind, executor, chainparams):
    '''
    Test that penalty transactions are RBFed.
    '''
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    to_self_delay = 10
    # l1 is the thief, which causes our honest upstanding lightningd
    # code to break, so l1 can fail.
    # Initially, disconnect before the HTLC can be resolved.
    l1 = node_factory.get_node(options={'dev-disable-commit-after': 1},
                               may_fail=True, allow_broken_log=True)
    l2 = node_factory.get_node(options={'dev-disable-commit-after': 1,
                                        'watchtime-blocks': to_self_delay,
                                        'plugin': coin_mvt_plugin})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**7)
    channel_id = first_channel_id(l1, l2)

    # Trigger an HTLC being added.
    t = executor.submit(l1.pay, l2, 1000000 * 1000)

    # Make sure the channel is still alive.
    assert len(l1.getactivechannels()) == 2
    assert len(l2.getactivechannels()) == 2

    # Wait for the disconnection.
    l1.daemon.wait_for_log('dev-disable-commit-after: disabling')
    l2.daemon.wait_for_log('dev-disable-commit-after: disabling')
    # Make sure l1 gets the new HTLC.
    l1.daemon.wait_for_log('got commitsig')

    # l1 prepares a theft commitment transaction
    theft_tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    # Now continue processing until fulfilment.
    l1.rpc.dev_reenable_commit(l2.info['id'])
    l2.rpc.dev_reenable_commit(l1.info['id'])

    # Wait for the fulfilment.
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_FULFILL_HTLC')
    l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')
    l2.daemon.wait_for_log('peer_out WIRE_UPDATE_FULFILL_HTLC')
    l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # Now payment should complete.
    t.result(timeout=10)

    # l1 goes offline and bribes the miners to censor transactions from l2.
    l1.rpc.stop()

    def censoring_sendrawtx(r):
        return {'id': r['id'], 'result': {}}

    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', censoring_sendrawtx)

    # l1 now performs the theft attack!
    bitcoind.rpc.sendrawtransaction(theft_tx)
    bitcoind.generate_block(1)

    # l2 notices.
    l2.daemon.wait_for_log(' to ONCHAIN')

    def get_rbf_tx(self, depth, name, resolve):
        r = self.daemon.wait_for_log('Broadcasting RBF {} .* to resolve {} depth={}'
                                     .format(name, resolve, depth))
        return re.search(r'.* \(([0-9a-fA-F]*)\)', r).group(1)

    rbf_txes = []
    # Now the censoring miners generate some blocks.
    for depth in range(2, 8):
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l2])
        # l2 should RBF, twice even, one for the l1 main output,
        # one for the l1 HTLC output.
        rbf_txes.append(get_rbf_tx(l2, depth,
                                   'OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/THEIR_HTLC'))
        rbf_txes.append(get_rbf_tx(l2, depth,
                                   'OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM'))

    # Now that the transactions have high fees, independent miners
    # realize they can earn potentially more money by grabbing the
    # high-fee censored transactions, and fresh, non-censoring
    # hashpower arises, evicting the censor.
    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)

    # Check that the order in which l2 generated RBF transactions
    # would be acceptable to Bitcoin.
    for tx in rbf_txes:
        # Use the bcli interface as well, so that we also check the
        # bcli interface.
        l2.rpc.call('sendrawtransaction', [tx, True])

    # Now the non-censoring miners overpower the censoring miners.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l2])

    # And l2 should consider it resolved now.
    l2.daemon.wait_for_log('Resolved THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM by our proposal OUR_PENALTY_TX')
    l2.daemon.wait_for_log('Resolved THEIR_REVOKED_UNILATERAL/THEIR_HTLC by our proposal OUR_PENALTY_TX')

    # And l2 should consider it in its listfunds.
    assert(len(l2.rpc.listfunds()['outputs']) >= 1)

    assert account_balance(l2, channel_id) == 0

    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('cid1', ['penalty'], ['to_wallet'], 'C'), ('cid1', ['penalty'], ['to_wallet'], 'D')],
        'C': [('wallet', ['deposit'], None, None)],
        'D': [('wallet', ['deposit'], None, None)]
    }

    if anchor_expected():
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    check_utxos_channel(l2, [channel_id], expected_2)


@pytest.mark.developer("uses dev_sign_last_tx")
def test_penalty_rbf_burn(node_factory, bitcoind, executor, chainparams):
    '''
    Test that penalty transactions are RBFed and we are willing to burn
    it all up to spite the thief.
    '''
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    to_self_delay = 10
    # l1 is the thief, which causes our honest upstanding lightningd
    # code to break, so l1 can fail.
    # Initially, disconnect before the HTLC can be resolved.
    l1 = node_factory.get_node(options={'dev-disable-commit-after': 1},
                               may_fail=True, allow_broken_log=True)
    l2 = node_factory.get_node(options={'dev-disable-commit-after': 1,
                                        'watchtime-blocks': to_self_delay,
                                        'plugin': coin_mvt_plugin})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**7)
    channel_id = first_channel_id(l1, l2)

    # Trigger an HTLC being added.
    t = executor.submit(l1.pay, l2, 1000000 * 1000)

    # Make sure the channel is still alive.
    assert len(l1.getactivechannels()) == 2
    assert len(l2.getactivechannels()) == 2

    # Wait for the disconnection.
    l1.daemon.wait_for_log('dev-disable-commit-after: disabling')
    l2.daemon.wait_for_log('dev-disable-commit-after: disabling')
    # Make sure l1 gets the new HTLC.
    l1.daemon.wait_for_log('got commitsig')

    # l1 prepares a theft commitment transaction
    theft_tx = l1.rpc.dev_sign_last_tx(l2.info['id'])['tx']

    # Now continue processing until fulfilment.
    l1.rpc.dev_reenable_commit(l2.info['id'])
    l2.rpc.dev_reenable_commit(l1.info['id'])

    # Wait for the fulfilment.
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_FULFILL_HTLC')
    l1.daemon.wait_for_log('peer_out WIRE_REVOKE_AND_ACK')
    l2.daemon.wait_for_log('peer_out WIRE_UPDATE_FULFILL_HTLC')
    l1.daemon.wait_for_log('peer_in WIRE_REVOKE_AND_ACK')

    # Now payment should complete.
    t.result(timeout=10)

    # l1 goes offline and bribes the miners to censor transactions from l2.
    l1.rpc.stop()

    def censoring_sendrawtx(r):
        return {'id': r['id'], 'result': {}}

    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', censoring_sendrawtx)

    # l1 now performs the theft attack!
    bitcoind.rpc.sendrawtransaction(theft_tx)
    bitcoind.generate_block(1)

    # l2 notices.
    l2.daemon.wait_for_log(' to ONCHAIN')

    def get_rbf_tx(self, depth, name, resolve):
        r = self.daemon.wait_for_log('Broadcasting RBF {} .* to resolve {} depth={}'
                                     .format(name, resolve, depth))
        return re.search(r'.* \(([0-9a-fA-F]*)\)', r).group(1)

    rbf_txes = []
    # Now the censoring miners generate some blocks.
    for depth in range(2, 10):
        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, [l2])
        # l2 should RBF, twice even, one for the l1 main output,
        # one for the l1 HTLC output.
        rbf_txes.append(get_rbf_tx(l2, depth,
                                   'OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/THEIR_HTLC'))
        rbf_txes.append(get_rbf_tx(l2, depth,
                                   'OUR_PENALTY_TX',
                                   'THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM'))

    # Now that the transactions have high fees, independent miners
    # realize they can earn potentially more money by grabbing the
    # high-fee censored transactions, and fresh, non-censoring
    # hashpower arises, evicting the censor.
    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)

    # Check that the last two txes can be broadcast.
    # These should donate the total amount to miners.
    rbf_txes = rbf_txes[-2:]
    for tx in rbf_txes:
        l2.rpc.call('sendrawtransaction', [tx, True])

    # Now the non-censoring miners overpower the censoring miners.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l2])

    # And l2 should consider it resolved now.
    l2.daemon.wait_for_log('Resolved THEIR_REVOKED_UNILATERAL/DELAYED_CHEAT_OUTPUT_TO_THEM by our proposal OUR_PENALTY_TX')
    l2.daemon.wait_for_log('Resolved THEIR_REVOKED_UNILATERAL/THEIR_HTLC by our proposal OUR_PENALTY_TX')

    # l2 donated it to the miners, so it owns nothing
    assert(len(l2.rpc.listfunds()['outputs']) == 0)
    assert account_balance(l2, channel_id) == 0

    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('cid1', ['penalty'], ['to_miner'], 'C'), ('cid1', ['penalty'], ['to_miner'], 'D')],
    }

    if anchor_expected():
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    check_utxos_channel(l2, [channel_id], expected_2)


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_first_commit(node_factory, bitcoind):
    """Onchain handling where opener immediately drops to chain"""

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    # HTLC 1->2, 1 fails just after funding.
    disconnects = ['+WIRE_FUNDING_LOCKED', 'permfail']
    # Make locktime different, as we once had them reversed!
    l1, l2 = node_factory.line_graph(2, opts=[{'disconnect': disconnects,
                                               'plugin': coin_mvt_plugin},
                                              {'watchtime-blocks': 10,
                                               'plugin': coin_mvt_plugin}],
                                     fundchannel=False)
    l1.fundwallet(10**7)
    l1.rpc.fundchannel(l2.info['id'], 10**6)
    l1.daemon.wait_for_log('sendrawtx exit 0')

    bitcoind.generate_block(1)

    # l1 will drop to chain.
    l1.daemon.wait_for_log('permfail')
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1)
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


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_unwatch(node_factory, bitcoind):
    """Onchaind should not watch random spends"""
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1, l2 = node_factory.line_graph(2, opts={'plugin': coin_mvt_plugin})
    channel_id = first_channel_id(l1, l2)

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

    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0
    # Note: for this test we leave onchaind running, so we can detect
    # any leaks!


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchaind_replay(node_factory, bitcoind):
    disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1, l2 = node_factory.line_graph(2, opts=[{'watchtime-blocks': 201, 'cltv-delta': 101,
                                               'disconnect': disconnects,
                                               'feerates': (7500, 7500, 7500, 7500)},
                                              {'watchtime-blocks': 201, 'cltv-delta': 101}])

    inv = l2.rpc.invoice(10**8, 'onchaind_replay', 'desc')
    rhash = inv['payment_hash']
    routestep = {
        'msatoshi': 10**8 - 1,
        'id': l2.info['id'],
        'delay': 101,
        'channel': '1x1x1'
    }
    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
    l1.daemon.wait_for_log('sendrawtx exit 0')
    bitcoind.generate_block(1, wait_for_mempool=1)

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


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_dust_out(node_factory, bitcoind, executor):
    """Onchain handling of outgoing dust htlcs (they should fail)"""
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    # HTLC 1->2, 1 fails after it's irrevocably committed
    disconnects = ['-WIRE_REVOKE_AND_ACK', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'disconnect': disconnects,
                                            'feerates': (7500, 7500, 7500, 7500),
                                            'plugin': coin_mvt_plugin},
                                           {'plugin': coin_mvt_plugin}])

    channel_id = first_channel_id(l1, l2)

    # Must be dust!
    inv = l2.rpc.invoice(1, 'onchain_dust_out', 'desc')
    rhash = inv['payment_hash']
    routestep = {
        'msatoshi': 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])
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
        l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'])

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

    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_timeout(node_factory, bitcoind, executor):
    """Onchain handling of outgoing failed htlcs"""
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    # HTLC 1->2, 1 fails just after it's irrevocably committed
    disconnects = ['+WIRE_REVOKE_AND_ACK*3', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'disconnect': disconnects,
                                            'feerates': (7500, 7500, 7500, 7500),
                                            'plugin': coin_mvt_plugin},
                                           {'plugin': coin_mvt_plugin}])

    channel_id = first_channel_id(l1, l2)

    inv = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')
    rhash = inv['payment_hash']
    # We underpay, so it fails.
    routestep = {
        'msatoshi': 10**8 - 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'], groupid=1)
    with pytest.raises(RpcError):
        l1.rpc.waitsendpay(rhash)

    # Make sure CLTVs are different, in case it confuses onchaind.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    # Second one will cause drop to chain.
    l1.rpc.sendpay([routestep], rhash, payment_secret=inv['payment_secret'], groupid=2)
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
        payfuture.result(TIMEOUT)

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
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    # Graph of coin_move events we expect
    expected_1 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('cid1', ['delayed_to_us'], ['to_wallet'], 'C'), ('cid1', ['htlc_timeout'], ['htlc_timeout'], 'D')],
        'C': [('wallet', ['deposit'], None, None)],
        'D': [('cid1', ['htlc_tx'], ['to_wallet'], 'E')],
        'E': [('wallet', ['deposit'], None, None)]
    }

    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('external', ['htlc_timeout'], None, None)]
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    # We use a subset of tags in expected_2 that are used in expected_1
    tags = check_utxos_channel(l1, [channel_id], expected_1)
    # Passing the same tags in to the check again will verify that the
    # txids 'unify' across both event sets (in other words, we're talking
    # about the same tx's when we say 'A' in each
    check_utxos_channel(l2, [channel_id], expected_2, tags)


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_middleman_simple(node_factory, bitcoind):
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    # HTLC 1->2->3, 1->2 goes down after 2 gets preimage from 3.
    disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'plugin': coin_mvt_plugin},
                                                 {'plugin': coin_mvt_plugin,
                                                  'disconnect': disconnects},
                                                 {}])

    # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.fundchannel(l1, 10**6)
    c23, _ = l2.fundchannel(l3, 10**6)
    channel_id = first_channel_id(l1, l2)

    # Make sure routes finalized.
    mine_funding_to_announce(bitcoind, [l1, l2, l3])
    l1.wait_channel_active(c23)

    # Give l1 some money to play with.
    l2.pay(l1, 2 * 10**8)

    # Must be bigger than dust!
    inv = l3.rpc.invoice(10**8, 'middleman', 'desc')
    rhash = inv['payment_hash']

    route = l1.rpc.getroute(l3.info['id'], 10**8, 1)["route"]
    assert len(route) == 2

    q = queue.Queue()

    def try_pay():
        try:
            l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
            l1.rpc.waitsendpay(rhash)
            q.put(None)
        except Exception as err:
            q.put(err)

    t = threading.Thread(target=try_pay)
    t.daemon = True
    t.start()

    # l2 will drop to chain.
    l2.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1, wait_for_mempool=1)
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

    # Verify accounting for l1 & l2
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    # Graph of coin_move events we expect
    expected_2 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        # This is ugly, but this wallet deposit is either unspent or used
        # in the next channel open
        'A': [('wallet', ['deposit'], ((['withdrawal'], 'F'), (None, None))), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        '1': [('wallet', ['deposit'], ['withdrawal'], 'F')],
        'B': [('cid1', ['delayed_to_us'], ['to_wallet'], 'C'), ('cid1', ['htlc_fulfill'], ['htlc_fulfill'], 'D'), ('external', ['to_them'], None, None)],
        'C': [('wallet', ['deposit'], None, None)],
        'D': [('cid1', ['htlc_tx'], ['to_wallet'], 'E')],
        'E': [('wallet', ['deposit'], None, None)],
        'F': [('wallet', ['deposit'], None, None), ('cid2', ['channel_open', 'opener'], None, None)]
    }

    expected_1 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('external', ['htlc_fulfill'], ['htlc_fulfill'], 'D'), ('wallet', ['deposit'], None, None)]
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    chan2_id = first_channel_id(l2, l3)
    tags = check_utxos_channel(l2, [channel_id, chan2_id], expected_2)
    check_utxos_channel(l1, [channel_id, chan2_id], expected_1, tags)


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_middleman_their_unilateral_in(node_factory, bitcoind):
    """ This is the same as test_onchain_middleman, except that
        node l1 drops to chain, not l2, reversing the unilateral
        handling logic """
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    l1_disconnects = ['=WIRE_UPDATE_FULFILL_HTLC', 'permfail']
    l2_disconnects = ['-WIRE_UPDATE_FULFILL_HTLC']

    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'plugin': coin_mvt_plugin,
                                                  'disconnect': l1_disconnects},
                                                 {'plugin': coin_mvt_plugin,
                                                  'disconnect': l2_disconnects},
                                                 {}])
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    c12, _ = l2.fundchannel(l1, 10**6)
    c23, _ = l2.fundchannel(l3, 10**6)
    channel_id = first_channel_id(l1, l2)

    # Make sure routes finalized.
    mine_funding_to_announce(bitcoind, [l1, l2, l3])
    l1.wait_channel_active(c23)

    # Make sure l3 sees gossip for channel now; it can get upset
    # and give bad gossip msg if channel is closed before it sees
    # node announcement.
    wait_for(lambda: l3.rpc.listchannels(c12)['channels'] != [])

    # Give l1 some money to play with.
    l2.pay(l1, 2 * 10**8)

    # Must be bigger than dust!
    inv = l3.rpc.invoice(10**8, 'middleman', 'desc')
    rhash = inv['payment_hash']

    route = l1.rpc.getroute(l3.info['id'], 10**8, 1)["route"]
    assert len(route) == 2

    q = queue.Queue()

    def try_pay():
        try:
            l1.rpc.sendpay(route, rhash, payment_secret=inv['payment_secret'])
            l1.rpc.waitsendpay(rhash)
            q.put(None)
        except Exception as err:
            q.put(err)

    t = threading.Thread(target=try_pay)
    t.daemon = True
    t.start()

    # l1 will drop to chain.
    l1.daemon.wait_for_log(' to AWAITING_UNILATERAL')
    l1.daemon.wait_for_log('sendrawtx exit 0')
    l1.bitcoin.generate_block(1)
    l2.daemon.wait_for_log(' to ONCHAIN')
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log('THEIR_UNILATERAL/THEIR_HTLC')

    # l2 should fulfill HTLC onchain, immediately
    l2.wait_for_onchaind_broadcast('THEIR_HTLC_FULFILL_TO_US',
                                   'THEIR_UNILATERAL/THEIR_HTLC')

    # Payment should succeed.
    l1.bitcoin.generate_block(1)
    l1.daemon.wait_for_log('OUR_UNILATERAL/OUR_HTLC gave us preimage')
    err = q.get(timeout=10)
    if err:
        print("Got err from sendpay thread")
        raise err
    t.join(timeout=1)
    assert not t.is_alive()

    l1.bitcoin.generate_block(6)
    l1.wait_for_onchaind_broadcast('OUR_DELAYED_RETURN_TO_WALLET',
                                   'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')

    # 100 blocks after last spend, l1 should be done.
    l1.bitcoin.generate_block(100)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Verify accounting for l1 & l2
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    # Graph of coin_move events we expect
    expected_2 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        # This is ugly, but this wallet deposit is either unspent or used
        # in the next channel open
        'A': [('wallet', ['deposit'], ((['withdrawal'], 'D'), (None, None))), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        '1': [('wallet', ['deposit'], ['withdrawal'], 'D')],
        'B': [('external', ['to_them'], None, None), ('wallet', ['deposit'], None, None), ('cid1', ['htlc_fulfill'], ['to_wallet'], 'C')],
        'C': [('wallet', ['deposit'], None, None)],
        'D': [('wallet', ['deposit'], None, None), ('cid2', ['channel_open', 'opener'], None, None)]
    }

    expected_1 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('external', ['htlc_fulfill'], ['htlc_fulfill'], 'C'), ('cid1', ['delayed_to_us'], ['to_wallet'], 'E')],
        'E': [('wallet', ['deposit'], None, None)]
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    chan2_id = first_channel_id(l2, l3)
    tags = check_utxos_channel(l2, [channel_id, chan2_id], expected_2)
    check_utxos_channel(l1, [channel_id, chan2_id], expected_1, tags)


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_their_unilateral_out(node_factory, bitcoind):
    """ Very similar to the test_onchain_middleman, except there's no
        middleman, we simply want to check that our offered htlc
        on their unilateral returns to us (and is accounted
        for correctly) """
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']

    l1, l2 = node_factory.line_graph(2, opts=[{'plugin': coin_mvt_plugin},
                                              {'disconnect': disconnects,
                                               'plugin': coin_mvt_plugin}])
    channel_id = first_channel_id(l1, l2)

    route = l1.rpc.getroute(l2.info['id'], 10**8, 1)["route"]
    assert len(route) == 1

    q = queue.Queue()

    def try_pay():
        try:
            # rhash is fake (so is payment_secret)
            rhash = 'B1' * 32
            l1.rpc.sendpay(route, rhash, payment_secret=rhash)
            q.put(None)
        except Exception as err:
            q.put(err)

    t = threading.Thread(target=try_pay)
    t.daemon = True
    t.start()

    # l2 will drop to chain.
    l2.daemon.wait_for_log(' to AWAITING_UNILATERAL')
    l2.daemon.wait_for_log('sendrawtx exit 0')
    l2.bitcoin.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')
    l1.daemon.wait_for_log('THEIR_UNILATERAL/OUR_HTLC')

    # l1 should wait til to_self_delay (10), then fulfill onchain
    l2.bitcoin.generate_block(9)
    l1.wait_for_onchaind_broadcast('OUR_HTLC_TIMEOUT_TO_US',
                                   'THEIR_UNILATERAL/OUR_HTLC')
    l2.daemon.wait_for_log('Ignoring output .*_UNILATERAL/THEIR_HTLC')

    err = q.get(timeout=10)
    if err:
        print("Got err from sendpay thread")
        raise err
    t.join(timeout=1)
    assert not t.is_alive()

    # 100 blocks after last spend, l1+l2 should be done.
    l2.bitcoin.generate_block(100)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Verify accounting for l1 & l2
    assert account_balance(l2, channel_id) == 0
    assert account_balance(l1, channel_id) == 0

    # Graph of coin_move events we expect
    expected_1 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        # This is ugly, but this wallet deposit is either unspent or used
        # in the next channel open
        'A': [('wallet', ['deposit'], None, None), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('cid1', ['htlc_timeout'], ['to_wallet'], 'C')],
        'C': [('wallet', ['deposit'], None, None)],
    }

    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('external', ['htlc_timeout'], None, None)],
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    tags = check_utxos_channel(l1, [channel_id], expected_1)
    check_utxos_channel(l2, [channel_id], expected_2, tags)


def test_listfunds_after_their_unilateral(node_factory, bitcoind):
    """We keep spending info around for their unilateral closes.

Make sure we show the address.
    """
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    # FIXME: We can get warnings from unilteral changes, since we treat
    # such errors a soft because LND.
    l1, l2 = node_factory.line_graph(2, opts=[{'plugin': coin_mvt_plugin,
                                               "allow_warning": True},
                                              {'plugin': coin_mvt_plugin}])
    channel_id = first_channel_id(l1, l2)

    # listfunds will show 1 output change, and channels.
    assert len([o for o in l1.rpc.listfunds()['outputs'] if not o['reserved']]) == 1

    l1.stop()
    l2.rpc.close(l1.info['id'], unilateraltimeout=1)
    l2.wait_for_channel_onchain(l1.info['id'])
    bitcoind.generate_block(100)

    l1.start()
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)
    assert all(['address' in o for o in l1.rpc.listfunds()['outputs']])

    # Verify accounting for l1 & l2
    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0


@pytest.mark.developer("needs DEVELOPER=1")
def test_onchain_feechange(node_factory, bitcoind, executor):
    """Onchain handling when we restart with different fees"""
    # HTLC 1->2, 2 fails just after they're both irrevocably committed
    # We need 2 to drop to chain, because then 1's HTLC timeout tx
    # is generated on-the-fly, and is thus feerate sensitive.
    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']
    l1, l2 = node_factory.line_graph(2, opts=[
        {
            'may_reconnect': True,
            'allow_warning': True,
        }, {
            'may_reconnect': True,
            'disconnect': disconnects,
        }
    ])

    inv = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')
    rhash = inv['payment_hash']
    # We underpay, so it fails.
    routestep = {
        'msatoshi': 10**8 - 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    executor.submit(l1.rpc.sendpay, [routestep], rhash, payment_secret=inv['payment_secret'])

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


@pytest.mark.skip("Lisa, please fix this!")
@pytest.mark.developer("needs DEVELOPER=1 for dev-set-fees")
def test_onchain_all_dust(node_factory, bitcoind, executor):
    """Onchain handling when we reduce output to all dust"""
    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')

    # HTLC 1->2, 2 fails just after they're both irrevocably committed
    # We need 2 to drop to chain, because then 1's HTLC timeout tx
    # is generated on-the-fly, and is thus feerate sensitive.
    disconnects = ['-WIRE_UPDATE_FAIL_HTLC', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None,
                                        'plugin': coin_mvt_plugin},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects, options={'plugin': coin_mvt_plugin})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)
    channel_id = first_channel_id(l1, l2)

    inv = l2.rpc.invoice(10**8, 'onchain_timeout', 'desc')
    rhash = inv['payment_hash']
    # We underpay, so it fails.
    routestep = {
        'msatoshi': 10**7 - 1,
        'id': l2.info['id'],
        'delay': 5,
        'channel': '1x1x1'
    }

    executor.submit(l1.rpc.sendpay, [routestep], rhash, payment_secret=inv['payment_secret'])

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
    l1.daemon.wait_for_log('Ignoring output .*: THEIR_UNILATERAL/OUR_HTLC')

    # 100 deep and l2 forgets.
    bitcoind.generate_block(93)
    sync_blockheight(bitcoind, [l1, l2])
    assert not l2.daemon.is_in_log('onchaind complete, forgetting peer')
    assert not l1.daemon.is_in_log('onchaind complete, forgetting peer')
    bitcoind.generate_block(1)
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # l1 does not wait for ignored payment.
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    assert account_balance(l1, channel_id) == 0
    assert account_balance(l2, channel_id) == 0

    # Graph of coin_move events we expect
    expected_1 = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None), ('cid1', ['channel_open', 'opener'], ['channel_close'], 'B')],
        'B': [('wallet', ['deposit'], None, None), ('cid1', ['htlc_timeout'], ['ignored'], 'C')],
        'C': [('wallet', ['deposit'], None, None)],
    }

    expected_2 = {
        'A': [('cid1', ['channel_open'], ['channel_close'], 'B')],
        'B': [('external', ['to_them'], None, None), ('external', ['htlc_timeout'], None, None)],
    }

    if anchor_expected():
        expected_1['B'].append(('external', ['anchor'], None, None))
        expected_2['B'].append(('external', ['anchor'], None, None))
        expected_1['B'].append(('wallet', ['anchor'], None, None))
        expected_2['B'].append(('wallet', ['anchor'], None, None))

    tags = check_utxos_channel(l1, [channel_id], expected_1)
    check_utxos_channel(l2, [channel_id], expected_2, tags)


@pytest.mark.developer("needs DEVELOPER=1 for dev_fail")
def test_onchain_different_fees(node_factory, bitcoind, executor):
    """Onchain handling when we've had a range of fees"""
    l1, l2 = node_factory.line_graph(2, fundchannel=True, fundamount=10**7,
                                     opts={'may_reconnect': True})

    l2.rpc.dev_ignore_htlcs(id=l1.info['id'], ignore=True)
    p1 = executor.submit(l1.pay, l2, 1000000000)
    l2.daemon.wait_for_log('htlc 0: SENT_ADD_ACK_COMMIT->RCVD_ADD_ACK_REVOCATION')

    l1.set_feerates((16000, 11000, 7500, 3750))
    p2 = executor.submit(l1.pay, l2, 900000000)
    l2.daemon.wait_for_log('htlc 1: SENT_ADD_ACK_COMMIT->RCVD_ADD_ACK_REVOCATION')

    # Restart with different feerate for second HTLC.
    l1.set_feerates((5000, 5000, 5000, 3750))
    l1.restart()
    l1.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE')

    p3 = executor.submit(l1.pay, l2, 800000000)
    l2.daemon.wait_for_log('htlc 2: SENT_ADD_ACK_COMMIT->RCVD_ADD_ACK_REVOCATION')

    # Drop to chain
    l1.rpc.dev_fail(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    # Both sides should have correct feerate
    assert l1.db_query('SELECT min_possible_feerate, max_possible_feerate FROM channels;') == [{
        'min_possible_feerate': 5000,
        'max_possible_feerate': 11000
    }]
    assert l2.db_query('SELECT min_possible_feerate, max_possible_feerate FROM channels;') == [{
        'min_possible_feerate': 5000,
        'max_possible_feerate': 11000
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


@pytest.mark.developer("needs DEVELOPER=1")
def test_permfail_new_commit(node_factory, bitcoind, executor):
    # Test case where we have two possible commits: it will use new one.
    disconnects = ['-WIRE_REVOKE_AND_ACK', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)

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
    inv = nodes[0].rpc.invoice(msatoshi=10**8, label='x', description='desc',
                               preimage=preimage)
    h = inv['payment_hash']
    nodes[-1].rpc.invoice(msatoshi=10**8, label='x', description='desc',
                          preimage=preimage)['payment_hash']

    # First, the failed attempts (paying wrong node).  CLTV1
    r = nodes[0].rpc.getroute(nodes[-2].info['id'], 10**8, 1)["route"]
    nodes[0].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        nodes[0].rpc.waitsendpay(h)

    r = nodes[-1].rpc.getroute(nodes[1].info['id'], 10**8, 1)["route"]
    nodes[-1].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])
    with pytest.raises(RpcError, match=r'INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS'):
        nodes[-1].rpc.waitsendpay(h)

    # Now increment CLTV -> CLTV2
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, nodes)

    # Now, the live attempts with CLTV2 (blackholed by end nodes)
    r = nodes[0].rpc.getroute(nodes[-1].info['id'], 10**8, 1)["route"]
    nodes[0].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])
    r = nodes[-1].rpc.getroute(nodes[0].info['id'], 10**8, 1)["route"]
    nodes[-1].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])

    # We send second HTLC from different node, since they refuse to send
    # multiple with same hash.
    r = nodes[1].rpc.getroute(nodes[-1].info['id'], 10**8, 1)["route"]
    nodes[1].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])
    r = nodes[-2].rpc.getroute(nodes[0].info['id'], 10**8, 1)["route"]
    nodes[-2].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])

    # Now increment CLTV -> CLTV3.
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, nodes)

    r = nodes[2].rpc.getroute(nodes[-1].info['id'], 10**8, 1)["route"]
    nodes[2].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])
    r = nodes[-3].rpc.getroute(nodes[0].info['id'], 10**8, 1)["route"]
    nodes[-3].rpc.sendpay(r, h, payment_secret=inv['payment_secret'])

    # Make sure HTLCs have reached the end.
    nodes[0].daemon.wait_for_logs(['peer_in WIRE_UPDATE_ADD_HTLC'] * 3)
    nodes[-1].daemon.wait_for_logs(['peer_in WIRE_UPDATE_ADD_HTLC'] * 3)

    return h, nodes


@pytest.mark.developer("needs DEVELOPER=1 for dev_ignore_htlcs")
@pytest.mark.slow_test
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


@pytest.mark.developer("needs DEVELOPER=1 for dev_ignore_htlcs")
@pytest.mark.slow_test
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


@pytest.mark.developer("needs DEVELOPER=1")
def test_permfail_htlc_in(node_factory, bitcoind, executor):
    # Test case where we fail with unsettled incoming HTLC.
    disconnects = ['-WIRE_UPDATE_FULFILL_HTLC', 'permfail']
    # Feerates identical so we don't get gratuitous commit to update them
    l1 = node_factory.get_node(options={'dev-no-reconnect': None},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node(disconnect=disconnects)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)

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


@pytest.mark.developer("needs DEVELOPER=1")
def test_permfail_htlc_out(node_factory, bitcoind, executor):
    # Test case where we fail with unsettled outgoing HTLC.
    disconnects = ['+WIRE_REVOKE_AND_ACK', 'permfail']
    l1 = node_factory.get_node(options={'dev-no-reconnect': None})
    # Feerates identical so we don't get gratuitous commit to update them
    l2 = node_factory.get_node(disconnect=disconnects,
                               feerates=(7500, 7500, 7500, 7500))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('Handed peer, entering loop')
    l2.fundchannel(l1, 10**6)

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


@pytest.mark.developer("needs DEVELOPER=1")
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
            and re.fullmatch(r'ONCHAIN:.* outputs unresolved: in 4 blocks will spend DELAYED_OUTPUT_TO_US \(.*:.*\) using OUR_DELAYED_RETURN_TO_WALLET', billboard[1])
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
        addr = scriptpubkey_addr(txout['scriptPubKey'])
        assert(addr == o['address'])

    addr = l1.bitcoin.getnewaddress()
    l1.rpc.withdraw(addr, "all")


@pytest.mark.developer("needs DEVELOPER=1")
def test_shutdown(node_factory):
    # Fail, in that it will exit before cleanup.
    l1 = node_factory.get_node(may_fail=True)
    if not node_factory.valgrind:
        leaks = l1.rpc.dev_memleak()['leaks']
        if len(leaks):
            raise Exception("Node {} has memory leaks: {}"
                            .format(l1.daemon.lightning_dir, leaks))
    l1.rpc.stop()


@pytest.mark.developer("needs to set upfront_shutdown_script")
def test_option_upfront_shutdown_script(node_factory, bitcoind, executor):
    l1 = node_factory.get_node(start=False, allow_warning=True)
    # Insist on upfront script we're not going to match.
    # '0014' + l1.rpc.call('dev-listaddrs', [10])['addresses'][-1]['bech32_redeemscript']
    l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = "00143d43d226bcc27019ade52d7a3dc52a7ac1be28b8"
    l1.start()

    l2 = node_factory.get_node(allow_warning=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 1000000, False)

    # This will block, as l1 will send a warning but l2 will retry.
    fut = executor.submit(l1.rpc.close, l2.info['id'])

    # l2 will send a warning when it dislikes shutdown script.
    l1.daemon.wait_for_log(r'WARNING.*scriptpubkey .* is not as agreed upfront \(00143d43d226bcc27019ade52d7a3dc52a7ac1be28b8\)')

    # Close from l2's side and clear channel.
    l2.rpc.close(l1.info['id'], unilateraltimeout=1)
    bitcoind.generate_block(1, wait_for_mempool=1)
    fut.result(TIMEOUT)
    wait_for(lambda: [c['state'] for c in only_one(l1.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN'])
    wait_for(lambda: [c['state'] for c in only_one(l2.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN'])

    # Works when l2 closes channel, too.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 1000000, False)

    l2.rpc.close(l1.info['id'], unilateraltimeout=5)

    # l2 will send warning unilaterally when it dislikes shutdown script.
    l1.daemon.wait_for_log(r'WARNING.*scriptpubkey .* is not as agreed upfront \(00143d43d226bcc27019ade52d7a3dc52a7ac1be28b8\)')

    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: [c['state'] for c in only_one(l1.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN', 'ONCHAIN'])
    wait_for(lambda: [c['state'] for c in only_one(l2.rpc.listpeers()['peers'])['channels']] == ['ONCHAIN', 'ONCHAIN'])

    # Figure out what address it will try to use.
    keyidx = int(l1.db_query("SELECT intval FROM vars WHERE name='bip32_max_index';")[0]['intval'])

    # Expect 1 for change address, plus 1 for the funding address of the actual
    # funding tx.
    addr = l1.rpc.call('dev-listaddrs', [keyidx + 2])['addresses'][-1]
    # the above used to be keyidx + 3, but that was when `fundchannel`
    # used the `txprepare`-`txdiscard`-`txprepare` trick, which skipped
    # one address in the discarded tx.
    # Now we use PSBTs, which means we never discard and skip an address.

    # Now, if we specify upfront and it's OK, all good.
    l1.stop()
    # We need to prepend the segwit version (0) and push opcode (14).
    l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = '0014' + addr['bech32_redeemscript']
    l1.start()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.fundchannel(l2.info['id'], 1000000)
    l1.rpc.close(l2.info['id'])
    wait_for(lambda: sorted([c['state'] for c in only_one(l1.rpc.listpeers()['peers'])['channels']]) == ['CLOSINGD_COMPLETE', 'ONCHAIN', 'ONCHAIN'])


@pytest.mark.developer("needs to set upfront_shutdown_script")
def test_invalid_upfront_shutdown_script(node_factory, bitcoind, executor):
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    l1 = node_factory.get_node(start=False, allow_warning=True)
    # Insist on upfront script we're not going to match.
    l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = "76a91404b61f7dc1ea0dc99424464cc4064dc564d91e8988ac00"
    l1.start()

    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    with pytest.raises(RpcError, match=r'Unacceptable upfront_shutdown_script'):
        l1.fundchannel(l2, 1000000, False)


@pytest.mark.developer("needs to set upfront_shutdown_script")
@pytest.mark.slow_test
def test_segwit_shutdown_script(node_factory, bitcoind, executor):
    """
Try a range of future segwit versions as shutdown scripts.  We create many nodes, so this is quite slow under valgrind
"""
    l1 = node_factory.get_node(allow_warning=True)

    # BOLT #2:
    # 5. if (and only if) `option_shutdown_anysegwit` is negotiated:
    #    * `OP_1` through `OP_16` inclusive, followed by a single push of 2 to 40 bytes
    #    (witness program versions 1 through 16)
    edge_valid = ['51020000', '5128' + '00' * 0x28,
                  '60020000', '6028' + '00' * 0x28]
    other_valid = ['52020000', '5228' + '00' * 0x28,
                   '53020000', '5328' + '00' * 0x28,
                   '54020000', '5428' + '00' * 0x28,
                   '55020000', '5528' + '00' * 0x28,
                   '56020000', '5628' + '00' * 0x28,
                   '57020000', '5728' + '00' * 0x28,
                   '58020000', '5828' + '00' * 0x28,
                   '59020000', '5928' + '00' * 0x28,
                   '5A020000', '5A28' + '00' * 0x28,
                   '5B020000', '5B28' + '00' * 0x28,
                   '5C020000', '5C28' + '00' * 0x28,
                   '5D020000', '5D28' + '00' * 0x28,
                   '5E020000', '5E28' + '00' * 0x28,
                   '5F020000', '5F28' + '00' * 0x28]

    invalid = ['50020000',  # Not OP_1-OP_16
               '61020000',  # Not OP_1-OP_16
               '5102000000',  # Extra bytes
               '510100',  # Too short
               '5129' + '00' * 0x29]  # Too long

    # Don't stress CI; just test edge cases
    if SLOW_MACHINE:
        valid = edge_valid
    else:
        valid = edge_valid + other_valid

    # More efficient to create them all up-front.
    nodes = node_factory.get_nodes(len(valid) + len(invalid))

    # Give it one UTXO to spend for each node.
    addresses = {}
    for n in nodes:
        addresses[l1.rpc.newaddr()['bech32']] = (10**6 + 100000) / 10**8
    bitcoind.rpc.sendmany("", addresses)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == len(addresses))

    # FIXME: Since we don't support other non-v0 encodings, we need a protocol
    # test for this (we're actually testing our upfront check, not the real
    # shutdown one!),
    for script in valid:
        # Insist on upfront script we're not going to match.
        l1.stop()
        l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = script
        l1.start()

        l2 = nodes.pop()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.fundchannel(l2.info['id'], 10**6)

    for script in invalid:
        # Insist on upfront script we're not going to match.
        l1.stop()
        l1.daemon.env["DEV_OPENINGD_UPFRONT_SHUTDOWN_SCRIPT"] = script
        l1.start()

        l2 = nodes.pop()
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError, match=r'Unacceptable upfront_shutdown_script'):
            l1.rpc.fundchannel(l2.info['id'], 10**6)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "Needs anchor_outputs")
@pytest.mark.developer("needs to set dev-disconnect")
def test_closing_higherfee(node_factory, bitcoind, executor):
    """With anchor outputs we can ask for a *higher* fee than the last commit tx"""

    # We change the feerate before it starts negotiating close, so it aims
    # for *higher* than last commit tx.
    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'feerates': (7500, 7500, 7500, 7500),
                                               'disconnect': ['-WIRE_CLOSING_SIGNED']},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'feerates': (7500, 7500, 7500, 7500)}])
    # This will trigger disconnect.
    fut = executor.submit(l1.rpc.close, l2.info['id'])
    l1.daemon.wait_for_log('dev_disconnect')

    # Now adjust fees so l1 asks for more on reconnect.
    l1.set_feerates((30000,) * 4, False)
    l2.set_feerates((30000,) * 4, False)
    l1.restart()
    l2.restart()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # This causes us to *exceed* previous requirements!
    l1.daemon.wait_for_log(r'deriving max fee from rate 30000 -> 16440sat \(not 1000000sat\)')

    # This will fail because l1 restarted!
    with pytest.raises(RpcError, match=r'Channel forgotten before proper close.'):
        fut.result(TIMEOUT)

    # But we still complete negotiation!
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'])['channels'][0]['state'] == 'CLOSINGD_COMPLETE')
    wait_for(lambda: only_one(l2.rpc.listpeers()['peers'])['channels'][0]['state'] == 'CLOSINGD_COMPLETE')


@unittest.skipIf(True, "Test is extremely flaky")
@pytest.mark.developer("needs dev_disconnect")
def test_htlc_rexmit_while_closing(node_factory, executor):
    """Retranmitting an HTLC revocation while shutting down should work"""
    # FIXME: This should be in lnprototest!  UNRELIABLE.
    # l1 disconnects after sending second COMMITMENT_SIGNED.
    # Then it stops receiving after sending WIRE_SHUTDOWN (which is before it
    # reads the revoke_and_ack).
    disconnects = ['+WIRE_COMMITMENT_SIGNED*2',
                   'xWIRE_SHUTDOWN']

    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'disconnect': disconnects},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None}])

    # Start payment, will disconnect
    l1.pay(l2, 200000)
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'])['connected'] is False)

    # Tell it to close (will block)
    fut = executor.submit(l1.rpc.close, l2.info['id'])

    # Original problem was with multiple disconnects, but to simplify we make
    # l2 send shutdown too.
    fut2 = executor.submit(l2.rpc.close, l1.info['id'])

    # Reconnect, shutdown will continue disconnect again
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Now l2 should be in CLOSINGD_SIGEXCHANGE, l1 still waiting on
    # WIRE_REVOKE_AND_ACK.
    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state'] == 'CLOSINGD_SIGEXCHANGE')
    assert only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_SHUTTING_DOWN'

    # They don't realize they're not talking, so disconnect and reconnect.
    l1.rpc.disconnect(l2.info['id'], force=True)

    # Now it hangs, since l1 is expecting rexmit of revoke-and-ack.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    fut.result(TIMEOUT)
    fut2.result(TIMEOUT)


@pytest.mark.openchannel('v1')
@pytest.mark.developer("needs dev_disconnect")
def test_you_forgot_closed_channel(node_factory, executor):
    """Ideally you'd keep talking to us about closed channels: simple"""
    disconnects = ['xWIRE_CLOSING_SIGNED']

    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'disconnect': disconnects},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None}])

    l1.pay(l2, 200000)

    fut = executor.submit(l1.rpc.close, l2.info['id'])

    # l2 considers the closing done, l1 does not
    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state'] == 'CLOSINGD_COMPLETE')
    assert only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CLOSINGD_SIGEXCHANGE'

    # l1 reconnects, it should succeed.
    if only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected']:
        l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    fut.result(TIMEOUT)


@pytest.mark.developer("needs dev_disconnect")
def test_you_forgot_closed_channel_onchain(node_factory, bitcoind, executor):
    """Ideally you'd keep talking to us about closed channels: even if close is mined"""
    disconnects = ['xWIRE_CLOSING_SIGNED']

    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True,
                                               'dev-no-reconnect': None,
                                               'disconnect': disconnects},
                                              {'may_reconnect': True,
                                               'dev-no-reconnect': None}])

    l1.pay(l2, 200000)

    fut = executor.submit(l1.rpc.close, l2.info['id'])

    # l2 considers the closing done, l1 does not
    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state'] == 'CLOSINGD_COMPLETE')
    assert only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CLOSINGD_SIGEXCHANGE'

    # l1 does not see any new blocks.
    def no_new_blocks(req):
        return {"result": {"blockhash": None, "block": None}}

    l1.daemon.rpcproxy.mock_rpc('getrawblockbyheight', no_new_blocks)

    # Close transaction mined
    bitcoind.generate_block(1, wait_for_mempool=1)

    wait_for(lambda: only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['state'] == 'ONCHAIN')

    # l1 reconnects, it should succeed.
    # l1 will disconnect once it sees block
    wait_for(lambda: only_one(l1.rpc.listpeers()['peers'])['connected'] is False)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    fut.result(TIMEOUT)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Uses regtest addresses")
@pytest.mark.developer("too slow without fast polling for blocks")
def test_segwit_anyshutdown(node_factory, bitcoind, executor):
    """Try a range of future segwit versions for shutdown"""
    l1, l2 = node_factory.line_graph(2, fundchannel=False)

    l1.fundwallet(10**7)

    # Based on BIP-320, but all changed to regtest.
    addrs = ("BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080",
             "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
             "bcrt1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0ylj56",
             "BCRT1SW50QT2UWHA",
             "bcrt1zw508d6qejxtdg4y5r3zarvaryv2wuatf",
             "bcrt1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseswlauz7",
             "bcrt1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesyga46z",
             "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6")

    for addr in addrs:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        l1.rpc.fundchannel(l2.info['id'], 10**6)
        # If we don't actually make a payment, two of the above cases fail
        # because the resulting tx is too small!  Balance channel so close
        # has two outputs.
        bitcoind.generate_block(1, wait_for_mempool=1)
        wait_for(lambda: any([c['state'] == 'CHANNELD_NORMAL' for c in only_one(l1.rpc.listpeers()['peers'])['channels']]))
        l1.pay(l2, 10**9 // 2)
        l1.rpc.close(l2.info['id'], destination=addr)
        bitcoind.generate_block(1, wait_for_mempool=1)
        wait_for(lambda: all([c['state'] == 'ONCHAIN' for c in only_one(l1.rpc.listpeers()['peers'])['channels']]))


@pytest.mark.developer("needs to manipulate features")
@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Uses regtest addresses")
def test_anysegwit_close_needs_feature(node_factory, bitcoind):
    """Rather than have peer reject our shutdown, we should refuse to shutdown toa v1+ address if they don't support it"""
    # L2 says "no option_shutdown_anysegwit"
    l1, l2 = node_factory.line_graph(2, opts=[{'may_reconnect': True},
                                              {'may_reconnect': True,
                                               'dev-force-features': -27}])

    with pytest.raises(RpcError, match=r'Peer does not allow v1\+ shutdown addresses'):
        l1.rpc.close(l2.info['id'], destination='bcrt1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0ylj56')

    # From TFM: "Tell your friends to upgrade!"
    l2.stop()
    del l2.daemon.opts['dev-force-features']
    l2.start()

    # Now it will work!
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.close(l2.info['id'], destination='bcrt1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0ylj56')
    wait_for(lambda: only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CLOSINGD_COMPLETE')
    bitcoind.generate_block(1, wait_for_mempool=1)


def test_close_feerate_range(node_factory, bitcoind, chainparams):
    """Test the quick-close fee range negotiation"""
    l1, l2 = node_factory.line_graph(2)

    notifications = []

    def save_notifications(message, progress, request, **kwargs):
        notifications.append(message)

    # Lowball the range here.
    with l1.rpc.notify(save_notifications):
        l1.rpc.close(l2.info['id'], feerange=['253perkw', 'normal'])

    if not chainparams['elements']:
        l1_range = [138, 4110]
        l2_range = [1027, 1000000]
    else:
        # That fee output is a little chunky.
        l1_range = [220, 6547]
        l2_range = [1636, 1000000]

    l1.daemon.wait_for_log('Negotiating closing fee between {}sat and {}sat satoshi'.format(l1_range[0], l1_range[1]))
    l2.daemon.wait_for_log('Negotiating closing fee between {}sat and {}sat satoshi'.format(l2_range[0], l2_range[1]))

    overlap = [max(l1_range[0], l2_range[0]), min(l1_range[1], l2_range[1])]
    l1.daemon.wait_for_log('performing quickclose in range {}sat-{}sat'.format(overlap[0], overlap[1]))

    log = l1.daemon.is_in_log('Their actual closing tx fee is .*sat')
    rate = re.match('.*Their actual closing tx fee is ([0-9]*sat).*', log).group(1)

    assert notifications == ['Sending closing fee offer {}, with range {}sat-{}sat'.format(rate,
                                                                                           l1_range[0],
                                                                                           l1_range[1]),
                             'Received closing fee offer {}, with range {}sat-{}sat'.format(rate,
                                                                                            l2_range[0],
                                                                                            l2_range[1])]


def test_close_twice(node_factory, executor):
    # First feerate is too low, second fixes it.
    l1, l2 = node_factory.line_graph(2, opts=[{'allow_warning': True,
                                               'may_reconnect': True},
                                              {'allow_warning': True,
                                               'may_reconnect': True,
                                               'feerates': (15000, 15000, 15000, 15000)}])

    # This makes it disconnect, since feerate is too low.
    fut = executor.submit(l1.rpc.close, l2.info['id'], feerange=['253perkw', '500perkw'])
    l1.daemon.wait_for_log('WARNING.*Unable to agree on a feerate')

    fut2 = executor.submit(l1.rpc.close, l2.info['id'], feerange=['253perkw', '15000perkw'])

    # Now reconnect, it should work.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    assert fut.result(TIMEOUT)['type'] == 'mutual'
    assert fut2.result(TIMEOUT)['type'] == 'mutual'


def test_close_weight_estimate(node_factory, bitcoind):
    """closingd uses the expected closing tx weight to constrain fees; make sure that lightningd agrees
    once it has the actual agreed tx"""
    l1, l2 = node_factory.line_graph(2)
    l1.rpc.close(l2.info['id'])

    # Closingd gives this estimate before it begins
    log = l1.daemon.wait_for_log('Expected closing weight = ')
    expected_weight = int(re.match('.*Expected closing weight = ([0-9]*),.*', log).group(1))

    # This is the actual weight: in theory this could use their
    # actual sig, and thus vary, but we don't do that.
    log = l1.daemon.wait_for_log('Their actual closing tx fee is')
    actual_weight = int(re.match('.*: weight is ([0-9]*).*', log).group(1))

    assert actual_weight == expected_weight

    log = l1.daemon.wait_for_log('sendrawtransaction: ')
    tx = re.match('.*sendrawtransaction: ([0-9a-f]*).*', log).group(1)

    # This could actually be a bit shorter: 1 in 256 chance we get
    # lucky with a sig and it's shorter.  We have 2 sigs, so that's
    # 1 in 128.  Unlikely to do better than 2 bytes off though!
    signed_weight = int(bitcoind.rpc.decoderawtransaction(tx)['weight'])
    assert signed_weight <= actual_weight
    assert signed_weight >= actual_weight - 2


@pytest.mark.developer("needs dev_disconnect")
def test_onchain_close_upstream(node_factory, bitcoind):
    """https://github.com/ElementsProject/lightning/issues/4649

We send an HTLC, and peer unilaterally closes: do we close upstream?
    """
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts=[{'feerates': (7500, 7500, 7500, 7500)},
                                               # Second commitment_signed is to l3
                                               {'disconnect': ['xWIRE_COMMITMENT_SIGNED*2'],
                                                # We want htlc killed by timeout, not a close due to ping timer.
                                                'dev-no-ping-timer': None},
                                               {'dev-no-ping-timer': None}])

    ph1 = l3.rpc.invoice(msatoshi="10000sat", label='x1', description='desc2')['payment_hash']
    ph2 = l3.rpc.invoice(msatoshi="10000sat", label='x2', description='desc2')['payment_hash']

    route = l1.rpc.getroute(l3.info['id'], 1, 1)['route']

    # Start a payment
    l1.rpc.sendpay(route, ph1)

    # l3 sends commitment_signed, then silence.
    l2.daemon.wait_for_log('dev_disconnect: xWIRE_COMMITMENT_SIGNED')

    # Send another payment, this times out.
    l1.rpc.sendpay(route, ph2)

    # This can take 30 seconds...
    l2.daemon.wait_for_log('Adding HTLC 1 too slow: killing connection',
                           timeout=TIMEOUT + 30)
    l2.daemon.wait_for_log('Failing HTLC 1 due to peer death')

    with pytest.raises(RpcError, match=r'WIRE_TEMPORARY_CHANNEL_FAILURE \(reply from remote\)'):
        l1.rpc.waitsendpay(ph2, timeout=TIMEOUT)

    # l3 closes unilaterally.
    wait_for(lambda: only_one(l3.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)
    l3.rpc.close(l2.info['id'], 1)

    l3.daemon.wait_for_log('sendrawtransaction')

    # Mine it
    bitcoind.generate_block(1, wait_for_mempool=1)

    # l2 tells onchaind to look for missing HTLC.
    l2.daemon.wait_for_logs(['Their unilateral tx',
                             r'We want to know if htlc 0 is missing \(later\)'])

#    # l1 disconnects now
#    l1.rpc.disconnect(l2.info['id'], force=True)
#    # Restart now, and reconnect
#    l2.restart()
#    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # After three blocks, onchaind says: definitely missing htlc
    bitcoind.generate_block(3)
    l2.daemon.wait_for_log('Sending 1 missing htlc messages')

    # l2 will tell l1 it has failed the htlc.
#    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_FAIL_HTLC')

    with pytest.raises(RpcError, match=r'WIRE_PERMANENT_CHANNEL_FAILURE \(reply from remote\)'):
        l1.rpc.waitsendpay(ph1, timeout=TIMEOUT)
