from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from flaky import flaky  # noqa: F401
from utils import EXPERIMENTAL_FEATURES, only_one, sync_blockheight

import os
import unittest


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_two_sided_open(node_factory, bitcoind):
    # We need a plugin to get l2 to contribute funds
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    fund_amount = 200000
    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'plugin': plugin_path})

    l1.fundwallet(200000000)
    l2.fundwallet(200000000)

    l2_utxos = l2.rpc.listfunds()['outputs']
    assert(only_one(l2_utxos))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We use an even amount, so l2 wil match
    l1.rpc.fundchannel(l2.info['id'], fund_amount)
    l1.bitcoin.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2])

    # Check that channel established correctly
    for node in [l1, l2]:
        node.daemon.wait_for_log(r'State changed from CHANNELD_AWAITING_LOCKIN to CHANNELD_NORMAL')
        channel = node.rpc.listpeers()['peers'][0]['channels'][0]
        # Funding amount should be double
        assert fund_amount * 2 * 1000 == channel['msatoshi_total']
        assert fund_amount * 1000 == channel['msatoshi_to_us']
        # Reserve should be 1% or the dust limit
        assert channel['their_channel_reserve_satoshis'] == max(fund_amount * 2 // 100, 546)
        assert channel['our_channel_reserve_satoshis'] == max(fund_amount * 2 // 100, 546)

    # Check that l2's original utxos have been spent
    for o in l2.rpc.listfunds()['outputs']:
        assert(o.status == 'confirmed')
        for t in l2_utxos:
            assert(not (o['txid'] == t['txid'] and o['output'] == t['output']))


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_reservation_crash(node_factory, bitcoind):
    # we shouldn't reset to available if we crash with reserved utxos
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'plugin': plugin_path})

    l1.fundwallet(200000000)
    l2.fundwallet(200000000)

    amount = 200000
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']

    prep = l1.rpc.txprepare([{funding_addr: amount}], zero_out_change=True)
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # One output will be correct.
    if decode['vout'][0]['value'] == Decimal('0.00200000'):
        txout = 0
    elif decode['vout'][1]['value'] == Decimal('0.00200000'):
        txout = 1
    else:
        assert False

    txid = l1.rpc.fundchannel_complete(l2.info['id'], prep['txid'], txout)['txid']
    assert only_one(l1.rpc.listpeers()['peers'])['channels'] is not None

    # Funds should be committed to this channel open
    chan = only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])
    assert chan['msatoshi_to_us'] == amount * 1000
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert not only_one(funds['reserved_outputs'])['reservation_expired']

    # now we crash l2, who's got some reserved funds
    l2.daemon.kill()
    l2.start()

    # check that our funds are still marked as reserved
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert not only_one(funds['reserved_outputs'])['reservation_expired']

    # discard reserved tx so we don't leak on quit
    l1.rpc.txdiscard(txid)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_cancel_channel_twice(node_factory):
    # check that we can cancel a channel 'twice' (two utxos in a different open)
    assert True


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_rbf(node_factory, bitcoind):
    assert True


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_double_spends(node_factory, bitcoind):
    # We re-use inputs if the tx hasn't been broadcast within a few hours/blocks
    # In the case that this happens, we should gracefully shutdown the
    # channels associated with the double-spent utxo
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'plugin': plugin_path})
    l3 = node_factory.get_node()

    l1.fundwallet(200000000)
    l2.fundwallet(200000000)
    l3.fundwallet(200000000)

    amount = 200000
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']

    prep = l1.rpc.txprepare([{funding_addr: amount}], zero_out_change=True)
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # One output will be correct.
    if decode['vout'][0]['value'] == Decimal('0.00200000'):
        txout = 0
    elif decode['vout'][1]['value'] == Decimal('0.00200000'):
        txout = 1
    else:
        assert False

    txid = l1.rpc.fundchannel_complete(l2.info['id'], prep['txid'], txout)['txid']
    assert only_one(l1.rpc.listpeers()['peers'])['channels'] is not None

    # Funds should be committed to this channel open
    chan = only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])
    assert chan['msatoshi_to_us'] == amount * 1000
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert not only_one(funds['reserved_outputs'])['reservation_expired']
    originally_reserved_at = only_one(funds['reserved_outputs'])['reserved_at_height']

    # l1 doesn't broadcast, let's advance 18 blocks (UTXO_RESERVATION_BLOCKS)
    l1.bitcoin.generate_block(18)
    sync_blockheight(bitcoind, [l2])

    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert only_one(funds['reserved_outputs'])['reservation_expired']

    # try to fundchannel from l3 <-> l2 now
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l3.rpc.fundchannel(l2.info['id'], amount)

    # before the block is confirmed, we should still have both channels available
    # and awaiting lock-in
    funds = l2.rpc.listfunds()
    reserved_out = only_one(funds['reserved_outputs'])
    reserved_out['reserved_at_height'] > originally_reserved_at
    for c in funds['channels']:
        utxo_rez = only_one(c['utxo_reservations'])
        assert utxo_rez['txid'] == reserved_out['txid'] and utxo_rez['output'] == reserved_out['output']
    # the reserved output's txid + outpoint should be in each of the pending channels
    peers = l2.rpc.listpeers()['peers']
    assert len(peers) == 2
    for p in peers:
        assert only_one(p['channels'])['state'] == 'CHANNELD_AWAITING_LOCKIN'

    # Go ahead and sink the funding tx for l2<->l3
    l1.bitcoin.generate_block(1)
    sync_blockheight(bitcoind, [l2])

    peers = l2.rpc.listpeers()['peers']
    assert len(peers) == 1
    for p in peers:
        only_one(p['channels'])['state'] == 'CHANNELD_NORMAL'

    # Check that the reserved funds have gone away!
    funds = l2.rpc.listfunds()
    assert len(funds['reserved_outputs']) == 0
    only_one(funds['channels'])['channel_sat'] == amount
    only_one(funds['channels'])['channel_total_sat'] == amount * 2
    assert 'utxo_reservations' not in only_one(funds['channels'])

    # Clean up prepped tx, otherwise we leak on quit
    l1.rpc.txdiscard(txid)
