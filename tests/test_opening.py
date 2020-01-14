from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from flaky import flaky  # noqa: F401
from lightning import RpcError
from utils import EXPERIMENTAL_FEATURES, only_one, sync_blockheight, wait_for

import os
import pytest
import unittest


def gen_funding_tx(bitcoind, node1, node2, amount):
    """ Creates a valid funding transaction for node1->node2
        for <funding_amount> """
    node1.rpc.connect(node2.info['id'], 'localhost', node2.port)
    funding_addr = node1.rpc.fundchannel_start(node2.info['id'], amount)['funding_address']

    prep = node1.rpc.txprepare([{funding_addr: amount}], zero_out_change=True)
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # One output will be correct.
    if decode['vout'][0]['value'] == Decimal(str(amount / 10 ** 8)):
        txout = 0
    elif decode['vout'][1]['value'] == Decimal(str(amount / 10 ** 8)):
        txout = 1
    else:
        assert False

    return node1.rpc.fundchannel_complete(node2.info['id'], prep['txid'], txout)['txid']


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
def test_rbf(node_factory, bitcoind):
    # TODO: implement RBF!
    assert True


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_cancel_channel_twice(node_factory, bitcoind):
    # check that we are ok when a channel comes up for cancel twice
    # two utxos in the funding tx, each 'burnt' in a different tx (affects both
    # l1 and l2)
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node()
    l2 = node_factory.get_node(options={'plugin': plugin_path})
    l3 = node_factory.get_node()

    l1.fundwallet(200000000)
    l3.fundwallet(200000000)

    # Two funding inputs for l2
    l2.fundwallet(10000000)
    l2.fundwallet(10000000)
    assert len(l2.rpc.listfunds()['outputs']) == 2

    # `amount` is big enough to require 2 inputs from l2
    small_amount = 200000
    amount = 10000000 + small_amount
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']

    prep = l1.rpc.txprepare([{funding_addr: amount}], zero_out_change=True)
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # One output will be correct.
    if decode['vout'][0]['value'] == Decimal('0.10200000'):
        txout = 0
    elif decode['vout'][1]['value'] == Decimal('0.10200000'):
        txout = 1
    else:
        assert False

    txid = l1.rpc.fundchannel_complete(l2.info['id'], prep['txid'], txout)['txid']
    assert only_one(l1.rpc.listpeers()['peers'])['channels'] is not None

    # Funds should be committed to this channel open
    chan = only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])
    assert chan['msatoshi_to_us'] == amount * 1000

    # Both got put into the channel funding
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    for o in funds['reserved_outputs']:
        assert not o['reservation_expired']

    # l1 doesn't broadcast, let's advance 18 blocks (UTXO_RESERVATION_BLOCKS)
    l1.bitcoin.generate_block(18)
    sync_blockheight(bitcoind, [l2])

    # Check that reservations have expired for reserved outputs
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    for o in funds['reserved_outputs']:
        assert o['reservation_expired']

    # try to fundchannel from l3 <-> l2 now
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Use `small_amount` so we only use one utxo
    l3.rpc.fundchannel(l2.info['id'], small_amount)

    # before tx is block-confirmed, both channels are awaiting lock-in
    for c in l2.rpc.listfunds()['channels']:
        assert c['state'] == 'CHANNELD_AWAITING_LOCKIN'
        # check that the l3 channel only has one utxo reservation
        if c['peer_id'] == l3.info['id']:
            assert len(c['utxo_reservations']) == 1
        else:
            # but l1 should have both
            assert len(c['utxo_reservations']) == 2

    # We'll also withdraw a utxo for l2 to ourself, this should spend
    # the other utxo in the l1l2 channel open that we're borking
    l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all')

    # Go ahead and sink the funding tx for l2<->l3 and the withdrawal
    l1.bitcoin.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3])

    funds = l2.rpc.listfunds()
    # Check the withdrawal worked
    avail_out = only_one(funds['outputs'])
    assert avail_out['value'] < 10000000 and avail_out['value'] > 9000000
    assert avail_out['status'] == 'confirmed'
    assert len(funds['reserved_outputs']) == 0
    for c in funds['channels']:
        if c['peer_id'] == l3.info['id']:
            c['state'] == 'CHANNELD_NORMAL'
            c['channel_sat'] == small_amount
        else:
            c['state'] == 'CHANNELD_BORKED'
            c['channel_sat'] == amount

    assert only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_BORKED'

    # Roll forward to where the cleanup logic gets played
    l2.bitcoin.generate_block(5)
    sync_blockheight(bitcoind, [l1, l2, l3])

    wait_for(lambda: len(l1.rpc.listpeers()['peers']) == 0)

    # why did l2 not forget l1?
    assert only_one(l2.rpc.listfunds()['channels'])['state'] == 'CHANNELD_NORMAL'

    # l1's state is kind of fucked up because it's really not supposed to not
    # publish the funding tx
    len(l1.rpc.listfunds()['outputs']) == 0
    len(l1.rpc.listfunds()['reserved_outputs']) == 1
    # Clean up prepped tx, otherwise we leak on quit
    l1.rpc.txdiscard(txid)
    len(l1.rpc.listfunds()['outputs']) == 1
    len(l1.rpc.listfunds()['reserved_outputs']) == 0


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
        assert len(c['utxo_reservations']) == 1
        utxo_rez = c['utxo_reservations'][0]
        assert utxo_rez['txid'] == reserved_out['txid'] and utxo_rez['output'] == reserved_out['output']

    # the reserved output's txid + outpoint should be in each of the pending channels
    peers = l2.rpc.listpeers()['peers']
    assert len(peers) == 2
    for p in peers:
        assert only_one(p['channels'])['state'] == 'CHANNELD_AWAITING_LOCKIN'

    # Go ahead and sink the funding tx for l2<->l3
    l1.bitcoin.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3])

    peers = l2.rpc.listpeers()['peers']
    assert len(peers) == 2
    for p in peers:
        if p['id'] == l3.info['id']:
            only_one(p['channels'])['state'] == 'CHANNELD_NORMAL'
        else:
            only_one(p['channels'])['state'] == 'CHANNELD_BORKED'

    # Try to 'cancel' a BORKED channel
    with pytest.raises(RpcError, match=r'Channel is considered \'borked\' and is uncloseable'):
        l1.rpc.fundchannel_cancel(l2.info['id'])

    # Check that the reserved funds have gone away!
    funds = l2.rpc.listfunds()
    assert len(funds['reserved_outputs']) == 0
    for c in funds['channels']:
        assert c['channel_sat'] == amount
        assert c['channel_total_sat'] == amount * 2
        assert 'utxo_reservations' not in c

    assert only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_BORKED'

    # Attempt to close borked channel, shouldn't work (not active)
    with pytest.raises(RpcError, match=r'Peer has no active channel'):
        l1.rpc.close(l2.info['id'])

    # Clean up prepped tx, otherwise we leak on quit
    l1.rpc.txdiscard(txid)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_cancel_with_withdraw(node_factory, bitcoind):
    # We re-use inputs if the tx hasn't been broadcast within a few hours/blocks
    # Let's make sure we clean up the channel correctly if we withdraw
    # the funds after the reservation window has expired.
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

    # withdraw should fail here, since we don't have funds available
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
        l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all')

    # l1 doesn't broadcast, let's advance 18 blocks (UTXO_RESERVATION_BLOCKS)
    l1.bitcoin.generate_block(18)
    sync_blockheight(bitcoind, [l2])

    # now we can withdraw the funds, no problem
    l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], 'all')

    # before the block is confirmed, we should still have the channel available
    # and awaiting lock-in
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 1
    # there's a little bit of weirdness here, in that the reserved output
    # goes away, but we still show the utxos' for it in the awaiting channel;
    # it will get cleaned up as soon as the tx is mined and at depth 6
    assert len(funds['reserved_outputs']) == 0
    assert only_one(funds['channels'])['state'] == 'CHANNELD_AWAITING_LOCKIN'

    # Go ahead and sink the withdrawal
    l1.bitcoin.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2])

    # Check that the channel has been marked as borked, on both sides
    for node in [l1, l2]:
        chan_funds = node.rpc.listfunds()['channels']
        assert only_one(chan_funds)['state'] == 'CHANNELD_BORKED'

    # Clean up prepped tx, otherwise we leak on quit
    l1.rpc.txdiscard(txid)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_original_publishes(node_factory, bitcoind):
    """ Same thing as double_spend test, except that the original
        node publishes the tx, after the reservation has expired """
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

    l1_txid = l1.rpc.fundchannel_complete(l2.info['id'], prep['txid'], txout)['txid']
    assert only_one(l1.rpc.listpeers()['peers'])['channels'] is not None

    # Funds should be committed to this channel open
    chan = only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])
    assert chan['msatoshi_to_us'] == amount * 1000
    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert not only_one(funds['reserved_outputs'])['reservation_expired']

    # l1 doesn't broadcast, let's advance 18 blocks (UTXO_RESERVATION_BLOCKS)
    l1.bitcoin.generate_block(18)
    sync_blockheight(bitcoind, [l2])

    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert only_one(funds['reserved_outputs'])['reservation_expired']

    # try to fundchannel from l3 <-> l2 now
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l3.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']

    prep = l3.rpc.txprepare([{funding_addr: amount}], zero_out_change=True)
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # One output will be correct.
    if decode['vout'][0]['value'] == Decimal('0.00200000'):
        txout = 0
    elif decode['vout'][1]['value'] == Decimal('0.00200000'):
        txout = 1
    else:
        assert False

    l3_txid = l3.rpc.fundchannel_complete(l2.info['id'], prep['txid'], txout)['txid']
    assert only_one(l3.rpc.listpeers()['peers'])['channels'] is not None

    peers = l2.rpc.listpeers()['peers']
    assert len(peers) == 2
    for p in peers:
        assert only_one(p['channels'])['state'] == 'CHANNELD_AWAITING_LOCKIN'

    # Go ahead and sink the funding tx for l1<->l2
    l1.rpc.txsend(l1_txid)
    l1.bitcoin.generate_block(1)
    sync_blockheight(bitcoind, [l2, l3])

    peers = l2.rpc.listpeers()['peers']
    assert len(peers) == 2
    # The status for l1<->l2 is ok, l2<->l3 is borked
    for p in peers:
        if p['id'] == l1.info['id']:
            only_one(p['channels'])['state'] == 'CHANNELD_NORMAL'
        else:
            only_one(p['channels'])['state'] == 'CHANNELD_BORKED'

    # Check that the reserved funds have gone away!
    funds = l2.rpc.listfunds()
    assert len(funds['reserved_outputs']) == 0

    # There's still two channel entries; one's normal the other's borked
    assert len(funds['channels']) == 2
    for c in funds['channels']:
        c['channel_sat'] == amount
        c['channel_total_sat'] == amount * 2
        assert 'utxo_reservations' not in c

    assert only_one(only_one(l3.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_BORKED'

    # What happens if l3 tries to broadcast?
    with pytest.raises(RpcError, match=r'Missing inputs. Unsent tx discarded'):
        l3.rpc.txsend(l3_txid)

    assert only_one(only_one(l3.rpc.listpeers()['peers'])['channels'])['state'] == 'CHANNELD_BORKED'

    # Now sink the 'borking' transaction so that the borked channel gets cleaned up
    l1.bitcoin.generate_block(5)
    sync_blockheight(bitcoind, [l2, l3])

    # Check that l2 has canceled / thrown away l3
    assert len(l2.rpc.listpeers()['peers']) == 1
    # Check that l3 has canceled / thrown away l2
    assert len(l3.rpc.listpeers()['peers']) == 0


# This assumes that EXPERIMENTAL_FEATURES implies DEVELOPER
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "needs EXPERIMENTAL_FEATURES=1")
def test_borked_tx_reorg(node_factory, bitcoind):
    """ We should be able to bork a transaction, then reorg and confirm it.
        We should also be able to confirm a tx, reorg and then bork it."""
    # Rescan to detect reorg at restart and may_reconnect so channeld
    # will restart.  Reorg can cause bad gossip msg.
    opts = {'funding-confirms': 6, 'rescan': 10}
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node(options=opts)
    l3 = node_factory.get_node(options=opts)

    # Add the plugin path, so that l2 does the double funding thing
    opts['plugin'] = plugin_path
    l2 = node_factory.get_node(options=opts)

    l1.fundwallet(10000000)                         # height 101
    l2.fundwallet(10000000)                         # height 102
    l2.fundwallet(10000000)                         # height 103
    l3.fundwallet(10000000)                         # height 104

    funding_amount = 1000000
    gen_funding_tx(bitcoind, l1, l2, funding_amount)
    bitcoind.generate_block(1)                      # height 105

    l3l2_funding_txid = gen_funding_tx(bitcoind, l3, l2, funding_amount)

    # Generate 18 more so that l2 can withdraw at least one of the txs
    bitcoind.generate_block(17)                     # heights 106-122
    sync_blockheight(bitcoind, [l2])

    # Go ahead and withdraw some money for l2. Because of the 1
    # block difference, only the l1l2 funding_tx should be available
    l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], funding_amount)

    # Ship the other funding_tx
    l3.rpc.txsend(l3l2_funding_txid)

    bitcoind.generate_block(3)                      # heights 123-125
    sync_blockheight(bitcoind, [l1, l2, l3])

    # Ok, one channel should be borked, the other channel should
    # be awaiting lockin, with a scid
    assert only_one(l1.rpc.listpeers()['peers'])['channels'][0]['state'] == 'CHANNELD_BORKED'
    l3_channel = only_one(l3.rpc.listpeers()['peers'])['channels'][0]
    assert l3_channel['state'] == 'CHANNELD_AWAITING_LOCKIN'
    assert 'short_channel_id' not in l3_channel

    # Stop l1 before the reorg
    l1.stop()
    bitcoind.simple_reorg(122)                      # height 122
    sync_blockheight(bitcoind, [l2, l3])

    # Check that they got rolled back to 'awaiting lockin'
    # QUES: why does mining a single block move this channel to NORMAL?
    # it should be in 'AWAITING_LOCKIN', no?
    for node in [l3]:
        l3_channel = only_one(node.rpc.listpeers()['peers'])['channels'][0]
        assert l3_channel['state'] == 'CHANNELD_NORMAL'
        assert 'short_channel_id' in l3_channel

    # ideally we'd evict them both from the pool and re-do things (i.e. swap
    # who's borked and who isn't) but i'm not sure how to do that, so for now
    # we'll just assume a roll forward again is a similar enough, tho weaker, check
    bitcoind.generate_block(6)                      # heights 123-125
    l1.start()
    sync_blockheight(bitcoind, [l1, l2, l3])

    # run the same state check!
    assert not l1.rpc.listpeers()['peers']
    l3_channel = only_one(l3.rpc.listpeers()['peers'])['channels'][0]
    assert l3_channel['state'] == 'CHANNELD_NORMAL'
    assert 'short_channel_id' in l3_channel


# This assumes that EXPERIMENTAL_FEATURES implies DEVELOPER
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "needs EXPERIMENTAL_FEATURES=1")
def test_borked_tx_restart(node_factory, bitcoind):
    # Test that restarting a node while a transaction is borked/getting borked/
    # buried works as expected
    opts = {'funding-confirms': 6, 'rescan': 10}
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node(options=opts)
    opts['plugin'] = plugin_path
    l2 = node_factory.get_node(options={'plugin': plugin_path})

    l1.fundwallet(10000000)
    l2.fundwallet(10000000)

    funding_amount = 1000000
    gen_funding_tx(bitcoind, l1, l2, funding_amount)

    l1.stop()

    # Have l2 spend their funds elsewhere, and mine it
    bitcoind.generate_block(18)
    sync_blockheight(bitcoind, [l2])
    l2.rpc.withdraw(l2.rpc.newaddr()['bech32'], funding_amount)
    bitcoind.generate_block(1)

    l1.start()
    sync_blockheight(bitcoind, [l1])

    assert only_one(l1.rpc.listfunds()['channels'])['state'] == 'CHANNELD_BORKED'

    l1.restart()
    # Wait for the sync to finish
    sync_blockheight(bitcoind, [l1])

    # Still in BORKED state
    assert len(l1.rpc.listfunds()['channels']) == 1
    assert only_one(l1.rpc.listfunds()['channels'])['state'] == 'CHANNELD_BORKED'

    l1.stop()
    bitcoind.generate_block(5)      # Push the borking tx down to 6
    l1.start()
    sync_blockheight(bitcoind, [l1])
    assert len(l1.rpc.listpeers()['peers']) == 0
    assert len(l1.rpc.listfunds()['channels']) == 0


# Test closing a channel that's not on-chain yet (but going to be borked?)
# Test fundchannel_cancel'ing a channel that's not on-chain yet (but will be borked?)
# - we shouldn't be able to cancel these, but we can 'bork' them by spending their input
# - an enterprising human can do this pretty straightforwardly. hmmmmmm
