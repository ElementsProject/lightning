from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from flaky import flaky  # noqa: F401
from lightning import RpcError
from utils import EXPERIMENTAL_FEATURES, only_one, sync_blockheight

import os
import pytest
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

    # l1 doesn't broadcast, let's advance 18 blocks (UTXO_RESERVATION_BLOCKS)
    l1.bitcoin.generate_block(18)
    sync_blockheight(bitcoind, [l2])

    funds = l2.rpc.listfunds()
    assert len(funds['outputs']) == 0
    assert only_one(funds['reserved_outputs'])['reservation_expired']

    # try to fundchannel from l3 <-> l2 now
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l3.rpc.fundchannel(l2.info['id'], amount)

    # since we haven't updated our lookup for available utxos yet,
    # we get a warning!!
    l2.daemon.wait_for_log(r'Attempting to fund channel for 20000sat when max was set to 0sat')

    # Clean up prepped tx, otherwise we leak on quit
    l1.rpc.txdiscard(txid)


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_peer_publish_afterburn(node_factory, bitcoind):
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(options={'plugin': plugin_path},
                               may_reconnect=True)

    l1.fundwallet(200000000)
    l2.fundwallet(200000000)

    amount = 1000000
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    funding_addr = l1.rpc.fundchannel_start(l2.info['id'], amount)['funding_address']

    prep = l1.rpc.txprepare([{funding_addr: amount}])
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']

    # One output will be correct.
    if decode['vout'][0]['value'] == Decimal('0.01000000'):
        txout = 0
    elif decode['vout'][1]['value'] == Decimal('0.01000000'):
        txout = 1
    else:
        assert False

    complete = l1.rpc.fundchannel_complete(l2.info['id'], prep['txid'], txout)
    assert complete['commitments_secured']
    txid = complete['txid']

    # First prevent the burn from happening
    def mock_sendrawtransaction(r):
        return {'id': r['id'], 'error': {'code': 100, 'message': 'sendrawtransaction disabled'}}

    # Prevent funder from broadcasting funding tx (any tx really).
    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_sendrawtransaction)

    # Spin up a burn, but fail to publish it
    l2.bitcoin.generate_block(132 + 25)
    sync_blockheight(bitcoind, [l2])

    # We should have been blocked from sending transaction
    l2.daemon.wait_for_log(r'Unable to publish burn transaction. Errno 100')
    assert len(l2.rpc.listfunds()['outputs']) == 0
    assert len(l1.rpc.listfunds()['outputs']) == 0

    # Remove the block, try again
    l2.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)
    l2.bitcoin.generate_block(25)
    sync_blockheight(bitcoind, [l2])

    # Shared txs should have burned, now
    l2.daemon.wait_for_log(r'Found 1 burnable output at blockheight')
    only_one(l2.rpc.listfunds()['outputs'])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    only_one(l1.rpc.listpeers()['peers'])['channels'] is None

    # Try sending the transaction
    with pytest.raises(RpcError, match=r'Error broadcasting transaction:'):
        l1.rpc.txsend(txid)

    # tx should not be around anymore
    with pytest.raises(RpcError, match=r'not an unreleased txid'):
        l1.rpc.txdiscard(txid)

    assert only_one(l1.rpc.listfunds()['outputs'])


@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual funding is experimental")
def test_accepter_burns(node_factory, bitcoind):
    # We need a plugin to get l2 to contribute funds
    plugin_path = os.path.join(os.getcwd(), 'tests/plugins/funder.py')

    l1 = node_factory.get_node(may_reconnect=True)
    l2 = node_factory.get_node(may_reconnect=True)
    l3 = node_factory.get_node(options={'plugin': plugin_path},
                               may_reconnect=True)

    l1.fundwallet(200000000)
    l2.fundwallet(200000000)
    l3.fundwallet(200000000)
    l3.fundwallet(100000000)

    assert len(l3.rpc.listfunds()['outputs']) == 2

    fund_amount = 200000

    def mock_sendrawtransaction(r):
        return {'id': r['id'], 'error': {'code': 100, 'message': 'sendrawtransaction disabled'}}

    # Have two nodes attempt to connect with l3
    for node in [l1, l2]:
        # Prevent funder from broadcasting funding tx (any tx really).
        node.daemon.rpcproxy.mock_rpc('sendrawtransaction', mock_sendrawtransaction)
        node.rpc.connect(l3.info['id'], 'localhost', l3.port)
        with pytest.raises(RpcError):
            node.rpc.fundchannel(l3.info['id'], fund_amount)

    # Outputs should be in 'shared' state
    assert len(l3.rpc.listfunds()['outputs']) == 0

    # Advance the blockchain til we hit the burn
    l3.bitcoin.generate_block(132 + 25)
    sync_blockheight(bitcoind, [l3])

    # Shared txs should have burned
    l3.daemon.wait_for_log(r'Found 2 burnable outputs at blockheight')
    o = only_one(l3.rpc.listfunds()['outputs'])

    # Should be one utxo roughly the value of the two orignal
    # utxos, minus fees
    assert(o['value'] < 300000000 and o['value'] > 299900000)

    # Check that channel has been cancelled/forgotten
    for node in [l1, l2]:
        node.rpc.connect(l3.info['id'], 'localhost', l3.port)
        only_one(node.rpc.listpeers()['peers'])['channels'] is None
        assert only_one(node.rpc.listfunds()['outputs'])['value'] == 200000000
