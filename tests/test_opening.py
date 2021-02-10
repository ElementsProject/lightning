from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import (
    only_one, wait_for, sync_blockheight, EXPERIMENTAL_FEATURES
)

import pytest
import unittest


def find_next_feerate(node, peer):
    chan = only_one(only_one(node.rpc.listpeers(peer.info['id'])['peers'])['channels'])
    return chan['next_feerate']


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual-funding is experimental only")
def test_v2_rbf(node_factory, bitcoind, chainparams):
    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'dev-force-features': '+223'},
                                          {'dev-force-features': '+223'}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    res = l1.rpc.fundchannel(l2.info['id'], chan_amount)
    chan_id = res['channel_id']
    vins = bitcoind.rpc.decoderawtransaction(res['tx'])['vin']
    assert(only_one(vins))
    prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]

    # Check that we're waiting for lockin
    l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Do the bump
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])

    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])
    assert update['commitments_secured']

    # Sign our inputs, and continue
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']
    l1.rpc.openchannel_signed(chan_id, signed_psbt)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')

    # Shut l2 down, force close the channel.
    l2.stop()
    resp = l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    assert resp['type'] == 'unilateral'
    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
    l1.daemon.wait_for_log('sendrawtx exit 0')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual-funding is experimental only")
def test_rbf_reconnect_init(node_factory, bitcoind, chainparams):
    disconnects = ['-WIRE_INIT_RBF',
                   '@WIRE_INIT_RBF',
                   '+WIRE_INIT_RBF']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'dev-force-features': '+223',
                                           'disconnect': disconnects,
                                           'may_reconnect': True},
                                          {'dev-force-features': '+223',
                                           'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    res = l1.rpc.fundchannel(l2.info['id'], chan_amount)
    chan_id = res['channel_id']
    vins = bitcoind.rpc.decoderawtransaction(res['tx'])['vin']
    assert(only_one(vins))
    prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]

    # Check that we're waiting for lockin
    l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Do the bump!?
    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
        assert l1.rpc.getpeer(l2.info['id']) is not None

    # This should succeed
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual-funding is experimental only")
def test_rbf_reconnect_ack(node_factory, bitcoind, chainparams):
    disconnects = ['-WIRE_ACK_RBF',
                   '@WIRE_ACK_RBF',
                   '+WIRE_ACK_RBF']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'dev-force-features': '+223',
                                           'may_reconnect': True},
                                          {'dev-force-features': '+223',
                                           'disconnect': disconnects,
                                           'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    res = l1.rpc.fundchannel(l2.info['id'], chan_amount)
    chan_id = res['channel_id']
    vins = bitcoind.rpc.decoderawtransaction(res['tx'])['vin']
    assert(only_one(vins))
    prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]

    # Check that we're waiting for lockin
    l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Do the bump!?
    for d in disconnects:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
        assert l1.rpc.getpeer(l2.info['id']) is not None

    # This should succeed
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "dual-funding is experimental only")
def test_rbf_reconnect_tx_construct(node_factory, bitcoind, chainparams):
    disconnects = ['=WIRE_TX_ADD_INPUT',  # Initial funding succeeds
                   '-WIRE_TX_ADD_INPUT',
                   '@WIRE_TX_ADD_INPUT',
                   '+WIRE_TX_ADD_INPUT',
                   '-WIRE_TX_ADD_OUTPUT',
                   '@WIRE_TX_ADD_OUTPUT',
                   '+WIRE_TX_ADD_OUTPUT',
                   '-WIRE_TX_COMPLETE',
                   '@WIRE_TX_COMPLETE',
                   '+WIRE_TX_COMPLETE']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'dev-force-features': '+223',
                                           'disconnect': disconnects,
                                           'may_reconnect': True},
                                          {'dev-force-features': '+223',
                                           'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    res = l1.rpc.fundchannel(l2.info['id'], chan_amount)
    chan_id = res['channel_id']
    vins = bitcoind.rpc.decoderawtransaction(res['tx'])['vin']
    assert(only_one(vins))
    prev_utxos = ["{}:{}".format(vins[0]['txid'], vins[0]['vout'])]

    # Check that we're waiting for lockin
    l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Run through TX_ADD wires
    for d in disconnects[1:-3]:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        with pytest.raises(RpcError):
            l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
        assert l1.rpc.getpeer(l2.info['id']) is not None

    # Now we finish off the completes failure check
    for d in disconnects[-3:]:
        l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
        bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
        with pytest.raises(RpcError):
            update = l1.rpc.openchannel_update(chan_id, bump['psbt'])

    # Now we succeed
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])
    assert update['commitments_secured']
