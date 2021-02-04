from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from utils import (
    only_one, wait_for, sync_blockheight, EXPERIMENTAL_FEATURES
)

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

    # Check that feerate info is correct
    info_1 = only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])
    assert info_1['initial_feerate'] == info_1['last_feerate']
    rate = int(info_1['last_feerate'][:-5])
    assert int(info_1['next_feerate'][:-5]) == rate + rate // 4
    assert info_1['next_fee_step'] == 1

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

    # Check that feerate info has incremented
    info_2 = only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])
    assert info_1['initial_feerate'] == info_2['initial_feerate']
    assert info_1['next_feerate'] == info_2['last_feerate']

    rate = int(info_2['last_feerate'][:-5])
    assert int(info_2['next_feerate'][:-5]) == rate + rate // 4
    assert info_2['next_fee_step'] == 2

    # Sign our inputs, and continue
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']
    l1.rpc.openchannel_signed(chan_id, signed_psbt)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')

    # Check that feerate info is gone
    info_1 = only_one(only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['channels'])
    assert 'initial_feerate' not in info_1
    assert 'last_feerate' not in info_1
    assert 'next_feerate' not in info_1
    assert 'next_fee_step' not in info_1

    # Shut l2 down, force close the channel.
    l2.stop()
    resp = l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    assert resp['type'] == 'unilateral'
    l1.daemon.wait_for_log(' to CHANNELD_SHUTTING_DOWN')
    l1.daemon.wait_for_log('sendrawtx exit 0')

