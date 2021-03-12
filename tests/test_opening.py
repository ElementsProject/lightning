from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError
from utils import (
    only_one, wait_for, sync_blockheight, DEVELOPER, first_channel_id
)

import pytest
import re
import unittest


def find_next_feerate(node, peer):
    chan = only_one(only_one(node.rpc.listpeers(peer.info['id'])['peers'])['channels'])
    return chan['next_feerate']


@unittest.skipIf(not DEVELOPER, "disconnect=... needs DEVELOPER=1")
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_multifunding_v2_best_effort(node_factory, bitcoind):
    '''
    Check that best_effort flag works.
    '''
    disconnects = ["-WIRE_INIT",
                   "-WIRE_ACCEPT_CHANNEL",
                   "-WIRE_FUNDING_SIGNED"]
    l1 = node_factory.get_node(options={'experimental-dual-fund': None},
                               allow_warning=True,
                               may_reconnect=True)
    l2 = node_factory.get_node(options={'experimental-dual-fund': None},
                               allow_warning=True,
                               may_reconnect=True)
    l3 = node_factory.get_node(disconnect=disconnects)
    l4 = node_factory.get_node()

    l1.fundwallet(2000000)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 50000},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 50000}]

    for i, d in enumerate(disconnects):
        failed_sign = d == "-WIRE_FUNDING_SIGNED"
        # Should succeed due to best-effort flag.
        min_channels = 1 if failed_sign else 2
        l1.rpc.multifundchannel(destinations, minchannels=min_channels)

        bitcoind.generate_block(6, wait_for_mempool=1)

        # l3 should fail to have channels; l2 also fails on last attempt
        node_list = [l1, l4] if failed_sign else [l1, l2, l4]
        for node in node_list:
            node.daemon.wait_for_log(r'to CHANNELD_NORMAL')

        # There should be working channels to l2 and l4 for every run
        # but the last
        working_chans = [l4] if failed_sign else [l2, l4]
        for ldest in working_chans:
            inv = ldest.rpc.invoice(5000, 'i{}'.format(i), 'i{}'.format(i))['bolt11']
            l1.rpc.pay(inv)

        # Function to find the SCID of the channel that is
        # currently open.
        # Cannot use LightningNode.get_channel_scid since
        # it assumes the *first* channel found is the one
        # wanted, but in our case we close channels and
        # open again, so multiple channels may remain
        # listed.
        def get_funded_channel_scid(n1, n2):
            peers = n1.rpc.listpeers(n2.info['id'])['peers']
            assert len(peers) == 1
            peer = peers[0]
            channels = peer['channels']
            assert channels
            for c in channels:
                state = c['state']
                if state in ('DUALOPEND_AWAITING_LOCKIN', 'CHANNELD_AWAITING_LOCKIN', 'CHANNELD_NORMAL'):
                    return c['short_channel_id']
            assert False

        # Now close channels to l2 and l4, for the next run.
        if not failed_sign:
            l1.rpc.close(get_funded_channel_scid(l1, l2))
        l1.rpc.close(get_funded_channel_scid(l1, l4))

        for node in node_list:
            node.daemon.wait_for_log(r'to CLOSINGD_COMPLETE')

    # With 2 down, it will fail to fund channel
    l2.stop()
    l3.stop()
    with pytest.raises(RpcError, match=r'Connection refused'):
        l1.rpc.multifundchannel(destinations, minchannels=2)

    # This works though.
    l1.rpc.multifundchannel(destinations, minchannels=1)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not DEVELOPER, "disconnect=... needs DEVELOPER=1")
def test_v2_open_sigs_restart(node_factory, bitcoind):
    disconnects_1 = ['-WIRE_TX_SIGNATURES']
    disconnects_2 = ['+WIRE_TX_SIGNATURES']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'dev-force-features': '+223',
                                           'disconnect': disconnects_1,
                                           'may_reconnect': True},
                                          {'dev-force-features': '+223',
                                           'disconnect': disconnects_2,
                                           'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fund the channel, should appear to finish ok even though the
    # peer fails
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], chan_amount)

    chan_id = first_channel_id(l1, l2)
    log = l1.daemon.is_in_log('{} psbt'.format(chan_id))
    psbt = re.search("psbt (.*)", log).group(1)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('Peer has reconnected, state DUALOPEND_OPEN_INIT')
    with pytest.raises(RpcError):
        l1.rpc.openchannel_signed(chan_id, psbt)

    l2.daemon.wait_for_log('Broadcasting funding tx')
    txid = l2.rpc.listpeers(l1.info['id'])['peers'][0]['channels'][0]['funding_txid']
    bitcoind.generate_block(6, wait_for_mempool=txid)

    # Make sure we're ok.
    l2.daemon.wait_for_log(r'to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'to CHANNELD_NORMAL')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not DEVELOPER, "disconnect=... needs DEVELOPER=1")
def test_v2_open_sigs_restart_while_dead(node_factory, bitcoind):
    # Same thing as above, except the transaction mines
    # while we're asleep
    disconnects_1 = ['-WIRE_TX_SIGNATURES']
    disconnects_2 = ['+WIRE_TX_SIGNATURES']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'experimental-dual-fund': None,
                                           'disconnect': disconnects_1,
                                           'may_reconnect': True},
                                          {'experimental-dual-fund': None,
                                           'disconnect': disconnects_2,
                                           'may_reconnect': True}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Fund the channel, should appear to finish ok even though the
    # peer fails
    with pytest.raises(RpcError):
        l1.rpc.fundchannel(l2.info['id'], chan_amount)

    chan_id = first_channel_id(l1, l2)
    log = l1.daemon.is_in_log('{} psbt'.format(chan_id))
    psbt = re.search("psbt (.*)", log).group(1)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_log('Peer has reconnected, state DUALOPEND_OPEN_INIT')
    with pytest.raises(RpcError):
        l1.rpc.openchannel_signed(chan_id, psbt)

    l2.daemon.wait_for_log('Broadcasting funding tx')

    l1.stop()
    l2.stop()
    bitcoind.generate_block(6)
    l1.restart()
    l2.restart()

    # Make sure we're ok.
    l2.daemon.wait_for_log(r'to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'to CHANNELD_NORMAL')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_v2_rbf(node_factory, bitcoind, chainparams):
    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'experimental-dual-fund': None},
                                          {'experimental-dual-fund': None}])

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


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_v2_rbf_multi(node_factory, bitcoind, chainparams):
    l1, l2 = node_factory.get_nodes(2,
                                    opts={'experimental-dual-fund': None,
                                          'may_reconnect': True,
                                          'allow_warning': True})

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

    # Attempt to do abort, should fail since we've
    # already gotten an inflight
    with pytest.raises(RpcError):
        l1.rpc.openchannel_abort(chan_id)

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Do the bump
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])

    # Abort this open attempt! We will re-try
    aborted = l1.rpc.openchannel_abort(chan_id)
    assert not aborted['channel_canceled']

    # Do the bump, again
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])

    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])
    assert update['commitments_secured']

    # Sign our inputs, and continue
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']
    l1.rpc.openchannel_signed(chan_id, signed_psbt)

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF, double the channel amount this time
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount * 2, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Do the bump
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount * 2, initpsbt['psbt'])

    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])
    assert update['commitments_secured']

    # Sign our inputs, and continue
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']
    l1.rpc.openchannel_signed(chan_id, signed_psbt)

    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@unittest.skipIf(not DEVELOPER, "disconnect=... needs DEVELOPER=1")
def test_rbf_reconnect_init(node_factory, bitcoind, chainparams):
    disconnects = ['-WIRE_INIT_RBF',
                   '@WIRE_INIT_RBF',
                   '+WIRE_INIT_RBF']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'experimental-dual-fund': None,
                                           'disconnect': disconnects,
                                           'may_reconnect': True},
                                          {'experimental-dual-fund': None,
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
@unittest.skipIf(not DEVELOPER, "disconnect=... needs DEVELOPER=1")
def test_rbf_reconnect_ack(node_factory, bitcoind, chainparams):
    disconnects = ['-WIRE_ACK_RBF',
                   '@WIRE_ACK_RBF',
                   '+WIRE_ACK_RBF']

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'experimental-dual-fund': None,
                                           'may_reconnect': True},
                                          {'experimental-dual-fund': None,
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
@unittest.skipIf(not DEVELOPER, "disconnect=... needs DEVELOPER=1")
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
                                    opts=[{'experimental-dual-fund': None,
                                           'disconnect': disconnects,
                                           'may_reconnect': True},
                                          {'experimental-dual-fund': None,
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


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_rbf_reconnect_tx_sigs(node_factory, bitcoind, chainparams):
    disconnects = ['=WIRE_TX_SIGNATURES',  # Initial funding succeeds
                   '-WIRE_TX_SIGNATURES',  # When we send tx-sigs, RBF
                   '=WIRE_TX_SIGNATURES',  # When we reconnect
                   '@WIRE_TX_SIGNATURES',  # When we RBF again
                   '=WIRE_TX_SIGNATURES',  # When we reconnect
                   '+WIRE_TX_SIGNATURES']  # When we RBF again

    l1, l2 = node_factory.get_nodes(2,
                                    opts=[{'experimental-dual-fund': None,
                                           'disconnect': disconnects,
                                           'may_reconnect': True},
                                          {'experimental-dual-fund': None,
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
    l1.daemon.wait_for_log('Broadcasting funding tx')
    l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])

    # Sign our inputs, and continue
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']

    # First time we error when we send our sigs
    with pytest.raises(RpcError, match='Owning subdaemon dualopend died'):
        l1.rpc.openchannel_signed(chan_id, signed_psbt)

    # We reconnect and try again. feerate should have bumped
    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # l2 gets our sigs and broadcasts them
    l2.daemon.wait_for_log('peer_in WIRE_CHANNEL_REESTABLISH')
    l2.daemon.wait_for_log('peer_in WIRE_TX_SIGNATURES')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # Wait until we've done re-establish, if we try to
    # RBF again too quickly, it'll fail since they haven't
    # had time to process our sigs yet
    l1.daemon.wait_for_log('peer_in WIRE_CHANNEL_REESTABLISH')
    l1.daemon.wait_for_log('peer_in WIRE_TX_SIGNATURES')

    # Now we initiate the RBF
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])

    # Sign our inputs, and continue
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']

    # Second time we error after we send our sigs
    with pytest.raises(RpcError, match='Owning subdaemon dualopend died'):
        l1.rpc.openchannel_signed(chan_id, signed_psbt)

    # We reconnect and try again. feerate should have bumped
    next_feerate = find_next_feerate(l1, l2)

    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.utxopsbt(chan_amount, next_feerate, startweight,
                               prev_utxos, reservedok=True,
                               min_witness_weight=110,
                               excess_as_change=True)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # l2 gets our sigs and broadcasts them
    l2.daemon.wait_for_log('peer_in WIRE_CHANNEL_REESTABLISH')
    l2.daemon.wait_for_log('peer_in WIRE_TX_SIGNATURES')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # Wait until we've done re-establish, if we try to
    # RBF again too quickly, it'll fail since they haven't
    # had time to process our sigs yet
    l1.daemon.wait_for_log('peer_in WIRE_CHANNEL_REESTABLISH')
    l1.daemon.wait_for_log('peer_in WIRE_TX_SIGNATURES')

    # 3rd RBF
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])
    update = l1.rpc.openchannel_update(chan_id, bump['psbt'])
    signed_psbt = l1.rpc.signpsbt(update['psbt'])['signed_psbt']

    # Third time we error after we send our sigs
    with pytest.raises(RpcError, match='Owning subdaemon dualopend died'):
        l1.rpc.openchannel_signed(chan_id, signed_psbt)

    # l2 gets our sigs
    l2.daemon.wait_for_log('peer_in WIRE_TX_SIGNATURES')
    l2.daemon.wait_for_log('sendrawtx exit 0')

    # mine a block?
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log(' to CHANNELD_NORMAL')

    # Check that they have matching funding txid
    l1_funding_txid = only_one(only_one(l1.rpc.listpeers()['peers'])['channels'])['funding_txid']
    l2_funding_txid = only_one(only_one(l2.rpc.listpeers()['peers'])['channels'])['funding_txid']
    assert l1_funding_txid == l2_funding_txid


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_rbf_no_overlap(node_factory, bitcoind, chainparams):
    l1, l2 = node_factory.get_nodes(2,
                                    opts={'experimental-dual-fund': None,
                                          'allow_warning': True})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    amount = 2**24
    chan_amount = 100000
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8 + 0.01)
    bitcoind.generate_block(1)
    # Wait for it to arrive.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    res = l1.rpc.fundchannel(l2.info['id'], chan_amount)
    chan_id = res['channel_id']

    # Check that we're waiting for lockin
    l1.daemon.wait_for_log(' to DUALOPEND_AWAITING_LOCKIN')

    next_feerate = find_next_feerate(l1, l2)

    # Initiate an RBF
    startweight = 42 + 172  # base weight, funding output
    initpsbt = l1.rpc.fundpsbt(chan_amount, next_feerate, startweight,
                               min_witness_weight=110,
                               excess_as_change=True)

    # Do the bump
    bump = l1.rpc.openchannel_bump(chan_id, chan_amount, initpsbt['psbt'])

    with pytest.raises(RpcError, match='No overlapping input present.'):
        l1.rpc.openchannel_update(chan_id, bump['psbt'])
