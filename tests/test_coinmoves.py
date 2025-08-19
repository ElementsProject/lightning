from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from utils import (
    sync_blockheight, wait_for, only_one
)

import unittest
import pytest
import re
import time
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND


def check_moves(moves, expected):
    for m in moves:
        del m['timestamp']
    assert moves == expected


def check_channel_moves(node, expected):
    check_moves(node.rpc.listchannelmoves()['channelmoves'], expected)


def check_chain_moves(node, expected):
    check_moves(node.rpc.listchainmoves()['chainmoves'], expected)


def account_balances(accounts):
    """Gather all the credits / debits for all accounts"""
    balances = {}
    for a in accounts:
        if a['account_id'] not in balances:
            balances[a['account_id']] = []
        balances[a['account_id']].append(a['credit_msat'])
        balances[a['account_id']].append(-a['debit_msat'])
    return balances


def check_balances(l1, l2, channel_id, msats_sent_to_2):
    channel1 = account_balances(l1.rpc.listchannelmoves()['channelmoves'])
    channel2 = account_balances(l2.rpc.listchannelmoves()['channelmoves'])
    chain1 = account_balances(l1.rpc.listchainmoves()['chainmoves'])
    chain2 = account_balances(l2.rpc.listchainmoves()['chainmoves'])

    # Our initial setup_channel sends 50000000000 msat
    msats_sent_to_2 += 50000000000
    # Channel balances should reflect sats transferred
    assert sum(channel1[channel_id]) == -msats_sent_to_2
    assert sum(channel2[channel_id]) == msats_sent_to_2

    # Chain balances for the channels should be opposite the channel balances.
    assert sum(chain1[channel_id]) == -sum(channel1[channel_id])
    assert sum(chain2[channel_id]) == -sum(channel2[channel_id])

    # Wallet balances should reflect reality
    l1_wallet = sum([o['amount_msat'] for o in l1.rpc.listfunds()['outputs']])
    l2_wallet = sum([o['amount_msat'] for o in l2.rpc.listfunds()['outputs']])

    if sum(chain1['wallet']) != l1_wallet:
        print(f"sum({chain1['wallet']}) != {l1_wallet}")
        assert False
    if sum(chain2['wallet']) != l2_wallet:
        print(f"sum({chain2['wallet']}) != {l2_wallet}")
        assert False


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', "Amounts are for regtest.")
def test_coinmoves(node_factory, bitcoind):
    l1, l2, l3 = node_factory.get_nodes(3)

    # Empty
    expected_channel1 = []
    expected_channel2 = []
    expected_chain1 = []
    expected_chain2 = []
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_DEPOSIT
    addr = l1.rpc.newaddr()['bech32']
    txid_deposit = bitcoind.rpc.sendtoaddress(addr, 200000000 / 10**8)
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])
    vout_deposit = only_one([out['n'] for out in bitcoind.rpc.gettransaction(txid_deposit, False, True)['decoded']['vout'] if out['scriptPubKey']['address'] == addr])

    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 102,
                         'credit_msat': 200000000000,
                         'debit_msat': 0,
                         'output_msat': 200000000000,
                         'primary_tag': 'deposit',
                         'extra_tags': [],
                         'utxo': f"{txid_deposit}:{vout_deposit}"}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_WITHDRAWAL
    addr = l3.rpc.newaddr()['bech32']
    withdraw = l1.rpc.withdraw(addr, 100000000)
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])
    vout_withdrawal = only_one([out['n'] for out in bitcoind.rpc.decoderawtransaction(withdraw['tx'])['vout'] if out['scriptPubKey']['address'] == addr])

    expected_chain1 += [{'account_id': 'external',
                         'blockheight': 0,
                         'credit_msat': 100000000000,
                         'debit_msat': 0,
                         'output_msat': 100000000000,
                         'originating_account': 'wallet',
                         'primary_tag': 'deposit',
                         'extra_tags': [],
                         'utxo': f"{withdraw['txid']}:{vout_withdrawal}"},
                        # Spend
                        {'account_id': 'wallet',
                         'blockheight': 103,
                         'credit_msat': 0,
                         'debit_msat': 200000000000,
                         'primary_tag': 'withdrawal',
                         'output_msat': 200000000000,
                         'extra_tags': [],
                         'spending_txid': withdraw['txid'],
                         'utxo': f"{txid_deposit}:{vout_deposit}"},
                        # Change
                        {'account_id': 'wallet',
                         'blockheight': 103,
                         'credit_msat': 99995433000,
                         'debit_msat': 0,
                         'primary_tag': 'deposit',
                         'extra_tags': [],
                         'output_msat': 99995433000,
                         'utxo': f"{withdraw['txid']}:{vout_withdrawal ^ 1}"}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_CHANNEL_OPEN
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    fundchannel = l1.rpc.fundchannel(l2.info['id'], 'all')
    bitcoind.generate_block(1, wait_for_mempool=fundchannel['txid'])
    wait_for(lambda: all([c['state'] == 'CHANNELD_NORMAL' for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']]))
    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 99995433000,
                         'output_msat': 99995433000,
                         'primary_tag': 'withdrawal',
                         'extra_tags': [],
                         'spending_txid': fundchannel['txid'],
                         'utxo': f"{withdraw['txid']}:{vout_withdrawal ^ 1}"},
                        {'account_id': 'wallet',
                         'blockheight': 104,
                         'credit_msat': 25000000,
                         'debit_msat': 0,
                         'output_msat': 25000000,
                         'primary_tag': 'deposit',
                         'extra_tags': [],
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum'] ^ 1}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 99965813000,
                         'debit_msat': 0,
                         'output_msat': 99965813000,
                         'peer_id': l2.info['id'],
                         'primary_tag': 'channel_open',
                         'extra_tags': ['opener'],
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"}]
    expected_chain2 += [{'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 0,
                         'output_msat': 99965813000,
                         'peer_id': l1.info['id'],
                         'primary_tag': 'channel_open',
                         'extra_tags': [],
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_INVOICE
    inv = l2.rpc.invoice('any', 'test_coinmoves', 'test_coinmoves')
    l1.rpc.xpay(inv['bolt11'], '1000sat')
    # Make sure it's fully settled.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])
    # We cheat and extract group id.
    group_id = l1.rpc.listchannelmoves()['channelmoves'][-1]['group_id']
    expected_channel1 += [{'account_id': fundchannel['channel_id'],
                           'credit_msat': 0,
                           'debit_msat': 1000000,
                           'primary_tag': 'invoice',
                           'fees_msat': 0,
                           'payment_hash': inv['payment_hash'],
                           'group_id': group_id,
                           'part_id': 1}]
    expected_channel2 += [{'account_id': fundchannel['channel_id'],
                           'credit_msat': 1000000,
                           'debit_msat': 0,
                           'primary_tag': 'invoice',
                           'fees_msat': 0,
                           'payment_hash': inv['payment_hash']}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_PUSHED
    l3.rpc.connect(l1.info['id'], 'localhost', l1.port)
    if not EXPERIMENTAL_DUAL_FUND:
        l3fundchannel = l3.rpc.fundchannel(l1.info['id'], 40000000, push_msat=100000)
    else:
        l3fundchannel = l3.rpc.fundchannel(l1.info['id'], 40000000)
    bitcoind.generate_block(1, wait_for_mempool=1)
    wait_for(lambda: all([c['state'] == 'CHANNELD_NORMAL' for c in l1.rpc.listpeerchannels(l3.info['id'])['channels']]))
    expected_chain1 += [{'account_id': l3fundchannel['channel_id'],
                         'blockheight': 105,
                         'credit_msat': 0,
                         'debit_msat': 0,
                         'output_msat': 40000000000,
                         'peer_id': l3.info['id'],
                         'primary_tag': 'channel_open',
                         'extra_tags': [],
                         'utxo': f"{l3fundchannel['txid']}:{l3fundchannel['outnum']}"}]
    if not EXPERIMENTAL_DUAL_FUND:
        expected_channel1 += [{'account_id': l3fundchannel['channel_id'],
                               'credit_msat': 100000,
                               'debit_msat': 0,
                               'fees_msat': 0,
                               'primary_tag': 'pushed'}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_ROUTED
    # Make sure l3 sees l2.
    bitcoind.generate_block(5)
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 4)
    inv = l2.rpc.invoice('any', 'test_coinmoves2', 'test_coinmoves2')
    l3.rpc.xpay(inv['bolt11'], '10000000sat')
    # Make sure it's fully settled.
    wait_for(lambda: only_one(l3.rpc.listpeerchannels(l1.info['id'])['channels'])['htlcs'] == [])
    expected_channel1 += [{'account_id': fundchannel['channel_id'],
                           'credit_msat': 0,
                           'debit_msat': 10000000000,
                           'fees_msat': 100001,
                           'payment_hash': inv['payment_hash'],
                           'primary_tag': 'routed'},
                          {'account_id': l3fundchannel['channel_id'],
                           'credit_msat': 10000100001,
                           'debit_msat': 0,
                           'fees_msat': 100001,
                           'payment_hash': inv['payment_hash'],
                           'primary_tag': 'routed'}]
    expected_channel2 += [{'account_id': fundchannel['channel_id'],
                           'credit_msat': 10000000000,
                           'debit_msat': 0,
                           'fees_msat': 0,
                           'payment_hash': inv['payment_hash'],
                           'primary_tag': 'invoice'}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # MVT_CHANNEL_CLOSE
    close = l1.rpc.close(fundchannel['channel_id'])
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])
    # Determining our own output is harder than you might think!
    l1_addrs = [a['p2tr'] for a in l1.rpc.listaddresses()['addresses'] if 'p2tr' in a]
    l1_vout_close = only_one([out['n'] for out in bitcoind.rpc.decoderawtransaction(only_one(close['txs']))['vout'] if out['scriptPubKey']['address'] in l1_addrs])
    l2_addrs = [a['p2tr'] for a in l2.rpc.listaddresses()['addresses'] if 'p2tr' in a]
    l2_vout_close = only_one([out['n'] for out in bitcoind.rpc.decoderawtransaction(only_one(close['txs']))['vout'] if out['scriptPubKey']['address'] in l2_addrs])
    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 111,
                         'credit_msat': 89961918000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 89961918000,
                         'primary_tag': 'deposit',
                         'utxo': f"{only_one(close['txids'])}:{l1_vout_close}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 111,
                         'credit_msat': 0,
                         'debit_msat': 89964813000,
                         'extra_tags': [],
                         'output_count': 2,
                         'output_msat': 99965813000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 111,
                         'credit_msat': 10001000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 10001000000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close['txids'])}:{l1_vout_close ^ 1}"}]
    expected_chain2 += [{'account_id': 'wallet',
                         'blockheight': 111,
                         'credit_msat': 10001000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 10001000000,
                         'primary_tag': 'deposit',
                         'utxo': f"{only_one(close['txids'])}:{l2_vout_close}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 111,
                         'credit_msat': 0,
                         'debit_msat': 10001000000,
                         'extra_tags': [],
                         'output_count': 2,
                         'output_msat': 99965813000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 111,
                         'credit_msat': 89961918000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 89961918000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close['txids'])}:{l2_vout_close ^ 1}"}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)


def setup_channel(bitcoind, l1, l2):
    """Set up a balanced l1->l2 channel, return:

    l1's expected channel moves
    l2's expected channel moves
    l1's expected chain moves
    l2's expected chain moves
    The fundchannel return
    """
    expected_channel1 = []
    expected_channel2 = []
    expected_chain1 = []
    expected_chain2 = []

    addr = l1.rpc.newaddr()['bech32']
    txid_deposit = bitcoind.rpc.sendtoaddress(addr, 100000000 / 10**8)
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1])
    vout_deposit = only_one([out['n'] for out in bitcoind.rpc.gettransaction(txid_deposit, False, True)['decoded']['vout'] if out['scriptPubKey']['address'] == addr])

    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 102,
                         'credit_msat': 100000000000,
                         'debit_msat': 0,
                         'output_msat': 100000000000,
                         'primary_tag': 'deposit',
                         'extra_tags': [],
                         'utxo': f"{txid_deposit}:{vout_deposit}"}]
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    fundchannel = l1.rpc.fundchannel(l2.info['id'], 'all')
    bitcoind.generate_block(1, wait_for_mempool=fundchannel['txid'])
    wait_for(lambda: all([c['state'] == 'CHANNELD_NORMAL' for c in l1.rpc.listpeerchannels(l2.info['id'])['channels']]))
    expected_chain1 += [{'account_id': 'wallet',  # Spent UTXO
                         'blockheight': 103,
                         'credit_msat': 0,
                         'debit_msat': 100000000000,
                         'output_msat': 100000000000,
                         'primary_tag': 'withdrawal',
                         'extra_tags': [],
                         'spending_txid': fundchannel['txid'],
                         'utxo': f"{txid_deposit}:{vout_deposit}"},
                        {'account_id': 'wallet',  # Change
                         'blockheight': 103,
                         'credit_msat': 25000000,
                         'debit_msat': 0,
                         'output_msat': 25000000,
                         'primary_tag': 'deposit',
                         'extra_tags': [],
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum'] ^ 1}"},
                        {'account_id': fundchannel['channel_id'],  # Channel open
                         'blockheight': 103,
                         'credit_msat': 99970073000,
                         'debit_msat': 0,
                         'output_msat': 99970073000,
                         'peer_id': l2.info['id'],
                         'primary_tag': 'channel_open',
                         'extra_tags': ['opener'],
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"}]
    expected_chain2 += [{'account_id': fundchannel['channel_id'],  # Channel open
                         'blockheight': 103,
                         'credit_msat': 0,
                         'debit_msat': 0,
                         'output_msat': 99970073000,
                         'peer_id': l1.info['id'],
                         'primary_tag': 'channel_open',
                         'extra_tags': [],
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    inv = l2.rpc.invoice('any', 'setup_channel', 'setup_channel')
    routestep = {
        'amount_msat': 50000000000,
        'id': l2.info['id'],
        'delay': 5,
        'channel': l1.get_channel_scid(l2),
    }
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'], bolt11=inv['bolt11'])
    wait_for(lambda: only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['htlcs'] == [])
    expected_channel1 += [{'account_id': fundchannel['channel_id'],
                           'credit_msat': 0,
                           'debit_msat': 50000000000,
                           'primary_tag': 'invoice',
                           'fees_msat': 0,
                           'payment_hash': inv['payment_hash'],
                           'group_id': 1,
                           'part_id': 0}]
    expected_channel2 += [{'account_id': fundchannel['channel_id'],
                           'credit_msat': 50000000000,
                           'debit_msat': 0,
                           'primary_tag': 'invoice',
                           'fees_msat': 0,
                           'payment_hash': inv['payment_hash']}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    return (expected_channel1, expected_channel2, expected_chain1, expected_chain2, fundchannel)


# There are many unilateral close variants to test:
# - HTLC not yet included in tx.
# - HTLC included in tx, times out.
# - HTLC included in tx, we fulfill.
# - HTLC not included in tx, because one side considers it fulfilled.
# - HTLC is too small to appear in tx, lost to fees.
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', "Amounts are for regtest.")
def test_coinmoves_unilateral_htlc_before_included(node_factory, bitcoind):
    # l2 includes it, but l1 doesn't get commitment, so it drops to chain without it.
    if EXPERIMENTAL_DUAL_FUND:
        disc = ['-WIRE_COMMITMENT_SIGNED*4']
    else:
        disc = ['-WIRE_COMMITMENT_SIGNED*3']
    l1, l2 = node_factory.get_nodes(2, opts=[{}, {'disconnect': disc}])

    expected_channel1, expected_channel2, expected_chain1, expected_chain2, fundchannel = setup_channel(bitcoind, l1, l2)

    # This HTLC doesn't make it to full confirmation.
    inv = l2.rpc.invoice('any', 'test_coinmoves_unilateral_htlc_in_before_included', 'test_coinmoves_unilateral_htlc_in_before_included')
    routestep = {
        # Too small to make it worth spending anchor
        'amount_msat': 1000000,
        'id': l2.info['id'],
        'delay': 5,
        'channel': l1.get_channel_scid(l2),
    }
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'], bolt11=inv['bolt11'])
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)

    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    close_info = l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    bitcoind.generate_block(1, wait_for_mempool=1)

    # Make sure onchaind has digested it.
    l1.daemon.wait_for_log('5 outputs unresolved: in 4 blocks will spend DELAYED_OUTPUT_TO_US')
    l2.daemon.wait_for_log('All outputs resolved: waiting 100 more blocks before forgetting channel')

    # Which outputs are anchors, and which are to us and which to them?
    # Use onchaind's logs, eg:
    # Tracking output 0e1cfbc2be0aada02222a163a1a413fd0b06bae8017c3626cbf8816499dadc09:0: OUR_UNILATERAL/ANCHOR_TO_THEM
    line = l1.daemon.is_in_log('Tracking output.*/ANCHOR_TO_THEM')
    anch_to_l2 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/ANCHOR_TO_US')
    anch_to_l1 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/DELAYED_OUTPUT_TO_US')
    to_l1 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/OUTPUT_TO_THEM')
    to_l2 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))

    expected_chain1 += [{'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 99970073000 - 50000000000,
                         'extra_tags': [],
                         'output_count': 4,
                         'output_msat': 99970073000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close_info['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l2}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l1}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 50000000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 50000000000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l2}"}]
    expected_chain2 += [{'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 50000000000,
                         'extra_tags': [],
                         'output_count': 4,
                         'output_msat': 99970073000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close_info['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l2}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l1}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 49965193000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 49965193000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"},
                        {'account_id': 'wallet',
                         'blockheight': 104,
                         'credit_msat': 50000000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 50000000000,
                         'primary_tag': 'deposit',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l2}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    bitcoind.generate_block(4)
    l1.daemon.wait_for_log('waiting confirmation that we spent DELAYED_OUTPUT_TO_US')
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    bitcoind.generate_block(1, wait_for_mempool=1)

    line = l1.daemon.wait_for_log('Resolved OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by our proposal OUR_DELAYED_RETURN_TO_WALLET')
    to_us_txid = re.search(r'by our proposal OUR_DELAYED_RETURN_TO_WALLET \(([0-9a-f]{64})\)', line).group(1)

    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 109,
                         'credit_msat': 49965059000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 49965059000,
                         'primary_tag': 'deposit',
                         'utxo': f"{to_us_txid}:0"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 49965193000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 49965193000,
                         'primary_tag': 'delayed_to_us',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 109,
                         'credit_msat': 0,
                         'debit_msat': 49965193000,
                         'extra_tags': [],
                         'output_msat': 49965193000,
                         'primary_tag': 'to_wallet',
                         'spending_txid': to_us_txid,
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    # Make sure it's stable!
    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l1, l2])
    time.sleep(5)
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # We didn't send any HTLCs
    check_balances(l1, l2, fundchannel['channel_id'], 0)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', "Amounts are for regtest.")
def test_coinmoves_unilateral_htlc_timeout(node_factory, bitcoind):
    """HTLC times out"""
    l1, l2 = node_factory.get_nodes(2, opts=[{},
                                             {'disconnect': ['-WIRE_UPDATE_FAIL_HTLC']}])

    expected_channel1, expected_channel2, expected_chain1, expected_chain2, fundchannel = setup_channel(bitcoind, l1, l2)

    inv = l2.rpc.invoice('any', 'test_coinmoves_unilateral_htlc_timeout', 'test_coinmoves_unilateral_htlc_timeout')
    l2.rpc.delinvoice('test_coinmoves_unilateral_htlc_timeout', 'unpaid')
    routestep = {
        # We will spend anchor to make this confirm.
        'amount_msat': 100000000,
        'id': l2.info['id'],
        'delay': 10,
        'channel': l1.get_channel_scid(l2),
    }
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'], bolt11=inv['bolt11'])
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)

    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    close_info = l1.rpc.close(l2.info['id'], unilateraltimeout=1)

    # We will spend anchor to confirm this.
    line = l1.daemon.wait_for_log("Creating anchor spend for local commit tx ")
    anchor_spend_txid = re.search(r'Creating anchor spend for local commit tx ([0-9a-f]{64})', line).group(1)

    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])

    # Make sure onchaind has digested it.
    l1.daemon.wait_for_log('6 outputs unresolved: in 4 blocks will spend DELAYED_OUTPUT_TO_US')
    l2.daemon.wait_for_log('6 outputs unresolved')

    # Which outputs are anchors, and which are to us and which to them?
    # Use onchaind's logs, eg:
    # Tracking output 0e1cfbc2be0aada02222a163a1a413fd0b06bae8017c3626cbf8816499dadc09:0: OUR_UNILATERAL/ANCHOR_TO_THEM
    line = l1.daemon.is_in_log('Tracking output.*/ANCHOR_TO_THEM')
    anch_to_l2 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/ANCHOR_TO_US')
    anch_to_l1 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/DELAYED_OUTPUT_TO_US')
    to_l1 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/OUTPUT_TO_THEM')
    to_l2 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/OUR_HTLC')
    htlc = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))

    expected_chain1 += [{'account_id': 'wallet',  # Anchor spend from fundchannel change
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 25000000,
                         'extra_tags': [],
                         'output_msat': 25000000,
                         'primary_tag': 'withdrawal',
                         'spending_txid': anchor_spend_txid,
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum'] ^ 1}"},
                        {'account_id': 'wallet',  # change from anchor spend
                         'blockheight': 104,
                         'credit_msat': 15579000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 15579000,
                         'primary_tag': 'deposit',
                         'utxo': f"{anchor_spend_txid}:0"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 99970073000 - 50000000000,
                         'extra_tags': [],
                         'output_count': 5,
                         'output_msat': 99970073000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close_info['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l2}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l1}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 50000000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 50000000000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l2}"}]
    expected_chain2 += [{'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 50000000000,
                         'extra_tags': [],
                         'output_count': 5,
                         'output_msat': 99970073000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close_info['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l2}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l1}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 49864547000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 49864547000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"},
                        {'account_id': 'wallet',
                         'blockheight': 104,
                         'credit_msat': 50000000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 50000000000,
                         'primary_tag': 'deposit',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l2}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    bitcoind.generate_block(4)
    l1.daemon.wait_for_log('waiting confirmation that we spent DELAYED_OUTPUT_TO_US')
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    bitcoind.generate_block(1, wait_for_mempool=1)

    line = l1.daemon.wait_for_log('Resolved OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by our proposal OUR_DELAYED_RETURN_TO_WALLET')
    to_l1_txid = re.search(r'by our proposal OUR_DELAYED_RETURN_TO_WALLET \(([0-9a-f]{64})\)', line).group(1)

    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 109,
                         'credit_msat': 49864413000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 49864413000,
                         'primary_tag': 'deposit',
                         'utxo': f"{to_l1_txid}:0"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 49864547000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 49864547000,
                         'primary_tag': 'delayed_to_us',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 109,
                         'credit_msat': 0,
                         'debit_msat': 49864547000,
                         'extra_tags': [],
                         'output_msat': 49864547000,
                         'primary_tag': 'to_wallet',
                         'spending_txid': to_l1_txid,
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    # When l1 spends the htlc_tx, it will grab a UTXO.  Remove existing ones
    # so it's deterministic.
    l1.rpc.fundpsbt('all', 0, 0, reserve=100)

    bitcoind.generate_block(5)
    l1.daemon.wait_for_log('waiting confirmation that we spent OUR_HTLC')
    bitcoind.generate_block(1, wait_for_mempool=1)

    line = l1.daemon.wait_for_log('Resolved OUR_UNILATERAL/OUR_HTLC by our proposal OUR_HTLC_TIMEOUT_TX')
    htlc_timeout_txid = re.search(r'by our proposal OUR_HTLC_TIMEOUT_TX \(([0-9a-f]{64})\)', line).group(1)
    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 115,
                         'credit_msat': 0,
                         'debit_msat': 15579000,
                         'extra_tags': [],
                         'output_msat': 15579000,
                         'primary_tag': 'withdrawal',
                         'spending_txid': htlc_timeout_txid,
                         'utxo': f"{anchor_spend_txid}:0"},
                        {'account_id': 'wallet',
                         'blockheight': 115,
                         'credit_msat': 6358000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 6358000,
                         'primary_tag': 'deposit',
                         'utxo': f"{htlc_timeout_txid}:1"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 100000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 100000000,
                         'primary_tag': 'htlc_timeout',
                         'utxo': f"{only_one(close_info['txids'])}:{htlc}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 115,
                         'credit_msat': 0,
                         'debit_msat': 100000000,
                         'extra_tags': [],
                         'output_msat': 100000000,
                         'primary_tag': 'htlc_timeout',
                         'spending_txid': htlc_timeout_txid,
                         'utxo': f"{only_one(close_info['txids'])}:{htlc}"}]
    expected_chain2 += [{'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 100000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 100000000,
                         'primary_tag': 'htlc_timeout',
                         'utxo': f"{only_one(close_info['txids'])}:{htlc}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    l1.daemon.wait_for_log("Telling lightningd about OUR_DELAYED_RETURN_TO_WALLET to resolve OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US after block 119")
    bitcoind.generate_block(4)
    l1.daemon.wait_for_log("waiting confirmation that we spent DELAYED_OUTPUT_TO_US .* using OUR_DELAYED_RETURN_TO_WALLET")
    bitcoind.generate_block(1, wait_for_mempool=1)
    line = l1.daemon.wait_for_log('Resolved OUR_HTLC_TIMEOUT_TX/DELAYED_OUTPUT_TO_US by our proposal OUR_DELAYED_RETURN_TO_WALLET')
    htlc_to_l1_txid = re.search(r'by our proposal OUR_DELAYED_RETURN_TO_WALLET \(([0-9a-f]{64})\)', line).group(1)

    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 120,
                         'credit_msat': 99866000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 99866000,
                         'primary_tag': 'deposit',
                         'utxo': f"{htlc_to_l1_txid}:0"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 115,
                         'credit_msat': 100000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 100000000,
                         'primary_tag': 'htlc_tx',
                         'utxo': f"{htlc_timeout_txid}:0"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 120,
                         'credit_msat': 0,
                         'debit_msat': 100000000,
                         'extra_tags': [],
                         'output_msat': 100000000,
                         'primary_tag': 'to_wallet',
                         'spending_txid': htlc_to_l1_txid,
                         'utxo': f"{htlc_timeout_txid}:0"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    # Make sure it's stable!
    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l1, l2])
    time.sleep(5)
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # We didn't send any HTLCs
    check_balances(l1, l2, fundchannel['channel_id'], 0)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', "Amounts are for regtest.")
def test_coinmoves_unilateral_htlc_dust(node_factory, bitcoind):
    """HTLC too small to appear in tx, lost to fees"""
    l1, l2 = node_factory.get_nodes(2, opts=[{},
                                             {'disconnect': ['-WIRE_UPDATE_FAIL_HTLC']}])

    expected_channel1, expected_channel2, expected_chain1, expected_chain2, fundchannel = setup_channel(bitcoind, l1, l2)

    inv = l2.rpc.invoice('any', 'test_coinmoves_unilateral_htlc_dust', 'test_coinmoves_unilateral_htlc_dust')
    l2.rpc.delinvoice('test_coinmoves_unilateral_htlc_dust', 'unpaid')
    routestep = {
        'amount_msat': 10000,
        'id': l2.info['id'],
        'delay': 10,
        'channel': l1.get_channel_scid(l2),
    }
    l1.rpc.sendpay([routestep], inv['payment_hash'], payment_secret=inv['payment_secret'], bolt11=inv['bolt11'])
    wait_for(lambda: only_one(l1.rpc.listpeers(l2.info['id'])['peers'])['connected'] is False)

    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    close_info = l1.rpc.close(l2.info['id'], unilateraltimeout=1)
    bitcoind.generate_block(1, wait_for_mempool=1)
    sync_blockheight(bitcoind, [l1, l2])

    # Make sure onchaind has digested it.
    l1.daemon.wait_for_log('5 outputs unresolved: in 4 blocks will spend DELAYED_OUTPUT_TO_US')
    l2.daemon.wait_for_log("All outputs resolved: waiting 100 more blocks before forgetting channel")

    # Which outputs are anchors, and which are to us and which to them?
    # Use onchaind's logs, eg:
    # Tracking output 0e1cfbc2be0aada02222a163a1a413fd0b06bae8017c3626cbf8816499dadc09:0: OUR_UNILATERAL/ANCHOR_TO_THEM
    line = l1.daemon.is_in_log('Tracking output.*/ANCHOR_TO_THEM')
    anch_to_l2 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/ANCHOR_TO_US')
    anch_to_l1 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/DELAYED_OUTPUT_TO_US')
    to_l1 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))
    line = l1.daemon.is_in_log('Tracking output.*/OUTPUT_TO_THEM')
    to_l2 = int(re.search(r'output [0-9a-f]{64}:([0-9]):', line).group(1))

    expected_chain1 += [{'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 99970073000 - 50000000000,
                         'extra_tags': [],
                         'output_count': 4,
                         'output_msat': 99970073000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close_info['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l2}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l1}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 50000000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 50000000000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l2}"}]
    expected_chain2 += [{'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 0,
                         'debit_msat': 50000000000,
                         'extra_tags': [],
                         'output_count': 4,
                         'output_msat': 99970073000,
                         'primary_tag': 'channel_close',
                         'spending_txid': only_one(close_info['txids']),
                         'utxo': f"{fundchannel['txid']}:{fundchannel['outnum']}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l2}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 330000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 330000,
                         'primary_tag': 'anchor',
                         'utxo': f"{only_one(close_info['txids'])}:{anch_to_l1}"},
                        {'account_id': 'external',
                         'blockheight': 104,
                         'credit_msat': 49965183000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 49965183000,
                         'primary_tag': 'to_them',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"},
                        {'account_id': 'wallet',
                         'blockheight': 104,
                         'credit_msat': 50000000000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'originating_account': fundchannel['channel_id'],
                         'output_msat': 50000000000,
                         'primary_tag': 'deposit',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l2}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    bitcoind.generate_block(4)
    l1.daemon.wait_for_log("waiting confirmation that we spent DELAYED_OUTPUT_TO_US .* using OUR_DELAYED_RETURN_TO_WALLET")
    bitcoind.generate_block(1, wait_for_mempool=1)

    line = l1.daemon.wait_for_log('Resolved OUR_UNILATERAL/DELAYED_OUTPUT_TO_US by our proposal OUR_DELAYED_RETURN_TO_WALLET')
    to_l1_txid = re.search(r'by our proposal OUR_DELAYED_RETURN_TO_WALLET \(([0-9a-f]{64})\)', line).group(1)

    expected_chain1 += [{'account_id': 'wallet',
                         'blockheight': 109,
                         'credit_msat': 49965049000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 49965049000,
                         'primary_tag': 'deposit',
                         'utxo': f"{to_l1_txid}:0"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 104,
                         'credit_msat': 49965183000,
                         'debit_msat': 0,
                         'extra_tags': [],
                         'output_msat': 49965183000,
                         'primary_tag': 'delayed_to_us',
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"},
                        {'account_id': fundchannel['channel_id'],
                         'blockheight': 109,
                         'credit_msat': 0,
                         'debit_msat': 49965183000,
                         'extra_tags': [],
                         'output_msat': 49965183000,
                         'primary_tag': 'to_wallet',
                         'spending_txid': to_l1_txid,
                         'utxo': f"{only_one(close_info['txids'])}:{to_l1}"}]
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)

    l1.daemon.wait_for_log('All outputs resolved: waiting 100 more blocks before forgetting channel')

    # Make sure it's stable!
    bitcoind.generate_block(100)
    sync_blockheight(bitcoind, [l1, l2])
    time.sleep(5)
    check_channel_moves(l1, expected_channel1)
    check_chain_moves(l1, expected_chain1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l2, expected_chain2)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # We send a HTLC but it didn't finalize.
    check_balances(l1, l2, fundchannel['channel_id'], 0)

    # FIXME:
    #   MVT_PENALTY,
    #   MVT_PENALIZED,
    #   MVT_STOLEN,
    #   MVT_TO_MINER,
    #   MVT_LEASE_FEE,
    #   MVT_CHANNEL_PROPOSED,
    # Extra tags
    #   MVT_SPLICE,
    #   MVT_LEASED,
    #   MVT_STEALABLE,
