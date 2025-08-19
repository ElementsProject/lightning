from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from utils import (
    sync_blockheight, wait_for, only_one
)

import unittest
import pytest
from pyln.testing.utils import EXPERIMENTAL_DUAL_FUND


def check_moves(moves, expected):
    for m in moves:
        del m['timestamp']
    assert moves == expected


def check_channel_moves(node, expected):
    check_moves(node.rpc.listchannelmoves()['channelmoves'], expected)


def check_chain_moves(node, expected):
    check_moves(node.rpc.listchainmoves()['chainmoves'], expected)


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
                         'utxo': f"{only_one(close['txids'])}:{fundchannel['outnum']}"},
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
                         'utxo': f"{only_one(close['txids'])}:{fundchannel['outnum'] ^ 1}"}]
    check_channel_moves(l1, expected_channel1)
    check_channel_moves(l2, expected_channel2)
    check_chain_moves(l1, expected_chain1)
    check_chain_moves(l2, expected_chain2)

    # FIXME:
    #   MVT_PENALTY,
    #   MVT_CHANNEL_TO_US,
    #   MVT_HTLC_TIMEOUT,
    #   MVT_HTLC_FULFILL,
    #   MVT_HTLC_TX,
    #   MVT_TO_WALLET,
    #   MVT_ANCHOR,
    #   MVT_TO_THEM,
    #   MVT_PENALIZED,
    #   MVT_STOLEN,
    #   MVT_TO_MINER,
    #   MVT_LEASE_FEE,
    #   MVT_CHANNEL_PROPOSED,
    # Extra tags
    #   MVT_SPLICE,
    #   MVT_LEASED,
    #   MVT_STEALABLE,
