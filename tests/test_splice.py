from fixtures import *  # noqa: F401,F403
from pathlib import Path
from pyln.client import Millisatoshi
import pytest
import unittest
from utils import (
    bkpr_account_balance, check_coin_moves, first_channel_id,
    TEST_NETWORK, only_one, wait_for
)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_splice_out(node_factory, bitcoind, chainparams):
    fundamt = 1000000

    coin_mvt_plugin = Path(__file__).parent / "plugins" / "coin_movements.py"
    l1, l2 = node_factory.line_graph(2, fundamount=fundamt, wait_for_announce=True,
                                     opts={'experimental-splicing': None,
                                           'plugin': coin_mvt_plugin})

    initial_wallet_balance = Millisatoshi(bkpr_account_balance(l1, 'wallet'))
    initial_channel_balance = Millisatoshi(bkpr_account_balance(l1, first_channel_id(l1, l2)))
    assert initial_channel_balance == Millisatoshi(fundamt * 1000)

    # Splice out 100k from first channel, explicitly putting result less fees into onchain wallet
    spliceamt = 100000
    l1.rpc.splice(f"*:? -> {spliceamt}; 100%-fee -> wallet", force_feerate=True, debug_log=True)
    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])

    assert p1['inflight'][0]['splice_amount'] == -1 * spliceamt
    assert p1['inflight'][0]['total_funding_msat'] == (fundamt - spliceamt) * 1000
    assert p1['inflight'][0]['our_funding_msat'] == fundamt * 1000
    assert p2['inflight'][0]['splice_amount'] == 0
    assert p2['inflight'][0]['total_funding_msat'] == (fundamt - spliceamt) * 1000
    assert p2['inflight'][0]['our_funding_msat'] == 0
    bitcoind.generate_block(6, wait_for_mempool=1)
    l2.daemon.wait_for_log(r'lightningd, splice_locked clearing inflights')

    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['to_us_msat'] == (fundamt - spliceamt) * 1000
    assert p1['total_msat'] == (fundamt - spliceamt) * 1000
    assert p2['to_us_msat'] == 0
    assert p2['total_msat'] == (fundamt - spliceamt) * 1000
    assert 'inflight' not in p1
    assert 'inflight' not in p2

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)
    wait_for(lambda: len(l1.rpc.listfunds()['channels']) == 1)

    # At the end we'd expect the balance of channel 1 to be down by the splice amount
    end_channel_balance = Millisatoshi(bkpr_account_balance(l1, first_channel_id(l1, l2)))
    end_wallet_balance = Millisatoshi(bkpr_account_balance(l1, 'wallet'))
    assert initial_channel_balance - Millisatoshi(spliceamt * 1000) == end_channel_balance

    # The fee is assumed to be the difference between the start+end balances?
    fee_guess = initial_wallet_balance + initial_channel_balance - end_channel_balance - end_wallet_balance

    # We'd expect the following coin movements
    starting_wallet_msat = 2000000000
    expected_wallet_moves = [
        #  initial deposit
        {'type': 'chain_mvt', 'credit_msat': starting_wallet_msat, 'debit_msat': 0, 'tags': ['deposit']},
        #  channel open spend
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': starting_wallet_msat, 'tags': ['withdrawal']},
        #  channel open change
        {'type': 'chain_mvt', 'credit_msat': initial_wallet_balance, 'debit_msat': 0, 'tags': ['deposit']},
        #  deposit of spliceamt - fees
        {'type': 'chain_mvt', 'credit_msat': Millisatoshi(spliceamt * 1000) - fee_guess, 'debit_msat': 0, 'tags': ['deposit']},
    ]

    check_coin_moves(l1, 'wallet', expected_wallet_moves, chainparams)
    expected_channel_moves = [
        # channel_open  [utxo created], chain_mvt   (fundamt - spliceamt)
        {'type': 'chain_mvt', 'credit_msat': fundamt * 1000, 'debit_msat': 0, 'tags': ['channel_open', 'opener']},
        # channel_close [utxo spend], chain_mvt     (fundamt)
        {'type': 'chain_mvt', 'debit_msat': fundamt * 1000, 'credit_msat': 0, 'tags': ['channel_close', 'splice']},
        # channel_open  [utxo created], chain_mvt   (fundamt - spliceamt)
        {'type': 'chain_mvt', 'credit_msat': (fundamt - spliceamt) * 1000, 'debit_msat': 0, 'tags': ['channel_open', 'opener']},
    ]
    check_coin_moves(l1, first_channel_id(l1, l2), expected_channel_moves, chainparams)

    # Make sure the channel isn't marked as closed in bookkeeper
    account_id = first_channel_id(l1, l2)
    account_info = only_one([acct for acct in l1.rpc.bkpr_listbalances()['accounts'] if acct['account'] == account_id])
    assert not account_info['account_closed']

    # We'd also expect the wallet to be up by splice amt - fees
    onchain_fees = [fee for fee in l1.rpc.bkpr_listincome()['income_events'] if fee['tag'] == 'onchain_fee']
    assert len(onchain_fees) == 2
    total_fees = sum([x['debit_msat'] for x in onchain_fees])
    assert starting_wallet_msat == end_wallet_balance + total_fees + end_channel_balance

    # Now close the channel and check that everything resolves as expected
    l1.rpc.close(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])
    account_info = only_one([acct for acct in l1.rpc.bkpr_listbalances()['accounts'] if acct['account'] == account_id])
    assert not account_info['account_closed']


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_splice_in(node_factory, bitcoind, chainparams):
    fundamt = 1000000

    coin_mvt_plugin = Path(__file__).parent / "plugins" / "coin_movements.py"
    l1, l2 = node_factory.line_graph(2, fundamount=fundamt, wait_for_announce=True,
                                     opts={'experimental-splicing': None,
                                           'plugin': coin_mvt_plugin})

    initial_wallet_balance = Millisatoshi(bkpr_account_balance(l1, 'wallet'))
    initial_channel_balance = Millisatoshi(bkpr_account_balance(l1, first_channel_id(l1, l2)))
    assert initial_channel_balance == Millisatoshi(fundamt * 1000)

    # Splice in 100k sats into first channel, explicitly taking out 200k sats from wallet
    # and letting change go automatically back to wallet (100k less onchain fees)
    spliceamt = 100000
    withdraw_amt = 200000
    starting_wallet_msat = withdraw_amt * 10000

    l1.rpc.splice(f"wallet -> {withdraw_amt}; {spliceamt} -> *:?", force_feerate=True, debug_log=True)
    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['inflight'][0]['splice_amount'] == spliceamt
    assert p1['inflight'][0]['total_funding_msat'] == (fundamt + spliceamt) * 1000
    assert p1['inflight'][0]['our_funding_msat'] == fundamt * 1000
    assert p2['inflight'][0]['splice_amount'] == 0
    assert p2['inflight'][0]['total_funding_msat'] == (fundamt + spliceamt) * 1000
    assert p2['inflight'][0]['our_funding_msat'] == 0
    bitcoind.generate_block(6, wait_for_mempool=1)
    l2.daemon.wait_for_log(r'lightningd, splice_locked clearing inflights')

    p1 = only_one(l1.rpc.listpeerchannels(peer_id=l2.info['id'])['channels'])
    p2 = only_one(l2.rpc.listpeerchannels(l1.info['id'])['channels'])
    assert p1['to_us_msat'] == (fundamt + spliceamt) * 1000
    assert p1['total_msat'] == (fundamt + spliceamt) * 1000
    assert p2['to_us_msat'] == 0
    assert p2['total_msat'] == (fundamt + spliceamt) * 1000
    assert 'inflight' not in p1
    assert 'inflight' not in p2

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    wait_for(lambda: len(l1.rpc.listfunds()['channels']) == 1)

    # At the end we'd expect the balance of channel 1 to be up by the splice amount
    end_channel_balance = Millisatoshi(bkpr_account_balance(l1, first_channel_id(l1, l2)))
    end_wallet_balance = Millisatoshi(bkpr_account_balance(l1, 'wallet'))
    assert initial_channel_balance + Millisatoshi(spliceamt * 1000) == end_channel_balance

    # The fee is assumed to be the difference between the start+end balances?
    fee_guess = initial_wallet_balance + initial_channel_balance - end_channel_balance - end_wallet_balance

    # We'd expect the following coin movements
    expected_wallet_moves = [
        #  initial deposit
        {'type': 'chain_mvt', 'credit_msat': starting_wallet_msat, 'debit_msat': 0, 'tags': ['deposit']},
        #  channel open spend
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': starting_wallet_msat, 'tags': ['withdrawal']},
        #  channel open change
        {'type': 'chain_mvt', 'credit_msat': initial_wallet_balance, 'debit_msat': 0, 'tags': ['deposit']},
        # splice-in spend
        {'type': 'chain_mvt', 'debit_msat': initial_wallet_balance, 'credit_msat': 0, 'tags': ['withdrawal']},
        #  post-splice deposit
        {'type': 'chain_mvt', 'credit_msat': initial_wallet_balance - Millisatoshi(spliceamt * 1000) - fee_guess, 'debit_msat': 0, 'tags': ['deposit']},
    ]

    check_coin_moves(l1, 'wallet', expected_wallet_moves, chainparams)
    expected_channel_moves = [
        # channel_open  [utxo created], chain_mvt
        {'type': 'chain_mvt', 'credit_msat': fundamt * 1000, 'debit_msat': 0, 'tags': ['channel_open', 'opener']},
        # channel_close [utxo spend], chain_mvt     (fundamt)
        {'type': 'chain_mvt', 'debit_msat': fundamt * 1000, 'credit_msat': 0, 'tags': ['channel_close', 'splice']},
        # channel_open  [utxo created], chain_mvt   (fundamt - spliceamt)
        {'type': 'chain_mvt', 'credit_msat': (fundamt + spliceamt) * 1000, 'debit_msat': 0, 'tags': ['channel_open', 'opener']},
    ]
    check_coin_moves(l1, first_channel_id(l1, l2), expected_channel_moves, chainparams)

    # Make sure the channel isn't marked as closed in bookkeeper
    account_id = first_channel_id(l1, l2)
    account_info = only_one([acct for acct in l1.rpc.bkpr_listbalances()['accounts'] if acct['account'] == account_id])
    assert not account_info['account_closed']

    # We'd also expect the wallet to be down by splice amt + fees
    onchain_fees = [fee for fee in l1.rpc.bkpr_listincome()['income_events'] if fee['tag'] == 'onchain_fee']
    assert len(onchain_fees) == 2
    total_fees = sum([x['debit_msat'] for x in onchain_fees])
    assert starting_wallet_msat == end_wallet_balance + total_fees + end_channel_balance

    # Now close the channel and check that everything resolves as expected
    l1.rpc.close(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])
    account_info = only_one([acct for acct in l1.rpc.bkpr_listbalances()['accounts'] if acct['account'] == account_id])
    assert not account_info['account_closed']
