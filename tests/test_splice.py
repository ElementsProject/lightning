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
    l1.rpc.splice(f"*:? -> {spliceamt}; 100%-fee -> wallet", debug_log=True)
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

    l1.rpc.splice(f"wallet -> {withdraw_amt}; {spliceamt} -> *:?", debug_log=True)
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


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_in(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id1 = l2.get_channel_id(l1)
    chan_id2 = l2.get_channel_id(l3)

    # l2 will splice funds into the channels with l1 and l3 at the same time
    result = l2.rpc.splice(f"wallet -> 200000+fee; 100000 -> {chan_id1}; 100000 -> {chan_id2}")

    l3.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    assert result['txid'] in list(bitcoind.rpc.getrawmempool(True).keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l3.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    inv = l3.rpc.invoice(10**2, '2', 'no_2')
    l2.rpc.pay(inv['bolt11'])


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_out(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    # We need to get funds into l1 -> l2 channel so we can splice it out
    inv = l2.rpc.invoice(100000000, '1', 'no_1')
    l1.rpc.pay(inv['bolt11'])

    chan_id1 = l2.get_channel_id(l1)
    chan_id2 = l2.get_channel_id(l3)

    # l2 will splice funds out of the channels with l1 and l3 at the same time
    result = l2.rpc.splice(f"{chan_id1} -> 100000; {chan_id2} -> 100000")

    l3.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    assert result['txid'] in list(bitcoind.rpc.getrawmempool(True).keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l3.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '2', 'no_2')
    l1.rpc.pay(inv['bolt11'])

    inv = l3.rpc.invoice(10**2, '3', 'no_3')
    l2.rpc.pay(inv['bolt11'])


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_inout(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id1 = l2.get_channel_id(l1)
    chan_id2 = l2.get_channel_id(l3)

    # move sats from chan 2 into chan 1
    result = l2.rpc.splice(f"wallet -> 10000; 100000 -> {chan_id1}; {chan_id2} -> 100000")

    l3.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l2.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')
    l1.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)
    assert result['txid'] in list(bitcoind.rpc.getrawmempool(True).keys())

    bitcoind.generate_block(6, wait_for_mempool=1)

    l3.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l2.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')
    l1.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    inv = l2.rpc.invoice(10**2, '2', 'no_2')
    l1.rpc.pay(inv['bolt11'])

    inv = l3.rpc.invoice(10**2, '3', 'no_3')
    l2.rpc.pay(inv['bolt11'])


# Makes channels going from node 1 -> 2, 2 -> 3, etc up to 'qty' number channels.
# If balanced is True, than each channel will be balanced -- otherwise the lower
# index channel will have funds in the channel to the higher indexed one.
#
# The channels for the second node are returned in chanids
def make_chans(node_factory, qty=2, fundamount=1000000, balanced=True):
    nodes = node_factory.line_graph(qty + 1, fundamount=fundamount, opts={'experimental-splicing': None, 'allow_bad_gossip': True})
    chanids = []

    for i in range(len(nodes) - 1):
        nodes[i].daemon.wait_for_log(' to CHANNELD_NORMAL')
        if balanced:
            inv = nodes[i + 1].rpc.invoice(1000 * fundamount // 2, 'balance', 'balance')
            nodes[i].rpc.pay(inv['bolt11'])

    chanids.insert(0, nodes[1].get_channel_id(nodes[0]))
    if qty > 1:
        chanids.insert(0, nodes[1].get_channel_id(nodes[2]))

    return [nodes, chanids]


def verify_chans(nodes, bitcoind, txid, payment_check_style=1, payamount=1000000):
    for node in nodes:
        node.daemon.wait_for_log(r'CHANNELD_NORMAL to CHANNELD_AWAITING_SPLICE')

    wait_for(lambda: len(list(bitcoind.rpc.getrawmempool(True).keys())) == 1)

    bitcoind.generate_block(6, wait_for_mempool=1)

    for node in nodes:
        node.daemon.wait_for_log(r'CHANNELD_AWAITING_SPLICE to CHANNELD_NORMAL')

    if payment_check_style == 1:
        for i in range(len(nodes) - 1):
            inv = nodes[i + 1].rpc.invoice(payamount, str(i) + "test", str(i) + "test")
            nodes[i].rpc.pay(inv['bolt11'])


def execute_script(node_factory, bitcoind, script):
    nodes, chanids = make_chans(node_factory, script.count("{}"))
    result = nodes[1].rpc.splice(script.format(*chanids), debug_log=True)
    verify_chans(nodes, bitcoind, result['txid'])


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_b(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 10000; {} -> 100000; {} -> 100000")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_c(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 10000; 100000 -> {}; {} -> 100000")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_d(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 250000; 100000 -> {}; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_e(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "{} -> 100000; {} -> 100000")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_f(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "{} -> 200000; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_g(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "{} -> 200000; 100000 -> {}; * -> wallet")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_h(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 200000+fee; 100000 -> {}; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_ii(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "100000 -> {}; {} -> 100000+fee")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_j(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "100000-fee -> {}; {} -> 100000")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_k(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "{} -> 10000; 1000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_l(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 100000; * -> {}; * -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_m(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> *+fee; 100000 -> {}; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_n(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 100%+fee; {} -> 50%; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_oo(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> *+fee; {} -> 50%; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_p(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> *; {} -> 50%+fee; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_q(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> *; {} -> 50000+fee; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_r(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 0+fee; {} -> 100000; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_s(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 50000; {} -> 50000+fee; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_t(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 100%; {} -> 50000+fee; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_u(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 100%; {} -> 50000; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_v(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 100%; {} -> 100000; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_x(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "* -> wallet; * -> {}; {} -> 100000")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_y(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> *; 100000 -> {}; 100000 -> {}")


@pytest.mark.xfail(strict=True)
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_script_two_chan_splice_z(node_factory, bitcoind):
    execute_script(node_factory, bitcoind, "wallet -> 100000; 70% -> {}; 30% -> {}")
