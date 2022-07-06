from fixtures import *  # noqa: F401,F403
from decimal import Decimal
from pyln.client import Millisatoshi, RpcError
from fixtures import TEST_NETWORK
from utils import (
    sync_blockheight, wait_for, only_one
)

import os
import pytest
import unittest


def find_tags(evs, tag):
    return [e for e in evs if e['tag'] == tag]


def find_first_tag(evs, tag):
    ev = find_tags(evs, tag)
    assert len(ev) > 0
    return ev[0]


@pytest.mark.developer("dev-ignore-htlcs")
@unittest.skipIf(TEST_NETWORK != 'regtest', "fixme: broadcast fails, dusty")
def test_bookkeeping_closing_trimmed_htlcs(node_factory, bitcoind, executor):
    l1, l2 = node_factory.line_graph(2)

    # Send l2 funds via the channel
    l1.pay(l2, 11000000)

    l1.rpc.dev_ignore_htlcs(id=l2.info['id'], ignore=True)
    # This will get stuck due to l3 ignoring htlcs
    executor.submit(l2.pay, l1, 100001)
    l1.daemon.wait_for_log('their htlc 0 dev_ignore_htlcs')

    l1.rpc.dev_fail(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])

    bitcoind.generate_block(1)
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    bitcoind.generate_block(5)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
    bitcoind.generate_block(20)
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log(r'All outputs resolved.*')

    evs = l1.rpc.bkpr_listaccountevents()['events']
    close = find_first_tag(evs, 'channel_close')
    delayed_to = find_first_tag(evs, 'delayed_to_us')

    # find the chain fee entry for the channel close
    fees = find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    assert close_fee[0]['credit_msat'] + delayed_to['credit_msat'] == close['debit_msat']

    # l2's fees should equal the trimmed htlc out
    evs = l2.rpc.bkpr_listaccountevents()['events']
    close = find_first_tag(evs, 'channel_close')
    deposit = find_first_tag(evs, 'deposit')
    fees = find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    # sent htlc was too small, we lose it, rounded up to nearest sat
    assert close_fee[0]['credit_msat'] == Millisatoshi('101000msat')
    assert close_fee[0]['credit_msat'] + deposit['credit_msat'] == close['debit_msat']


@unittest.skipIf(TEST_NETWORK != 'regtest', "fixme: broadcast fails, dusty")
def test_bookkeeping_closing_subsat_htlcs(node_factory, bitcoind, chainparams):
    """Test closing balances when HTLCs are: sub 1-satoshi"""
    l1, l2 = node_factory.line_graph(2)

    l1.pay(l2, 111)
    l1.pay(l2, 222)
    l1.pay(l2, 4000000)

    l2.stop()
    l1.rpc.close(l2.info['id'], 1)
    bitcoind.generate_block(5, wait_for_mempool=1)

    l2.start()
    sync_blockheight(bitcoind, [l1])
    l1.daemon.wait_for_log('Broadcasting OUR_DELAYED_RETURN_TO_WALLET')
    bitcoind.generate_block(80)

    sync_blockheight(bitcoind, [l1, l2])
    evs = l1.rpc.bkpr_listaccountevents()['events']
    # check that closing equals onchain deposits + fees
    close = find_first_tag(evs, 'channel_close')
    delayed_to = find_first_tag(evs, 'delayed_to_us')
    fees = find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    assert close_fee[0]['credit_msat'] + delayed_to['credit_msat'] == close['debit_msat']

    evs = l2.rpc.bkpr_listaccountevents()['events']
    close = find_first_tag(evs, 'channel_close')
    deposit = find_first_tag(evs, 'deposit')
    fees = find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    # too small to fit, we lose them as miner fees
    assert close_fee[0]['credit_msat'] == Millisatoshi('333msat')
    assert close_fee[0]['credit_msat'] + deposit['credit_msat'] == close['debit_msat']


@unittest.skipIf(TEST_NETWORK != 'regtest', "External wallet support doesn't work with elements yet.")
def test_bookkeeping_external_withdraws(node_factory, bitcoind):
    """ Withdrawals to an external address shouldn't be included
    in the income statements until confirmed"""
    l1 = node_factory.get_node()
    addr = l1.rpc.newaddr()['bech32']

    amount = 1111111
    amount_msat = Millisatoshi(amount * 1000)
    bitcoind.rpc.sendtoaddress(addr, amount / 10**8)
    bitcoind.rpc.sendtoaddress(addr, amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)

    waddr = l1.bitcoin.rpc.getnewaddress()

    # Ok, now we send some funds to an external address
    out = l1.rpc.withdraw(waddr, amount // 2)

    # Make sure bitcoind received the withdrawal
    unspent = l1.bitcoin.rpc.listunspent(0)
    withdrawal = [u for u in unspent if u['txid'] == out['txid']]

    assert withdrawal[0]['amount'] == Decimal('0.00555555')
    incomes = l1.rpc.bkpr_listincome()['income_events']
    # There should only be two income events: deposits to wallet
    # for {amount}
    assert len(incomes) == 2
    for inc in incomes:
        assert inc['account'] == 'wallet'
        assert inc['tag'] == 'deposit'
        assert inc['credit_msat'] == amount_msat
    # The event should show up in the 'bkpr_listaccountevents' however
    events = l1.rpc.bkpr_listaccountevents()['events']
    assert len(events) == 3
    external = [e for e in events if e['account'] == 'external'][0]
    assert external['credit_msat'] == Millisatoshi(amount // 2 * 1000)

    btc_balance = only_one(only_one(l1.rpc.bkpr_listbalances()['accounts'])['balances'])
    assert btc_balance['balance_msat'] == amount_msat * 2

    # Restart the node, issues a balance snapshot
    # If we were counting these incorrectly,
    # we'd have a new journal_entry
    l1.restart()

    # the number of account + income events should be unchanged
    incomes = l1.rpc.bkpr_listincome()['income_events']
    assert len(find_tags(incomes, 'journal_entry')) == 0
    assert len(incomes) == 2
    events = l1.rpc.bkpr_listaccountevents()['events']
    assert len(events) == 3
    assert len(find_tags(events, 'journal_entry')) == 0

    # the wallet balance should be unchanged
    btc_balance = only_one(only_one(l1.rpc.bkpr_listbalances()['accounts'])['balances'])
    assert btc_balance['balance_msat'] == amount_msat * 2

    # ok now we mine a block
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    # expect the withdrawal to appear in the incomes
    # and there should be an onchain fee
    incomes = l1.rpc.bkpr_listincome()['income_events']
    # 2 wallet deposits, 1 wallet withdrawal, 1 onchain_fee
    assert len(incomes) == 4
    withdraw_amt = find_tags(incomes, 'withdrawal')[0]['debit_msat']
    assert withdraw_amt == Millisatoshi(amount // 2 * 1000)

    fee_events = find_tags(incomes, 'onchain_fee')
    assert len(fee_events) == 1
    fees = fee_events[0]['debit_msat']

    # wallet balance is decremented now
    btc_balance = only_one(only_one(l1.rpc.bkpr_listbalances()['accounts'])['balances'])
    assert btc_balance['balance_msat'] == amount_msat * 2 - withdraw_amt - fees


@unittest.skipIf(TEST_NETWORK != 'regtest', "External wallet support doesn't work with elements yet.")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Depends on sqlite3 database location")
def test_bookkeeping_external_withdraw_missing(node_factory, bitcoind):
    """ Withdrawals to an external address turn up as
    extremely large onchain_fees when they happen before
    our accounting plugin is attached"""
    l1 = node_factory.get_node()

    basedir = l1.daemon.opts.get("lightning-dir")
    addr = l1.rpc.newaddr()['bech32']

    amount = 1111111
    amount_msat = Millisatoshi(amount * 1000)
    bitcoind.rpc.sendtoaddress(addr, amount / 10**8)
    bitcoind.rpc.sendtoaddress(addr, amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)

    waddr = l1.bitcoin.rpc.getnewaddress()

    # Ok, now we send some funds to an external address
    l1.rpc.withdraw(waddr, amount // 2)

    # There should only be two income events: deposits to wallet
    assert len(l1.rpc.bkpr_listincome()['income_events']) == 2
    # There are three account events: 2 wallet deposits, 1 external deposit
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == 3

    # Stop node and remove the accounts data
    l1.stop()
    os.remove(os.path.join(basedir, TEST_NETWORK, 'accounts.sqlite3'))
    l1.start()

    # the number of income events should be unchanged
    assert len(l1.rpc.bkpr_listincome()['income_events']) == 2
    # we're now missing the external deposit
    events = l1.rpc.bkpr_listaccountevents()['events']
    assert len(events) == 2
    assert len([e for e in events if e['account'] == 'external']) == 0
    assert len(find_tags(events, 'journal_entry')) == 0

    # the wallet balance should be unchanged
    btc_balance = only_one(only_one(l1.rpc.bkpr_listbalances()['accounts'])['balances'])
    assert btc_balance['balance_msat'] == amount_msat * 2

    # ok now we mine a block
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    # expect the withdrawal to appear in the incomes
    # and there should be an onchain fee
    incomes = l1.rpc.bkpr_listincome()['income_events']
    # 2 wallet deposits, 1 onchain_fee
    assert len(incomes) == 3
    assert len(find_tags(incomes, 'withdrawal')) == 0

    fee_events = find_tags(incomes, 'onchain_fee')
    assert len(fee_events) == 1
    fees = fee_events[0]['debit_msat']
    assert fees > Millisatoshi(amount // 2 * 1000)

    # wallet balance is decremented now
    bal = only_one(only_one(l1.rpc.bkpr_listbalances()['accounts'])['balances'])
    assert bal['balance_msat'] == amount_msat * 2 - fees


@unittest.skipIf(TEST_NETWORK != 'regtest', "External wallet support doesn't work with elements yet.")
def test_bookkeeping_rbf_withdraw(node_factory, bitcoind):
    """ If a withdraw to an external gets RBF'd,
        it should *not* show up in our income ever.
        (but it will show up in our account events)
    """
    l1 = node_factory.get_node()
    addr = l1.rpc.newaddr()['bech32']

    amount = 1111111
    bitcoind.rpc.sendtoaddress(addr, amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == 1
    assert len(l1.rpc.bkpr_listincome()['income_events']) == 1

    # Ok, now we send some funds to an external address
    waddr = l1.bitcoin.rpc.getnewaddress()
    out1 = l1.rpc.withdraw(waddr, amount // 2, feerate='253perkw')
    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert out1['txid'] in list(mempool.keys())

    # another account event, still one income event
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == 2
    assert len(l1.rpc.bkpr_listincome()['income_events']) == 1

    # unreserve the existing output
    l1.rpc.unreserveinputs(out1['psbt'], 200)

    # resend the tx
    out2 = l1.rpc.withdraw(waddr, amount // 2, feerate='1000perkw')
    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert out2['txid'] in list(mempool.keys())

    # another account event, still one income event
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == 3
    assert len(l1.rpc.bkpr_listincome()['income_events']) == 1

    # ok now we mine a block
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    acct_evs = l1.rpc.bkpr_listaccountevents()['events']
    externs = [e for e in acct_evs if e['account'] == 'external']
    assert len(externs) == 2
    assert externs[0]['outpoint'][:-2] == out1['txid']
    assert externs[0]['blockheight'] == 0
    assert externs[1]['outpoint'][:-2] == out2['txid']
    assert externs[1]['blockheight'] > 0

    withdraws = find_tags(l1.rpc.bkpr_listincome()['income_events'], 'withdrawal')
    assert len(withdraws) == 1
    assert withdraws[0]['outpoint'][:-2] == out2['txid']

    # make sure no onchain fees are counted for the replaced tx
    fees = find_tags(acct_evs, 'onchain_fee')
    assert len(fees) > 1
    for fee in fees:
        assert fee['txid'] == out2['txid']

    fees = find_tags(l1.rpc.bkpr_listincome(consolidate_fees=False)['income_events'], 'onchain_fee')
    assert len(fees) == 2
    fees = find_tags(l1.rpc.bkpr_listincome(consolidate_fees=True)['income_events'], 'onchain_fee')
    assert len(fees) == 1


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "turns off bookkeeper at start")
def test_bookkeeping_onchaind_txs(node_factory, bitcoind):
    """
    Test for a channel that's closed, but whose close tx
    re-appears in the rescan
    """
    l1, l2 = node_factory.line_graph(2,
                                     wait_for_announce=True,
                                     opts={'disable-plugin': 'bookkeeper'})

    # Double check there's no bookkeeper plugin on
    assert l1.daemon.opts['disable-plugin'] == 'bookkeeper'
    with pytest.raises(RpcError):
        l1.rpc.listincome()

    # Send l2 funds via the channel
    l1.pay(l2, 11000000)
    bitcoind.generate_block(10)

    # Amicably close the channel, mine 101 blocks (channel forgotten)
    l1.rpc.close(l2.info['id'])
    l1.wait_for_channel_onchain(l2.info['id'])

    bitcoind.generate_block(101)
    sync_blockheight(bitcoind, [l1])

    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Now turn the bookkeeper on and restart
    l1.stop()
    del l1.daemon.opts['disable-plugin']
    # Roll back -- close is picked up for a forgotten channel
    l1.daemon.opts['rescan'] = 102
    l1.start()

    # Wait for the balance snapshot to fire/finish
    l1.daemon.wait_for_log('Snapshot balances updated')

    # We should have the deposit and then the journal entry
    events = l1.rpc.bkpr_listaccountevents()['events']
    assert len(events) == 2
    assert events[0]['account'] == 'wallet'
    assert events[0]['tag'] == 'deposit'
    assert events[1]['account'] == 'wallet'
    assert events[1]['tag'] == 'journal_entry'

    wallet_bal = only_one(l1.rpc.bkpr_listbalances()['accounts'])
    assert wallet_bal['account'] == 'wallet'
    funds = l1.rpc.listfunds()
    assert len(funds['channels']) == 0
    outs = sum([out['amount_msat'] for out in funds['outputs']])
    assert outs == only_one(wallet_bal['balances'])['balance_msat']


def test_bookkeeping_descriptions(node_factory, bitcoind, chainparams):
    """
    When an 'invoice' type event comes through, we look up the description details
    to include about the item. Particularly useful for CSV outputs etc.
    """
    l1, l2 = node_factory.line_graph(2, opts={'experimental-offers': None})

    # Send l2 funds via the channel
    bolt11_desc = 'test "bolt11" description, 🥰🪢'
    l1.pay(l2, 11000000, label=bolt11_desc)
    l1.daemon.wait_for_log('coin_move .* [(]invoice[)] 0msat -11000000msat')
    l2.daemon.wait_for_log('coin_move .* [(]invoice[)] 11000000msat')

    # Test paying an bolt11 invoice (rcvr)
    l1_inc_ev = l1.rpc.bkpr_listincome()['income_events']
    inv = only_one([ev for ev in l1_inc_ev if ev['tag'] == 'invoice'])
    assert inv['description'] == bolt11_desc

    # Test paying an bolt11 invoice (sender)
    l2_inc_ev = l2.rpc.bkpr_listincome()['income_events']
    inv = only_one([ev for ev in l2_inc_ev if ev['tag'] == 'invoice'])
    assert inv['description'] == bolt11_desc

    # Make an offer (l1)
    bolt12_desc = 'test "bolt12" description, 🥰🪢'
    offer = l1.rpc.call('offer', [100, bolt12_desc])
    invoice = l2.rpc.call('fetchinvoice', {'offer': offer['bolt12']})
    paid = l2.rpc.pay(invoice['invoice'])
    l1.daemon.wait_for_log('coin_move .* [(]invoice[)] 100msat')
    l2.daemon.wait_for_log('coin_move .* [(]invoice[)] 0msat -100msat')

    # Test paying an offer (bolt12) (rcvr)
    l1_inc_ev = l1.rpc.bkpr_listincome()['income_events']
    inv = only_one([ev for ev in l1_inc_ev if 'payment_id' in ev and ev['payment_id'] == paid['payment_hash']])
    assert inv['description'] == bolt12_desc

    # Test paying an offer (bolt12) (sender)
    l2_inc_ev = l2.rpc.bkpr_listincome()['income_events']
    inv = only_one([ev for ev in l2_inc_ev if 'payment_id' in ev and ev['payment_id'] == paid['payment_hash'] and ev['tag'] == 'invoice'])
    assert inv['description'] == bolt12_desc

    # Check the CSVs look groovy
    l1.rpc.bkpr_dumpincomecsv('koinly', 'koinly.csv')
    l2.rpc.bkpr_dumpincomecsv('koinly', 'koinly.csv')
    koinly_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'koinly.csv')
    l1_koinly_csv = open(koinly_path, 'rb').read()
    bolt11_exp = bytes('invoice,"test \'bolt11\' description, 🥰🪢",', 'utf-8')
    bolt12_exp = bytes('invoice,"test \'bolt12\' description, 🥰🪢",', 'utf-8')

    assert l1_koinly_csv.find(bolt11_exp) >= 0
    assert l1_koinly_csv.find(bolt12_exp) >= 0

    koinly_path = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'koinly.csv')
    l2_koinly_csv = open(koinly_path, 'rb').read()
    assert l2_koinly_csv.find(bolt11_exp) >= 0
    assert l2_koinly_csv.find(bolt12_exp) >= 0
