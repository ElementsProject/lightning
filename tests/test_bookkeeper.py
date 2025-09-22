from fixtures import *  # noqa: F401,F403
from decimal import Decimal
from pyln.client import Millisatoshi, RpcError
from fixtures import TEST_NETWORK
from utils import (
    sync_blockheight, wait_for, only_one, first_channel_id, TIMEOUT
)

from pathlib import Path
import os
import pytest
import time
import unittest


def find_tags(evs, tag):
    return [e for e in evs if e['tag'] == tag]


def find_first_tag(evs, tag):
    ev = find_tags(evs, tag)
    assert len(ev) > 0
    return ev[0]


def check_events(node, channel_id, exp_events):
    chan_events = [ev for ev in node.rpc.bkpr_listaccountevents()['events'] if ev['account'] == channel_id]
    stripped = [{k: d[k] for k in ('tag', 'credit_msat', 'debit_msat') if k in d} for d in chan_events]
    assert stripped == exp_events


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

    _, txid, blocks = l1.wait_for_onchaind_tx('OUR_DELAYED_RETURN_TO_WALLET',
                                              'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
    assert blocks == 4
    bitcoind.generate_block(4)
    bitcoind.generate_block(20, wait_for_mempool=txid)
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

    # Make sure l2 bookkeeper processes event before we stop it!
    wait_for(lambda: len([e for e in l2.rpc.bkpr_listaccountevents()['events'] if e['tag'] == 'invoice']) == 3)

    l2.stop()
    l1.rpc.close(l2.info['id'], 1)
    bitcoind.generate_block(1, wait_for_mempool=1)

    _, txid, blocks = l1.wait_for_onchaind_tx('OUR_DELAYED_RETURN_TO_WALLET',
                                              'OUR_UNILATERAL/DELAYED_OUTPUT_TO_US')
    assert blocks == 4
    bitcoind.generate_block(4)

    l2.start()
    bitcoind.generate_block(80, wait_for_mempool=txid)

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
    # There are two income events: deposits to wallet
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
def test_bookkeeping_rbf_withdraw(node_factory, bitcoind):
    """ If a withdraw to an external gets RBF'd,
        it should *not* show up in our income ever.
        (but it will show up in our account events)
    """
    l1 = node_factory.get_node()
    addr = l1.rpc.newaddr()['bech32']

    amount = 1111111
    event_counter = 0
    income_counter = 0

    bitcoind.rpc.sendtoaddress(addr, amount / 10**8)
    event_counter += 1
    income_counter += 1

    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == event_counter
    assert len(l1.rpc.bkpr_listincome()['income_events']) == income_counter

    # Ok, now we send some funds to an external address
    waddr = l1.bitcoin.rpc.getnewaddress()
    out1 = l1.rpc.withdraw(waddr, amount // 2, feerate='253perkw')
    event_counter += 1

    mempool = bitcoind.rpc.getrawmempool(True)
    assert len(list(mempool.keys())) == 1
    assert out1['txid'] in list(mempool.keys())

    # another account event, still one income event
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == event_counter
    assert len(l1.rpc.bkpr_listincome()['income_events']) == income_counter

    # unreserve the existing output
    l1.rpc.unreserveinputs(out1['psbt'], 200)

    # resend the tx
    out2 = l1.rpc.withdraw(waddr, amount // 2, feerate='1000perkw')
    mempool = bitcoind.rpc.getrawmempool(True)
    event_counter += 1

    assert len(list(mempool.keys())) == 1
    assert out2['txid'] in list(mempool.keys())

    # another account event, still one income event
    assert len(l1.rpc.bkpr_listaccountevents()['events']) == event_counter
    assert len(l1.rpc.bkpr_listincome()['income_events']) == income_counter

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


@pytest.mark.openchannel('v2')
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "turns off bookkeeper at start")
@unittest.skipIf(TEST_NETWORK != 'regtest', "network fees hardcoded")
def test_bookkeeping_missed_chans_leases(node_factory, bitcoind):
    """
    Test that a lease is correctly recorded if bookkeeper was off
    """

    coin_mvt_plugin = Path(__file__).parent / "plugins" / "coin_movements.py"
    opts = {'funder-policy': 'match', 'funder-policy-mod': 100,
            'lease-fee-base-sat': '100sat', 'lease-fee-basis': 100,
            'plugin': str(coin_mvt_plugin),
            'disable-plugin': 'bookkeeper'}

    l1, l2 = node_factory.get_nodes(2, opts=opts)

    open_amt = 500000
    feerate = 2000
    lease_fee = 6268000
    invoice_msat = 11000000

    l1.fundwallet(open_amt * 1000)
    l2.fundwallet(open_amt * 1000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # l1 leases a channel from l2
    compact_lease = l2.rpc.funderupdate()['compact_lease']
    txid = l1.rpc.fundchannel(l2.info['id'], open_amt, request_amt=open_amt,
                              feerate='{}perkw'.format(feerate),
                              compact_lease=compact_lease)['txid']
    bitcoind.generate_block(1, wait_for_mempool=[txid])
    wait_for(lambda: l1.channel_state(l2) == 'CHANNELD_NORMAL')
    scid = l1.get_channel_scid(l2)
    l1.wait_local_channel_active(scid)
    channel_id = first_channel_id(l1, l2)

    l1.pay(l2, invoice_msat)
    l1.daemon.wait_for_log(r'coin movement:.*\'invoice\'')

    # Now turn the bookkeeper on and restart
    l1.stop()
    l2.stop()
    del l1.daemon.opts['disable-plugin']
    del l2.daemon.opts['disable-plugin']
    l1.start()
    l2.start()

    # l1 events: nothing missed!
    exp_events = [{'tag': 'channel_open', 'credit_msat': open_amt * 1000 + lease_fee, 'debit_msat': 0},
                  {'tag': 'lease_fee', 'credit_msat': 0, 'debit_msat': lease_fee},
                  {'tag': 'onchain_fee', 'credit_msat': 1314000, 'debit_msat': 0},
                  {'tag': 'invoice', 'credit_msat': 0, 'debit_msat': invoice_msat}]
    check_events(l1, channel_id, exp_events)

    exp_events = [{'tag': 'channel_open', 'credit_msat': open_amt * 1000, 'debit_msat': 0},
                  {'tag': 'lease_fee', 'credit_msat': lease_fee, 'debit_msat': 0},
                  {'tag': 'onchain_fee', 'credit_msat': 894000, 'debit_msat': 0},
                  {'tag': 'invoice', 'credit_msat': invoice_msat, 'debit_msat': 0}]
    check_events(l2, channel_id, exp_events)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "turns off bookkeeper at start")
@unittest.skipIf(TEST_NETWORK != 'regtest', "network fees hardcoded")
@pytest.mark.openchannel('v1', 'Uses push-msat')
def test_bookkeeping_missed_chans_pushed(node_factory, bitcoind):
    """
    Test for a push_msat value in a missed channel open.
    """
    coin_mvt_plugin = Path(__file__).parent / "plugins" / "coin_movements.py"
    l1, l2 = node_factory.get_nodes(2, opts={'disable-plugin': 'bookkeeper',
                                             'plugin': str(coin_mvt_plugin)})

    # Double check there's no bookkeeper plugin on
    assert l1.daemon.opts['disable-plugin'] == 'bookkeeper'
    assert l2.daemon.opts['disable-plugin'] == 'bookkeeper'

    open_amt = 10**7
    push_amt = 10**6 * 1000
    invoice_msat = 11000000

    l1.fundwallet(200000000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    txid = l1.rpc.fundchannel(l2.info['id'], open_amt, push_msat=push_amt)['txid']
    bitcoind.generate_block(1, wait_for_mempool=[txid])
    wait_for(lambda: l1.channel_state(l2) == 'CHANNELD_NORMAL')
    scid = l1.get_channel_scid(l2)
    l1.wait_local_channel_active(scid)
    channel_id = first_channel_id(l1, l2)

    # Sigh.  bookkeeper sorts events by timestamp.  If the invoice event happens
    # too close, it can change the order, so sleep here.
    time.sleep(1)

    # Send l2 funds via the channel
    l1.pay(l2, invoice_msat)
    # Make sure they're completely settled, so accounting correct.
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    # Now turn the bookkeeper on and restart
    l1.stop()
    l2.stop()
    del l1.daemon.opts['disable-plugin']
    del l2.daemon.opts['disable-plugin']
    l1.start()
    l2.start()

    # l1 events
    exp_events = [{'tag': 'channel_open', 'credit_msat': open_amt * 1000, 'debit_msat': 0},
                  {'tag': 'pushed', 'credit_msat': 0, 'debit_msat': push_amt},
                  {'tag': 'onchain_fee', 'credit_msat': 4927000, 'debit_msat': 0},
                  {'tag': 'invoice', 'credit_msat': 0, 'debit_msat': invoice_msat}]
    check_events(l1, channel_id, exp_events)

    # l2 events
    exp_events = [{'tag': 'channel_open', 'credit_msat': 0, 'debit_msat': 0},
                  {'tag': 'pushed', 'credit_msat': push_amt, 'debit_msat': 0},
                  {'tag': 'invoice', 'credit_msat': invoice_msat, 'debit_msat': 0}]
    check_events(l2, channel_id, exp_events)


@unittest.skipIf(TEST_NETWORK != 'regtest', "network fees hardcoded")
@pytest.mark.openchannel('v1')
def test_bookkeeping_inspect_multifundchannel(node_factory, bitcoind):
    """
    Test that bookkeeper splits multifundchannel fees correctly for single funded channels.
    For single funded channels, l1 pays the entirety of the fee associated with multifundchannel, and the fee is
    split into each channel and is viewed from the opener's perspective.
    """
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    l1.fundwallet(200000000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 25000},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 25000},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 25000}]

    multifundchannel_return = l1.rpc.multifundchannel(destinations)

    multifundchannel_txid = multifundchannel_return['txid']

    channel_ids = multifundchannel_return['channel_ids']

    channel_12_channel_id = channel_ids[0]['channel_id']
    channel_13_channel_id = channel_ids[1]['channel_id']
    channel_14_channel_id = channel_ids[2]['channel_id']

    bitcoind.generate_block(1, wait_for_mempool=[multifundchannel_txid])
    wait_for(lambda: l1.channel_state(l2) == 'CHANNELD_NORMAL')
    wait_for(lambda: l1.channel_state(l3) == 'CHANNELD_NORMAL')
    wait_for(lambda: l1.channel_state(l4) == 'CHANNELD_NORMAL')

    # now use getblock to get the tx fee from bitcoin-cli's perspective
    multifundchannel_rawtx = l1.bitcoin.rpc.getrawtransaction(multifundchannel_txid, True)
    blockhash = multifundchannel_rawtx['blockhash']
    getblock_tx = l1.bitcoin.rpc.getblock(blockhash, 2)['tx']
    getblock_fee_btc = 0
    for tx in getblock_tx:
        if tx['txid'] == multifundchannel_txid:
            getblock_fee_btc = tx['fee']

    # now sum bookkeeper fees for each channel to get the total fees for this tx
    channel_12_multifundchannel_fee_msat = l1.rpc.bkpr_inspect(channel_12_channel_id)['txs'][0]['fees_paid_msat']
    channel_13_multifundchannel_fee_msat = l1.rpc.bkpr_inspect(channel_13_channel_id)['txs'][0]['fees_paid_msat']
    channel_14_multifundchannel_fee_msat = l1.rpc.bkpr_inspect(channel_14_channel_id)['txs'][0]['fees_paid_msat']

    bkpr_total_fee_msat = (channel_12_multifundchannel_fee_msat
                           + channel_13_multifundchannel_fee_msat
                           + channel_14_multifundchannel_fee_msat)

    assert bkpr_total_fee_msat == int(getblock_fee_btc * 100000000000)


@unittest.skipIf(TEST_NETWORK != 'regtest', "network fees hardcoded")
@pytest.mark.openchannel('v2')
def test_bookkeeping_inspect_mfc_dual_funded(node_factory, bitcoind):
    """
    Test that bookkeeper splits multifundchannel fees correctly for dual funded channels.
    For dual funded channels, the other nodes also pay part of the fees associated with multifundchannel, since they
    are also funding the channel.  To calculate the total fees spent for the multifundchannel tx, the
    other nodes' fees paid must be included.
    """
    opts = {'experimental-dual-fund': None, 'funder-policy': 'match',
            'funder-policy-mod': 100, 'funder-lease-requests-only': False}
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)

    l1.fundwallet(2000000000)
    l2.fundwallet(2000000000)
    l3.fundwallet(2000000000)
    l4.fundwallet(2000000000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l1.rpc.connect(l4.info['id'], 'localhost', l4.port)

    destinations = [{"id": '{}@localhost:{}'.format(l2.info['id'], l2.port),
                     "amount": 25000,
                     "announce": True},
                    {"id": '{}@localhost:{}'.format(l3.info['id'], l3.port),
                     "amount": 25000,
                     "announce": True},
                    {"id": '{}@localhost:{}'.format(l4.info['id'], l4.port),
                     "amount": 25000,
                     "announce": True}]

    multifundchannel_return = l1.rpc.multifundchannel(destinations)
    multifundchannel_txid = multifundchannel_return['txid']
    channel_ids = multifundchannel_return['channel_ids']

    channel_12_channel_id = channel_ids[0]['channel_id']
    channel_13_channel_id = channel_ids[1]['channel_id']
    channel_14_channel_id = channel_ids[2]['channel_id']

    bitcoind.generate_block(5, wait_for_mempool=[multifundchannel_txid])
    wait_for(lambda: l1.channel_state(l2) == 'CHANNELD_NORMAL')
    wait_for(lambda: l1.channel_state(l3) == 'CHANNELD_NORMAL')
    wait_for(lambda: l1.channel_state(l4) == 'CHANNELD_NORMAL')

    # now use getblock to get the tx fee from bitcoin-cli's perspective
    multifundchannel_rawtx = l1.bitcoin.rpc.getrawtransaction(multifundchannel_txid, True)
    blockhash = multifundchannel_rawtx['blockhash']
    getblock_tx = l1.bitcoin.rpc.getblock(blockhash, 2)['tx']
    getblock_fee_btc = 0
    for tx in getblock_tx:
        if tx['txid'] == multifundchannel_txid:
            getblock_fee_btc = tx['fee']

    # now sum bookkeeper fees for each node to get the total fees for this tx
    channel_12_multifundchannel_fee_msat = l1.rpc.bkpr_inspect(channel_12_channel_id)['txs'][0]['fees_paid_msat']
    channel_21_multifundchannel_fee_msat = l2.rpc.bkpr_inspect(channel_12_channel_id)['txs'][0]['fees_paid_msat']
    channel_13_multifundchannel_fee_msat = l1.rpc.bkpr_inspect(channel_13_channel_id)['txs'][0]['fees_paid_msat']
    channel_31_multifundchannel_fee_msat = l3.rpc.bkpr_inspect(channel_13_channel_id)['txs'][0]['fees_paid_msat']
    channel_14_multifundchannel_fee_msat = l1.rpc.bkpr_inspect(channel_14_channel_id)['txs'][0]['fees_paid_msat']
    channel_41_multifundchannel_fee_msat = l4.rpc.bkpr_inspect(channel_14_channel_id)['txs'][0]['fees_paid_msat']

    bkpr_total_fee_msat = (channel_12_multifundchannel_fee_msat
                           + channel_21_multifundchannel_fee_msat
                           + channel_13_multifundchannel_fee_msat
                           + channel_31_multifundchannel_fee_msat
                           + channel_14_multifundchannel_fee_msat
                           + channel_41_multifundchannel_fee_msat)

    assert bkpr_total_fee_msat == int(getblock_fee_btc * 100000000000)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "turns off bookkeeper at start")
@unittest.skipIf(TEST_NETWORK != 'regtest', "network fees hardcoded")
@pytest.mark.openchannel('v1', 'Uses push-msat')
def test_bookkeeping_missed_chans_pay_after(node_factory, bitcoind):
    """
    Route a payment through a channel that we didn't have open when the bookkeeper
    was around
    """
    coin_mvt_plugin = Path(__file__).parent / "plugins" / "coin_movements.py"
    l1, l2 = node_factory.get_nodes(2, opts={'disable-plugin': 'bookkeeper',
                                             'may_reconnect': True,
                                             'plugin': str(coin_mvt_plugin)})

    # Double check there's no bookkeeper plugin on
    assert l1.daemon.opts['disable-plugin'] == 'bookkeeper'
    assert l2.daemon.opts['disable-plugin'] == 'bookkeeper'

    open_amt = 10**7
    invoice_msat = 11000000

    l1.fundwallet(200000000)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    txid = l1.rpc.fundchannel(l2.info['id'], open_amt)['txid']
    bitcoind.generate_block(1, wait_for_mempool=[txid])
    wait_for(lambda: l1.channel_state(l2) == 'CHANNELD_NORMAL')
    scid = l1.get_channel_scid(l2)
    l1.wait_local_channel_active(scid)
    channel_id = first_channel_id(l1, l2)

    # Now turn the bookkeeper on and restart
    l1.stop()
    l2.stop()
    del l1.daemon.opts['disable-plugin']
    del l2.daemon.opts['disable-plugin']
    l1.start()
    l2.start()

    # Should have channel in both, with balances
    for n in [l1, l2]:
        accts = [ba['account'] for ba in n.rpc.bkpr_listbalances()['accounts']]
        assert channel_id in accts

    # Send a payment, should be ok.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.wait_local_channel_active(scid)
    l1.pay(l2, invoice_msat)
    l1.daemon.wait_for_log(r'coin movement:.*\'invoice\'')

    # l1 events
    exp_events = [{'tag': 'channel_open', 'credit_msat': open_amt * 1000, 'debit_msat': 0},
                  {'tag': 'onchain_fee', 'credit_msat': 4927000, 'debit_msat': 0},
                  {'tag': 'invoice', 'credit_msat': 0, 'debit_msat': invoice_msat}]
    check_events(l1, channel_id, exp_events)

    # l2 events
    exp_events = [{'tag': 'channel_open', 'credit_msat': 0, 'debit_msat': 0},
                  {'tag': 'invoice', 'credit_msat': invoice_msat, 'debit_msat': 0}]
    check_events(l2, channel_id, exp_events)


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "turns off bookkeeper at start")
def test_bookkeeping_onchaind_txs(node_factory, bitcoind):
    """
    Test for a channel that's closed, but whose close tx
    re-appears in the rescan
    """
    coin_mvt_plugin = Path(__file__).parent / "plugins" / "coin_movements.py"
    l1, l2 = node_factory.line_graph(2,
                                     wait_for_announce=True,
                                     opts={'disable-plugin': 'bookkeeper',
                                           'plugin': str(coin_mvt_plugin)})

    # Double check there's no bookkeeper plugin on
    assert l1.daemon.opts['disable-plugin'] == 'bookkeeper'

    # Send l2 funds via the channel
    l1.pay(l2, 11000000)
    l1.daemon.wait_for_log(r'coin movement:.*\'invoice\'')
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

    # We should have everything.
    events = l1.rpc.bkpr_listaccountevents()['events']
    assert len(events) == 12

    wallet_bal = only_one([a for a in l1.rpc.bkpr_listbalances()['accounts'] if a['account'] == 'wallet'])
    funds = l1.rpc.listfunds()
    assert len(funds['channels']) == 0
    outs = sum([out['amount_msat'] for out in funds['outputs']])
    assert outs == only_one(wallet_bal['balances'])['balance_msat']


def test_bookkeeping_descriptions(node_factory, bitcoind, chainparams):
    """
    When an 'invoice' type event comes through, we look up the description details
    to include about the item. Particularly useful for CSV outputs etc.
    """
    l1, l2 = node_factory.line_graph(2)

    # Send l2 funds via the channel
    bolt11_desc = 'test "bolt11" description, 🥰🪢'
    l1.pay(l2, 11000000, label=bolt11_desc)
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])

    # Need to call bookkeeper to trigger analysis!
    l1_inc_ev = l1.rpc.bkpr_listincome()['income_events']
    l1.daemon.wait_for_log('coin_move .* [(]invoice[)] 0msat -11000000msat')
    l2.rpc.bkpr_listincome()
    l2.daemon.wait_for_log('coin_move .* [(]invoice[)] 11000000msat')

    # Test paying an bolt11 invoice (rcvr)
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
    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])
    wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['htlcs'] == [])
    l1_inc_ev = l1.rpc.bkpr_listincome()['income_events']
    l1.daemon.wait_for_log('coin_move .* [(]invoice[)] 100msat')
    l2.rpc.bkpr_listincome()
    l2.daemon.wait_for_log('coin_move .* [(]invoice[)] 0msat -100msat')

    # Test paying an offer (bolt12) (rcvr)
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

    # Test that we can update the description, payment id
    edited_desc_payid = 'edited payment_id description'
    for node in [l1, l2]:
        results = node.rpc.bkpr_editdescriptionbypaymentid(paid['payment_hash'], edited_desc_payid)
        assert only_one(results['updated'])['description'] == edited_desc_payid

    # Test that we can update the description, outpoint
    edited_desc_outpoint = 'edited outpoint description'
    deposits = [ev for ev in l1_inc_ev if ev['tag'] == 'deposit']
    assert len(deposits) > 0
    results = l1.rpc.bkpr_editdescriptionbyoutpoint(deposits[0]['outpoint'], edited_desc_outpoint)
    assert only_one(results['updated'])['description'] == edited_desc_outpoint

    # Test that input that doesn't match an event returns empty list
    fake_outpoint = '01' * 32 + ':100'
    results = l1.rpc.bkpr_editdescriptionbyoutpoint(fake_outpoint, edited_desc_outpoint)
    assert len(results['updated']) == 0

    # Make sure that only one event actually updated
    acct_evs = l1.rpc.bkpr_listaccountevents()['events']
    income_evs = l1.rpc.bkpr_listincome()['income_events']
    for evs in [acct_evs, income_evs]:
        assert only_one([ev for ev in evs if 'description' in ev and ev['description'] == edited_desc_payid])
        assert only_one([ev for ev in evs if 'description' in ev and ev['description'] == edited_desc_outpoint])

    # Test persistence!
    l1.restart()
    assert l1.rpc.bkpr_listaccountevents()['events'] == acct_evs
    assert l1.rpc.bkpr_listincome()['income_events'] == income_evs


def test_empty_node(node_factory, bitcoind):
    """
    Make sure that the bookkeeper commands don't blow up
    on an empty accounts database.
    """
    l1 = node_factory.get_node()

    bkpr_cmds = [
        ('channelsapy', []),
        ('listaccountevents', []),
        ('listbalances', []),
        ('listincome', [])]
    for cmd, params in bkpr_cmds:
        l1.rpc.call('bkpr-' + cmd, params)

    # inspect fails for non-channel accounts
    # FIXME: implement for all accounts?
    with pytest.raises(RpcError, match=r'not supported for non-channel accounts'):
        l1.rpc.bkpr_inspect('wallet')


@pytest.mark.xfail(strict=True)
def test_rebalance_tracking(node_factory, bitcoind):
    """
    We identify rebalances (invoices paid and received by our node),
    this allows us to filter them out of "incomes" (self-transfers are not income/exp)
    and instead only display the cost incurred to move the payment (correctly
    marked as a rebalance)

    1 -> 2 -> 3 -> 1
    """

    rebal_amt = 3210
    l1, l2, l3 = node_factory.get_nodes(3)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l1.info['id'], 'localhost', l1.port)
    c12, _ = l1.fundchannel(l2, 10**7, wait_for_active=True)
    c23, _ = l2.fundchannel(l3, 10**7, wait_for_active=True)
    c31, _ = l3.fundchannel(l1, 10**7, wait_for_active=True)

    # Build a rebalance payment
    invoice = l1.rpc.invoice(rebal_amt, 'to_self', 'to_self')
    pay_hash = invoice['payment_hash']
    pay_sec = invoice['payment_secret']

    route = [{
        'id': l2.info['id'],
        'channel': c12,
        'direction': int(not l1.info['id'] < l2.info['id']),
        'amount_msat': rebal_amt + 1001,
        'style': 'tlv',
        'delay': 24,
    }, {
        'id': l3.info['id'],
        'channel': c23,
        'direction': int(not l2.info['id'] < l3.info['id']),
        'amount_msat': rebal_amt + 500,
        'style': 'tlv',
        'delay': 16,
    }, {
        'id': l1.info['id'],
        'channel': c31,
        'direction': int(not l3.info['id'] < l1.info['id']),
        'amount_msat': rebal_amt,
        'style': 'tlv',
        'delay': 8,
    }]

    l1.rpc.sendpay(route, pay_hash, payment_secret=pay_sec)
    result = l1.rpc.waitsendpay(pay_hash, TIMEOUT)
    assert result['status'] == 'complete'

    wait_for(lambda: 'invoice' not in [ev['tag'] for ev in l1.rpc.bkpr_listincome()['income_events']])
    inc_evs = l1.rpc.bkpr_listincome()['income_events']
    outbound_chan_id = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['channel_id']

    outbound_ev = only_one([ev for ev in inc_evs if ev['tag'] == 'rebalance_fee'])
    assert outbound_ev['account'] == outbound_chan_id
    assert outbound_ev['debit_msat'] == Millisatoshi(1001)
    assert outbound_ev['credit_msat'] == Millisatoshi(0)
    assert outbound_ev['payment_id'] == pay_hash

    # Will reload on restart!
    l1.restart()

    inc_evs = l1.rpc.bkpr_listincome()['income_events']
    outbound_chan_id = only_one(l1.rpc.listpeerchannels(l2.info['id'])['channels'])['channel_id']

    outbound_ev = only_one([ev for ev in inc_evs if ev['tag'] == 'rebalance_fee'])
    assert outbound_ev['account'] == outbound_chan_id
    assert outbound_ev['debit_msat'] == Millisatoshi(1001)
    assert outbound_ev['credit_msat'] == Millisatoshi(0)
    assert outbound_ev['payment_id'] == pay_hash


def test_bookkeeper_custom_notifs(node_factory, chainparams):
    # FIXME: what happens if we send internal funds to 'external' wallet?
    plugin = os.path.join(
        os.path.dirname(__file__), "plugins", "bookkeeper_custom_coins.py"
    )
    l1, l2 = node_factory.line_graph(2, opts=[{'plugin': plugin}, {}])

    outpoint_in = 'aa' * 32 + ':0'
    spend_txid = 'bb' * 32
    amount = 180000000
    withdraw_amt = 55555000
    fee = 2000

    change_deposit = 'bb' * 32 + ':0'
    external_deposit = 'bb' * 32 + ':1'
    acct = "nifty's secret stash"

    l1.rpc.senddeposit(acct, False, outpoint_in, amount)
    l1.daemon.wait_for_log(r"Foreign chain event: deposit \(nifty's secret stash\) 180000000msat -0msat 1679955976 111 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0")
    l1.rpc.sendspend(acct, outpoint_in, spend_txid, amount)
    l1.daemon.wait_for_log(r"Foreign chain event: withdrawal \(nifty's secret stash\) 0msat -180000000msat 1679955976 111 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    # balance should be zero
    bals = l1.rpc.bkpr_listbalances()['accounts']
    for bal in bals:
        if bal['account'] == acct:
            # FIXME: how to account for withdraw to external
            assert only_one(bal['balances'])['balance_msat'] == Millisatoshi(0)

    l1.rpc.senddeposit(acct, False, change_deposit, amount - withdraw_amt - fee)
    l1.daemon.wait_for_log(r"Foreign chain event: deposit \(nifty's secret stash\) .* -0msat 1679955976 111 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0")

    # balance should be equal to amount
    events = l1.rpc.bkpr_listaccountevents(acct)['events']
    for bal in l1.rpc.bkpr_listbalances()['accounts']:
        if bal['account'] == acct:
            assert only_one(bal['balances'])['balance_msat'] == Millisatoshi(amount - fee - withdraw_amt)

    onchain_fee_one = only_one([x['credit_msat'] for x in events if x['type'] == 'onchain_fee'])
    assert onchain_fee_one == fee + withdraw_amt

    l1.rpc.senddeposit(acct, True, external_deposit, withdraw_amt)
    l1.daemon.wait_for_log(r"Foreign chain event: deposit \(external\) .* -0msat 1679955976 111 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:1")
    events = l1.rpc.bkpr_listaccountevents(acct)['events']
    onchain_fees = [x for x in events if x['type'] == 'onchain_fee']
    assert len(onchain_fees) == 2
    assert onchain_fees[0]['credit_msat'] == onchain_fee_one
    assert onchain_fees[1]['debit_msat'] == withdraw_amt
    assert events == [{'account': "nifty's secret stash",
                       'blockheight': 111,
                       'credit_msat': 180000000,
                       'currency': chainparams['bip173_prefix'],
                       'debit_msat': 0,
                       'outpoint': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0',
                       'tag': 'deposit',
                       'timestamp': 1679955976,
                       'type': 'chain'},
                      {'account': "nifty's secret stash",
                       'blockheight': 111,
                       'credit_msat': 0,
                       'currency': chainparams['bip173_prefix'],
                       'debit_msat': 180000000,
                       'outpoint': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:0',
                       'tag': 'withdrawal',
                       'timestamp': 1679955976,
                       'txid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                       'type': 'chain'},
                      {'account': "nifty's secret stash",
                       'blockheight': 111,
                       'credit_msat': 124443000,
                       'currency': chainparams['bip173_prefix'],
                       'debit_msat': 0,
                       'outpoint': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:0',
                       'tag': 'deposit',
                       'timestamp': 1679955976,
                       'type': 'chain'},
                      {'account': "nifty's secret stash",
                       'credit_msat': 55557000,
                       'currency': chainparams['bip173_prefix'],
                       'debit_msat': 0,
                       'tag': 'onchain_fee',
                       'timestamp': 1679955976,
                       'txid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                       'type': 'onchain_fee'},
                      {'account': "nifty's secret stash",
                       'credit_msat': 0,
                       'currency': chainparams['bip173_prefix'],
                       'debit_msat': 55555000,
                       'tag': 'onchain_fee',
                       'timestamp': 1679955976,
                       'txid': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                       'type': 'onchain_fee'}]

    # This should not blow up
    incomes = l1.rpc.bkpr_listincome()['income_events']
    acct_fee = only_one([inc['debit_msat'] for inc in incomes if inc['account'] == acct and inc['tag'] == 'onchain_fee'])
    assert acct_fee == Millisatoshi(fee)


@unittest.skipIf(TEST_NETWORK != 'regtest', "Snapshots are bitcoin regtest.")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "uses snapshots")
def test_migration(node_factory, bitcoind):
    generate = False

    if generate:
        l1, l2 = node_factory.line_graph(2)

        l1.pay(l2, 12345678, label="Rusty's payment")

        wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['htlcs'] == [])
        wait_for(lambda: only_one(l2.rpc.listpeerchannels()['channels'])['htlcs'] == [])

        chan = only_one(l1.rpc.listpeerchannels()['channels'])
        # Label change output and funding output
        l1.rpc.bkpr_editdescriptionbyoutpoint(f"{chan['funding_txid']}:{chan['funding_outnum']}",
                                              "Rusty's channel")
        l1.rpc.bkpr_editdescriptionbyoutpoint(f"{chan['funding_txid']}:{chan['funding_outnum'] ^ 1}",
                                              "Rusty's change")
    else:
        bitcoind.generate_block(1)
        l1 = node_factory.get_node(dbfile="l1-before-moves-in-db.sqlite3.xz",
                                   bkpr_dbfile="l1-bkpr-accounts.sqlite3.xz",
                                   options={'database-upgrade': True})
        l2 = node_factory.get_node(dbfile="l2-before-moves-in-db.sqlite3.xz",
                                   bkpr_dbfile="l2-bkpr-accounts.sqlite3.xz",
                                   options={'database-upgrade': True})

        chan = only_one(l1.rpc.listpeerchannels()['channels'])

    payment = only_one(l1.rpc.listsendpays()['payments'])
    events = l1.rpc.bkpr_listaccountevents()['events']

    pay_event = only_one([e for e in events if e.get('description') == "Rusty's payment"])
    del pay_event['timestamp']
    assert pay_event == {'account': chan['channel_id'],
                         'credit_msat': 0,
                         'currency': 'bcrt',
                         'debit_msat': 12345678,
                         'description': "Rusty's payment",
                         'is_rebalance': False,
                         'part_id': 0,
                         'payment_id': payment['payment_hash'],
                         'tag': 'invoice',
                         'type': 'channel'}
    open_event = only_one([e for e in events if e.get('description') == "Rusty's channel"])
    del open_event['timestamp']
    assert open_event == {'account': chan['channel_id'],
                          'blockheight': 103,
                          'credit_msat': 1000000000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'description': "Rusty's channel",
                          'outpoint': f"{chan['funding_txid']}:{chan['funding_outnum']}",
                          'tag': 'channel_open',
                          'type': 'chain'}

    change_event = only_one([e for e in events if e.get('description') == "Rusty's change"])
    del change_event['timestamp']
    assert change_event == {'account': 'wallet',
                            'blockheight': 103,
                            'credit_msat': 995073000,
                            'currency': 'bcrt',
                            'debit_msat': 0,
                            'description': "Rusty's change",
                            'outpoint': f"{chan['funding_txid']}:{chan['funding_outnum'] ^ 1}",
                            'tag': 'deposit',
                            'type': 'chain'}

    # When generating, we want to stop so you can grab databases.
    assert generate is False

    l1_events = l1.rpc.bkpr_listaccountevents()['events']
    for e in l1_events:
        del e['timestamp']

    l2_events = l2.rpc.bkpr_listaccountevents()['events']
    for e in l2_events:
        del e['timestamp']

    # These were snapshotted before the bkpr migration, so should
    # be the same!
    assert l1_events == [{'account': 'wallet',
                          'blockheight': 102,
                          'credit_msat': 2000000000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'outpoint': '63c59b312976320528552c258ae51563498dfd042b95bb0c842696614d59bb89:1',
                          'tag': 'deposit',
                          'type': 'chain'},
                         {'account': 'wallet',
                          'blockheight': 103,
                          'credit_msat': 0,
                          'currency': 'bcrt',
                          'debit_msat': 2000000000,
                          'outpoint': '63c59b312976320528552c258ae51563498dfd042b95bb0c842696614d59bb89:1',
                          'tag': 'withdrawal',
                          'txid': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe',
                          'type': 'chain'},
                         {'account': 'wallet',
                          'blockheight': 103,
                          'credit_msat': 995073000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'description': "Rusty's change",
                          'outpoint': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe:1',
                          'tag': 'deposit',
                          'type': 'chain'},
                         {'account': 'be7f3755c04abec58212fe9287898c76364d1a0d12a1828bf9fc3ac4a8b25a67',
                          'blockheight': 103,
                          'credit_msat': 1000000000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'description': "Rusty's channel",
                          'outpoint': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe:0',
                          'tag': 'channel_open',
                          'type': 'chain'},
                         {'account': 'be7f3755c04abec58212fe9287898c76364d1a0d12a1828bf9fc3ac4a8b25a67',
                          'credit_msat': 0,
                          'currency': 'bcrt',
                          'debit_msat': 12345678,
                          'description': "Rusty's payment",
                          'is_rebalance': False,
                          'part_id': 0,
                          'payment_id': '7ccef7e9fabbf4a841af44b1fc7319bc70ce98697b77ce6dacffa84bebcd4350',
                          'tag': 'invoice',
                          'type': 'channel'},
                         {'account': 'be7f3755c04abec58212fe9287898c76364d1a0d12a1828bf9fc3ac4a8b25a67',
                          'credit_msat': 4927000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'tag': 'onchain_fee',
                          'txid': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe',
                          'type': 'onchain_fee'},
                         {'account': 'wallet',
                          'credit_msat': 1004927000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'tag': 'onchain_fee',
                          'txid': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe',
                          'type': 'onchain_fee'},
                         {'account': 'wallet',
                          'credit_msat': 0,
                          'currency': 'bcrt',
                          'debit_msat': 1004927000,
                          'tag': 'onchain_fee',
                          'txid': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe',
                          'type': 'onchain_fee'}]

    assert l2_events == [{'account': 'be7f3755c04abec58212fe9287898c76364d1a0d12a1828bf9fc3ac4a8b25a67',
                          'blockheight': 103,
                          'credit_msat': 0,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'outpoint': '675ab2a8c43afcf98b82a1120d1a4d36768c898792fe1282c5be4ac055377fbe:0',
                          'tag': 'channel_open',
                          'type': 'chain'},
                         {'account': 'be7f3755c04abec58212fe9287898c76364d1a0d12a1828bf9fc3ac4a8b25a67',
                          'credit_msat': 12345678,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'description': "Rusty's payment",
                          'is_rebalance': False,
                          'part_id': 0,
                          'payment_id': '7ccef7e9fabbf4a841af44b1fc7319bc70ce98697b77ce6dacffa84bebcd4350',
                          'tag': 'invoice',
                          'type': 'channel'}]


@unittest.skipIf(TEST_NETWORK != 'regtest', "Snapshots are bitcoin regtest.")
@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "uses snapshots")
def test_migration_no_bkpr(node_factory, bitcoind):
    """These nodes need to invent coinmoves to make the balances work"""
    bitcoind.generate_block(1)
    l1 = node_factory.get_node(dbfile="l1-before-moves-in-db.sqlite3.xz",
                               options={'database-upgrade': True})
    l2 = node_factory.get_node(dbfile="l2-before-moves-in-db.sqlite3.xz",
                               options={'database-upgrade': True})

    chan = only_one(l1.rpc.listpeerchannels()['channels'])

    l1_events = l1.rpc.bkpr_listaccountevents()['events']
    for e in l1_events:
        del e['timestamp']

    l2_events = l2.rpc.bkpr_listaccountevents()['events']
    for e in l2_events:
        del e['timestamp']

    assert l1_events == [{'account': chan['channel_id'],
                          'blockheight': 103,
                          'credit_msat': 1000000000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'outpoint': f"{chan['funding_txid']}:{chan['funding_outnum']}",
                          'tag': 'channel_open',
                          'type': 'chain'},
                         {'account': 'wallet',
                          'blockheight': 103,
                          'credit_msat': 995073000,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'outpoint': f"{chan['funding_txid']}:{chan['funding_outnum'] ^ 1}",
                          'tag': 'deposit',
                          'type': 'chain'},
                         {'account': chan['channel_id'],
                          'credit_msat': 0,
                          'currency': 'bcrt',
                          'debit_msat': 12345678,
                          'is_rebalance': False,
                          'tag': 'journal_entry',
                          'type': 'channel'}]

    assert l2_events == [{'account': chan['channel_id'],
                          'blockheight': 103,
                          'credit_msat': 0,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'outpoint': f"{chan['funding_txid']}:{chan['funding_outnum']}",
                          'tag': 'channel_open',
                          'type': 'chain'},
                         {'account': chan['channel_id'],
                          'credit_msat': 12345678,
                          'currency': 'bcrt',
                          'debit_msat': 0,
                          'is_rebalance': False,
                          'tag': 'journal_entry',
                          'type': 'channel'}]
