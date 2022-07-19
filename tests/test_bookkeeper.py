from fixtures import *  # noqa: F401,F403
from pyln.client import Millisatoshi
from utils import (
    sync_blockheight
)

import pytest


@pytest.mark.developer("dev-ignore-htlcs")
def test_closing_trimmed_htlcs(node_factory, bitcoind, executor):
    l1, l2 = node_factory.line_graph(2)

    # give l2 an output!?
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

    def _find_tags(evs, tag):
        return [e for e in evs if e['tag'] == tag]

    def _find_first_tag(evs, tag):
        ev = _find_tags(evs, tag)
        assert len(ev) > 0
        return ev[0]

    evs = l1.rpc.listaccountevents()['events']
    close = _find_first_tag(evs, 'channel_close')
    delayed_to = _find_first_tag(evs, 'delayed_to_us')

    # find the chain fee entry for the channel close
    fees = _find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    assert Millisatoshi(close_fee[0]['credit']) + Millisatoshi(delayed_to['credit']) == Millisatoshi(close['debit'])

    # l2's fees should equal the trimmed htlc out
    evs = l2.rpc.listaccountevents()['events']
    close = _find_first_tag(evs, 'channel_close')
    deposit = _find_first_tag(evs, 'deposit')
    fees = _find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    # sent htlc was too small, we lose it, rounded up to nearest sat
    assert close_fee[0]['credit'] == '101000msat'
    assert Millisatoshi(close_fee[0]['credit']) + Millisatoshi(deposit['credit']) == Millisatoshi(close['debit'])


def test_closing_subsat_htlcs(node_factory, bitcoind, chainparams):
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

    def _find_tags(evs, tag):
        return [e for e in evs if e['tag'] == tag]

    def _find_first_tag(evs, tag):
        ev = _find_tags(evs, tag)
        assert len(ev) > 0
        return ev[0]

    sync_blockheight(bitcoind, [l1, l2])
    evs = l1.rpc.listaccountevents()['events']
    # check that closing equals onchain deposits + fees
    close = _find_first_tag(evs, 'channel_close')
    delayed_to = _find_first_tag(evs, 'delayed_to_us')
    fees = _find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    assert Millisatoshi(close_fee[0]['credit']) + Millisatoshi(delayed_to['credit']) == Millisatoshi(close['debit'])

    evs = l2.rpc.listaccountevents()['events']
    close = _find_first_tag(evs, 'channel_close')
    deposit = _find_first_tag(evs, 'deposit')
    fees = _find_tags(evs, 'onchain_fee')
    close_fee = [e for e in fees if e['txid'] == close['txid']]
    assert len(close_fee) == 1
    # too small to fit, we lose them as miner fees
    assert close_fee[0]['credit'] == '333msat'
    assert Millisatoshi(close_fee[0]['credit']) + Millisatoshi(deposit['credit']) == Millisatoshi(close['debit'])
