from bitcoin.rpc import JSONRPCError
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from utils import (
    only_one, wait_for, sync_blockheight,
    VALGRIND, check_coin_moves, TailableProc, scriptpubkey_addr,
    check_utxos_channel, check_feerate, did_short_sig
)

import os
import pytest
import subprocess
import sys
import time
import unittest


WAIT_TIMEOUT = 60  # Wait timeout for processes

# Errors codes
HSM_GENERIC_ERROR = 20
HSM_ERROR_IS_ENCRYPT = 21
HSM_BAD_PASSWORD = 22


@unittest.skipIf(TEST_NETWORK != 'regtest', "Test relies on a number of example addresses valid only in regtest")
def test_withdraw(node_factory, bitcoind):
    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True, options={'log-level': 'io'})
    l2 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['bech32']

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

    # Reach around into the db to check that outputs were added
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 10

    waddr = l1.bitcoin.rpc.getnewaddress()
    # Now attempt to withdraw some (making sure we collect multiple inputs)

    # These violate schemas!
    l1.rpc.check_request_schemas = False
    with pytest.raises(RpcError):
        l1.rpc.withdraw('not an address', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, 'not an amount')
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, -amount)
    with pytest.raises(RpcError, match=r'Could not afford'):
        l1.rpc.withdraw(waddr, amount * 100)
    l1.rpc.check_request_schemas = True

    out = l1.rpc.withdraw(waddr, 2 * amount)

    # Side note: sendrawtransaction will trace back to withdrawl
    myname = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    l1.daemon.wait_for_log(r': "{}:withdraw#[0-9]*/cln:withdraw#[0-9]*/txprepare:sendpsbt#[0-9]*/cln:sendrawtransaction#[0-9]*"\[OUT\]'.format(myname))

    # Make sure bitcoind received the withdrawal
    unspent = l1.bitcoin.rpc.listunspent(0)
    withdrawal = [u for u in unspent if u['txid'] == out['txid']]

    assert(withdrawal[0]['amount'] == Decimal('0.02'))

    l1.bitcoin.generate_block(1)
    sync_blockheight(l1.bitcoin, [l1])

    # Check that there are no unconfirmed outputs (change should be confirmed)
    for o in l1.rpc.listfunds()['outputs']:
        assert o['status'] == 'confirmed'

    # Now make sure two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 2

    # Now send some money to l2.
    # lightningd uses P2SH-P2WPKH
    waddr = l2.rpc.newaddr('bech32')['bech32']
    l1.rpc.withdraw(waddr, 2 * amount)

    # Now make sure an additional two of them were marked as reserved
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 2
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=1')[0]['c'] == 2

    # They're turned into spent once the node sees them mined.
    bitcoind.generate_block(1)
    sync_blockheight(l1.bitcoin, [l1, l2])

    # Make sure l2 received the withdrawal.
    assert len(l2.rpc.listfunds()['outputs']) == 1
    outputs = l2.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 2 * amount

    # Now make sure an additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 4
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=1')[0]['c'] == 0

    # Simple test for withdrawal to P2WPKH
    # Address from: https://bc-2.jp/tools/bech32demo/index.html
    waddr = 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'
    with pytest.raises(RpcError):
        l1.rpc.withdraw('xx1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1pw508d6qejxtdg4y5r3zarvary0c5xw7kdl9fad', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxxxxxx', 2 * amount)
    l1.rpc.withdraw(waddr, 2 * amount)
    bitcoind.generate_block(1)
    sync_blockheight(l1.bitcoin, [l1])
    # Now make sure additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 6

    # Simple test for withdrawal to P2WSH
    # Address from: https://bc-2.jp/tools/bech32demo/index.html
    waddr = 'bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry'
    with pytest.raises(RpcError):
        l1.rpc.withdraw('xx1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1prp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsm03tq', 2 * amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qxxxxxx', 2 * amount)
    l1.rpc.withdraw(waddr, 2 * amount)
    bitcoind.generate_block(1)
    sync_blockheight(l1.bitcoin, [l1])
    # Now make sure additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 8

    # failure testing for invalid SegWit addresses, from BIP173
    # HRP character out of range
    with pytest.raises(RpcError):
        l1.rpc.withdraw(' 1nwldj5', 2 * amount)
    # overall max length exceeded
    with pytest.raises(RpcError):
        l1.rpc.withdraw('an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx', 2 * amount)
    # No separator character
    with pytest.raises(RpcError):
        l1.rpc.withdraw('pzry9x0s0muk', 2 * amount)
    # Empty HRP
    with pytest.raises(RpcError):
        l1.rpc.withdraw('1pzry9x0s0muk', 2 * amount)
    # Invalid witness version
    with pytest.raises(RpcError):
        l1.rpc.withdraw('BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2', 2 * amount)
    # Invalid program length for witness version 0 (per BIP141)
    with pytest.raises(RpcError):
        l1.rpc.withdraw('BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 2 * amount)
    # Mixed case
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7', 2 * amount)
    # Non-zero padding in 8-to-5 conversion
    with pytest.raises(RpcError):
        l1.rpc.withdraw('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv', 2 * amount)

    # Should have 6 outputs available.
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 6

    # Test withdrawal to self.
    l1.rpc.withdraw(l1.rpc.newaddr('bech32')['bech32'], 'all', minconf=0)
    bitcoind.generate_block(1)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 1

    l1.rpc.withdraw(waddr, 'all', minconf=0)
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 0

    # This should fail, can't even afford fee.
    with pytest.raises(RpcError, match=r'Could not afford'):
        l1.rpc.withdraw(waddr, 'all')

    # Add some funds to withdraw
    for i in range(12):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 12)

    # Try passing in a utxo set
    utxos = [utxo["txid"] + ":" + str(utxo["output"]) for utxo in l1.rpc.listfunds()["outputs"]][:4]

    withdrawal = l1.rpc.withdraw(waddr, 2 * amount, utxos=utxos)
    decode = bitcoind.rpc.decoderawtransaction(withdrawal['tx'])
    assert decode['txid'] == withdrawal['txid']

    # Check that correct utxos are included
    assert len(decode['vin']) == 4
    vins = ["{}:{}".format(v['txid'], v['vout']) for v in decode['vin']]
    for utxo in utxos:
        assert utxo in vins

    # Try passing unconfirmed utxos
    unconfirmed_utxos = [l1.rpc.withdraw(l1.rpc.newaddr()["bech32"], 10**5)
                         for _ in range(5)]
    uutxos = [u["txid"] + ":0" for u in unconfirmed_utxos]
    l1.rpc.withdraw(waddr, "all", minconf=0, utxos=uutxos)

    # Try passing minimum feerates (for relay)
    l1.rpc.withdraw(l1.rpc.newaddr()["bech32"], 10**5, feerate="253perkw")
    l1.rpc.withdraw(l1.rpc.newaddr()["bech32"], 10**5, feerate="1000perkb")


def test_minconf_withdraw(node_factory, bitcoind):
    """Issue 2518: ensure that ridiculous confirmation levels don't overflow

    The number of confirmations is used to compute a maximum height that is to
    be accepted. If the current height is smaller than the number of
    confirmations we wrap around and just select everything. The fix is to
    clamp the maxheight parameter to a positive small number.

    """
    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr()['bech32']

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)
    # This violates the request schema!
    l1.rpc.check_request_schemas = False

    with pytest.raises(RpcError):
        l1.rpc.withdraw(destination=addr, satoshi=10000, feerate='normal', minconf=9999999)


def test_addfunds_from_block(node_factory, bitcoind):
    """Send funds to the daemon without telling it explicitly
    """
    # Previous runs with same bitcoind can leave funds!
    coin_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1 = node_factory.get_node(random_hsm=True, options={'plugin': coin_plugin})

    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 0.1)
    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = l1.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 10000000

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr

    # Send all our money to a P2WPKH address this time.
    addr = l1.rpc.newaddr("bech32")['bech32']
    l1.rpc.withdraw(addr, "all")
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr

    # We don't print a 'external deposit' event
    # for funds that come back to our own wallet
    expected_utxos = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None)],
    }

    check_utxos_channel(l1, [], expected_utxos)


def test_txprepare_multi(node_factory, bitcoind):
    amount = 10000000
    l1 = node_factory.get_node(random_hsm=True)

    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'], amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = []
    for i in range(9):
        outputs.append({l1.rpc.newaddr()['bech32']: Millisatoshi(amount * 100)})
    prep = l1.rpc.txprepare(outputs=outputs)
    l1.rpc.txdiscard(prep['txid'])


def feerate_from_psbt(chainparams, bitcoind, node, psbt):
    # signpsbt insists they are reserved!
    node.rpc.reserveinputs(psbt, exclusive=False)
    final = node.rpc.dev_finalizepsbt(node.rpc.signpsbt(psbt)['signed_psbt'])
    node.rpc.unreserveinputs(psbt)
    if chainparams['elements']:
        # Already v1
        psbt = final['psbt']
    else:
        psbt = node.rpc.setpsbtversion(final['psbt'], 0)['psbt']
    # analyzepsbt gives a vsize, but not a weight!
    # e.g. 'estimated_vsize': 356, 'estimated_feerate': Decimal('0.00030042'), 'fee': Decimal('0.00010695')
    fee = int(bitcoind.rpc.analyzepsbt(psbt)['fee'] * 100_000_000)
    weight = bitcoind.rpc.decoderawtransaction(final['tx'])['weight']
    return fee / weight * 1000


def test_txprepare(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True, options={'dev-warn-on-overgrind': None},
                               broken_log='overgrind: short signature length')
    addr = chainparams['example_addr']

    # Add some funds to withdraw later
    for i in range(10):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)
    for est in l1.rpc.feerates('perkw')['perkw']['estimates']:
        if est['blockcount'] == 12:
            normal_feerate_perkw = est['feerate']

    prep = l1.rpc.txprepare(outputs=[{addr: Millisatoshi(amount * 3 * 1000)}])
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']
    # 4 inputs, 2 outputs (3 if we have a fee output).
    assert len(decode['vin']) == 4
    assert len(decode['vout']) == 2 if not chainparams['feeoutput'] else 3
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep['psbt']), normal_feerate_perkw)

    # One output will be correct.
    outnum = [i for i, o in enumerate(decode['vout']) if o['value'] == Decimal(amount * 3) / 10**8][0]

    for i, o in enumerate(decode['vout']):
        if i == outnum:
            assert o['scriptPubKey']['type'] == 'witness_v0_keyhash'
            assert scriptpubkey_addr(o['scriptPubKey']) == addr
        else:
            if chainparams['elements']:
                o['scriptPubKey']['type'] in ['witness_v0_keyhash', 'fee']
            else:
                assert o['scriptPubKey']['type'] in ['witness_v1_taproot', 'fee']

    # Now prepare one with no change.
    prep2 = l1.rpc.txprepare([{addr: 'all'}])
    decode = bitcoind.rpc.decoderawtransaction(prep2['unsigned_tx'])
    assert decode['txid'] == prep2['txid']
    # 6 inputs, 1 outputs.
    assert len(decode['vin']) == 6
    assert len(decode['vout']) == 1 if not chainparams['feeoutput'] else 2

    # Some fees will be paid.
    assert decode['vout'][0]['value'] < Decimal(amount * 6) / 10**8
    assert decode['vout'][0]['value'] > Decimal(amount * 6) / 10**8 - Decimal(0.0002)
    assert decode['vout'][0]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert scriptpubkey_addr(decode['vout'][0]['scriptPubKey']) == addr
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep2['psbt']), normal_feerate_perkw)

    # If I cancel the first one, I can get those first 4 outputs.
    discard = l1.rpc.txdiscard(prep['txid'])
    assert discard['txid'] == prep['txid']
    assert discard['unsigned_tx'] == prep['unsigned_tx']

    prep3 = l1.rpc.txprepare([{addr: 'all'}])
    decode = bitcoind.rpc.decoderawtransaction(prep3['unsigned_tx'])
    assert decode['txid'] == prep3['txid']
    # 4 inputs, 1 outputs.
    assert len(decode['vin']) == 4
    assert len(decode['vout']) == 1 if not chainparams['feeoutput'] else 2

    # Some fees will be taken
    assert decode['vout'][0]['value'] < Decimal(amount * 4) / 10**8
    assert decode['vout'][0]['value'] > Decimal(amount * 4) / 10**8 - Decimal(0.0002)
    assert decode['vout'][0]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert scriptpubkey_addr(decode['vout'][0]['scriptPubKey']) == addr
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep3['psbt']), normal_feerate_perkw)

    # Cannot discard twice.
    with pytest.raises(RpcError, match=r'not an unreleased txid'):
        l1.rpc.txdiscard(prep['txid'])

    # Discard everything, we should now spend all inputs.
    l1.rpc.txdiscard(prep2['txid'])
    l1.rpc.txdiscard(prep3['txid'])
    prep4 = l1.rpc.txprepare([{addr: 'all'}])
    decode = bitcoind.rpc.decoderawtransaction(prep4['unsigned_tx'])
    assert decode['txid'] == prep4['txid']
    # 10 inputs, 1 outputs.
    assert len(decode['vin']) == 10
    assert len(decode['vout']) == 1 if not chainparams['feeoutput'] else 2

    # Some fees will be taken
    assert decode['vout'][0]['value'] < Decimal(amount * 10) / 10**8
    assert decode['vout'][0]['value'] > Decimal(amount * 10) / 10**8 - Decimal(0.0003)
    assert decode['vout'][0]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert scriptpubkey_addr(decode['vout'][0]['scriptPubKey']) == addr
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep4['psbt']), normal_feerate_perkw)
    l1.rpc.txdiscard(prep4['txid'])

    # Try passing in a utxo set
    utxos = [utxo["txid"] + ":" + str(utxo["output"])
             for utxo in l1.rpc.listfunds()["outputs"]][:4]
    prep5 = l1.rpc.txprepare([{addr:
                             Millisatoshi(amount * 3.5 * 1000)}], utxos=utxos)
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep3['psbt']), normal_feerate_perkw)

    # Try passing unconfirmed utxos
    unconfirmed_utxo = l1.rpc.withdraw(l1.rpc.newaddr()["bech32"], 10**5)
    uutxos = [unconfirmed_utxo["txid"] + ":0"]
    with pytest.raises(RpcError, match=r"Could not afford"):
        l1.rpc.txprepare([{addr: Millisatoshi(amount * 3.5 * 1000)}],
                         utxos=uutxos)
    # Feerate should be ~ as we asked for
    unconfirmed_tx = bitcoind.rpc.getrawmempool(True)[unconfirmed_utxo["txid"]]
    feerate_perkw = int(unconfirmed_tx['fees']['base'] * 100_000_000) * 1000 / unconfirmed_tx['weight']
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_perkw, normal_feerate_perkw)

    decode = bitcoind.rpc.decoderawtransaction(prep5['unsigned_tx'])
    assert decode['txid'] == prep5['txid']

    # Check that correct utxos are included
    assert len(decode['vin']) == 4
    vins = ["{}:{}".format(v['txid'], v['vout']) for v in decode['vin']]
    for utxo in utxos:
        assert utxo in vins

    # We should have a change output, so this is exact
    assert len(decode['vout']) == 3 if chainparams['feeoutput'] else 2
    # Change output pos is random.
    for vout in decode['vout']:
        if vout['scriptPubKey']['type'] == 'fee':
            continue
        if scriptpubkey_addr(vout['scriptPubKey']) == addr:
            changeout = vout

    assert changeout['value'] == Decimal(amount * 3.5) / 10**8
    assert changeout['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert scriptpubkey_addr(changeout['scriptPubKey']) == addr

    # Discard prep4 and get all funds again
    l1.rpc.txdiscard(prep5['txid'])
    # You can have one which is all, but not two.
    prep5 = l1.rpc.txprepare([{addr: Millisatoshi(amount * 3 * 1000)},
                              {addr: 'all'}])
    # Feerate should be ~ as we asked for
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep5['psbt']), normal_feerate_perkw)
    l1.rpc.txdiscard(prep5['txid'])
    with pytest.raises(RpcError, match=r"'all'"):
        prep5 = l1.rpc.txprepare([{addr: 'all'}, {addr: 'all'}])

    prep5 = l1.rpc.txprepare([{addr: Millisatoshi(amount * 3 * 500 + 100000)},
                              {addr: Millisatoshi(amount * 3 * 500 - 100000)}])
    # Feerate should be ~ as we asked for
    if not chainparams['elements']:  # FIXME
        check_feerate([l1], feerate_from_psbt(chainparams, bitcoind, l1, prep5['psbt']), normal_feerate_perkw)
    decode = bitcoind.rpc.decoderawtransaction(prep5['unsigned_tx'])
    assert decode['txid'] == prep5['txid']
    # 4 inputs, 3 outputs(include change).
    assert len(decode['vin']) == 4
    assert len(decode['vout']) == 4 if chainparams['feeoutput'] else 3

    # One output will be correct.
    for i in range(3 + chainparams['feeoutput']):
        if decode['vout'][i - 1]['value'] == Decimal('0.01500100'):
            outnum1 = i - 1
        elif decode['vout'][i - 1]['value'] == Decimal('0.01499900'):
            outnum2 = i - 1
        else:
            changenum = i - 1

    assert decode['vout'][outnum1]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert scriptpubkey_addr(decode['vout'][outnum1]['scriptPubKey']) == addr

    assert decode['vout'][outnum2]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert scriptpubkey_addr(decode['vout'][outnum2]['scriptPubKey']) == addr

    if chainparams['elements']:
        assert decode['vout'][changenum]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    else:
        assert decode['vout'][changenum]['scriptPubKey']['type'] == 'witness_v1_taproot'

    l1.rpc.txdiscard(prep5['txid'])


def test_txprepare_feerate(node_factory, bitcoind, chainparams):
    # Make sure it works at different feerates!
    l1, l2 = node_factory.get_nodes(2, opts={'dev-warn-on-overgrind': None,
                                             'broken_log': 'overgrind: short signature length'})

    # Add some funds to withdraw later
    for i in range(20):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   1000 / 10**8)

    bitcoind.generate_block(1)
    out_addrs = l2.rpc.newaddr('all')
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 20)

    for addrtype in ('bech32', 'p2tr'):
        for feerate in range(255, 1000, 250):
            prep = l1.rpc.txprepare([{out_addrs[addrtype]: Millisatoshi(9000)}], f"{feerate}perkw")
            actual_feerate = feerate_from_psbt(chainparams, bitcoind, l1, prep['psbt'])
            assert feerate - 2 < actual_feerate
            # Feerate can be larger, if it chose not to give change output.
            if chainparams['elements']:
                fee_output = 1
            else:
                fee_output = 0
            if len(bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])['vout']) == 1 + 1 + fee_output and not did_short_sig(l1):
                assert actual_feerate < feerate + 2
            l1.rpc.txdiscard(prep['txid'])


@pytest.mark.parametrize("addrtype", ["bech32", "p2tr"])
@unittest.skipIf(TEST_NETWORK != 'regtest', "FIXME: Elements fees are not quite right")
def test_fundpsbt_feerates(node_factory, bitcoind, chainparams, addrtype):
    l1 = node_factory.get_node(options={'dev-warn-on-overgrind': None},
                               broken_log='overgrind: short signature length')

    # Add some funds to withdraw later
    for i in range(20):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr(addrtype)[addrtype],
                                   5000 / 10**8)

    # See utxo_spend_weight()
    if addrtype == 'bech32':
        witness_weight = 1 + 71 + 1 + 33
    elif addrtype == 'p2tr':
        witness_weight = 1 + 64
    else:
        assert False

    input_weight = 1 + witness_weight + (32 + 4 + 4 + 1) * 4
    if chainparams['elements']:
        input_weight += 6

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 20)

    # version, input count, output count, locktime, segwit marker, flag
    base_weight = (4 + 1 + 1 + 4) * 4 + 1 + 1
    if chainparams['elements']:
        # Elements has empty surjection and rangeproof
        base_weight += 2 * 4
        # And fee output (bitcoin_tx_output_weight(0)):
        base_weight += (8 + 1 + 0) * 4 + (32 + 1 + 1 + 1) * 4
        # Bech32 change output
        change_weight = (8 + 1 + (1 + 1 + 20)) * 4
    else:
        # P2TR output
        change_weight = (8 + 1 + (1 + 1 + 32)) * 4

    # Both minimal and higher feerate
    for feerate in (253, 1000):
        # Try with both 1 and 2 inputs
        for amount, num_inputs in ((260, 1), (5000, 2)):
            prep = l1.rpc.fundpsbt(amount, f"{feerate}perkw", base_weight, excess_as_change=True)
            assert prep['estimated_final_weight'] == base_weight + change_weight + input_weight * num_inputs
            signed = l1.rpc.signpsbt(prep['psbt'])['signed_psbt']
            sent = l1.rpc.sendpsbt(signed)
            txinfo = bitcoind.rpc.getmempoolentry(sent['txid'])
            if did_short_sig(l1):
                assert txinfo['weight'] <= prep['estimated_final_weight']
            else:
                assert txinfo['weight'] == prep['estimated_final_weight']
            # We never actually added that `amount` output to PSBT, so that appears as "fee"
            fee = int(txinfo['fees']['base'] * 100_000_000) - amount
            actual_feerate = fee / (txinfo['weight'] / 1000)
            check_feerate([l1], actual_feerate, feerate)


def test_reserveinputs(node_factory, bitcoind, chainparams):
    amount = 1000000
    total_outs = 12
    l1 = node_factory.get_node(feerates=(7500, 7500, 7500, 7500))

    outputs = []
    # Add a medley of funds to withdraw
    for i in range(total_outs):
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                          amount / 10**8)
        outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    assert not any(o['reserved'] for o in l1.rpc.listfunds()['outputs'])

    # Try reserving one at a time.
    for out in outputs:
        psbt = bitcoind.rpc.createpsbt([{'txid': out[0], 'vout': out[1]}], [])
        l1.rpc.reserveinputs(psbt)

    assert all(o['reserved'] for o in l1.rpc.listfunds()['outputs'])
    reserveheight = bitcoind.rpc.getblockchaininfo()['blocks'] + 72
    assert all(o['reserved_to_block'] == reserveheight for o in l1.rpc.listfunds()['outputs'])

    # Unreserve as a batch.
    psbt = bitcoind.rpc.createpsbt([{'txid': out[0], 'vout': out[1]} for out in outputs], [])
    l1.rpc.unreserveinputs(psbt)
    assert not any(o['reserved'] for o in l1.rpc.listfunds()['outputs'])
    assert not any('reserved_to_block' in o for o in l1.rpc.listfunds()['outputs'])

    # Reserve twice fails unless exclusive.
    l1.rpc.reserveinputs(psbt)
    with pytest.raises(RpcError, match=r"already reserved"):
        l1.rpc.reserveinputs(psbt)
    l1.rpc.reserveinputs(psbt, False)
    assert all(o['reserved_to_block'] == reserveheight + 72 for o in l1.rpc.listfunds()['outputs'])
    l1.rpc.unreserveinputs(psbt)
    assert all(o['reserved'] for o in l1.rpc.listfunds()['outputs'])
    assert all(o['reserved_to_block'] == reserveheight for o in l1.rpc.listfunds()['outputs'])

    # Stays reserved across restarts.
    l1.restart()
    assert all(o['reserved'] for o in l1.rpc.listfunds()['outputs'])
    assert all(o['reserved_to_block'] == reserveheight for o in l1.rpc.listfunds()['outputs'])

    # Final unreserve works.
    l1.rpc.unreserveinputs(psbt)
    assert not any(o['reserved'] for o in l1.rpc.listfunds()['outputs'])
    assert not any('reserved_to_block' in o for o in l1.rpc.listfunds()['outputs'])


def test_fundpsbt(node_factory, bitcoind, chainparams):
    amount = 1000000
    total_outs = 4
    l1 = node_factory.get_node()

    # CLN returns PSBTv0 and PSETv2, for now
    is_psbt_v2 = chainparams['elements']

    outputs = []
    # Add a medley of funds to withdraw later
    for i in range(total_outs):
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                          amount / 10**8)
        outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    feerate = '7500perkw'

    # Should get one input, plus some excess
    funding = l1.rpc.fundpsbt(amount // 2, feerate, 0, reserve=0)

    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    # We can fuzz this up to 99 blocks back.
    assert funding['excess_msat'] > Millisatoshi(0)
    assert funding['excess_msat'] < Millisatoshi(amount // 2 * 1000)
    assert funding['feerate_per_kw'] == 7500
    assert 'estimated_final_weight' in funding
    assert 'reservations' not in funding

    if is_psbt_v2:
        assert psbt['fallback_locktime'] > bitcoind.rpc.getblockcount() - 100
        assert psbt['fallback_locktime'] <= bitcoind.rpc.getblockcount()
        assert psbt['input_count'] == 1
    else:
        assert psbt['tx']['locktime'] > bitcoind.rpc.getblockcount() - 100
        assert psbt['tx']['locktime'] <= bitcoind.rpc.getblockcount()
        assert len(psbt['tx']['vin']) == 1

    # This should add 99 to the weight, but otherwise be identical (might choose different inputs though!) except for locktime.
    funding2 = l1.rpc.fundpsbt(amount // 2, feerate, 99, reserve=0, locktime=bitcoind.rpc.getblockcount() + 1)
    psbt2 = bitcoind.rpc.decodepsbt(funding2['psbt'])

    if is_psbt_v2:
        assert psbt2['fallback_locktime'] == bitcoind.rpc.getblockcount() + 1
        assert psbt2['input_count'] == 1
    else:
        assert psbt2['tx']['locktime'] == bitcoind.rpc.getblockcount() + 1
        assert len(psbt2['tx']['vin']) == 1

    assert funding2['excess_msat'] < funding['excess_msat']
    assert funding2['feerate_per_kw'] == 7500
    # Naively you'd expect this to be +99, but it might have selected a non-p2sh output...
    assert funding2['estimated_final_weight'] > funding['estimated_final_weight']

    # Cannot afford this one (too much)
    with pytest.raises(RpcError, match=r"not afford"):
        l1.rpc.fundpsbt(amount * total_outs, feerate, 0)

    # Nor this (depth insufficient)
    with pytest.raises(RpcError, match=r"not afford"):
        l1.rpc.fundpsbt(amount // 2, feerate, 0, minconf=2)

    funding3 = l1.rpc.fundpsbt(amount // 2, feerate, 0, reserve=0, excess_as_change=True)
    assert funding3['excess_msat'] == Millisatoshi(0)
    # Should have the excess msat as the output value (minus fee for change)
    psbt = bitcoind.rpc.decodepsbt(funding3['psbt'])

    if is_psbt_v2:
        change = Millisatoshi("{}btc".format(psbt["outputs"][funding3['change_outnum']]["amount"]))
    else:
        change = Millisatoshi("{}btc".format(psbt['tx']['vout'][funding3['change_outnum']]['value']))

    # The weight should be greater (now includes change output)
    change_weight = funding3['estimated_final_weight'] - funding['estimated_final_weight']
    assert change_weight > 0
    # Check that the amount is ok (equal to excess minus change fee)
    change_fee = Millisatoshi(7500 * change_weight)
    assert funding['excess_msat'] == change + change_fee

    # Should get two inputs.
    psbt = bitcoind.rpc.decodepsbt(l1.rpc.fundpsbt(amount, feerate, 0, reserve=0)['psbt'])
    if is_psbt_v2:
        assert psbt['input_count'] == 2
    else:
        assert len(psbt['tx']['vin']) == 2

    # Should not use reserved outputs.
    psbt = bitcoind.rpc.createpsbt([{'txid': out[0], 'vout': out[1]} for out in outputs], [])
    l1.rpc.reserveinputs(psbt)
    with pytest.raises(RpcError, match=r"not afford"):
        l1.rpc.fundpsbt(amount // 2, feerate, 0)

    # Will use first one if unreserved.
    l1.rpc.unreserveinputs(bitcoind.rpc.createpsbt([{'txid': outputs[0][0], 'vout': outputs[0][1]}], []))
    psbt = l1.rpc.fundpsbt(amount // 2, feerate, 0)['psbt']

    # Should have passed to reserveinputs.
    with pytest.raises(RpcError, match=r"already reserved"):
        l1.rpc.reserveinputs(psbt)

    # And now we can't afford any more.
    with pytest.raises(RpcError, match=r"not afford"):
        l1.rpc.fundpsbt(amount // 2, feerate, 0)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_addpsbtoutput(node_factory, bitcoind, chainparams):
    amount1 = 1000000
    amount2 = 3333333
    locktime = 111
    l1 = node_factory.get_node()

    result = l1.rpc.addpsbtoutput(amount1, locktime=locktime)
    assert result['outnum'] == 0

    psbt_info = bitcoind.rpc.decodepsbt(l1.rpc.setpsbtversion(result['psbt'], 0)['psbt'])

    assert len(psbt_info['tx']['vout']) == 1
    assert psbt_info['tx']['vout'][0]['n'] == result['outnum']
    assert psbt_info['tx']['vout'][0]['value'] * 100000000 == amount1
    assert psbt_info['tx']['locktime'] == locktime

    result = l1.rpc.addpsbtoutput(amount2, result['psbt'])
    n = result['outnum']

    psbt_info = bitcoind.rpc.decodepsbt(l1.rpc.setpsbtversion(result['psbt'], 0)['psbt'])

    assert len(psbt_info['tx']['vout']) == 2
    assert psbt_info['tx']['vout'][n]['value'] * 100000000 == amount2
    assert psbt_info['tx']['vout'][n]['n'] == result['outnum']

    dest = l1.rpc.newaddr('p2tr')['p2tr']
    result = l1.rpc.addpsbtoutput(amount2, result['psbt'], destination=dest)
    n = result['outnum']

    psbt_info = bitcoind.rpc.decodepsbt(l1.rpc.setpsbtversion(result['psbt'], 0)['psbt'])

    assert len(psbt_info['tx']['vout']) == 3
    assert psbt_info['tx']['vout'][n]['value'] * 100000000 == amount2
    assert psbt_info['tx']['vout'][n]['n'] == result['outnum']
    assert psbt_info['tx']['vout'][n]['scriptPubKey']['address'] == dest


def test_utxopsbt(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node()

    # CLN returns PSBTv0 and PSETv2, for now
    is_psbt_v2 = chainparams['elements']

    outputs = []
    # Add a funds to withdraw later
    for _ in range(2):
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                          amount / 10**8)
        outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == len(outputs))

    fee_val = 7500
    feerate = '{}perkw'.format(fee_val)

    # Explicitly spend the first output above.
    funding = l1.rpc.utxopsbt(amount // 2, feerate, 0,
                              ['{}:{}'.format(outputs[0][0], outputs[0][1])],
                              reserve=0)
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    # We can fuzz this up to 99 blocks back.
    assert funding['excess_msat'] > Millisatoshi(0)
    assert funding['excess_msat'] < Millisatoshi(amount // 2 * 1000)
    assert funding['feerate_per_kw'] == 7500
    assert 'estimated_final_weight' in funding
    assert 'reservations' not in funding

    if is_psbt_v2:
        assert psbt['fallback_locktime'] > bitcoind.rpc.getblockcount() - 100
        assert psbt['fallback_locktime'] <= bitcoind.rpc.getblockcount()
        assert psbt['input_count'] == 1
    else:
        assert psbt['tx']['locktime'] > bitcoind.rpc.getblockcount() - 100
        assert psbt['tx']['locktime'] <= bitcoind.rpc.getblockcount()
        assert len(psbt['tx']['vin']) == 1

    # This should add 99 to the weight, but otherwise be identical except for locktime.
    start_weight = 99
    funding2 = l1.rpc.utxopsbt(amount // 2, feerate, start_weight,
                               ['{}:{}'.format(outputs[0][0], outputs[0][1])],
                               reserve=0, locktime=bitcoind.rpc.getblockcount() + 1)
    psbt2 = bitcoind.rpc.decodepsbt(funding2['psbt'])

    if is_psbt_v2:
        assert psbt2['fallback_locktime'] == bitcoind.rpc.getblockcount() + 1
        assert psbt2['inputs'] == psbt['inputs']
    else:
        assert psbt2['tx']['locktime'] == bitcoind.rpc.getblockcount() + 1
        assert psbt2['tx']['vin'] == psbt['tx']['vin']

    if chainparams['elements']:
        assert is_psbt_v2
        # elements includes the fee as an output
        addl_fee = Millisatoshi((fee_val * start_weight + 999) // 1000 * 1000)
        assert psbt2['outputs'][0]['amount'] == psbt['outputs'][0]['amount'] + addl_fee.to_btc()
    else:
        assert psbt2['tx']['vout'] == psbt['tx']['vout']
    assert funding2['excess_msat'] < funding['excess_msat']
    assert funding2['feerate_per_kw'] == 7500
    assert funding2['estimated_final_weight'] == funding['estimated_final_weight'] + 99
    assert 'reservations' not in funding2

    # Cannot afford this one (too much)
    with pytest.raises(RpcError, match=r"not afford"):
        l1.rpc.utxopsbt(amount, feerate, 0,
                        ['{}:{}'.format(outputs[0][0], outputs[0][1])])

    # Nor this (even with both)
    with pytest.raises(RpcError, match=r"not afford"):
        l1.rpc.utxopsbt(amount * 2, feerate, 0,
                        ['{}:{}'.format(outputs[0][0], outputs[0][1]),
                         '{}:{}'.format(outputs[1][0], outputs[1][1])])

    funding3 = l1.rpc.utxopsbt(amount // 2, feerate, 0,
                               ['{}:{}'.format(outputs[0][0], outputs[0][1])],
                               reserve=0,
                               excess_as_change=True)
    assert funding3['excess_msat'] == Millisatoshi(0)
    # Should have the excess msat as the output value (minus fee for change)
    psbt = bitcoind.rpc.decodepsbt(funding3['psbt'])
    if is_psbt_v2:
        change = Millisatoshi("{}btc".format(psbt['outputs'][funding3['change_outnum']]['amount']))
    else:
        change = Millisatoshi("{}btc".format(psbt['tx']['vout'][funding3['change_outnum']]['value']))

    # The weight should be greater (now includes change output)
    change_weight = funding3['estimated_final_weight'] - funding['estimated_final_weight']
    assert change_weight > 0
    # Check that the amount is ok (equal to excess minus change fee)
    change_fee = Millisatoshi(fee_val * change_weight // 1000 * 1000)
    assert funding['excess_msat'] == change + change_fee

    # Do it again, but without enough for change!
    funding4 = l1.rpc.utxopsbt(amount - 3500,
                               feerate, 0,
                               ['{}:{}'.format(outputs[0][0], outputs[0][1])],
                               reserve=0,
                               excess_as_change=True)
    assert 'change_outnum' not in funding4

    # Should get two inputs (and reserve!)
    funding = l1.rpc.utxopsbt(amount, feerate, 0,
                              ['{}:{}'.format(outputs[0][0], outputs[0][1]),
                               '{}:{}'.format(outputs[1][0], outputs[1][1])])
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    if is_psbt_v2:
        assert psbt['input_count'] == 2
    else:
        assert len(psbt['tx']['vin']) == 2
    assert len(funding['reservations']) == 2
    assert funding['reservations'][0]['txid'] == outputs[0][0]
    assert funding['reservations'][0]['vout'] == outputs[0][1]
    assert funding['reservations'][0]['was_reserved'] is False
    assert funding['reservations'][0]['reserved'] is True
    assert funding['reservations'][1]['txid'] == outputs[1][0]
    assert funding['reservations'][1]['vout'] == outputs[1][1]
    assert funding['reservations'][1]['was_reserved'] is False
    assert funding['reservations'][1]['reserved'] is True

    # Should refuse to use reserved outputs.
    with pytest.raises(RpcError, match=r"already reserved"):
        l1.rpc.utxopsbt(amount, feerate, 0,
                        ['{}:{}'.format(outputs[0][0], outputs[0][1]),
                         '{}:{}'.format(outputs[1][0], outputs[1][1])])

    # Unless we tell it that's ok.
    l1.rpc.utxopsbt(amount, feerate, 0,
                    ['{}:{}'.format(outputs[0][0], outputs[0][1]),
                     '{}:{}'.format(outputs[1][0], outputs[1][1])],
                    reservedok=True)


def test_sign_external_psbt(node_factory, bitcoind, chainparams):
    """
    A PSBT w/ one of our inputs should be signable (we can fill
    in the required UTXO data).
    """
    l1 = node_factory.get_node(feerates=(7500, 7500, 7500, 7500))
    amount = 1000000
    total_outs = 4

    # Add a medley of funds to withdraw later
    for i in range(total_outs):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    # Build a PSBT using all our inputs, externally
    inputs = []
    for inp in l1.rpc.listfunds()['outputs']:
        inputs.append({'txid': inp['txid'], 'vout': inp['output']})
    addr = l1.rpc.newaddr()['bech32']
    psbt = bitcoind.rpc.createpsbt(inputs, [{addr: (amount * 3) / 10**8}])

    l1.rpc.reserveinputs(psbt)
    l1.rpc.signpsbt(psbt)


def test_psbt_version(node_factory, bitcoind, chainparams):

    sats_amount = 10**8

    # CLN returns PSBTv0 and PSETv2, for now
    is_elements = chainparams['elements']

    l1 = node_factory.get_node()
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                               sats_amount / 100000000)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    funding = l1.rpc.fundpsbt(satoshi=int(sats_amount / 2),
                              feerate=7500,
                              startweight=42)['psbt']

    # Short elements test
    if is_elements:
        # Only v2 is allowed, and is a no-op
        for i in [0, 1, 3, 4, 5]:
            with pytest.raises(RpcError, match=r"Could not set PSBT version"):
                l1.rpc.setpsbtversion(funding, i)
        assert funding == l1.rpc.setpsbtversion(funding, 2)['psbt']
        # And elementsd can understand it
        bitcoind.rpc.decodepsbt(funding)
        return

    # Non-elements test
    v2_funding = l1.rpc.setpsbtversion(funding, 2)['psbt']

    # Bitcoind cannot understand PSBTv2 yet
    with pytest.raises(JSONRPCError, match=r"TX decode failed Unsupported version number"):
        bitcoind.rpc.decodepsbt(v2_funding)

    # But it round-trips fine enough
    v0_funding = l1.rpc.setpsbtversion(v2_funding, 0)['psbt']

    # CLN returns v0 for now
    assert funding == v0_funding

    # And we reject non-0/2 args
    for i in [1, 3, 4, 5]:
        with pytest.raises(RpcError, match=r"Could not set PSBT version"):
            l1.rpc.setpsbtversion(v2_funding, i)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', 'Core/Elements need joinpsbt support for v2')
def test_sign_and_send_psbt(node_factory, bitcoind, chainparams):
    """
    Tests for the sign + send psbt RPCs
    """
    # CLN returns PSBTv0 and PSETv2, for now
    is_psbt_v2 = chainparams['elements']

    # Once support for v2 joinpsbt is added, below test should work verbatim
    assert not is_psbt_v2

    amount = 1000000
    total_outs = 12
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1 = node_factory.get_node(options={'plugin': coin_mvt_plugin},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()
    addr = chainparams['example_addr']
    out_total = Millisatoshi(amount * 3 * 1000)

    # Add a medley of funds to withdraw later
    for i in range(total_outs):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    # Make a PSBT out of our inputs
    funding = l1.rpc.fundpsbt(satoshi=out_total,
                              feerate=7500,
                              startweight=42)
    assert len([x for x in l1.rpc.listfunds()['outputs'] if x['reserved']]) == 4
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    if is_psbt_v2:
        saved_input = psbt['inputs'][0]
    else:
        saved_input = psbt['tx']['vin'][0]

    # Go ahead and unreserve the UTXOs, we'll use a smaller
    # set of them to create a second PSBT that we'll attempt to sign
    # and broadcast (to disastrous results)
    l1.rpc.unreserveinputs(funding['psbt'])

    # Re-reserve one of the utxos we just unreserved
    if is_psbt_v2:
        psbt = bitcoind.rpc.createpsbt([{'txid': saved_input['previous_txid'],
                                         'vout': saved_input['previous_vout']}], [])
    else:
        psbt = bitcoind.rpc.createpsbt([{'txid': saved_input['txid'],
                                         'vout': saved_input['vout']}], [])

    l1.rpc.reserveinputs(psbt)

    # We require the utxos be reserved before signing them
    with pytest.raises(RpcError, match=r"Aborting PSBT signing. UTXO .* is not reserved"):
        l1.rpc.signpsbt(funding['psbt'])['signed_psbt']

    # Now we unreserve the singleton, so we can reserve it again
    l1.rpc.unreserveinputs(psbt)

    # Now add an output. Note, we add the 'excess msat' to the output so
    # that our feerate is 'correct'. This is of particular importance to elementsd,
    # who requires that every satoshi be accounted for in a tx.
    out_1_ms = Millisatoshi(funding['excess_msat'])
    output_psbt = bitcoind.rpc.createpsbt([],
                                          [{addr: float((out_total + out_1_ms).to_btc())}])
    fullpsbt = bitcoind.rpc.joinpsbts([funding['psbt'], output_psbt])

    # We re-reserve the first set...
    l1.rpc.reserveinputs(fullpsbt)

    # Sign + send the PSBT we've created
    signed_psbt = l1.rpc.signpsbt(fullpsbt)['signed_psbt']
    broadcast_tx = l1.rpc.sendpsbt(signed_psbt)

    # Check that it was broadcast successfully
    l1.daemon.wait_for_log(r'sendrawtx exit 0 .* sendrawtransaction {}'.format(broadcast_tx['tx']))
    bitcoind.generate_block(1)

    # We didn't add a change output.
    expected_outs = total_outs - 4
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == expected_outs)

    # Let's try *sending* a PSBT that can't be finalized (it's unsigned)
    with pytest.raises(RpcError, match=r"PSBT not finalizeable"):
        l1.rpc.sendpsbt(fullpsbt)

    # Now we try signing a PSBT with an output that's already been spent
    with pytest.raises(RpcError, match=r"Aborting PSBT signing. UTXO .* is not reserved"):
        l1.rpc.signpsbt(fullpsbt)

    # Queue up another node, to make some PSBTs for us
    for i in range(total_outs):
        bitcoind.rpc.sendtoaddress(l2.rpc.newaddr()['bech32'],
                                   amount / 10**8)
    # Create a PSBT using L2
    bitcoind.generate_block(1)
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == total_outs)
    l2_funding = l2.rpc.fundpsbt(satoshi=out_total,
                                 feerate=7500,
                                 startweight=42)

    # Try to get L1 to sign it
    with pytest.raises(RpcError, match=r"No wallet inputs to sign"):
        l1.rpc.signpsbt(l2_funding['psbt'])

    # With signonly it will fail if it can't sign it.
    with pytest.raises(RpcError, match=r"is unknown"):
        l1.rpc.signpsbt(l2_funding['psbt'], signonly=[0])

    # Add some of our own PSBT inputs to it
    l1_funding = l1.rpc.fundpsbt(satoshi=out_total,
                                 feerate=7500,
                                 startweight=42)
    if is_psbt_v2:
        l1_num_inputs = bitcoind.rpc.decodepsbt(l1_funding['psbt'])["input_count"]
        l2_num_inputs = bitcoind.rpc.decodepsbt(l2_funding['psbt'])["input_count"]
    else:
        l1_num_inputs = len(bitcoind.rpc.decodepsbt(l1_funding['psbt'])['tx']['vin'])
        l2_num_inputs = len(bitcoind.rpc.decodepsbt(l2_funding['psbt'])['tx']['vin'])

    # Join and add an output (reorders!)
    out_2_ms = Millisatoshi(l1_funding['excess_msat'])
    out_amt = out_2_ms + Millisatoshi(l2_funding['excess_msat']) + out_total + out_total
    output_psbt = bitcoind.rpc.createpsbt([],
                                          [{addr: float(out_amt.to_btc())}])
    joint_psbt = bitcoind.rpc.joinpsbts([l1_funding['psbt'], l2_funding['psbt'],
                                         output_psbt])

    # Ask it to sign inputs it doesn't know, it will fail.
    with pytest.raises(RpcError, match=r"is unknown"):
        l1.rpc.signpsbt(joint_psbt,
                        signonly=list(range(l1_num_inputs + 1)))

    # Similarly, it can't sign inputs it doesn't know.
    sign_success = []
    for i in range(l1_num_inputs + l2_num_inputs):
        try:
            l1.rpc.signpsbt(joint_psbt, signonly=[i])
        except RpcError:
            continue
        sign_success.append(i)
    assert len(sign_success) == l1_num_inputs

    # But it can sign all the valid ones at once.
    half_signed_psbt = l1.rpc.signpsbt(joint_psbt, signonly=sign_success)['signed_psbt']
    for s in sign_success:
        assert bitcoind.rpc.decodepsbt(half_signed_psbt)['inputs'][s]['partial_signatures'] is not None

    totally_signed = l2.rpc.signpsbt(half_signed_psbt)['signed_psbt']

    broadcast_tx = l1.rpc.sendpsbt(totally_signed)
    l1.daemon.wait_for_log(r'sendrawtx exit 0 .* sendrawtransaction {}'.format(broadcast_tx['tx']))

    # Send a PSBT that's not ours
    l2_funding = l2.rpc.fundpsbt(satoshi=out_total,
                                 feerate=7500,
                                 startweight=42)
    out_amt = Millisatoshi(l2_funding['excess_msat'])
    output_psbt = bitcoind.rpc.createpsbt([],
                                          [{addr: float((out_total + out_amt).to_btc())}])
    psbt = bitcoind.rpc.joinpsbts([l2_funding['psbt'], output_psbt])
    l2_signed_psbt = l2.rpc.signpsbt(psbt)['signed_psbt']
    l1.rpc.sendpsbt(l2_signed_psbt)

    # Re-try sending the same tx?
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    # Expect an error here (bitcoind > 28 gives the UTXO set message)
    with pytest.raises(JSONRPCError, match=r"Transaction already in block chain|Transaction outputs already in utxo set"):
        bitcoind.rpc.sendrawtransaction(broadcast_tx['tx'])

    # Try an empty PSBT
    with pytest.raises(RpcError, match=r"psbt: Expected a PSBT: invalid token"):
        l1.rpc.signpsbt('')
    with pytest.raises(RpcError, match=r"psbt: Expected a PSBT: invalid token"):
        l1.rpc.sendpsbt('')

    # Try an invalid PSBT string
    invalid_psbt = 'cHNidP8BAM0CAAAABJ9446mTRp/ml8OxSLC1hEvrcxG1L02AG7YZ4syHon2sAQAAAAD9////JFJH/NjKwjwrP9myuU68G7t8Q4VIChH0KUkZ5hSAyqcAAAAAAP3///8Uhrj0XDRhGRno8V7qEe4hHvZcmEjt3LQSIXWc+QU2tAEAAAAA/f///wstLikuBrgZJI83VPaY8aM7aPe5U6TMb06+jvGYzQLEAQAAAAD9////AcDGLQAAAAAAFgAUyQltQ/QI6lJgICYsza18hRa5KoEAAAAAAAEBH0BCDwAAAAAAFgAUqc1Qh7Q5kY1noDksmj7cJmHaIbQAAQEfQEIPAAAAAAAWABS3bdYeQbXvBSryHNoyYIiMBwu5rwABASBAQg8AAAAAABepFD1r0NuqAA+R7zDiXrlP7J+/PcNZhwEEFgAUKvGgVL/ThjWE/P1oORVXh/ObucYAAQEgQEIPAAAAAAAXqRRsrE5ugA1VJnAith5+msRMUTwl8ocBBBYAFMrfGCiLi0ZnOCY83ERKJ1sLYMY8A='
    with pytest.raises(RpcError, match=r"psbt: Expected a PSBT: invalid token"):
        l1.rpc.signpsbt(invalid_psbt)

    wallet_coin_mvts = [
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 1000000000, 'debit_msat': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit_msat': 0, 'debit_msat': 1000000000, 'tags': ['withdrawal']},
    ]

    check_coin_moves(l1, 'wallet', wallet_coin_mvts, chainparams)


def test_txsend(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True)
    addr = chainparams['example_addr']

    # Add some funds to withdraw later
    for i in range(10):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

    prep = l1.rpc.txprepare([{addr: Millisatoshi(amount * 3 * 1000)}])
    out = l1.rpc.txsend(prep['txid'])

    # Cannot discard after send!
    with pytest.raises(RpcError, match=r'not an unreleased txid'):
        l1.rpc.txdiscard(prep['txid'])

    wait_for(lambda: prep['txid'] in bitcoind.rpc.getrawmempool())

    # Signed tx should have same txid
    decode = bitcoind.rpc.decoderawtransaction(out['tx'])
    assert decode['txid'] == prep['txid']

    bitcoind.generate_block(1)

    # Change output should appear.
    if decode['vout'][0]['value'] == Decimal(amount * 3) / 10**8:
        changenum = 1
    elif decode['vout'][1]['value'] == Decimal(amount * 3) / 10**8:
        changenum = 0
    else:
        assert False

    # Those spent outputs are gone, but change output has arrived.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10 - len(decode['vin']) + 1)

    # Change address should appear in listfunds()
    assert scriptpubkey_addr(decode['vout'][changenum]['scriptPubKey']) in [f['address'] for f in l1.rpc.listfunds()['outputs']]


def write_all(fd, bytestr):
    """Wrapper, since os.write can do partial writes"""
    off = 0
    while off < len(bytestr):
        off += os.write(fd, bytestr[off:])


@unittest.skipIf(VALGRIND, "It does not play well with prompt and key derivation.")
def test_hsm_secret_encryption(node_factory):
    l1 = node_factory.get_node(may_fail=True)  # May fail when started without key
    password = "reckful&é🍕\n"
    # We need to simulate a terminal to use termios in `lightningd`.
    master_fd, slave_fd = os.openpty()

    # Test we can encrypt an already-existing and not encrypted hsm_secret
    l1.stop()
    l1.daemon.opts.update({"encrypted-hsm": None})
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=False)
    l1.daemon.wait_for_log(r'Enter hsm_secret password')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log(r'Confirm hsm_secret password')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log("Server started with public key")
    id = l1.rpc.getinfo()["id"]
    l1.stop()

    # Test we cannot start the same wallet without specifying --encrypted-hsm
    l1.daemon.opts.pop("encrypted-hsm")
    with pytest.raises(subprocess.CalledProcessError, match=r'returned non-zero exit status {}'.format(HSM_ERROR_IS_ENCRYPT)):
        subprocess.check_call(l1.daemon.cmd_line)

    # Test we cannot restore the same wallet with another password
    l1.daemon.opts.update({"encrypted-hsm": None})
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=False, stderr_redir=True)
    l1.daemon.wait_for_log(r'Enter hsm_secret password')
    write_all(master_fd, password[2:].encode("utf-8"))
    assert(l1.daemon.proc.wait(WAIT_TIMEOUT) == HSM_BAD_PASSWORD)
    assert(l1.daemon.is_in_stderr("Wrong password for encrypted hsm_secret."))

    # Not sure why this helps, but seems to reduce flakiness where
    # tail() thread in testing/utils.py gets 'ValueError: readline of
    # closed file' and we get `ValueError: Process died while waiting for logs`
    # when waiting for "Server started with public key" below.
    time.sleep(10)

    # Test we can restore the same wallet with the same password
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=False)
    l1.daemon.wait_for_log(r'The hsm_secret is encrypted')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log("Server started with public key")
    assert id == l1.rpc.getinfo()["id"]
    l1.stop()

    # We can restore the same wallet with the same password provided through stdin
    l1.daemon.start(stdin=subprocess.PIPE, wait_for_initialized=False)
    l1.daemon.proc.stdin.write(password.encode("utf-8"))
    l1.daemon.proc.stdin.flush()
    l1.daemon.wait_for_log("Server started with public key")
    assert id == l1.rpc.getinfo()["id"]


class HsmTool(TailableProc):
    """Helper for testing the hsmtool as a subprocess"""
    def __init__(self, directory, *args):
        self.prefix = "hsmtool"
        TailableProc.__init__(self, os.path.join(directory, "hsmtool"))
        assert hasattr(self, "env")
        self.cmd_line = ["tools/hsmtool", *args]


@unittest.skipIf(VALGRIND, "It does not play well with prompt and key derivation.")
def test_hsmtool_secret_decryption(node_factory):
    l1 = node_factory.get_node()
    password = "reckless123#{ù}\n"
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    # We need to simulate a terminal to use termios in `lightningd`.
    master_fd, slave_fd = os.openpty()

    # Encrypt the master seed
    l1.stop()
    l1.daemon.opts.update({"encrypted-hsm": None})
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=False)
    l1.daemon.wait_for_log(r'Enter hsm_secret password')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log(r'Confirm hsm_secret password')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log("Server started with public key")
    node_id = l1.rpc.getinfo()["id"]
    l1.stop()

    # We can't use a wrong password !
    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool(node_factory.directory, "decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, "A wrong pass\n\n".encode("utf-8"))
    hsmtool.proc.wait(WAIT_TIMEOUT)
    hsmtool.is_in_log(r"Wrong password")

    # Decrypt it with hsmtool
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Then test we can now start it without password
    l1.daemon.opts.pop("encrypted-hsm")
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=True)
    assert node_id == l1.rpc.getinfo()["id"]
    l1.stop()

    # Test we can encrypt it offline
    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool(node_factory.directory, "encrypt", hsm_path)
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    hsmtool.wait_for_log(r"Confirm hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    # Now we need to pass the encrypted-hsm startup option
    l1.stop()
    with pytest.raises(subprocess.CalledProcessError, match=r'returned non-zero exit status {}'.format(HSM_ERROR_IS_ENCRYPT)):
        subprocess.check_call(l1.daemon.cmd_line)

    l1.daemon.opts.update({"encrypted-hsm": None})
    master_fd, slave_fd = os.openpty()
    l1.daemon.start(stdin=slave_fd,
                    wait_for_initialized=False)

    l1.daemon.wait_for_log(r'The hsm_secret is encrypted')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log("Server started with public key")
    print(node_id, l1.rpc.getinfo()["id"])
    assert node_id == l1.rpc.getinfo()["id"]
    l1.stop()

    # And finally test that we can also decrypt if encrypted with hsmtool
    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool(node_factory.directory, "decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    l1.daemon.opts.pop("encrypted-hsm")
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=True)
    assert node_id == l1.rpc.getinfo()["id"]

    # We can roundtrip encryption and decryption using a password provided
    # through stdin.
    hsmtool = HsmTool(node_factory.directory, "encrypt", hsm_path)
    hsmtool.start(stdin=subprocess.PIPE)
    hsmtool.proc.stdin.write(password.encode("utf-8"))
    hsmtool.proc.stdin.write(password.encode("utf-8"))
    hsmtool.proc.stdin.flush()
    hsmtool.wait_for_log("Successfully encrypted")
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool(node_factory.directory, "decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log("Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    hsmtool.wait_for_log("Successfully decrypted")
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', '')
def test_hsmtool_dump_descriptors(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l1.fundwallet(10**6)
    # Get a tpub descriptor of lightningd's wallet
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    cmd_line = ["tools/hsmtool", "dumponchaindescriptors", hsm_path, "testnet"]
    descriptors = subprocess.check_output(cmd_line).decode("utf8").split("\n")

    # Deprecated or empty line
    descriptors = [desc for desc in descriptors if not (desc.startswith("sh(wpkh(") or desc == '')]

    withdraw_addr = None
    index_offset = 2  # index starts handing out addrs at 2

    # Generate twenty addresses for all known descriptors
    cln_addrs = [l1.rpc.newaddr('all') for _ in range(20)]
    for descriptor in descriptors:
        for i, cln_addr in enumerate(cln_addrs):
            computed_addr = bitcoind.rpc.deriveaddresses(descriptor, [i + index_offset, i + index_offset])[0]
            if descriptor.startswith("wpkh"):
                assert cln_addr["bech32"] == computed_addr
                withdraw_addr = cln_addr["bech32"]
            elif descriptor.startswith("tr"):
                assert cln_addr["p2tr"] == computed_addr
                withdraw_addr = cln_addr["p2tr"]
            else:
                raise Exception('Unexpected descriptor!')

        # For last address per type:
        # Funds sent to lightningd can be retrieved by bitcoind
        txid = l1.rpc.withdraw(withdraw_addr, 10**3)["txid"]
        bitcoind.generate_block(1, txid, bitcoind.rpc.getnewaddress())
        l1.daemon.wait_for_log('Owning output .* txid {} CONFIRMED'.format(txid))
        actual_index = len(cln_addrs) - 1 + index_offset
        res = bitcoind.rpc.scantxoutset("start", [{"desc": descriptor, "range": [actual_index, actual_index]}])
        assert res["total_amount"] == Decimal('0.00001000')

def test_hsmtool_generatehsm_with_passphrase(node_factory):
    """Test generating mnemonic-based hsm_secret with passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)  # Remove the auto-generated one

    # Generate hsm_secret with mnemonic and passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "test_passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"New hsm_secret file created")
    hsmtool.is_in_log(r"Format: mnemonic with passphrase")

    # Verify file format
    with open(hsm_path, 'rb') as f:
        content = f.read()
        # First 32 bytes should NOT be zeros (has passphrase hash)
        assert content[:32] != b'\x00' * 32
        # Rest should be the mnemonic
        mnemonic_part = content[32:].decode('utf-8')
        assert "ritual idle hat sunny universe pluck key alpha wing cake have wedding" in mnemonic_part

    # Verify Lightning node can use it
    l1.start()
    node_id = l1.info['id']
    assert len(node_id) == 66  # Valid node ID
    l1.stop()

def test_hsmtool_generatehsm_no_passphrase(node_factory):
    """Test generating mnemonic-based hsm_secret without passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Generate hsm_secret with mnemonic but no passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))  # Empty passphrase
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"New hsm_secret file created")
    hsmtool.is_in_log(r"Format: mnemonic without passphrase")

    # Verify file format
    with open(hsm_path, 'rb') as f:
        content = f.read()
        # First 32 bytes should be zeros (no passphrase)
        assert content[:32] == b'\x00' * 32
        # Rest should be the mnemonic
        mnemonic_part = content[32:].decode('utf-8')
        assert "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" in mnemonic_part

    # Verify Lightning node can use it
    l1.start()
    node_id = l1.info['id']
    assert len(node_id) == 66  # Valid node ID
    l1.stop()


def test_hsmtool_checkhsm_with_passphrase(node_factory):
    """Test checkhsm with mnemonic that has a passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create hsm_secret with known mnemonic and passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "secret_passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test checkhsm with correct credentials
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")  # Decrypt file
    write_all(master_fd, "secret_passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")     # Backup verification
    write_all(master_fd, "secret_passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"OK")



def test_hsmtool_checkhsm_no_passphrase(node_factory):
    """Test checkhsm with mnemonic that has no passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create hsm_secret with known mnemonic and no passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))  # Empty passphrase
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test checkhsm with correct credentials (no file unlock needed)
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter your passphrase:")  # Verification passphrase
    write_all(master_fd, "\n".encode("utf-8"))  # Empty passphrase
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"OK")


def test_hsmtool_checkhsm_wrong_passphrase(node_factory):
    """Test that checkhsm fails with wrong passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create hsm_secret with known passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "correct_passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test checkhsm with wrong passphrase
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")  # Unlock file
    write_all(master_fd, "correct_passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")  # Wrong verification passphrase
    write_all(master_fd, "wrong_passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 5  # ERROR_KEYDERIV
    hsmtool.is_in_log(r"resulting hsm_secret did not match")


def test_hsmtool_checkhsm_wrong_mnemonic(node_factory):
    """Test that checkhsm fails with wrong mnemonic"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create hsm_secret with known mnemonic
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))  # No passphrase
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test checkhsm with wrong mnemonic
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))  # Correct passphrase (empty)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))  # Wrong mnemonic
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 5  # ERROR_KEYDERIV
    hsmtool.is_in_log(r"resulting hsm_secret did not match")


def test_hsmtool_detect_secret_types(node_factory):
    """Test that hsmtool correctly detects different hsm_secret types"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    
    # Test detection of mnemonic without passphrase
    os.remove(hsm_path)
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    
    # Test getnodeid works with mnemonic format
    cmd_line = ["tools/hsmtool", "getnodeid", hsm_path]
    out = subprocess.check_output(cmd_line).decode("utf8").strip()
    assert len(out) == 66
    assert out.startswith('02') or out.startswith('03')

    # Test detection of mnemonic with passphrase
    os.remove(hsm_path)
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "test_passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test getnodeid works with passphrase-protected mnemonic format
    cmd_line = ["tools/hsmtool", "getnodeid", hsm_path]
    proc = subprocess.Popen(cmd_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=b"test_passphrase\n")
    assert proc.returncode == 0
    node_id = stdout.decode("utf8").strip()
    assert len(node_id) == 66


def test_hsmtool_generatehsm_file_exists_error(node_factory):
    """Test that generatehsm fails if file already exists"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    
    # File already exists from node creation
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 2  # ERROR_USAGE
    hsmtool.is_in_log(r"hsm_secret file.*already exists")


def test_hsmtool_all_commands_work_with_mnemonic_formats(node_factory):
    """Test that all hsmtool commands work with mnemonic formats"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create a mnemonic-based hsm_secret (no passphrase for simplicity)
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test various commands work with mnemonic format
    test_commands = [
        (["getnodeid", hsm_path], lambda out: len(out.strip()) == 66),
        (["getcodexsecret", hsm_path, "test"], lambda out: out.strip().startswith("cl")),
        (["makerune", hsm_path], lambda out: len(out.strip()) > 0),
        (["dumponchaindescriptors", hsm_path], lambda out: "#" in out),  # Should have checksums
    ]
    
    for cmd_args, validator in test_commands:
        cmd_line = ["tools/hsmtool"] + cmd_args
        out = subprocess.check_output(cmd_line).decode("utf8")
        assert validator(out), f"Command {cmd_args[0]} failed validation"


def test_hsmtool_deterministic_node_ids(node_factory):
    """Test that same mnemonic+passphrase always produces same node ID"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    
    # Test with specific mnemonic and passphrase
    mnemonic = "ritual idle hat sunny universe pluck key alpha wing cake have wedding"
    passphrase = "test_passphrase"
    
    # Create first hsm_secret
    os.remove(hsm_path)
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, f"{mnemonic}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, f"{passphrase}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Get node ID
    cmd_line = ["tools/hsmtool", "getnodeid", hsm_path]
    proc = subprocess.Popen(cmd_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=f"{passphrase}\n".encode("utf-8"))
    first_node_id = stdout.decode("utf8").strip()

    # Create second hsm_secret with same credentials
    os.remove(hsm_path)
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, f"{mnemonic}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, f"{passphrase}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Get node ID again
    cmd_line = ["tools/hsmtool", "getnodeid", hsm_path]
    proc = subprocess.Popen(cmd_line, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(input=f"{passphrase}\n".encode("utf-8"))
    second_node_id = stdout.decode("utf8").strip()

    # Should be identical
    assert first_node_id == second_node_id == '02244b73339edd004bc6dfbb953a87984c88e9e7c02ca14ef6ec593ca6be622ba7'



# this test does a 'listtransactions' on a yet unconfirmed channel
def test_fundchannel_listtransaction(node_factory, bitcoind):
    l1, l2 = node_factory.get_nodes(2)
    l1.fundwallet(10**6)

    l1.connect(l2)
    txid = l1.rpc.fundchannel(l2.info['id'], 10**5)['txid']

    # next call warned about SQL Accessing a null column
    # and crashed the daemon for accessing random memory or null
    txs = l1.rpc.listtransactions()['transactions']

    tx = [t for t in txs if t['hash'] == txid][0]
    assert tx['blockheight'] == 0


def test_withdraw_nlocktime(node_factory):
    """
    Test that we don't set the nLockTime to 0 for withdrawal and
    txprepare transactions.
    """
    l1 = node_factory.get_node(1)
    l1.fundwallet(10**4)
    l1.fundwallet(10**4)

    # withdraw
    addr = l1.rpc.newaddr()["bech32"]
    tx = l1.rpc.withdraw(addr, 10**3)["tx"]
    nlocktime = node_factory.bitcoind.rpc.decoderawtransaction(tx)["locktime"]
    tip = node_factory.bitcoind.rpc.getblockcount()

    assert nlocktime > 0 and nlocktime <= tip

    # txprepare
    txid = l1.rpc.txprepare([{addr: 10**3}])["txid"]
    tx = l1.rpc.txsend(txid)["tx"]
    nlocktime = node_factory.bitcoind.rpc.decoderawtransaction(tx)["locktime"]
    tip = node_factory.bitcoind.rpc.getblockcount()

    assert nlocktime > 0 and nlocktime <= tip


@unittest.skipIf(VALGRIND, "A big loop is used to check fuzz.")
def test_withdraw_nlocktime_fuzz(node_factory, bitcoind):
    """
    Test that we eventually fuzz nLockTime for withdrawal transactions.
    """
    l1 = node_factory.get_node(1)
    l1.fundwallet(10**8)

    for i in range(100):
        addr = l1.rpc.newaddr()["bech32"]
        withdraw = l1.rpc.withdraw(addr, 10**3)
        bitcoind.generate_block(1)
        l1.daemon.wait_for_log('Owning output .* txid {} CONFIRMED'.
                               format(withdraw["txid"]))
        decoded = bitcoind.rpc.decoderawtransaction(withdraw["tx"])
        tip = node_factory.bitcoind.rpc.getblockcount()
        assert decoded["locktime"] > 0
        if decoded["locktime"] < tip:
            return
    else:
        raise Exception("No transaction with fuzzed nLockTime !")


def test_multiwithdraw_simple(node_factory, bitcoind, chainparams):
    """
    Test simple multiwithdraw usage.
    """
    coin_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'plugin': coin_plugin},
                                                 {}, {}])
    l1.fundwallet(10**8)

    addr2 = l2.rpc.newaddr()['bech32']
    amount2 = Millisatoshi(2222 * 1000)
    addr3 = l3.rpc.newaddr()['bech32']
    amount3 = Millisatoshi(3333 * 1000)

    # Multiwithdraw!
    txid = l1.rpc.multiwithdraw([{addr2: amount2}, {addr3: amount3}])["txid"]
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1, l2, l3])

    # l2 shoulda gotten money.
    funds2 = l2.rpc.listfunds()['outputs']
    assert only_one(funds2)["txid"] == txid
    assert only_one(funds2)["address"] == addr2
    assert only_one(funds2)["status"] == "confirmed"
    assert only_one(funds2)["amount_msat"] == amount2

    # l3 shoulda gotten money.
    funds3 = l3.rpc.listfunds()['outputs']
    assert only_one(funds3)["txid"] == txid
    assert only_one(funds3)["address"] == addr3
    assert only_one(funds3)["status"] == "confirmed"
    assert only_one(funds3)["amount_msat"] == amount3

    expected_utxos = {
        '0': [('wallet', ['deposit'], ['withdrawal'], 'A')],
        'A': [('wallet', ['deposit'], None, None),
              ('external', ['deposit'], None, None),
              ('external', ['deposit'], None, None)],
    }

    check_utxos_channel(l1, [], expected_utxos)


@unittest.skipIf(
    TEST_NETWORK == 'liquid-regtest',
    'Blinded elementsd addresses are not recognized')
def test_repro_4258(node_factory, bitcoind):
    """Reproduces issue #4258, invalid output encoding for txprepare.
    """
    l1 = node_factory.get_node()
    addr = l1.rpc.newaddr()['bech32']
    bitcoind.rpc.sendtoaddress(addr, 1)
    bitcoind.generate_block(1)

    wait_for(lambda: l1.rpc.listfunds()['outputs'] != [])
    out = l1.rpc.listfunds()['outputs'][0]

    addr = bitcoind.rpc.getnewaddress()

    # These violate the request schema!
    l1.rpc.check_request_schemas = False

    # Missing array parentheses for outputs
    with pytest.raises(RpcError, match=r"Expected an array of outputs"):
        l1.rpc.txprepare(
            outputs="{addr}:all".format(addr=addr),
            feerate="slow",
            minconf=1,
            utxos=["{txid}:{output}".format(**out)]
        )

    # Missing parentheses on the utxos array
    with pytest.raises(RpcError, match=r"Could not decode the outpoint array for utxos"):
        l1.rpc.txprepare(
            outputs=[{addr: "all"}],
            feerate="slow",
            minconf=1,
            utxos="{txid}:{output}".format(**out)
        )

    l1.rpc.check_request_schemas = True

    tx = l1.rpc.txprepare(
        outputs=[{addr: "all"}],
        feerate="slow",
        minconf=1,
        utxos=["{txid}:{output}".format(**out)]
    )

    tx = bitcoind.rpc.decoderawtransaction(tx['unsigned_tx'])

    assert(len(tx['vout']) == 1)
    o0 = tx['vout'][0]
    assert(scriptpubkey_addr(o0['scriptPubKey']) == addr)

    assert(len(tx['vin']) == 1)
    i0 = tx['vin'][0]
    assert([i0['txid'], i0['vout']] == [out['txid'], out['output']])


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "Uses regtest addresses")
def test_withdraw_bech32m(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l1.fundwallet(10000000)

    # Based on BIP-350, but all changed to valid regtest.
    addrs = ("BCRT1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KYGT080",
             "bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry",
             "bcrt1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k0ylj56",
             "BCRT1SW50QT2UWHA",
             "bcrt1zw508d6qejxtdg4y5r3zarvaryv2wuatf",
             "bcrt1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvseswlauz7",
             "bcrt1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesyga46z",
             "bcrt1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqc8gma6")

    for addr in addrs:
        l1.rpc.withdraw(addr, 10**3)
        bitcoind.generate_block(1, wait_for_mempool=1)
        print(l1.rpc.listfunds()['outputs'])
        wait_for(lambda: [o for o in l1.rpc.listfunds()['outputs'] if o['status'] == 'confirmed' and not o['reserved']] != [])

    # Test multiwithdraw
    args = []
    for addr in addrs:
        args += [{addr: 10**3}]
    res = l1.rpc.multiwithdraw(args)

    # Let's check to make sure outputs are as expected (plus change)
    outputs = bitcoind.rpc.decoderawtransaction(res['tx'])["vout"]
    assert set([output['scriptPubKey']['address'] for output in outputs]).issuperset([addr.lower() for addr in addrs])


@unittest.skipIf(TEST_NETWORK != 'regtest', "Elements-based schnorr is not yet supported")
def test_p2tr_deposit_withdrawal(node_factory, bitcoind):

    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True)

    # Can fetch p2tr addresses through 'all' or specifically
    deposit_addrs = [l1.rpc.newaddr('all')] * 3
    withdrawal_addr = l1.rpc.newaddr('p2tr')

    # Add some funds to withdraw
    for addr_type in ['p2tr', 'bech32']:
        for i in range(3):
            l1.bitcoin.rpc.sendtoaddress(deposit_addrs[i][addr_type], 1)

    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 6)
    for i in range(3):
        assert l1.rpc.listfunds()['outputs'][i]['address'] == deposit_addrs[i]['p2tr']
        assert l1.rpc.listfunds()['outputs'][i + 3]['address'] == deposit_addrs[i]['bech32']
    l1.rpc.withdraw(withdrawal_addr['p2tr'], 100000000 * 5)
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 1)
    raw_tx = bitcoind.rpc.getrawtransaction(bitcoind.rpc.getrawmempool()[0], 1)
    assert len(raw_tx['vin']) == 6
    assert len(raw_tx['vout']) == 2
    # Change goes to p2tr
    for output in raw_tx['vout']:
        assert output["scriptPubKey"]["type"] == "witness_v1_taproot"
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listtransactions()['transactions']) == 7)

    # Only self-send + change is left
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)

    # make sure tap derivation is embedded in PSBT output


@unittest.skipIf(TEST_NETWORK != 'regtest', "Address is network specific")
def test_upgradewallet(node_factory, bitcoind):
    # Make sure bitcoind doesn't think it's going backwards
    bitcoind.generate_block(104)
    l1 = node_factory.get_node()

    # Write the data/p2sh_wallet_hsm_secret to the hsm_path,
    # so node can spend funds at p2sh_wrapped_addr
    p2sh_wrapped_addr = '2N2V4ee2vMkiXe5FSkRqFjQhiS9hKqNytv3'

    # No funds in wallet, upgrading does nothing
    upgrade = l1.rpc.upgradewallet()
    assert upgrade['upgraded_outs'] == 0

    l1.fundwallet(10000000, addrtype="bech32")

    # Funds are in wallet but they're already native segwit
    upgrade = l1.rpc.upgradewallet()
    assert upgrade['upgraded_outs'] == 0

    # Send funds to wallet-compatible p2sh-segwit funds
    txid = bitcoind.rpc.sendtoaddress(p2sh_wrapped_addr, 20000000 / 10 ** 8)
    bitcoind.generate_block(1)
    l1.daemon.wait_for_log('Owning output .* txid {} CONFIRMED'.format(txid))

    upgrade = l1.rpc.upgradewallet()
    assert upgrade['upgraded_outs'] == 1
    assert bitcoind.rpc.getmempoolinfo()['size'] == 1

    # Should be reserved!
    res_funds = only_one([out for out in l1.rpc.listfunds()['outputs'] if out['reserved']])
    assert 'redeemscript' in res_funds

    # Running it again should be no-op because reservedok is false
    upgrade = l1.rpc.upgradewallet()
    assert upgrade['upgraded_outs'] == 0

    # Doing it with 'reserved ok' should have 1
    # We use a big feerate so we can get over the RBF hump
    upgrade = l1.rpc.upgradewallet(feerate="urgent", reservedok=True)
    assert upgrade['upgraded_outs'] == 1
    assert bitcoind.rpc.getmempoolinfo()['size'] == 1

    # Mine it, nothing to upgrade
    l1.bitcoin.generate_block(1)
    sync_blockheight(l1.bitcoin, [l1])
    upgrade = l1.rpc.upgradewallet(feerate="urgent", reservedok=True)
    assert upgrade['upgraded_outs'] == 0


def test_hsmtool_makerune(node_factory):
    """Test we can make a valid rune before the node really exists"""
    l1 = node_factory.get_node(start=False, options={
        'allow-deprecated-apis': True,
    })

    # get_node() creates a secret, but in usual case we generate one.
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing "
              "cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"New hsm_secret file created")

    # Test makerune with the passphrase
    hsmtool = HsmTool(node_factory.directory, "makerune", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    out = hsmtool.logs.split("\n")[-2]  # Get the rune output (last line before empty line)

    l1.start()

    # We have to generate a rune now, for commando to even start processing!
    rune = l1.rpc.createrune()['rune']
    assert rune == out


def test_hsmtool_getnodeid(node_factory):
    l1 = node_factory.get_node()

    cmd_line = ["tools/hsmtool", "getnodeid", os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")]
    out = subprocess.check_output(cmd_line).decode('utf-8').strip()
    assert out == l1.info['id']


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@unittest.skipIf(TEST_NETWORK != 'regtest', "elementsd doesn't use p2tr anyway")
def test_onchain_missing_no_p2tr_migrate(node_factory, bitcoind):
    """l1 and l2's db is from test_closing.py::test_onchain_p2tr_missed_txs before the fix"""

    blocks = ['0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f121ed0ffdd5a197230c7b58dd7512177ba827afeca6c2c82ecda3519566ac83d3d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002056e8e4767b39e3f2a4e98139da05354cc1430f6cebc315cdb3258f26db8cb67d29444f7b2b6f5c1fcf13acbbc101d29f0840f373cd16b85f1f92ed670614fbfa3e45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020a88aa9d26fa6e14d9019e8942e201ba2e4435d29fca4e30e84aaeda35b85f13c54d0cd7ee7880080019227edc9782d42d719794f995419197c254417c740abfa3e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020d98753686d7d90f18a7fed6eef810e367dd4eb5d9c950d32b2735a151aa89e27ec5ca82ec5538a841fe634fc178f73247db5e17adb48913e55d33b1155b9df753f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ec249c91bf3f5cb46f48c14bee378bebf1591fa5ed15809c164170754a8f1e2daac112a6d9cd3e9c22a9b49142fc8314a7dffb8ace5bc9d7a273f9aba5ac18dd3f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020c257c44ac8551b3b238ea57d21944f4614ce6956065074f2f473a6df9718887ef379a56ccc20580e4774874c3e1b1120a1adae13a47fdc6004946f404743c6113f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025600ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020e4e5a33bd5e84f1077de3843d2e480f7026e363872df300d5ce335208eea81537604d1903f67ddeeed3e6d9dfe107124b79d655d9c65c47a8baf97cee805d6793f45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025700ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000208a7461c453c09c8d3110e9b5dd3c5f438e3c760c9513655fe49fdf1edd4a4134f28bd7fc2be0d0719cbf109ff4aaf2317deb44c58a4f9131ffd87e06b150e5de4045e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025800ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000204f54cb2bc317899e636a616175936910336da0f733ed0165dd6084e61210d075a1cb573f8c475e11e0abbeb593575ca8d35a8b902f36d725d93382041bf8f2434045e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025900ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020dee1077d156feb2dac8be750ec1f6c0c8cc6148e98df6bf28e1f1d87369da70bc0bbbd7b242da54cabd90b3a9a10d86974615819d45fa3cb8aa97cdb488cc4ea4045e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025a00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002097cec18a4ef852e3d32e46ff8af809518e075dc050bc6d95ccf2c4ffee53dd51f429948b42f534e8adc8f9ce9ab5dff9d84b54c58085f78d7646ec99c9d8a5f94045e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025b00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202417a4c440947c1081326d24f4bfcd6eb4545759262603baf94a23befed47728756afebf5b153e8e609348dfa70fd288b0f981e50b37e08c51c9d5df6b53d4574045e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025c00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002045a0ff48b45af0766329cecd5c07a912dbcdcd547facb15f7acb3af5241e011b3aa7271b58360c7ccdbfc80f01de88b822924701fb4b21315d6a20ad212c6b234045e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025d00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ac1719324f9032c419aa4a7d993bd9f1cf34e5fcfa3aeefc1554cf2a37cd5c2771b97403a26c5b147e04544bf0cdde758dfbb0634a05a17c00324a3ccd6619904145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025e00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020622c40d273474af2ee1afbc67777a1212b07132e07f7e89e462687131931e4601d42312ac50a0cde27393ffa2071d74f8995c6a4873a14cf968ccf7e8f654c3b4145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025f00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020f8d147ccbbec397afd787241fab2b4ebde4fabf72c808b7cafd87fd54a82ac71fd4d27ac7efcdac809fa30b7a8b4801b9fb69a11a3511ffc78aeebd2dbd8c6d84145e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff026000ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020003dbb1e275d32254e34837b4c9b743be7d71f84779e4519a86ecf46fa6a5d506650b1d56c1a49a68206669ddfc0bafd899097dd4d1b8b31f6aa56afc7143c574145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020e24ee6f5ca1e5bf5ddf9b08d9c63c51df30308debc631243e7244560ddbee524d781b8ec7c6585ea570435c1e8d61cb064db79e0e37a85db01517db8bc3db9534145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ee545b3b41992c9194459ea63cbca7c6a3079d9d160760856344390ebd76394546b9a9f1bc1060a127cfd6ee2fb00dd18e190d2fcf5476d229b026fe6ebd2a964145e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ce65af7fae3cc1191ba3520ce19e793d8747d6f70df4e29bbfcd830882c2e45688dd607cf34bd52a1f37837304b1345e5f9bf1ad901db0ff527d4fdabc7bb4f74245e767ffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020f1f2036de5c385f42e6c3da3b54cc94ce81527939cc1ec243387a3939d9fed7ef5e2d409cf025faf43dd43f120629d62a1f9ae8ef655dbb22fd2916ae51d32db4245e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002027f7dadd90d2f5cc5ae451e12702f37e2b2dbc5aa8f01af6399183f74cab8663901757e211691030c4fde536d26cb992a0c3c149822273cb2630cd20922ff2694245e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011600ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002072253009326feaa2cf0a87af69a071e0fdbdcb052f82afbc0708768d7e42e502957696fea9a86ad913c32972ee7e76047678d83fba95ff78e920954850d293854245e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011700ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020805c0de280de48b539ef2e656d013247c24a2f9e72b45ec0d35b9b0a67712730990b38c53dbe4b000aaf0f8fde41739e488a0651af1eafd0c8c1154462426e474245e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011800ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000205580a32fa092f795359ef4fd8cf5683135ab94d338906ac2ca30d83b9224885cb33ac2bef57fe7b7b62bcd567147749870481d35732426bb70b3d3e09cb03d654245e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011900ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002043b881c5077dd5c49c80cf652ab96265f045fb8a4160baa1a1959456f1365674f5b5545b6a08283699c2f648e8822b4bfa151cc92e85f23096091bb217bec00c4345e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011a00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202cbe3c8d54a8acbd395d3f34f794c608c594f2933187dfab5798ae884976ba126639f0d15b87f22b52b22a2db662dc18073d73278a9f03dcafa11deaaea393d64345e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011b00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002052d8f545cd0cdb4098917c59f464bb06169f62100715c1f0e20261cc205a0721dcfa2b9623d8506335f6cfad8172e0a585f3d1499ff48ab09c63b4d8da17dc4e4345e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011c00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000203777dc93b80490c7d73c223d32b6f8e355bf4e1bc7682b126815dd6cf68c7402fc9ad8f5f17705057e81bbd26ee244b9919a66e493ba6d1f7b16a7ae742ef7464345e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011d00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002029d7ce4e03327a016d967b82832c1821a451b6c32daaae8063ddcfdcbe3c396bb97d9802063e424e198b252f1b4e3ecb45f15425ed7b96082394a5a8ba37e16f4345e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011e00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000203223f332a0ca3da6d9f16400f2e301d043b028453b0be9d046ea1a79bd787919affb4d62e0ce40708279c7c89b450fa5edbbf036add302889c7746c52393bbfb4345e767ffff7f200800000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011f00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020d740d4b227990a1ffd287929dc6d0c05b9a1da43f2c08bac3dc415921afcf86a52811ce56d03b94582212ef8338e98171aeffd0ca280898648031724074ef3654445e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012000ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ec7e7181e747198b39f3c6b031dace6cd4994a036082dd3e1989ecea3d01b005f6e35a9d2c2c9586dfeeb20a894ccc2231040e1c8576d9bd74d1ef4941ea66444445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000207d83089eb2a775b1c8dafc0af8118a20e0ea1d78f099522e2512c5355310fb5969c1daa9ed040c0ab3fe68ad802e637e69ffc777a8e0d77393a6049086e9bbe14445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000208c22dc5cdd4ac9dee3a7a1c20a2257c6fcea405f4eac404f7727d2848332da2ecb7f4811333231279dc6db9103df46e2452e1b995cf984240c3f157aabb581ee4445e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000201409a49dc6c1dcb74e1593d0df46e3c945487ad1c3e2cb3b3e72ba7bfe615d222be670b9cefbaac48b50e034dccd065606d5f4f1658dd4bcd8893e51586cc3414445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000203778a6471cd5892165f4ab9a06ec218e2e1ce24b9a705522b1bf6c2e20d5e9336ef2c5e22236835b35824f0a65b948e67e8f7acf612ae0c70a53e1b34da9357c4445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202ce848e935faeea98f38578fd04cae046277a2c2b8ce084809d0b38a22ca7f2745c08ea35070ca4b721625c70dbe78b9b0e5f981e9651450a27adbb2a43e5bad4545e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012600ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000205c086ca4598faea39c90dee6a511201141351df9b30a8535d2c3505a18294d38221e9d2b65f07b51ea8ed1a7d033f6a3b22f9ff5a1c8a866d42b9a2a03b0cf3d4545e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012700ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202cbe285d2d66722078a3fd6a51db34dc9e33246bbf76c5a7d04d2208998ba6225d755a5811c13a18decbba116c392422dad2ba32d51581c0d0a4dd891a3081ad4545e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012800ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020273b8d89d4c162df351089915bde50615b8e914fc158a97c0e38783e674ff36f1823c18340823c3a6b7f19ba786029dfb53aeca6cbf01235d7151de95fd5d1844545e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012900ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ccf17cebf95ff2f44c4f64fb514614494ee15630eb87c279825462195e9ca1294270f349315dab92f1f2311297c70e5353c635d368ef1e8ce37bfe64b15e6ce34545e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012a00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b1b0c0ac7b9e1d2a3cbf43ddf6e0a34968735fac65a95a9db98e9211d5b1820408619e4c9c71540ad6b952d4c5224602fa45af3fec4bc3aaaf41661b09bd62e54545e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012b00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002040ef97fd829af29a9e0a2c4ec3327b71da31a58bae4a8b2c3b0b74426dd83022823f16e2ada411bbb6dc3ad9335572d5ce7fe0ced9e4c4b485463c4931073e494645e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012c00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020523d20de744cab12a12ac8c71bc930e65c88e15db6e0c88f9f68e4e97473d578e60e8fb9e3c50f5dbd70a9113fdf50ede58b0f25c8db3bcd6b0d7befb49d2ce24645e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012d00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000205457d8f0682df35420c76853489f9b2d092ffe4a73bef96033216028138a0272a911ca2b3b45841c1eaac2df1e7af13c5b89fd2892b1594e24d39003a4027ac34645e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012e00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020a93b1446dad94fad245046d7777541a31cf75b3e1dc565c5899130b1627a6a65192c114e3cf1e91c337475804434f949a931bf1b55bea2dd5f4b698c7b92f84e4645e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012f00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020008db5f78bf19eb494df3bc95b4809f368d9f8c157affc76b9612e30061adb54de1ad09146535a6b0ef832eb1d79bfbb13784016c18258356ef67dd249574d3f4645e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013000ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020bf876a730f6b15c3f766aaf96312efa1208778487b8dd4a3ed28d331ff6ff369192df6ed3a7d289b4c37d6fa6c2b63dbe1f4b2e4562e263e577a15f7d69278744645e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002039ba6324e15c56ca6590989bb1e6d7426a5c8cc770e967015bd01dcb4d2a95181132dfafa4132f447f63fb999726fea98767e887cf98a259ef7ea7fd07dbb64e4745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020cd1dce463cd6b0fa6ba3500d380a1327200fae56efec37a2c5e435ff244a65443f1024e9b6ce06b809df3ec46e4a834e80e934190d590b62b6999378ca93ef0e4745e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020a44cc61dcaf4738c637bf540680665364b71d1c71fe09089b9c8ef8cf68c9e2db0749b3331bfa43b0d458f46f01204781a44c4830f7a08c7c050f87c67ee441c4745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020e61836b534a239642a830d7c029b85e1b1b754da2ce559e152d3ef2b60fe346b356fb9c2e9f571c39cbe561969058e889484262080fce71d7c6dc9851f91a41c4745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002068524ed04b0180e71d83fe6ae5efeb141e622de706e2b413b1862bb6df8fad66eef99ff3f436f643c8596cffd52f70254018b21839e10a4819e73d78a9fee8104745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013600ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000204d7c2f69eee5030e3e62cb3c4c498a8b804b5b048c7c460fee7421867bf6c5565f2b1ef4127dc4ad3f139362eefe24b7a28b00a446c093281920a0833b1b5f7e4745e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013700ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000203fb86b9c03e204833f4f2fa5d0bead1004ba4b0ebce1d41ec9a32ed76eefd54a3ce9ed4547ff51cb18c4f1f1e81d5275157b86852ca23e567aa970417c04731b4845e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013800ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002087fba8d6923025aa62a03e0181231ae3b378fef2b91c705f74a28f66e0651255f13e4a7f7c478a7721d137ad8dbf356ef57d119e857123939a4506aed215d16a4845e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013900ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000208358beaeb2fc8e9275f4004e67a87bca7c5915dcda0dcafca2f8fe9f6a90cd6b07b5e8d76cf2bbdab39b4706587b76d2f2d0068a63317a6abc1f2538b1db3d4f4845e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013a00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000209bcaa71b05385e5a0768fcddda0987e04751dddd5fa413b2be83f608f2f122610f94d40dc90ccca8e76fda5b7d0d49b4ed77fa8af29342a4a92e0065a531d2374845e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013b00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020cce44e08c9f2ceb0dc8c3243a9798b7d5e56177dab496beafc6c76cd179f1e69665c029fb980568403dd86b5d7ec77862abe828d0fb5ef02f28b5b4d373d2b054845e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013c00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202982c819e34a06d753f840e23f11031170bab285b319e859a6414e163f081b30afa2940431691af1258a548bd71477cf66c01c884c110da0d7e1c175568e41974845e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013d00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020d51d963aac276f16eda2ac14c9d229d9cc7f21edc5d6c84d92db757eb9cb491c6ee7239b57fc1ea359c2fd3c28292976bd095a6ac0e4540c7eb70c46de8339fb4945e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013e00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002088a273f1306813096a9870330f1a0db64db14ca501249d8d49639ac1a593fc4c804815be3e4114c5fffa96aad26c75cbedcbc854c8bac1ed3b3f9c16b13968e24945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013f00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b47c3ad1c5b0669701eeb6d04181e08f9a910d06b98153f6daa4eed4d480160a3d9bed639fdf277a9a768f5c3c71b220281bb24d77f7cf42ba38e2d432f641e54945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014000ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020a0ae01d6a9bccd9d4b014efa2808d266eeec9d76b597985711ab2f2d7300873b2e039380332fe0ee2922cfc85934546ca0487943e7bc3c1d053294a4e28d23d24945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b513e6b905f59ce167741ad3483c7a659bb66c28f0e893f61be48e7f1d0aa464cb52a1d2d0b7feb43e3707ab01883ecde8de9cd799d7b4554dfed6603e5a06784945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020cf7c32f21b0f8b5d1705027fce8a26e2c73233cc47cd149be4d5c87bdeec764eb03f8d3382d4dc3debe75cbda087b24367d7bbf843acd1759fd5f203d443f1574945e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000201366a9defec3e481f7d6b791bbec45586c8e375efa68a4d771ed0b9e9fb7a21b353d154182ddfaa565e6ca531324acc621cb9ee3b2286a075ed5921b02e5c03c4a45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020e227ff11ff22192eb7b7e4e45e7701427af5e6d4d6fce1469cc31a0f702829044206ac1718f4bc2bf712402b4b73317a4dc81d193ffdaeae84514a690cbedb834a45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020d49f5867985e23f97862c1335391d7070a7cd263565c9059a75d0a1ed33c4775731604dd425ce7ebec709b1c55ca1e28733ec589f024893ee02915964996e19c4a45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014600ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000200795c11d7aa402ab08599130953256038cba99027e992984c03f6eeb93532e6122675f9f5445b99caa2412d7a48d773813230fc5237a73851a7595e5eea813d64a45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014700ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000209461da337678c07e079d6bb700cd77ffa9ab6a17f983027c81f8fcb6120f8d654561d571492e2399e2cd0042ab552b33354c62642b489190d12d7a4e7c79c5414a45e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014800ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000204f28c8b5f7f75a74ee2c5c21cacaf34c4710e5d50104664d0ad6b21e6e90b570398c63d309b5fd1854ad095f2926a66692cbb0b75985648240feed65b9076e4f4a45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014900ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b34f81a7e63a3d553f7fcc75651bff5e399746363caf7ba6a515e6e81fe93c7309b05d9b40df1c48e5c0b4aa8093dcb809b8b9e95b695d6d00e4011744455e9e4b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014a00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002009239cc6231ba824fc9c84d25ff93ce4a1ade148eb58120bb6fe8e9694d948774d0507e1a56dd3cf62edfcd362a90369f9b553a4052bc2820d3c15d13bd964d24b45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014b00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020e1a0dc94ff484b1350a1fc45746111bfed0ca796b59ce537c847da1376183b4b3eb2e6938000f23a4b353692532deab714a9a905968b8e45c8f29775974766f34b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014c00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020f838d5ebd5ecc3d149b449607e93eda3afb9ca40e5efffb275c7cbf3255bc53d097d2824834a9dd2bc4906f1c3abf0ebf62548119ec8c63b709ce6f86531121e4b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014d00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000203e70699fb54df9b478ef032f7c7910da732953cf9c4b46a10882834b15c147485124cbf07e1a19ef7db7c32faa907d2cc14f8718e3b2492274d8189aeebaa86d4b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014e00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ce17449ebc7d3ed89635861fbadf771177fc6e9f89fb8568fa5391902a6d3835d493b31b5885c4cdcf1bf0323540e51efcb98b62ef2df2a8e2c98fb4c515fe0c4b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014f00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020e6dfcc5f0d0a99cdbcfd9159d38d6f22ecd15a4d58fb15eba0a6ddf4461d22531e907738f76c083edb201898dceb5450c00d932d1b4f6df9ccd20d4aa06bdcd94c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015000ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000209d1276b33097ca1f167d668e58eb02f808ed5ede95ae0646826517df4db91b11a21c9e516a0340e59cd385f817e3c25669751463e060b944098eea334e2c5edc4c45e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002064ab992bf9bd6b892dc119c31bf8783a7e9f19762afbae9430e7bb12a89ffd5c61b085a1dd14d757a4a16e4d1913f2874db46586875e90ccb98037ef333d7c424c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000207a7763f9cb7a778a222acc4ce585f9b2f5f783c097ebec310702c87ef37ecf121b0d55802404b5ed763b48418273e9a3afb894f0e35f95681278956f9c3aa4af4c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020c94c950a983a47b4a710edbf815dc4ccf0b087734a0f26744f9a097a3a0cc96872eee5cb323b070ee052ed2b2dfa84614017e58d48a75f379cdd04487eab0a554c45e767ffff7f200500000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002089255a3e8e9b7e76b5066a845ee682e5ed4241d51aa8788ec038a52f78760644abbe623aff5dea4eea5c5e6855f0d00d25573fb30d72b4b8767fa7f555f3d0f44c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ae3ddb931d73ed22b355c14f0c3349f7ab6c31fa56c0b6050b0c2717bfee7d374433c0b6cb0b30debfa8e3fef9328a43ef6f243d3c92b2a985a054770464abdb4d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015600ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020884d1649346a457132f5e752b2bd005eb83573eecf08bff4c0927519d9570d406cc13d704d9dea7f5c8ecb624e3f24fc0a2e75e7c6dbaab08d7f3c5ce315fe394d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015700ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002031b450c77ef3e50b3c356999d8e0732f053c2a470cfd20e016b067eab7ef916a0417caea9b477a95046067fda479ae367e63c3b521ef9243e3cad3e7f5606ac04d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015800ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020067c78e818d260aa51d34200106db04921a5c8654dfe11828a3e9cdd618da21896424aaee42438322942263255e7121bcda1e783b175af976f84b3d674172b124d45e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015900ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020d237a92f2a860a1342b7c37c30fd05be47ce6c1344ddc295d8a12dfea21f3447cad7c3cb50788dfb9eecc6f316efb46739ce4ba4703997a3c54c75cc7f0dcff84d45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015a00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002032ceebc14e86191162c4d8ec3fcacd9d6c1466a93aa5092c8f4b1a126db70b260c2932b748d4548575c282f3c4b8d956f7e65fa493a2ec17aa09d943de964f094d45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015b00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020807fb3f557726ae5a8e246b06e6e3364b9460c2c31dbc37e2ca87763f176fd6463933d80fe1db063acc4a89a154acc892c6f5c13b3c4452f4d5ce51ffac793004e45e767ffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015c00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002035201324cc84078292547aa0a1e0ff7f8727074feff5e319b2dfbb2fe885c01a1d3d9d3494e4652489e3f18a76a52cd492b32f8d18f6cab4fdbd6f24a1b9e3254e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015d00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002025a80bb6b4aa2c98c18aa828586d51eceb677b8975029ad477a6cf05d23a7527cce8fd4e16c15fe2e80f4af5c576fcaeac1503979e7a51eff66ff2bfe53efa844e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015e00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ed3b675338a6ba59799594e985173060205e73d7b099e30cb78d1d3690a2c03fdc713a241d2c56875a837de27262273728110ca55174eb09f88203a845b7f8104e45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015f00ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ea480607fa29df4d8ea8f8e788bb276159a8a61ba86ba14af483d651548e470156721b4da097ecb6ebc2303127ac2fdfe3eb1c00eaecef6eec40e498b17e00954e45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016000ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020fe360ca0152fecaacd045ca85a2bf08869cffdec799fdf64bea325b6532ad64227ce8d66be0c73025af9cfd24fc7245fad97357f8716eb38e8335f3a4e54c5c34e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016100ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ec427f7fb74c568fe04fdb414ffbf8b3c8b1e8c206a36024b012b057da73da690e62a987c35cfae251ac11f3d12957681b9a867bcd0bb0702d459a867ecd1d824f45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016200ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020245772e5852eb6bd20111392df098739d32b5b8a50377019787ece224254635563c6200669e2682bed224fd2b0bc68bf644af5098341a6ededf58a601d4fac204f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016300ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002047bd456d0d95607b24b0e927b639c8b7775803dedd7cdeb4b4a7dc8070179d271989230bf9b5397de410a9a294f7540c716753b74a7def0d00db84fef128af474f45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016400ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020de64fd4e9217b8456df1420b3effe314f40205800426a04070b71eabe9b2b3248290185184f3c2d9a243a1daddb4f17055a2749dbc0ab22cae7bfd791479f6034f45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016500ffffffff0200f2052a010000001600140544f594aa1610ff55e0797eeb4eb15cd07601cf0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000205ed61888928b352319efb1d85d636291a19ae45c55c4bd46f2a0f3d7a7512e71ad10099b91166668d725b5799ce29611347bf3118153be04971656fd3f0d35394f45e767ffff7f200100000003020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016600ffffffff021af3052a010000001600146a66b1bffe8368689cd695771ada2d78585c45330000000000000000266a24aa21a9edf9d7107703e8bc34556aee02bdc2c3b8eeea905deabf4e46a99528a5a733850d012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101121ed0ffdd5a197230c7b58dd7512177ba827afeca6c2c82ecda3519566ac83d0000000000fdffffff02f36ce72901000000160014982049ddf15138edeec1e5683c033ff8b63f7cc680841e000000000016001401fad90abcd66697e2592164722de4a95ebee16502473044022062107661a713637320a916de5a7eb7537706654f52188d286686741e7c9cf85a022063f0be207245a0a2a180c9ec2e2929dbb306ac3f115cef35d8f0148dbd0abbd60121032d8f3acac06981164dd33a38b5516f91520533c7746ab2f99279d48d1473d80e6500000002000000000101aa8b92c30cc63741018132abc34fc643c95ff6979390075c8670239c8da257410000000000fdffffff02e6e7c82901000000160014fad20f85fde37b24657a810c6730102e72ca699980841e000000000016001427213e2217b4f56bd19b6c8393dc9f61be6912330247304402201765295e2b53c15f50dddc82138e3190a98e368292fdc3d39fa77f2ef249a3820220253efe5c741e4531d9ca0414a65187965e2aca857ee152f331aac8893520c8a2012102529a967625c45f08195978925fa5b101d75db08a009f939e97d52ce9c7b74d2263000000', '00000020f5367ff88080f00f5ca8ba81ceeb5fddb974aeeb0eaf97c65f6fea352782b073a640a845f26e8cfd1e6d9e18a504cd871da0090f38b04066c96d30f194425f334f45e767ffff7f200000000003020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016700ffffffff027e18062a01000000160014a50a98c97a28195e9cab985d29218613ac9253770000000000000000266a24aa21a9eded976f675d4eaaec239ab7107adcd76964881d7c48cec52a265252abd224db9f012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101aa8b92c30cc63741018132abc34fc643c95ff6979390075c8670239c8da257410100000000fdffffff0240420f00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd012f0f000000000022512063ffee4ea7d51e6cadf9086e286a2527922aaa25b8c53aebf32fa32a0a627f5a0247304402200b13d9931afe81cd1b80495552eb16c74d7be8d0aa2d81241d924f4f2936cc4d0220749cc939eee907b6fedaf1426a0473a12568bad5b531f463132eedeb53f15524012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf6600000002000000000101594101f10f4e99a8917d2254d2bb769d2c8dcb3dc87a18358daa3d16c2449bcd0100000000fdffffff0240420f00000000002200208698658a01efb001e1cc4df6a8b6f3adb461fa3e679385fdaae400bd73996b32012f0f00000000002251208a16c01895ce90fb7b33bede1ceb6e390d13e453836b33413b5d6c608037616a0247304402204f60d329a4189e60a4f836a8257e37c7c33cb015d7a2208bd9e32a9a301ecc0e02205ad318b476744af50545c4b0674108b35c1a14d5b6f4ac2a2e082bf81698900801210207ec2b35534712d86ae030dd9bfaec08e2ddea1ec1cecffb9725ed7acb12ab6666000000', '00000020b17c929516b801d383bea1afca1fc02d024943a484ec59800a277cc0268bc96b1e7ccfab9bc76f42e5c198f8aaa16a967fe1a612f9cb3350a3f5dffb4fdfe3f85045e767ffff7f200200000003020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016800ffffffff022c02062a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ed04db5647ee6c59935b0df8bb1753eff47e0d9bad2ba51b413ffd7ef5a62b32970120000000000000000000000000000000000000000000000000000000000000000000000000020000000001015124f03a8c61ace7ca9932c89982c34a2ae7153145ec168f96344a783e6e246f0000000000ffffffff012a3a0f0000000000160014ba764c66bc9632a09388cb9558d17f7257a0e9d5040047304402203282dc395fb1f6c5ffb10aabfc55eb0a0f67b8aaa43aa11d0ab28bb8c697ddee02206b6ebd704b7705aaccf93844b176489e45e5994f18983d66f555ea82c9509c0f01473044022057a2551b9122960fb8182044afabfef7e09858b02143d50d3239e333a0ff64a502200d2ac549bf0c2f34da42136fb6354f40efad4e6068acdf097152ace877c61c9b0147522102d595ae92b3544c3250fb772f214ad8d4c51425033740a5bcc357190add6d7e7a2102d6063d022691b2490ab454dee73a57c6ff5d308352b461ece69f3c284f2c241252ae0000000002000000000101090ddae2714f734ead0f10bd4daaf5f02d936e3a51baeb94e1e198ea1178198c0000000000ffffffff012a3a0f0000000000160014071c49cad2f420f3c805f9f6b98a57269cb14150040047304402204b5d89aa633bb2f374e96f223618fdbef3548d8ec76d28ca723568098c9ea79802200688707c3a0f10cb6e7654858644d2fea2c17e43419f912a1fe9efaa22a7f2ee014730440220509cc2e94da95888cf0b4fe7d39aed0caf8c534cb84d7730528bd26b942f5ab902205d224e589686de10ca75e91fb9cd5942a68af67db1b3e7413c47e7f2bd64430c0147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae00000000', '0000002017dd07ba111707184f7e00f50b04b47b631f68131f2449efe7b48ff2a1b2045a86e925fd07fbc17df48648500fc93e29ea197f35f016a38e5c185007b5d2a3a55045e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016900ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020474f8bb6f27e2aa3328e239ec337c336ad0df73761af9093ebed74a8fec8020c37d1cb671915d13f14743540bf609b83eeafa289912d02cc64f0b1f20c32c23c5045e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016a00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002040c0ceb4b1de3ce6e1480e26c050646706f7cd210a35a6fc77102f06a2763e291e8a81d503e40a0ef0d8ef3b928e91e07d6c339a5651d324c3aa4ae5d28eb62a5045e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016b00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002024467c8a3801d4d43bb218b14fc55c9f63a898e8950c1d2dc9e48fdf4d090b5961d1cf953f7bb40cd75cc82955ff5a51f3e93bef270b2ac89b4ad53af07bc4da5045e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016c00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002009fdc4cb14d1a5add8d1c2dee11a1fce112ccf31e3bd37b0c0ec515a034a795392c4f42ee282a124f133d3954fefad6d76b674d1c47171ecf456d473c075c70b5045e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016d00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020398c9e3124bdf9e62ea492d0c992cc9b787c587d02f4b8c3f321f55efbf274728f2793a671bbfbcfc43b1adf3ecd29f2c4e53729dcd89ba3f7dc870fa3854dca5145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016e00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202ae1c7f5a9ed36967988734a4dba1a1166012c156ab72a430f8a9b8c34489f1532676376f9728fb6c9cf5d6372ec87d1deca0c0d7748d4051767dcd0b8a9b02d5145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016f00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020c2d72e960af6f011878d1e1f8ba3ad36d2b0820e9d290108f5fbb536a3a3995c94cf21609e9f30c371f9fbc1c0802ade0a24421e88c12bfd5a4117f49456d8275145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020bc41fc0dd3fd525af0625a0e89ab4d171980916767a7f5a9b6e6914f19c7b22d128810ac08156d6219ddfc00f12aa66c217d1a3dcfee52ee8d6e968c66e1b7655145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017100ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002060c9ef09223ce6c7516ee7b54e6a62ce8bceaab5a35b0ec463e30760362db664e34f33604bacf782dbe6a167b9714ed252b0f0ca28b19630137a65e7d46522945145e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017200ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020be0b41d357fb6c22d5f1f0dfadab28dba6c37b072024d0130cb0e0ec1df51a2b5cfe5c8f96ede90782a17fab4838884ee32dec55a82d43a3c1849350b6b78bf95145e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017300ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b0a8bb76d1328d15877946845e8545b94702bbaddb838da7aae84968d078a009468c98884e153b97b6aa5e39f46fd59f96f1b277ecd4300da791a981a4d31e9f5245e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017400ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002012f958a63852535164f1c16d95eba199acb359e1c9b1bb80eb49073bf8a3f869a2757578fe6075d4f0c90d406da080bc88870571169ad2c90ffb366fe84346b65245e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017500ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b39ef61835e31ee4209a20c07d61865b5a6d06c97916a952ff649037a0655b1c7f8ec0b00bb7bf9eb33a363f88e3480ef24c13c1285999a9def57f3484bec9bc5245e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017600ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020dc1685373f0ef48e5099f4c8cd12fa9133f71b7ec23bc165922a793aaaf61645d9d5000644b3a00091235216393430d104d66aba13df66b4b757e4ed01cbcc1c5245e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017700ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020a112806a01c656db35fa021b979cc48c1e929c5e8c98e811aac194737d65755ae3da1393891cd88a50acc5f9cdd1868120b616072976dc47a7dba7191959fa265245e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017800ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020cbe8dbdbd5bfd9443a048e50af5705d958601d63c46d04cd81ec11b220a4406c86930557e168f12def307992b5cec2185a75a190634f3dd402f1bd485b8bd6705245e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017900ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002012a8ca7721f80a55db15cddf7370f43c4a60082f60defe3ddbe978bc4a2d125b726a244fb370c5fc0def3556c4d7d2e23e0b252cbcd88619b6afc3f2774fae1f5345e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017a00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020be154f6c75dbda8161ef8f4f259b1e296dfc3aad8f21c1980064809c7c7f966f0c621bb4fd1f62f2b163fb497a8d25f5e7fd058904d0363d652bd15bfb3df9e15345e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017b00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020506a98d1afd6265b7705a80c338eeea9f7a24c946124ea96d23aa5af79bf1f3e04de253c09d40efd70920e73f1d14a34463dd0969b24e0a092f71177e6f7d0855345e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017c00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020178d05c02adfd564a4a2d1b8934c1cc72e6b61b3698194f58e5a2d171645d32c8043d16a43c399985018abc0c6f8d7c73c2ed226cbd523c0d4aeaecb42a4801a5345e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017d00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002035bcbd7497b0844507eb20ac1031c1b373e20d183184bc95bac48b175e74ed571c671387f330e37f64b7c5c507b183516cd8d12d387f6a44a72d5b1d43cf39d65345e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017e00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ac9c82e0e6b6669634df96486c7c4a2fe343e2cf18d55f5949c669583391b0647ac43806dd5ca67b39293ea22e64b783d682099b3641adc84484d50dd08f2d3e5345e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017f00ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020b318b5efbc31fa277c36f8d0e3d7b3841e6fe60ac26a0170236176a7fada93082849a03ae5161a917225029da51529e6ef8b92807a58ed6cc4b8c18bdbfa08935445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402800000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020959448c7dc9e5d511787aa9fe79a86511f22fd855872c5f40608ea7a3234684b5c541667cbc697855759573da2ba21bd77310dbf0671e7a2ea34260ffca5d6475445e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402810000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002063251e8e655ac6552b816b04e63a2b7a2807e71586d1974eb7ffdaa84507ed5e2048dee1eae334b48e2f1a125e47bff73cb5a280091849a739a73fda601364805445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402820000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000209792edd5fbb152812148da53084fa2e83a0b4cabbebc02d5e364ad15bdcb8038f0adf65f81bed42b6a9eecf6342872096144c3069bee6495195ed6a41249e77e5445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402830000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000209c8315e2c8c0510b76fe60854466a707d5a52f7df8538dcdc328f1db3b58ff6af12015d5a9bfe4c853f98fe35662f4782f5e0e8781bee16111e8653feb460cc45445e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402840000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020d85967913da39f5ac0e163f89795fb9813e9efac4af9cfde9d151d3e0b977958bbe91e6e214cc1ab3805b095d5a7ce176b86506fec47a673b082bb3525511ad55445e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402850000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ce1166ce40402ac786ccffbb3911c75155afe5b3d702742ac074794874772e1e9cf442623955f5f51409d259e0f112c64a751e01ff7264286a4a3c76310d17125545e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402860000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020112af4801eca6be7c1d5566c35d86e42ed0c7a93776b5760c91c093571f28a24399ae96bed6df9f309b68e970529c117f2f78a812b6505881808709550ed94b05545e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402870000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002017f7440e212cc64b1d343535ccce03d20a13d0bbcafc0730bdf890580d46df0c98c6cce0b18b45275a19543b192802f4988c168c8513ab56f5854f1cdc9457ed5545e767ffff7f200700000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402880000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020818d56a56b89301c1f81c7b73270ff2dcedf894d321b266e38a961c99caba438e70e2d41ac032e66e4971ba77c376073a1340e91d283726e616d0ff4a55f2afc5545e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402890000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000202005fdbbe76ee95acc24295138937f5a92144985e74b876b1fadfe68cbea05362fd13b52114f537b6008c46927374c7d0da1d5ff90efdf9091a6980d0dc02f555545e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028a0000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020c205b1d6c0d3e58288e396850a6a4b1404ba6b4eeee25fc13848c61e3629485ab9e4ad251e22f3f2b3ac3ffbe1e3ddaff0f914894c30152d57b38c764a2621685545e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028b0000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020ae9a8ba221d8d9adfd4d04557cdcb4e8069cb814f70f76a150b5a7a23f2506044468febe96990db1ceb20754b60e2bcda1ae6910ce62bbadcdf80e2a0fd7c74c5645e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028c0000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000002080b8d3ae945f5a1717b34a545c775d24786d1d1b14beba3021a3c9fd40eae20258659c5e76303059e26da6ab80ece214d536bf7feaa6f33cc13a8aa8d27020f65645e767ffff7f200800000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028d0000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020f0da206c7f7c3f8e858ad849dfe920ec002d533bff3ed8bb7baa52287d44790bc81675085e4bde33c31e88155a821cec9a7276fd70f86fdd194dbe1c6aceb5dc5645e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028e0000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000020c2b7db111cd824b485db60706e14b8148b84f52011a6c5769878933c5060eb40aee9d7480c3a9dd888b6cbef15de3d8629ff1785f1f3c3a34d00f79359202cfc5645e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028f0000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003041243723cfd31809ea5d27f36335806aaf8ba2e94e830b1a6f1f1a75cdb6da1c2d6ff82369cb5e9796ea98a9f0c62027aa1dbf79a290bbbe6cda734eec79accc5645e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402900000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030399cb0cbb9cd70b52b4b3e474a977e746910fcdb2331fc9d9c8a0c7f73aea608648f749194729b1b59a96e14ff44f0dff68c507356497fb5494b826f0a1ed5605645e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402910000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003081bc77107b5f564b5a9932c9426ada1904537f4c6b5b44937c6c482cfe9d6d5bf1fc1d6314bc7f54d7385c08821c3cf018c42c2d9ca7cc550519e901597035dd5745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402920000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030c971d8e2d12d0c75bc4f32a82c0885062fdc0458be380fd3f062a9531bca7f50cfd4723752ae9a144dbef60dad39c2d96dc9ba90728b5e72d843de1408c706695745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402930000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003062a4e5825ca5494f99f5a1f18f7ed53aa0fbb95f09d114591e3ba7d56164e61167e814795233e88c9f8e89249d1b03b5ecf383f53caea23a57b782c1a2702a035745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402940000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030839daf2a34725eadac848f28becb2f780ecae6ee515e208a47252555dd2cbd2505fec8540c7295f26305ef8228fe641b31ff3e211c324b627beef19070ea55065745e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402950000ffffffff0200f2052a01000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030e538757582a20bb1a8057dc94d7f4bcedb61f2bb53352b1dba1eaf1aeaf6f31471acb322f6c6ad997f0f099c49ab5b86bdc1794c84d1cd404a94e3d8755dffc25745e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402960000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030f8f0e1a4e5404270428fb68ddc09d092746aba6b4c39acef662d5ed4cb2a88080906f2966780605159145193bca4e3222566a00bf3b3f5dd4b7316bc877947185745e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402970000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000302d8167258ed66540dfa5ba5880743b94de8ab83d27a7a6b7cb7050ee592acb47bd34d45c6583b4343529e80ef4ea69b987b3067ca230efbb372aa39017f6f4d35845e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402980000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030842c80a35ab51a45c31e10db8a54f6b67795a7f016dead1edeac77ffc5c2590123159a9672cc09f89e9c1d82babde1b5faef2a55bd73b8ba9d3a017dfc0b1a305845e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402990000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000302a39a59278b6d7bbb585c939cae3a0cc05a5ea89f23f4c65afa72510f7e0477fdcd559186a927939f96c4486240318c4e8dc0e0097eeab39fe6bed4153d9d96b5845e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029a0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030cf3db2b72f837d5861ffbb32424a9292f8d74db5e8d86d02a5a6c772f756d64437b9bb82b46d3757d1373519e3c87c393948b81b4335f57df9d21e7c4dad02b75845e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029b0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000309ec59b0696e186d1b93bc8f3fe4ff47ec625528f139ab1e1872136574ef44c7e35c844a2ccebe0d6f31831bfccb377d79c1b87bd04e3a99a51ac5706d0de5e045845e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029c0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003000595b83332c77133287b13c57587c1d26e761aaec3fb2ae08fd7086005e285494d1ac097c6d6293bbbb4781102d1a853b86982a56f3e2667eeb37f1da79a7ac5845e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029d0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000304ed33349728239cd8e2450d372b009c2c39629b9b7051832e836449a2fbcb2204c07a4fb38ec0bc0a0870c7e5892ebb0bcb89a1c84c2c4ca39f31c48b0bce5695945e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029e0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000303a1cd4c9e9dbaaada0692df47668ff0f9afb664b27a397719771dac6cbcbe310fc882af8e2f021f3c3a03f585ee8c4d588d804c207c368528075fef3ec495b235945e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029f0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030bb938155e78b937df5ce511538515abad3d12daabba0ce20ede9b1c7a332105ec0499736f903d1e7d217a3c7ffb6bbc52ee2440013d259877ea1783825f843d85945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a00000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030662040ff51f64777f7494d20347fbc1e57de01577c504f2685925ee5d8942c5361935420a0b607d4857eebc67aa8362a4a004c8178ab4b89dece24c619fabe9d5945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a10000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030024b6383f4faaee8a46abb46153916a4db66791e76b4cf755d2484b25737666f43d8c328003f5a2e31f2644430e44aa3b126ba1b50a9c7908855a6b8c417c5b45945e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a20000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000303d9e4b3cf26d748a7bc0b51d75f47b698caa5d49404df8c7a36960422b469a5477d2c7308de83f064016d046c2cc2dff8b1ba2fdeefee2766b5387a66be3141d5945e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a30000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003016821fbda3a7813aabd2eb519f4625724b36b51f79814477b92fd7c458a2ad63e6ba0bb30c9813a3654c24bd3b1fc547ebe0b1bd6d2ea91f1e35b4822c479e4f5a45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a40000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003006c9cc8172034c14a960a3fe23ce4ab1623396307c4e8c93673946717a484d7fe5755b64f4a14b92ec68e96369a646d201aa9e9bc2d2311b136edd517b7677bc5a45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a50000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030a4a711824183601892260b060d90cdb8689039ec511b4785f5ef30ffa4b2e025f2ccbfbbdfee7808cbdacd7bec4194c9f13b94fe5ddebad1a86450f2cc93a25e5a45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a60000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003028d1ee846d8bccd01719c99e0def4f1f4a86df320a508fbb6b320241a9a7087ace4b6680134bbdf63822a4d3197613c8ab1aa897988960375cd9302249ebfe925a45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a70000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030ae7ea95fa9b43b206738c45c605a6611d5113f7b754a995e3f87c2dd10ff786360eb90fb2524f3be5fe1faef5dac0da7ace6f171ff566d3d54bbaf45b49cb70d5a45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a80000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000303ebcbfbbda57e0fc821764a8534b1e4c02450ed7262f809577722d46f7eabe27525b7a346619caafc949d4e2787ac4cd1ca35c0df75d5dda7560ab27709bd2ca5a45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a90000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030ee947752312f9115ea79a5187ba7c380af515b4b2754b229ada6794f7e719e418ee958de6ca1dddecef8fcc9ad765f3d2cfedb34f52be875ffb3fd9e20d0dd725b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402aa0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030ef06d81b99c621541533f4804f7b8645270bf69c0bc594e73453e493cb0b8b29165d399502a3d21cc1abc525a4f9c8be987c97913e6a4cb3a07f2cad962b3fd05b45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ab0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030c7dfee6970ae91486edc4415eb99cd03b8f0c3f36926915db7f01b13c069d027ec3f893af889af4cf417eb67065fcec3b58c54bc59f133006991f468e0cb94655b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ac0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030a456e513b80f842e98deced1cd507adf8e464d6c7504f1eb518548fd8dbce40c35ee412935da982bf45a17fa0f1b03dbbd43686323f4c4fdea1d24de09b948c65b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ad0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003076c26c3d94b09fda94f8d4e4281fe2fdc37618a324c11425befa5c1765919d37dd4640708b275b107d6f73c72f787d12498f0737326f228eca5dea4da47d4bc85b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ae0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030472c1af61662f83a21a4c64667e9d51ae0c58ce01c901878de3f82a9c953f1154e921ac66b4ef47398156a1221c17fc807ee716b3b145d4f3e52c0e0f4a6f3235b45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402af0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030b67bbc468af152cad458eebd674ebb426df002501dced9d768b1259e564645028c022328bd4acd790258e727526e6752afb0e712ac648abde199e0a3304d57f05c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b00000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030200621e8e33ec97e867f3ea1cbffffd3f294bf8fe1cf0692d0057ea2b919ec36221e35c58a2ac55440ee09bc9f0e311f4fb663f0fcfc0eada2600677e469401f5c45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b10000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000303b8b015859940691059a2e954c53204e85afb3a4ae1d32ede19971aa5d2fbe52cfa4ba2177ffb2b021c30320f89d0f910bf44efc07067114335780ba3f10bd765c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b20000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000304cfa59583423a05b452d15b985c2be9d3df88fcbdd031f96e8ad9d51e9b2b3441beffcee4d4c244e1e4ce7094b31646c6cc5567129082046627bb39e5310fe3c5c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b30000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000301e1e3efd764ddc5011f48108e89a163d50f50e29a377580507d803539fe052071d1a673c9b262898295d243626f5877b909d4598d91d13c75f082224bbb1b9055c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b40000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000305bac3ad01b70bb74f6c49063e1b818d39ff3366eddac4f7be9b2684883bca74bb6297f1767ccd20ddc3214e45b31ae868d15b520f05e4bd67b88ad28de08fce45c45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b50000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000300d7ca8158d5fe3a982b452b1d60315e32a92ee4d31b8dc3dcbe133333077c97e2758023341f0424bcfd5ab9940df921e88daa2aea0a13cb84aa6c4ec13d532015d45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b60000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030cce8fd6ca01c2112d6f6a0e2052002e9f71cdefff9b6cdf76547cb1f3a46af615f414285c888f66d5d6240b886287726ecbd5921b13acb2119e67805bb2d56705d45e767ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b70000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000301f0040ea70cf5a01e73546e86abdf30ba200c075968052b5e4418230d4acc44be05fec05e27d85f08438b0eab8a752b9b2733d922a377264c138ff059374bb595d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b80000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000309670a5b4400a07a83489bb2a1d24f4210417eebc39cabe880d2282ec384eee69b2735c7af36ee348970ea85cb9190bc48815a9209eccc537bfc54794cad6a4b35d45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402b90000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000305e6e7740529202f83cd844d3e0189d521a67334e96d356ba52525ff6fda3ab0c5483d2e59b5c73967fb844c59f96072098276b058a63d065830a3ebb4d4123595d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ba0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030474f309999d613e1de4e2b3ba181c0d2e8ecfa4d8310bc16094f9cb6d92e514658b16873f8d004be021fe039cf789ac456478117c7a6919c54a49ea6729d3e1c5d45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402bb0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003046089a2183b7b8419ac72919206d16b699975dbd85d3a4e34773af3115e21f30753e4df9a3a59c8be175866e7308443f2013ced01c7d6bdb7edc9bb850b9c5325e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402bc0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030bd0f28f06326941da6fbe578d7ad7549a37889ea6126471d7314de01eaebab21d6810504e2f55e89ebc0865310c7f1f1d55bf0b806825fa82787d4348141ec875e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402bd0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030a18d4637819250c31886aaa3ea89f7aff41855a9042340cf60b4b9456b6e7742b00fe5bd78b3a32c9da95eb99b7abfcb592a76cf8b34761c485342eb700b24185e45e767ffff7f200500000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402be0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030e9cb81ab54178bda14a8395e8f294c16d6e907e05b5f6b67f9fa79b4c7d0c86c33ed95c62e55c6235eaeb393d8ee6d426d56bf5b7d0d1190a8de8574524c7a4e5e45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402bf0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000309c90bb876b7f9a8cf5f162c4d9ac5a2ba20d65aecc65d3c5280de23d71acb57148c0ba0114bdf595a5c9dcdebcf922d46aa1057f8075e2168b3abe4d04ceca5d5e45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c00000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003031d701667675f5c9e2a8c143408dc074423d19ad6f410151972ee601de19921b2c4997f71d7d702720598f85730b126d66ddaa65a325ec75cb64bf865bb3f9d75e45e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c10000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030ec1b69c90796b5e7dedf4fac5bfaa38b08986a024cc81e252399d01452aece1ba9ae7a787e60e96a4ec00df22d513c2ec3b6bcf2d819a62b9a69fd4c16ae0ebe5f45e767ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c20000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030da4f5e26be854bcccfc3efe8bcc969251f9210ba7642fa7f531e70958ce1a53a2cd0938aeee842232c01f13e465fa19e1017b4e25401a3b512e284516675ef755f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c30000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030598fd05ef23fcbcf7c872b0c748c292874948c6842585d2419a6de5fabd15c1560018fbc99216e9e3cda1a7c1229975ab8228194bb4d4b2a9d5b1fc9792644325f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c40000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003039fbb34ad9e86a1ef54a9f7221dfd6aab1a9a93911baef457068d1c3880c594234b10d41685b1ef92b9a171e4e004f3d70d8c5b9b26c2542f96bdc5a292698ca5f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c50000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '000000306a39d1647473dc49f0e78278335dbc0418d91904ce473d824e66573a835b2d0262f7e36c68ad0debdcd31faa63810dc891834c0b8f136029a2c10d9ecee526175f45e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c60000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030253aee6ae859e35bed50d0b4e74463c3c30cea7c484f108379af5e00888bdf222a7169c0bae73b50004b1ad14d968ee0505a5ac40c1400fca17978b5479329465f45e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c70000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '0000003087e40026893cf19f73bcdaacb2adf1c5cc544abc2cb8ab7af4a3943f94d01a35578955ee09ebfbe14d75345d4d61499c39817542f32c18f2dec4006ae9ef5d8e6045e767ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c80000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030bea2746a48f9ad44a4857546914e4402c62d338e4b1e62699a0175da681f4a0a201e6181e3cddbe84b0b3dca0f97154792ead40dd174f4c5bdaa4574dffec38f6045e767ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402c90000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000', '00000030ad9a4d078baf27e222db419923bff2844fb2bd947951b71d585219c9d49f075304a69461d2decc1155ad72a3e725dd4ec2f321cb13f07a8815349cccd379bc0b6045e767ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ca0000ffffffff0200f9029500000000160014cbe7f8ee3e6133b9f975501d7fe827f6915ec0910000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000']
    bitcoind.restore_blocks(blocks)
    l1 = node_factory.get_node(dbfile='l1-missed-p2wpkh-CLOSINGD_COMPLETE.sqlite3.xz', options={'database-upgrade': True})
    l2 = node_factory.get_node(dbfile='l2-missed-p2wpkh-CLOSED.sqlite3.xz', options={'database-upgrade': True}, broken_log="Potentially missing 2 outputs from previous closes: scanning from block 103|Rescan found [0-9a-f:]*!|Rescan finished! 1 outputs recovered.  Let's never do that again")

    # They should both see the p2wpkh outputs.
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 2)

    # This can actually take a while for 100 blocks!
    l2.daemon.wait_for_log('Rescan finished! 1 outputs recovered')
