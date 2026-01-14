from bitcoin.rpc import JSONRPCError
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from utils import (
    only_one, wait_for, sync_blockheight, mine_funding_to_announce,
    VALGRIND, check_coin_moves, TailableProc, scriptpubkey_addr,
    check_utxos_channel, check_feerate, did_short_sig, first_scid,
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


def good_addrtype():
    """Elements doesn't support p2tr"""
    if TEST_NETWORK == 'regtest':
        return "p2tr"
    return "bech32"


@unittest.skipIf(TEST_NETWORK != 'regtest', "Test relies on a number of example addresses valid only in regtest")
def test_withdraw(node_factory, bitcoind):
    amount = 1000000
    # Don't get any funds from previous runs.
    l1 = node_factory.get_node(random_hsm=True, options={'log-level': 'io'})
    l2 = node_factory.get_node(random_hsm=True)
    addr = l1.rpc.newaddr('p2tr')['p2tr']

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
    # BIP86 wallets use P2TR addresses
    waddr = l2.rpc.newaddr('p2tr')['p2tr']
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

    # Should have 6 outputs available: 2 original unspent + 4 change outputs from withdrawals
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=0')[0]['c'] == 6

    # Test withdrawal to self.
    l1.rpc.withdraw(l1.rpc.newaddr('p2tr')['p2tr'], 'all', minconf=0)
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
    unconfirmed_utxos = [l1.rpc.withdraw(l1.rpc.newaddr("p2tr")["p2tr"], 10**5)
                         for _ in range(5)]
    uutxos = [u["txid"] + ":0" for u in unconfirmed_utxos]
    l1.rpc.withdraw(waddr, "all", minconf=0, utxos=uutxos)

    # Try passing minimum feerates (for relay)
    l1.rpc.withdraw(l1.rpc.newaddr("p2tr")["p2tr"], 10**5, feerate="253perkw")
    l1.rpc.withdraw(l1.rpc.newaddr("p2tr")["p2tr"], 10**5, feerate="1000perkb")


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
    addr = l1.rpc.newaddr(good_addrtype())[good_addrtype()]

    # Add some funds to withdraw later
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)
    # This violates the request schema!
    l1.rpc.check_request_schemas = False

    with pytest.raises(RpcError):
        l1.rpc.withdraw(destination=addr, satoshi=10000, feerate='normal', minconf=9999999)


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "BIP86 random_hsm not compatible with liquid-regtest bech32")
def test_addfunds_from_block(node_factory, bitcoind):
    """Send funds to the daemon without telling it explicitly
    """
    # Previous runs with same bitcoind can leave funds!
    coin_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1 = node_factory.get_node(random_hsm=True, options={'plugin': coin_plugin})

    addr = l1.rpc.newaddr(good_addrtype())[good_addrtype()]
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

    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('all')[good_addrtype()], amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = []
    for i in range(9):
        outputs.append({l1.rpc.newaddr('bech32')['bech32']: Millisatoshi(amount * 100)})
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


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "BIP86 random_hsm not compatible with liquid-regtest bech32")
def test_txprepare(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True, options={'dev-warn-on-overgrind': None},
                               broken_log='overgrind: short signature length')
    addr = chainparams['example_addr']

    # Add some funds to withdraw later
    for i in range(10):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr(good_addrtype())[good_addrtype()],
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
    unconfirmed_utxo = l1.rpc.withdraw(l1.rpc.newaddr("bech32")["bech32"], 10**5)
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
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
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
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
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
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
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
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
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
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
                                   amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    # Build a PSBT using all our inputs, externally
    inputs = []
    for inp in l1.rpc.listfunds()['outputs']:
        inputs.append({'txid': inp['txid'], 'vout': inp['output']})
    addr = l1.rpc.newaddr('bech32')['bech32']
    psbt = bitcoind.rpc.createpsbt(inputs, [{addr: (amount * 3) / 10**8}])

    l1.rpc.reserveinputs(psbt)
    l1.rpc.signpsbt(psbt)


def test_sign_signed_psbt(node_factory, bitcoind, chainparams):
    l1 = node_factory.get_node()
    l1.fundwallet(10**6)

    psbt = l1.rpc.txprepare([{l1.rpc.newaddr('bech32')['bech32']: 10000}])['psbt']
    signed_psbt = l1.rpc.signpsbt(psbt)['signed_psbt']

    if TEST_NETWORK != 'liquid-regtest':
        # FIXME: ideally this would succeed, as a noop.  But it shouldn't crash
        with pytest.raises(RpcError):
            l1.rpc.signpsbt(signed_psbt)['signed_psbt']
    else:
        # Non-taproot works fine.
        assert l1.rpc.signpsbt(signed_psbt)['signed_psbt'] == signed_psbt


def test_psbt_version(node_factory, bitcoind, chainparams):

    sats_amount = 10**8

    # CLN returns PSBTv0 and PSETv2, for now
    is_elements = chainparams['elements']

    l1 = node_factory.get_node()
    bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
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
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('bech32')['bech32'],
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
        bitcoind.rpc.sendtoaddress(l2.rpc.newaddr('bech32')['bech32'],
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


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "BIP86 random_hsm not compatible with liquid-regtest bech32")
def test_txsend(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True)
    addr = chainparams['example_addr']

    # Add some funds to withdraw later
    for i in range(10):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr(good_addrtype())[good_addrtype()],
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


class HsmTool(TailableProc):
    """Helper for testing the hsmtool as a subprocess"""
    def __init__(self, directory, *args):
        self.prefix = "lightning-hsmtool"
        TailableProc.__init__(self, os.path.join(directory, "lightning-hsmtool"))
        assert hasattr(self, "env")
        self.cmd_line = ["tools/lightning-hsmtool", *args]


@unittest.skipIf(VALGRIND, "It does not play well with prompt and key derivation.")
def test_hsmtool_secret_decryption(node_factory):
    """Test that we can encrypt and decrypt hsm_secret using hsmtool"""
    l1 = node_factory.get_node(start=False)  # Don't start the node
    password = "test_password\n"
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")

    # Write a known 32-byte key to hsm_secret
    known_secret = b'\x01' * 32  # 32 bytes of 0x01
    with open(hsm_path, 'wb') as f:
        f.write(known_secret)

    # Read the hsm_secret to verify it's what we expect
    with open(hsm_path, 'rb') as f:
        content = f.read()
        assert content == known_secret, f"Expected {known_secret}, got {content}"
        assert len(content) == 32, f"Expected 32 bytes, got {len(content)}"

    # Encrypt it using hsmtool
    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool(node_factory.directory, "encrypt", hsm_path)
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    hsmtool.wait_for_log(r"Confirm hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"Successfully encrypted")

    # Read the hsm_secret again - it should now be encrypted (73 bytes)
    with open(hsm_path, 'rb') as f:
        encrypted_content = f.read()
        assert len(encrypted_content) == 73, f"Expected 73 bytes after encryption, got {len(encrypted_content)}"
        assert encrypted_content != known_secret, "File should be encrypted and different from original"

    # Decrypt it using hsmtool
    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool(node_factory.directory, "decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"Successfully decrypted")

    # Read the hsm_secret again - it should now be back to the original 32 bytes
    with open(hsm_path, 'rb') as f:
        decrypted_content = f.read()
        assert decrypted_content == known_secret, f"Expected {known_secret}, got {decrypted_content}"
        assert len(decrypted_content) == 32, f"Expected 32 bytes after decryption, got {len(decrypted_content)}"


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', '')
def test_hsmtool_dump_descriptors(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l1.fundwallet(10**6)
    # Get a tpub descriptor of lightningd's wallet
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    cmd_line = ["tools/lightning-hsmtool", "dumponchaindescriptors", hsm_path, "testnet"]
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


@pytest.mark.parametrize("mnemonic,passphrase,expected_format", [
    ("ritual idle hat sunny universe pluck key alpha wing cake have wedding", "test_passphrase", "mnemonic with passphrase"),
    ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", "mnemonic without passphrase"),
])
def test_hsmtool_generatehsm_variants(node_factory, mnemonic, passphrase, expected_format):
    """Test generating mnemonic-based hsm_secret with various configurations"""
    # Only set hsm-passphrase option if there's actually a passphrase
    node_options = {'hsm-passphrase': None} if passphrase else {}
    l1 = node_factory.get_node(start=False, options=node_options)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)  # Remove the auto-generated one

    # Generate hsm_secret with mnemonic and passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list separated by space")
    write_all(master_fd, f"{mnemonic}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, f"{passphrase}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"New hsm_secret file created")
    hsmtool.is_in_log(f"Format: {expected_format}")

    # Verify file format
    with open(hsm_path, 'rb') as f:
        content = f.read()
        if passphrase:
            # First 32 bytes should NOT be zeros (has passphrase hash)
            assert content[:32] != b'\x00' * 32
            assert mnemonic.encode('utf-8') in content[32:]
        else:
            # First 32 bytes should be zeros (no passphrase)
            assert content[:32] == b'\x00' * 32
            # Rest should be the mnemonic
            mnemonic_part = content[32:].decode('utf-8')
            assert mnemonic in mnemonic_part

    # Verify Lightning node can use it
    if passphrase:
        # For passphrase case, start with hsm-passphrase option and handle prompt
        master_fd, slave_fd = os.openpty()
        l1.daemon.start(stdin=slave_fd, wait_for_initialized=False)
        # Wait for the passphrase prompt
        l1.daemon.wait_for_log("Enter hsm_secret passphrase:")
        write_all(master_fd, f"{passphrase}\n".encode("utf-8"))
        l1.daemon.wait_for_log("Server started with public key")
    else:
        # For no passphrase case, start normally without expecting a prompt
        l1.daemon.start(wait_for_initialized=False)
        l1.daemon.wait_for_log("Server started with public key")

    node_id = l1.rpc.getinfo()['id']
    print(f"Node ID for mnemonic '{mnemonic}' with passphrase '{passphrase}': {node_id}")
    assert len(node_id) == 66  # Valid node ID

    # Expected node IDs for deterministic testing
    expected_node_ids = {
        ("ritual idle hat sunny universe pluck key alpha wing cake have wedding", "test_passphrase"): "039020371fb803cd4ce1e9a909b502d7b0a9e0f10cccc35c3e9be959c52d3ba6bd",
        ("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", ""): "03653e90c1ce4660fd8505dd6d643356e93cfe202af109d382787639dd5890e87d",
    }

    expected_id = expected_node_ids.get((mnemonic, passphrase))
    if expected_id:
        assert node_id == expected_id, f"Expected node ID {expected_id}, got {node_id}"
    else:
        print(f"No expected node ID found for this combination, got: {node_id}")


@pytest.mark.parametrize("test_case", [
    pytest.param({
        "name": "with_passphrase",
        "mnemonic": "ritual idle hat sunny universe pluck key alpha wing cake have wedding",
        "passphrase": "secret_passphrase",
        "check_passphrase": "secret_passphrase",
        "check_mnemonic": "ritual idle hat sunny universe pluck key alpha wing cake have wedding",
        "expected_exit": 0,
        "expected_log": "OK"
    }, id="correct_mnemonic_with_passphrase"),
    pytest.param({
        "name": "no_passphrase",
        "mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "passphrase": "",
        "check_passphrase": "",
        "check_mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "expected_exit": 0,
        "expected_log": "OK"
    }, id="correct_mnemonic_no_passphrase"),
    pytest.param({
        "name": "wrong_passphrase",
        "mnemonic": "ritual idle hat sunny universe pluck key alpha wing cake have wedding",
        "passphrase": "correct_passphrase",
        "check_passphrase": "wrong_passphrase",
        "check_mnemonic": "ritual idle hat sunny universe pluck key alpha wing cake have wedding",
        "expected_exit": 5,  # ERROR_KEYDERIV
        "expected_log": "resulting hsm_secret did not match"
    }, id="wrong_passphrase_should_fail"),
    pytest.param({
        "name": "wrong_mnemonic",
        "mnemonic": "ritual idle hat sunny universe pluck key alpha wing cake have wedding",
        "passphrase": "",
        "check_passphrase": "",
        "check_mnemonic": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "expected_exit": 5,  # ERROR_KEYDERIV
        "expected_log": "resulting hsm_secret did not match"
    }, id="wrong_mnemonic_should_fail")
])
def test_hsmtool_checkhsm_variants(node_factory, test_case):
    """Test checkhsm with various configurations"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create hsm_secret with known mnemonic and passphrase
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list separated by space")
    write_all(master_fd, f"{test_case['mnemonic']}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, f"{test_case['passphrase']}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Test checkhsm with credentials
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)

    # If the original had a passphrase, we need to unlock the file first
    if test_case['passphrase']:
        hsmtool.wait_for_log(r"Enter hsm_secret password:")  # Decrypt file
        write_all(master_fd, f"{test_case['passphrase']}\n".encode("utf-8"))

    hsmtool.wait_for_log(r"Enter your mnemonic passphrase:")     # Backup verification
    write_all(master_fd, f"{test_case['check_passphrase']}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list separated by space")
    write_all(master_fd, f"{test_case['check_mnemonic']}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == test_case['expected_exit']
    hsmtool.is_in_log(test_case['expected_log'])


def test_hsmtool_checkhsm_legacy_encrypted_with_mnemonic_no_passphrase(node_factory):
    """Test checkhsm with legacy encrypted hsm_secret containing mnemonic without passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)
    seed_hex = "31bb58d1180831868fd5f562bb74659dca1e9673d034af635df53d677b9e5f03"
    seed_bytes = bytes.fromhex(seed_hex)

    # Write the 32-byte seed directly to file (simulating old generatehsm output)
    # Make sure we write exactly 32 bytes with no newline
    assert len(seed_bytes) == 32, f"Seed should be exactly 32 bytes, got {len(seed_bytes)}"
    with open(hsm_path, 'wb') as f:
        f.write(seed_bytes)

    # Verify it's exactly 32 bytes
    with open(hsm_path, 'rb') as f:
        content = f.read()
        print(content)
        assert content == seed_bytes, "File content doesn't match expected seed"

    # Now encrypt it using the legacy encrypt command
    encryption_password = "encryption_password"
    hsmtool = HsmTool(node_factory.directory, "encrypt", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, f"{encryption_password}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Confirm hsm_secret password:")
    write_all(master_fd, f"{encryption_password}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"Successfully encrypted")

    # Verify the file is now encrypted (73 bytes)
    with open(hsm_path, 'rb') as f:
        content = f.read()
        assert len(content) == 73, f"Expected 73 bytes after encryption, got {len(content)}"

    # Test checkhsm - should prompt for encryption password first, then mnemonic passphrase
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")  # Encryption password
    write_all(master_fd, f"{encryption_password}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your mnemonic passphrase:")     # Mnemonic passphrase (empty)
    write_all(master_fd, "\n".encode("utf-8"))  # Empty passphrase
    hsmtool.wait_for_log(r"Introduce your BIP39 word list separated by space")
    write_all(master_fd, "blame expire peanut sell door zoo bundle motor truth outside artist siren\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"OK")


def test_hsmtool_checkhsm_legacy_encrypted_with_mnemonic_passphrase(node_factory):
    """Test checkhsm with legacy encrypted hsm_secret containing mnemonic with passphrase"""
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Directly write the 32-byte seed from mnemonic with passphrase
    # Mnemonic: "blame expire peanut sell door zoo bundle motor truth outside artist siren"
    # Passphrase: "passphrase"
    # Expected BIP39 seed (first 32 bytes): 161d740bcfd3c5e2a1769159bee86868ab35e7544e83e825042a43b929ad950c
    seed_hex = "161d740bcfd3c5e2a1769159bee86868ab35e7544e83e825042a43b929ad950c"
    seed_bytes = bytes.fromhex(seed_hex)

    # Write the 32-byte seed directly to file (simulating old generatehsm output)
    with open(hsm_path, 'wb') as f:
        f.write(seed_bytes)

    # Verify it's 32 bytes
    with open(hsm_path, 'rb') as f:
        content = f.read()
        assert len(content) == 32, f"Expected 32 bytes, got {len(content)}"

    # Now encrypt it using the legacy encrypt command
    encryption_password = "encryption_password"
    hsmtool = HsmTool(node_factory.directory, "encrypt", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, f"{encryption_password}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Confirm hsm_secret password:")
    write_all(master_fd, f"{encryption_password}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"Successfully encrypted")

    # Verify the file is now encrypted (73 bytes)
    with open(hsm_path, 'rb') as f:
        content = f.read()
        assert len(content) == 73, f"Expected 73 bytes after encryption, got {len(content)}"

    # Test checkhsm - should prompt for encryption password first, then mnemonic passphrase
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")  # Encryption password
    write_all(master_fd, f"{encryption_password}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your mnemonic passphrase:")     # Mnemonic passphrase
    write_all(master_fd, "passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list separated by space")
    write_all(master_fd, "blame expire peanut sell door zoo bundle motor truth outside artist siren\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"OK")


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
        (["getnodeid", hsm_path], "03653e90c1ce4660fd8505dd6d643356e93cfe202af109d382787639dd5890e87d"),
        (["getsecret", hsm_path], "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
        (["makerune", hsm_path], "6VkrWMI2hm2a2UTkg-EyUrrBJN0RcuPB80I1pCVkTD89MA=="),
        (["dumponchaindescriptors", hsm_path],
         "wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#hjszq0wk\n"
         "sh(wpkh(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*))#u0t3u3xz\n"
         "tr(xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/0/*)#8e7pq23w"),
    ]

    for cmd_args, expected_output in test_commands:
        cmd_line = ["tools/lightning-hsmtool"] + cmd_args
        out = subprocess.check_output(cmd_line).decode("utf8")
        actual_output = out.strip()
        assert actual_output == expected_output, f"Command {cmd_args[0]} output mismatch"


def test_hsmtool_deterministic_node_ids(node_factory):
    """Test that HSM daemon creates deterministic node IDs in new mnemonic format"""
    # Create a node and start it to trigger HSM daemon to create new format
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")

    # Delete any existing hsm_secret so HSM daemon creates it in new format
    if os.path.exists(hsm_path):
        os.remove(hsm_path)

    # Start the node to get its node ID (this will create a new hsm_secret in new format)
    l1.start()
    normal_node_id = l1.rpc.getinfo()['id']
    l1.stop()

    # Verify the hsm_secret was created in the new mnemonic format
    with open(hsm_path, 'rb') as f:
        content = f.read()
        # Should be longer than 32 bytes (new format has 32-byte hash + mnemonic)
        assert len(content) > 32, f"Expected new mnemonic format, got {len(content)} bytes"

        # First 32 bytes should be the passphrase hash (likely zeros for no passphrase)
        passphrase_hash = content[:32]
        assert passphrase_hash == b'\x00' * 32
        mnemonic_bytes = content[32:]

        # Decode the mnemonic bytes
        mnemonic = mnemonic_bytes.decode('utf-8').strip()

        # Verify it's a valid mnemonic (should be 12 words)
        words = mnemonic.split()
        assert len(words) == 12, f"Expected 12 words, got {len(words)}: {mnemonic}"

    # Create a second node and use generatehsm with the mnemonic from the first node
    l2 = node_factory.get_node(start=False)
    hsm_path2 = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")

    # Delete any existing hsm_secret for the second node
    if os.path.exists(hsm_path2):
        os.remove(hsm_path2)

    # Generate hsm_secret with the mnemonic from the first node
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path2)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, f"{mnemonic}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    # Get the node ID from the generated hsm_secret
    cmd_line = ["tools/lightning-hsmtool", "getnodeid", hsm_path2]
    generated_node_id = subprocess.check_output(cmd_line).decode("utf8").strip()

    # Verify both node IDs are identical
    assert normal_node_id == generated_node_id, f"Node IDs don't match: {normal_node_id} != {generated_node_id}"


def setup_bip86_node(node_factory, mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"):
    """Helper function to set up a node with BIP86 support using a mnemonic-based HSM secret"""
    l1 = node_factory.get_node(start=False)

    # Set up node with a mnemonic HSM secret
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    if os.path.exists(hsm_path):
        os.remove(hsm_path)

    # Generate hsm_secret with the specified mnemonic
    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, f"{mnemonic}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "\n".encode("utf-8"))  # No passphrase
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    os.close(master_fd)
    os.close(slave_fd)

    l1.start()
    return l1


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_newaddr_rpc(node_factory, chainparams):
    """Test that BIP86 addresses can be generated via newaddr RPC"""
    l1 = setup_bip86_node(node_factory)

    # Test BIP86 address generation
    bip86_addr = l1.rpc.newaddr(addresstype="p2tr")
    assert 'p2tr' in bip86_addr
    assert 'bech32' not in bip86_addr

    # Verify address format (taproot addresses are longer)
    p2tr_addr = bip86_addr['p2tr']
    assert len(p2tr_addr) > 50

    # In regtest, should start with bcrt1p (or appropriate prefix)
    assert p2tr_addr.startswith('bcrt1p')

    # Test that we're using the correct 64-byte seed from the mnemonic
    # Expected seed for "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about":
    # "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"

    # Test that our BIP86 implementation follows the correct derivation path m/86'/0'/0'/0/index
    # Generate the same address again and verify it's identical
    bip86_addr2 = l1.rpc.newaddr(addresstype="p2tr")
    p2tr_addr2 = bip86_addr2['p2tr']

    # The second address should be different (next index)
    assert p2tr_addr != p2tr_addr2, "Consecutive BIP86 addresses should be different"

    # Test against known test vectors for the exact derivation path
    # The mainnet test vectors are:
    # m/86'/0'/0'/0/0: bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
    # m/86'/0'/0'/0/1: bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh
    # m/86'/0'/0'/0/2: bc1p0d0rhyynq0awa9m8cqrcr8f5nxqx3aw29w4ru5u9my3h0sfygnzs9khxz8

    # For regtest, the addresses should be the same but with bcrt1p prefix
    # Our addresses are for indices 1 and 2, so they should match the regtest versions
    expected_regtest_addr_1 = "bcrt1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0waslcutpz"  # index 1
    expected_regtest_addr_2 = "bcrt1p0d0rhyynq0awa9m8cqrcr8f5nxqx3aw29w4ru5u9my3h0sfygnzsl8t0dj"  # index 2

    # Assert on the exact test vectors since we have the correct seed
    assert p2tr_addr == expected_regtest_addr_1, f"First address should match test vector for index 1. Expected: {expected_regtest_addr_1}, Got: {p2tr_addr}"
    assert p2tr_addr2 == expected_regtest_addr_2, f"Second address should match test vector for index 2. Expected: {expected_regtest_addr_2}, Got: {p2tr_addr2}"


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_listaddresses(node_factory, chainparams):
    """Test that listaddresses includes BIP86 addresses and verifies first 10 addresses"""
    l1 = setup_bip86_node(node_factory)

    # Expected addresses for the first 10 indices (m/86'/0'/0'/0/1 through m/86'/0'/0'/0/10)
    # These are derived from the test mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    # Note: newaddr starts from index 1, not 0
    # Actual regtest addresses generated by the implementation
    expected_addrs = [
        "bcrt1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0waslcutpz",  # index 1
        "bcrt1p0d0rhyynq0awa9m8cqrcr8f5nxqx3aw29w4ru5u9my3h0sfygnzsl8t0dj",  # index 2
        "bcrt1py0vryk8aqusz65yzuudypggvswzkcpwtau8q0sjm0stctwup0xlqv86kkk",  # index 3
        "bcrt1pjpp8nwqvhkx6kdna6vpujdqglvz2304twfd308ve5ppyxpmcjufsy8x0tk",  # index 4
        "bcrt1pl4frjws098l3nslfjlnry6jxt46w694kuexvs5ar0cmkvxyahfkq42fumu",  # index 5
        "bcrt1p5sxs429uz2s2yn6tt98sf67qwytwvffae4dqnzracq586cu0t6zsn63pre",  # index 6
        "bcrt1pxsvy7ep2awd5x9lg90tgm4xre8wxcuj5cpgun8hmzwqnltqha8pqv84cl7",  # index 7
        "bcrt1ptk8pqtszta5pv5tymccfqkezf3f2q39765q4fj8zcr79np6wmj6qeek4z3",  # index 8
        "bcrt1p7pkeudt8wq7fc6nzj6yxkqmnrjg25fu4s9l777ca3w3qrxanjehq4tphz0",  # index 9
        "bcrt1pzhnqyfvxe08zl0d9e592t62pwvp3l2xwhau5a8dsfjcker6xmjuqppvxka",  # index 10
    ]

    # Generate the first 10 BIP86 addresses and verify they match expected values
    for i in range(10):
        addr_result = l1.rpc.newaddr('p2tr')
        assert addr_result['p2tr'] == expected_addrs[i]

    # Use listaddresses with start and limit parameters to verify the addresses were generated
    addrs = l1.rpc.listaddresses(start=1, limit=10)
    assert len(addrs['addresses']) == 10, f"Expected 10 addresses, got {len(addrs['addresses'])}"

    # Verify that listaddresses returns the correct addresses and key indices
    for i, addr_info in enumerate(addrs['addresses']):
        assert addr_info['keyidx'] == i + 1, f"Expected keyidx {i + 1}, got {addr_info['keyidx']}"
        # BIP86 addresses should have a p2tr field with the correct address
        assert 'p2tr' in addr_info, f"BIP86 address should have p2tr field, got: {addr_info}"
        assert addr_info['p2tr'] == expected_addrs[i], f"Address mismatch at index {i + 1}: expected {expected_addrs[i]}, got {addr_info['p2tr']}"
        # BIP86 addresses should NOT have a bech32 field (they're P2TR only)
        assert 'bech32' not in addr_info, f"BIP86 address should not have bech32 field, got: {addr_info}"


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_deterministic_addresses(node_factory):
    """Test that BIP86 addresses are deterministic and unique"""
    # Create two nodes with the same mnemonic
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    l1 = setup_bip86_node(node_factory, mnemonic)
    l2 = setup_bip86_node(node_factory, mnemonic)

    # Generate addresses with the same index
    addr1_0 = l1.rpc.newaddr('p2tr')['p2tr']
    addr2_0 = l2.rpc.newaddr('p2tr')['p2tr']

    addr1_1 = l1.rpc.newaddr('p2tr')['p2tr']
    addr2_1 = l2.rpc.newaddr('p2tr')['p2tr']

    # Addresses should be identical for the same index
    assert addr1_0 == addr2_0, f"Addresses for index 0 don't match: {addr1_0} != {addr2_0}"
    assert addr1_1 == addr2_1, f"Addresses for index 1 don't match: {addr1_1} != {addr2_1}"

    # Addresses should be different for different indices
    assert addr1_0 != addr1_1, f"Addresses for different indices should be different"


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_vs_regular_p2tr(node_factory):
    """Test that BIP86 addresses are different from regular P2TR addresses"""
    l1 = setup_bip86_node(node_factory)

    # Generate addresses of both types
    bip86_addr = l1.rpc.newaddr('p2tr')['p2tr']
    p2tr_addr = l1.rpc.newaddr('p2tr')['p2tr']

    # They should be different
    assert bip86_addr != p2tr_addr, "BIP86 and regular P2TR addresses should be different"

    # Both should be valid Taproot addresses (start with bcrt1p for regtest)
    assert bip86_addr.startswith('bcrt1p')
    assert p2tr_addr.startswith('bcrt1p')


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_full_bitcoin_integration(node_factory, bitcoind):
    """Test full Bitcoin integration: generate addresses, receive funds, list outputs"""
    l1 = setup_bip86_node(node_factory)

    # Generate a BIP86 address
    bip86_addr = l1.rpc.newaddr('p2tr')['p2tr']

    # Send funds to the BIP86 address
    amount = 1000000  # 0.01 BTC
    bitcoind.rpc.sendtoaddress(bip86_addr, amount / 10**8)

    # Mine a block to confirm the transaction
    bitcoind.generate_block(1)

    # Wait for the node to see the transaction
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Check that the funds are visible
    funds = l1.rpc.listfunds()
    bip86_outputs = [out for out in funds['outputs'] if out['address'] == bip86_addr]

    assert len(bip86_outputs) == 1, f"Expected 1 output, got {len(bip86_outputs)}"
    assert bip86_outputs[0]['amount_msat'] == amount * 1000, f"Amount mismatch: {bip86_outputs[0]['amount_msat']} != {amount * 1000}"
    assert bip86_outputs[0]['status'] == 'confirmed'

    # Test withdrawal from BIP86 address
    # Use bitcoind to generate withdrawal address since this node only supports BIP86
    withdraw_addr = bitcoind.rpc.getnewaddress()
    withdraw_amount = 500000  # 0.005 BTC

    l1.rpc.withdraw(withdraw_addr, withdraw_amount)

    # Mine another block
    bitcoind.generate_block(1)

    # Check that the withdrawal worked
    wait_for(lambda: len([out for out in l1.rpc.listfunds()['outputs'] if out['address'] == bip86_addr and out['status'] == 'confirmed']) == 0)


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_mnemonic_recovery(node_factory, bitcoind):
    """Test that funds can be recovered using the same mnemonic in a new wallet"""
    # Use a known mnemonic for predictable recovery
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    # Create first node and fund it
    l1 = setup_bip86_node(node_factory, mnemonic)
    bip86_addr = l1.rpc.newaddr('p2tr')['p2tr']

    # Send funds
    amount = 1000000  # 0.01 BTC
    bitcoind.rpc.sendtoaddress(bip86_addr, amount / 10**8)
    bitcoind.generate_block(1)

    # Wait for funds to be visible
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Create a second node with the same mnemonic
    l2 = setup_bip86_node(node_factory, mnemonic)

    # Wait for it to sync and see the funds
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) > 0)

    # Check that the second node can see the same funds
    funds2 = l2.rpc.listfunds()
    bip86_outputs2 = [out for out in funds2['outputs'] if out['address'] == bip86_addr]

    assert len(bip86_outputs2) == 1, f"Expected 1 output in recovered wallet, got {len(bip86_outputs2)}"
    assert bip86_outputs2[0]['amount_msat'] == amount * 1000, f"Amount mismatch in recovered wallet: {bip86_outputs2[0]['amount_msat']} != {amount * 1000}"


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_index_boundaries(node_factory):
    """Test BIP86 behavior at index boundaries"""
    l1 = setup_bip86_node(node_factory)

    # Test that we can generate multiple addresses in sequence
    # This tests the internal index management
    addresses = []
    for i in range(5):
        addr = l1.rpc.newaddr('p2tr')['p2tr']
        addresses.append(addr)
        # Each address should be unique
        assert addr not in addresses[:-1], f"Duplicate address generated: {addr}"

    # Test that addresses are deterministic - same node should generate same sequence
    l2 = setup_bip86_node(node_factory)  # Same mnemonic

    addresses2 = []
    for i in range(5):
        addr = l2.rpc.newaddr('p2tr')['p2tr']
        addresses2.append(addr)

    # Should generate the same addresses in the same order
    assert addresses == addresses2, "BIP86 addresses not deterministic across nodes with same mnemonic"

    # Test generating a large number of addresses to check for any overflow issues
    # Generate 100 more addresses to test higher indices
    for i in range(100):
        addr = l1.rpc.newaddr('p2tr')['p2tr']
        assert addr.startswith('bcrt1p'), f"Invalid BIP86 address format: {addr}"
        assert len(addr) > 50, f"BIP86 address too short: {addr}"


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_psbt_integration(node_factory, bitcoind, chainparams):
    """Test BIP86 addresses in PSBT workflows"""
    l1 = setup_bip86_node(node_factory)

    # Fund BIP86 address
    bip86_addr = l1.rpc.newaddr('p2tr')['p2tr']
    amount_sats = 1000000  # 0.01 BTC

    # Send funds to the BIP86 address
    bitcoind.rpc.sendtoaddress(bip86_addr, amount_sats / 10**8)
    bitcoind.generate_block(1)

    # Wait for the node to see the transaction
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) > 0)

    # Verify the funds are visible and confirmed
    funds = l1.rpc.listfunds()
    bip86_outputs = [out for out in funds['outputs'] if out['address'] == bip86_addr]
    assert len(bip86_outputs) == 1, f"Expected 1 BIP86 output, got {len(bip86_outputs)}"
    assert bip86_outputs[0]['amount_msat'] == amount_sats * 1000
    assert bip86_outputs[0]['status'] == 'confirmed'

    # Create PSBT with BIP86 input
    dest_addr = bitcoind.rpc.getnewaddress()
    send_amount = 500000  # 0.005 BTC

    # Use txprepare to create a PSBT
    psbt_result = l1.rpc.txprepare([{dest_addr: send_amount}])
    psbt_str = psbt_result['psbt']

    # Verify PSBT was created successfully
    assert psbt_str is not None and len(psbt_str) > 0, "PSBT creation failed"

    # Sign the PSBT
    signed_result = l1.rpc.signpsbt(psbt_str)
    assert 'signed_psbt' in signed_result, "PSBT signing failed - no signed_psbt returned"
    assert len(signed_result['signed_psbt']) > 0, "PSBT signing failed - empty signed_psbt"

    # Send the signed PSBT
    send_result = l1.rpc.sendpsbt(signed_result['signed_psbt'])
    sent_txid = send_result['txid']

    # Mine the transaction
    bitcoind.generate_block(1)

    # Wait for the transaction to be confirmed (blockheight > 0)
    wait_for(lambda: len([tx for tx in l1.rpc.listtransactions()['transactions']
                         if tx['hash'] == sent_txid and tx['blockheight'] > 0]) > 0)

    # Verify the transaction exists in the blockchain and is confirmed
    transactions = l1.rpc.listtransactions()['transactions']
    sent_tx = [tx for tx in transactions if tx['hash'] == sent_txid][0]
    assert sent_tx['blockheight'] > 0, "Transaction should be confirmed in a block"


@unittest.skipIf(TEST_NETWORK != 'regtest', "BIP86 tests are regtest-specific")
def test_bip86_address_type_validation(node_factory):
    """Test address type validation for BIP86 addresses"""
    l1 = setup_bip86_node(node_factory)

    # Test that 'p2tr' automatically uses BIP86 for mnemonic wallets
    bip86_addr = l1.rpc.newaddr('p2tr')['p2tr']

    # Test that we can list addresses
    addrs = l1.rpc.listaddresses()
    assert len(addrs['addresses']) >= 1, "No addresses found in listaddresses"

    # Verify the address structure
    for addr in addrs['addresses']:
        assert 'keyidx' in addr
        assert isinstance(addr['keyidx'], int)

    # We can find our address right?
    assert bip86_addr in [a.get('p2tr') for a in addrs['addresses']]


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
    addr = l1.rpc.newaddr("bech32")["bech32"]
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
        addr = l1.rpc.newaddr("bech32")["bech32"]
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

    addr2 = l2.rpc.newaddr('bech32')['bech32']
    amount2 = Millisatoshi(2222 * 1000)
    addr3 = l3.rpc.newaddr('bech32')['bech32']
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
    addr = l1.rpc.newaddr('bech32')['bech32']
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
    # Use BIP86 node to ensure consistent derivation for both P2TR and P2WPKH
    l1 = setup_bip86_node(node_factory)

    # Can fetch p2tr addresses through 'all' or specifically
    deposit_addrs = [l1.rpc.newaddr('all')] * 3
    withdrawal_addr = l1.rpc.newaddr('p2tr')

    # Add some funds to withdraw - only use P2TR to avoid derivation conflicts
    for i in range(6):
        if i < 3:
            l1.bitcoin.rpc.sendtoaddress(deposit_addrs[i]['p2tr'], 1)
        else:
            # Create additional P2TR addresses for more inputs
            addr = l1.rpc.newaddr('p2tr')
            l1.bitcoin.rpc.sendtoaddress(addr['p2tr'], 1)

    bitcoind.generate_block(1)

    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 6)
    # Verify we have P2TR outputs
    funds = l1.rpc.listfunds()
    for output in funds['outputs']:
        assert 'address' in output
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


@unittest.skipIf(TEST_NETWORK != 'regtest', "Elements-based schnorr is not yet supported")
def test_p2tr_deposit_withdrawal_with_bip86(node_factory, bitcoind):
    """Test P2TR deposit and withdrawal with BIP86 derivation (default for mnemonic nodes)"""

    # Set up a node with BIP86 support (mnemonic-based HSM secret)
    l1 = setup_bip86_node(node_factory)

    # Generate a BIP86 P2TR address for deposit
    deposit_addr = l1.rpc.newaddr('p2tr')

    # Send some funds to the P2TR address (uses BIP86 for mnemonic wallets)
    l1.bitcoin.rpc.sendtoaddress(deposit_addr['p2tr'], 1)
    bitcoind.generate_block(1)

    # Wait for the deposit to be visible
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    # Check that we have the deposit
    funds = l1.rpc.listfunds()
    assert len(funds['outputs']) == 1
    assert funds['outputs'][0]['amount_msat'] == 100000000000  # 1 BTC in msat

    # Generate another P2TR address for withdrawal (uses BIP86 for mnemonic wallets)
    withdrawal_addr = l1.rpc.newaddr('p2tr')

    # Withdraw to the new P2TR address
    l1.rpc.withdraw(withdrawal_addr['p2tr'], 50000000)  # 0.5 BTC
    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 1)

    # Check the withdrawal transaction
    raw_tx = bitcoind.rpc.getrawtransaction(bitcoind.rpc.getrawmempool()[0], 1)
    assert len(raw_tx['vin']) == 1  # Should use our 1 BTC input
    assert len(raw_tx['vout']) == 2  # Withdrawal output + change

    # Both outputs should be P2TR (BIP86)
    for output in raw_tx['vout']:
        assert output["scriptPubKey"]["type"] == "witness_v1_taproot"

    bitcoind.generate_block(1)

    # After withdrawal, we should have 2 outputs: the withdrawal destination + change
    # Both belong to the same node since we withdrew to our own BIP86 address
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 2)
    funds = l1.rpc.listfunds()

    # Check that we have exactly the addresses we expect
    fund_addresses = [output['address'] for output in funds['outputs']]
    assert withdrawal_addr['p2tr'] in fund_addresses, f"Withdrawal address {withdrawal_addr['p2tr']} not found in {fund_addresses}"

    # Find the withdrawal and change outputs
    withdrawal_output = next(output for output in funds['outputs'] if output['address'] == withdrawal_addr['p2tr'])
    change_output = next(output for output in funds['outputs'] if output['address'] != withdrawal_addr['p2tr'])

    # Verify amounts
    assert withdrawal_output['amount_msat'] == 50000000000  # Exactly 0.5 BTC
    assert change_output['amount_msat'] < 50000000000  # Less than 0.5 BTC due to fees
    assert change_output['amount_msat'] > 49000000000   # But more than 0.49 BTC

    # Verify total is close to original 1 BTC minus fees
    total_amount = sum(output['amount_msat'] for output in funds['outputs'])
    assert total_amount < 100000000000  # Less than 1 BTC due to fees
    assert total_amount > 99000000000   # But more than 0.99 BTC


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


def test_hsmtool_getnodeid(node_factory):
    l1 = node_factory.get_node()

    cmd_line = ["tools/lightning-hsmtool", "getnodeid", os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")]
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


@pytest.mark.parametrize("restart", [False, True])
@unittest.skipIf(TEST_NETWORK != 'regtest', "elementsd doesn't support psbt features we need")
def test_sendpsbt_confirm(node_factory, bitcoind, restart):
    """We should see our sendpsbt in wallet, and that it gets confirmed"""
    l1, l2 = node_factory.get_nodes(2)
    l1.fundwallet(100000)

    psbt = l1.rpc.fundpsbt(satoshi=10000,
                           feerate=7500,
                           startweight=42)['psbt']
    psbt = l2.rpc.addpsbtoutput(10000, psbt)['psbt']
    psbt = l1.rpc.signpsbt(psbt)['signed_psbt']
    sent = l1.rpc.sendpsbt(psbt)

    # Unconfirmed
    lt = only_one([t for t in l1.rpc.listtransactions()['transactions'] if t['rawtx'] == sent['tx']])
    assert lt['blockheight'] == 0

    if restart:
        l1.restart()

    bitcoind.generate_block(1, wait_for_mempool=sent['txid'])
    sync_blockheight(bitcoind, [l1])

    # Should be confirmed now!
    lt = only_one([t for t in l1.rpc.listtransactions()['transactions'] if t['rawtx'] == sent['tx']])
    assert lt['blockheight'] == bitcoind.rpc.getblockcount()


def test_old_htlcs_cleanup(node_factory, bitcoind):
    """We lazily delete htlcs from channel_htlcs table"""
    l1, l2 = node_factory.line_graph(2)

    for _ in range(10):
        l1.pay(l2, 1000)

    l1.rpc.close(l2.info['id'])
    bitcoind.generate_block(100, wait_for_mempool=1)
    wait_for(lambda: l1.rpc.listpeerchannels() == {'channels': []})
    # We don't see them!
    assert l1.rpc.listhtlcs() == {'htlcs': []}

    l1.stop()
    # They're still there.
    assert l1.db_query('SELECT COUNT(*) as c FROM channel_htlcs')[0]['c'] == 10

    l1.start()
    # Now they're not
    assert l1.db_query('SELECT COUNT(*) as c FROM channel_htlcs')[0]['c'] == 0
    assert l1.rpc.listhtlcs() == {'htlcs': []}


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@unittest.skipIf(TEST_NETWORK != 'regtest', "sqlite3 snapshot is regtest")
def test_pending_payments_cleanup(node_factory, bitcoind):
    bitcoind.generate_block(1)
    l1 = node_factory.get_node(dbfile='l1-pending-sendpays-with-no-htlc.sqlite3.xz', options={'database-upgrade': True})
    assert [p['status'] for p in l1.rpc.listsendpays()['payments']] == ['failed', 'pending']
    assert [p['status'] for p in l1.rpc.listpays()['pays']] == ['pending']


@unittest.skipIf(VALGRIND, "It does not play well with prompt and key derivation.")
def test_hsm_wrong_passphrase_crash(node_factory):
    """Test that hsmd handles wrong passphrase gracefully without crashing.

    This test reproduces a bug where hsmd would crash with "HSM sent unknown message type"
    when a wrong passphrase was provided. The issue was that hsmd_send_init_reply_failure
    was using write_all() instead of wire_sync_write(), missing the length prefix.
    """
    l1 = node_factory.get_node(start=False, expect_fail=True)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    os.remove(hsm_path)

    # Create hsm_secret with a passphrase
    passphrase = "correct_passphrase"
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, f"{mnemonic}\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, f"{passphrase}\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    os.close(master_fd)
    os.close(slave_fd)

    # Try to start with wrong passphrase
    l1.daemon.opts["hsm-passphrase"] = None
    master_fd2, slave_fd2 = os.openpty()
    l1.daemon.start(stdin=slave_fd2, wait_for_initialized=False, stderr_redir=True)
    l1.daemon.wait_for_log("Enter hsm_secret passphrase:")
    write_all(master_fd2, "wrong_passphrase\n".encode("utf-8"))

    # Should fail gracefully with proper error message, not "unknown message type"
    l1.daemon.wait()
    assert l1.daemon.is_in_stderr("Failed to load hsm_secret: Wrong passphrase")
    assert not l1.daemon.is_in_stderr("HSM sent unknown message type")
    assert not l1.daemon.is_in_stderr("send_backtrace")  # No backtrace for user error

    os.close(master_fd2)
    os.close(slave_fd2)


def test_unspend_during_reorg(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2)
    scid = first_scid(l1, l2)
    blockheight, txindex, _ = scid.split('x')

    # Use mainnet settings for rescan.
    l3 = node_factory.get_node(options={'rescan': 15})
    l3.connect(l2)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])
    bitcoind.generate_block(20)
    sync_blockheight(bitcoind, [l3])
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 2)

    # db shows it unspent.
    assert only_one(l1.db_query(f"SELECT spendheight as spendheight FROM utxoset WHERE blockheight={blockheight} AND txindex={txindex}"))['spendheight'] is None

    # Now, l3 sees the close, marks channel dying.
    l1.rpc.close(l2.info['id'])
    spentheight = bitcoind.rpc.getblockcount() + 1
    bitcoind.generate_block(14, wait_for_mempool=1)
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 2)

    # In one fell swoop it goes through dying, to dead (12 blocks)
    l3.daemon.wait_for_log(f"Adding block {spentheight}")
    l3.daemon.wait_for_log(f"gossipd: channel {scid} closing soon due to the funding outpoint being spent")
    l3.daemon.wait_for_log(f"gossipd: Deleting channel {scid} due to the funding outpoint being spent")

    # db shows it spent
    assert only_one(l3.db_query(f"SELECT spendheight as spendheight FROM utxoset WHERE blockheight={blockheight} AND txindex={txindex}"))['spendheight'] == spentheight

    # Restart, see replay.
    l3.stop()
    # This is enough to take channel from dying to dead.
    bitcoind.generate_block(10)

    l3.start()
    # Channel should still be dead.
    l3.daemon.wait_for_log(f"Adding block {spentheight}")

    sync_blockheight(bitcoind, [l3])
    assert only_one(l3.db_query(f"SELECT spendheight as spendheight FROM utxoset WHERE blockheight={blockheight} AND txindex={txindex}"))['spendheight'] == spentheight


@unittest.skipIf(os.getenv('TEST_DB_PROVIDER', 'sqlite3') != 'sqlite3', "Makes use of the sqlite3 db")
@unittest.skipIf(TEST_NETWORK != 'regtest', "sqlite3 snapshot is regtest")
def test_rescan_missing_utxo(node_factory, bitcoind):
    """Test that node which missed a UTXO gets fixed up correctly"""
    blocks = ['0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f52da139a043b1ab6d83399d190c01417d4d69b5e03b3e813c0eac7a6e5b78c7d152a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208c5a959466117e0a0475b21fec86a66b4e54c7c76b94c1ec6c9dcd6692af357e9352335f0f6aece912326336daf26379c9e6e862b7051dca270e930d4b0645b0162a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002094108db200c749306b1204541260d9fe756f93085c769bd03ce49446cc4fdc634cb62b3f4a569da2171f20f78fbc196827b5e8f78dba86d28b4404399ade40f4162a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d5918b62f3aba3486db20c1790055e770d88d48065649acaf68486e307bbba0445b6e735251260e246f09f0be1a3b66fcda9cd7c1b401f66514b1bf22e60935c172a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002002393a9fd4a0cba3abb63a9f4d23d33b86ce5b652f8d9fe9f6c936a14424c66e9835bd1e29c5123fd566e83216bce451ef4bc933dfdec84b26b7045a9178e5e0172a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c9a8b06bb1f7037463db49140f9f46c2bec8f08e79d3cb839148f3dd63342c238f995feea178133daa8d1f8013e92a317a9557a57b5af7f41a63a10f45222d7f172a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025600ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002022064b87e23df1509e53789b6158fb88c826380cd0c467de50f849f9c7b8cb058da6465d6762b835f1bd9383b5ff6541e63db6d9d23b26bbd83ec364b6166365172a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025700ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c2330d9fb01c4c0be15badce25be95c123a2dbb426afbee62d9cfed7cfd1e8387048e18507b622a700d95268b88e4220e868542de23b6948a1f1445df91b40e5182a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025800ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a567478d5513d9c33b89aaf3ed7194b2c9e01545070470a3a8914e4c59a27f084dd7721b8fdf0d6270624105cf6278a004977198a55c162bacd256af981bdde5182a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025900ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020547a191257da018e32e444978ab5149999ffdbb76616bc73f61e69c1c5c9f6762f1274c87f0818b2a46f79c06a4142da1023e9f4c01d055131181d427d6e2776182a2969ffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025a00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207a68b2fd0934c26b0385082a877a355bf5e017acfbd52f47066ac043b7f7884e7fb1c5a02c9c2ddd98ebed1e45e39b75e89def79463ea8d6781f072b4153ce2b182a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025b00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d8f69b6134d6fc97915fe5a2f7c83a6e5021420d0d19e4609d9026989fbd910cefcad07384f5e52ee6c5c1da177313d2f77285ed6e49ae1a6eaed4ffcb3c6d64182a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025c00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a9cab93401e02f1a0cf3f66ab78052a092c6752a9fcc0e78bd7277ae8a60cd23ef91d37d663a1edbd2158b19bf2501628b73b6b83f81a36a6a938f1039056d22182a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025d00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208ad77645bb51a5e8a488dd369a7cc88277a61009cbd8aa0e70f39ff1e160836484645044d2743ce460394be320f3679b290c9884cd0a85ab24b100f0c22a6f22192a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025e00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e96c0bd1ae8c6d32b3ae0218388cb32ea320f45b0814f7a025dbad1058644401a17604d721b3a1785562c544957d01b14c81c8d529e0c5c3d33499b80bf9e910192a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff025f00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002004af6dc77223e552c29784737ff6c90e7d05be417144bdf486d3773af33480064c032d076c64d4ef33562788d2e72a962e69df8062ff0be6f69a8647c55f02af192a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff026000ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fbd8d719279c9b404c78f3fd66d0978a6299bcb558b233a6da001125cc9bd42c8100ff83dd2a41c21d0f9153efb63987bf6bee3533eb536f6bae48174692e6d0192a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209fc351f2ea6199571f4516e4f887605f4da93d562ec7873ac067aa7797dfb601e73e69bc8cc455a9a5501b2bb6365f3a174c619d8ca3a86bc343641d231eff60192a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020df8d9a7f7ee80d9f3df911cc8e64c9157220a5f3aaace3d2986ac594331e6b0c5eda732e45783eaa24abe99f9cfe55c432aa27399153bd76a5998498b3546ea4192a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206eeb2fd80b0029f6a1488961b6776a071174b45a6581fcff0e4c0c8c6ca989575bca920a07db469a8b8cd087d834b6f6465f34b684d6e11c0d9c60eb05914d871a2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000202cf218caf1e3f35cb02f9d54802a6dab2f2d3add6ab9242bc88abadcf67da373b0ec908786dbf4002f3d5966a534d930efcba3185ddc27f9d9b41289088887461a2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206dedd36ebf7d677458f9fa01f2eaa0552a636271f5ddc9939a18fc8c45340e5ca618f3cdebd068825d98c3177034316e5e85698ce4d7042f1b2f2ff5206dd3fd1a2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011600ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fb877347e4912a14f8fd1d9e77437f7217fd68c2513ee5fea53a20ed485e8b0194bdc41c0b3049dd80e6f3089e6723f07fd7237df59ae4341f92232fd1ed67811a2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011700ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209747478e8bf80dfac799ec7d3ee1fa223179545e79a32ae3191c2ebcceb24648869b73563ab7c676b579d13f821b02e7a9bfafa2c18f604c177df858406b60981a2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011800ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206f58e303e58d75cd7f489ad2c71684d258aee7ec22c8ec609f6d7bad4ea7ad134dd0856eb024a897dc2dd407ddb58687717a7ed8404923c3f679e7c4b96d51761a2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011900ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000203f08ad4fbf974ab808ee222ac40f176976fff63373d6b4acf6319f00042ce500478badf14dde493c433d6776733a611f7ad1f19e827dc732335e41bb2d6ddd031b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011a00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000202e0ed4c1004610d86deef0fa3511af554dbb17d42671b0460ed4c1218c250d73f2ba3fa4e6932002457b7e82aed18df0b68db18a98260dd9bc3b76567c5c171d1b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011b00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020f8ec11127cb849bbc26cf3442afe685bdde92ac1a089a17694a4e6a4b8fbf620548cc001a7f489f8df9f2aa4d859b3976cc51b9a439cb673c41d52b2ffeb519e1b2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011c00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209e70ee32940c38ef0dfec669e22eceb745a10232dea3f8116a13eac0ff912e2c997bb6c32bb1eb6d32a0e8b8bbfa1bf98b8dbb8d6a8938eec3ce0ec0e275e7a11b2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011d00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205590ed28da6907a3eec219c4d0f3e5d3ca16d7b6d2d4429e0f8205256e5a945630f706e7f80b5f7eb0ded4933877c1c32c79dfec3cdcf044d662eb5f3310fa601b2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011e00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020885b76d77479c1ae7b2e6f5271d7eec84585851fb49685ab724b2367aae06e7df51e94d121f2b0aa1845d0f7b326d58278f13a6fa6eb21f7821b505413e0ba671b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03011f00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c37d21607fb50a28596728529fa53c1d87b849094e53370ada0d1ec98e99877c3dac60fda6012ce9cad896bb915f060ef2968ec5d1718513a65383f89b37c5e11c2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012000ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e90ee8d5e8ba1854daf067bb8c3cd5575ba51820881aa1021b8d02653e1b714ffcec153e94c5685b69a8acb7f8eb78140d2f99f506d7c1b18bf76ca06e6ae5d31c2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208008fbd63861e43430d0e556a050477e0575386182d7f58c40f1823dec68dd78d9ce2c898de6fd5fa6ee9d0d5cac08ee9b1127917c83b6452f93be7c0fb230491c2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000203e87c98cc8465c849309d0eda7a6531ccaa6d7487ac973948cd038856d97d040a9010d7974d5a99398a8c29eed68997ce4817b2ef44f2129edb1b22e45a197ee1c2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c0cf7fb210b940ba8b245b405bf2c1b261482c4691cd5aa8344ab57e30e2267fb240948b0364dd6c70a35cbe1ecbe11ff79380d37efab4e4b9bf0746038852321c2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205b1ea9b096b7b157ab35b3fae88013f0264edaca7d87d3db5636bd7fe3d6ce45172b79647b2ae84ccb2ef1152ce5f93a6127fee73e9b355fb00eb1fd0c860a651c2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020ad4627f6a68a753a604f3c11c02021e6a9fb3e631ffc825822188fc81fcbaa165a7105886e3bfe6520fa4b2cf9f36d71c9f750594c9f108a4949ff2e0f0096e81d2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012600ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020500c96b1d9bc7942cdfb926f19cb23f1a14000b5516eb3ec9a1a31234b29352a23a8e506d44061a01d8fbd04a2e59e4ac87d05bc8a8996a4f9d395f7f88238481d2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012700ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204f20de812bebdb98949d2f888118cb6dde527ff605fd276d67d5534ba9ba6e7055c762e7361b1eb311328dda9d1cb79afea60b3e1a3aa37aff7708798839c8131d2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012800ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002049c6a7cadcc410d08131d7ca758c300e50459b190d628ccd1a8ad3570d04b7313b85b40f939d91a628f025350fe5c5cb3269e186b11721cad6a0510bda07f4801d2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012900ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207eb303c9577702c80bc8db413b04c621bc2342e425d206215fe7388f1bbd796ffc396bf4209af9de413429f33ed86f3dca59e04fdaa6bbf73ebbd91b05dd6a551d2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012a00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000202d1bd9f64142080bea71d68472825815002d6514dff5ed80d57c0a0bcb38ef50bf837225c5ca1b8ab8717e1b5ef818eeed6043adb4cb15331aa0ed0df17fbe361d2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012b00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c38d38640f2ab040b54d4ad36c2f2f7a699c5f15628afc8bd7cbfa5cde692602dfc4d9ea815f0e4046ab17034bd7d97a66783279e2962072dd4057fb2a5a4c0c1e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012c00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020db80e4d37a30822d9beea585f235f430a20ff2714b199adafea728adacd26021ad5e9c4036f6a7c1d553db5aedb27e7163a0b83a5b4799f4e6de66092bd490e31e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012d00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020007c23c9517baf2ecf78e08480fef9672248ad91c9d47a660a08831e9da9df1425bc145b463fadf7251a741f753cbc95615a4b1e216d3da93c86879aabd815721e2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012e00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e3aa4efe18c57bb4127d0cf12ce706c2666543c4a8db1d832c9768441dd7df09ae286782092d0a655c0af698ba04d3dab6ca45f5bd6c41e77be6994594f9ac8d1e2a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03012f00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002042313acdcc5ee3eb44cae052ccecc885f4ba91b392ce4c35cff52eed47b03679efed73f490884900675f51f8faa0d779ef07085b71beff554f6c709a06e7894a1e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013000ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020459e7538188374dee3c2c4e5c9c65c4ebf08b233fe05627656315bcf565c6b65e55152905b18658610406d92371c5a5227f138ff559934dcd1dcd81ad61564471e2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c77caf00a937d7fbd6bc2a8769317c8bfeb12cc92b29621301e268354d5b9c4e21458ea30785c80ee0f7e44e2829117193f404cbba64f8d4524f5e402539ef851f2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204ae84dd5ea80d9faa7f1358217d0c37043b2afa14365e60d02fb621ca6623c30afbed5318056dd70582556702929e0fae72855f64d12c344e7fc186d15b6cf241f2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002043f672f249a3ab7be0dbe64b4b2debccd602486452f93fc47a7ec4e05141f45c7d62626f67065515d4a7ff22ce26a61e329c84786043055082f81e631799ffef1f2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002070c519e57152f5a0e107e1db1344bfa4035266fc5b3c641b4e12bcdcce40743aba95eeb88092dd0f4050ed71020a9239a5337dc4abcdfcb2552db460ccf165e61f2a2969ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a5e72f4c176d399ed025d1fdaad9e949e3fa14c8ac421164798f4e5bd62e7e53bd98f6668030a7a96c5c80ab47d07d62e089763f2975be5305f0fbe1a57cdc8b1f2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013600ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b8c824f9131aa396b5b2aa64649e608253830cdbc5c8514a1087667a40394856e9827b2e9667926ceca4e09997c2c473e6bdb28ebec3773b30add84974f899781f2a2969ffff7f200500000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013700ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002044804dd064ba84b6789ea146fcd2725dbba3aa4b8062526d1dee81b01035cc04ecf9ac58eba28a2cb1708d8b32cec54951c76146a289ef5791c7716cd2227ea6202a2969ffff7f200400000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013800ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000203c884c4beda99a2208cfa79d6a91b41b0dede8f9ce0d7e0e60399f57701af91915fb86a168086ba25b83821334667b34f82a743e64db67238cefaf74e7930700202a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013900ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020aa1d873294b20577fd54013e827aeb2b4c50488f7ad4b58a784fcf7b7d643e56fa7fd50867dc3256bdc5f4628ff65dda01cc8ff9326ae73cb8a3d9020431060c202a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013a00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020445db9cb7e0568631ea831555588828f793405835bca3f7394bfa207809e0f1273dbcf30c8e92c5b28e1b5d0131884b4db80e17a859551935ee080814cb8f94e202a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013b00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020317df9aa1013e01fe7a4e229527ba46b60a146fc9ede806dd0d7665bd992c62d6ed2d9bc9455235bb7f65a5199afaf84289caae8b7ecbec03b636d79932d123f202a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013c00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b110ba6c3ff9c6cb0798dba922e14359a8e506a540e02b7b5ee38fd190a9a37fd8c9710f9ac7b5b33d88ab100555bb8f1eb63bd38054abe14a08d3d827928ac6202a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013d00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002017957714be71341f2707fb80f215e749fb0b67ce599cdbf1adaac90051f8887ae762904f22f33e6567800fb0b3da51f45feb80125fd935d6ed2c0d6ece6323ca212a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013e00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020609856d5075afe1cc8533a0107feb48723e0c23eacdc262699d927da2dcd6b35c2534e833bcd4c3a03f88f108f882787a174b4d3f97a0c0d6e88e9771376df48212a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03013f00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020cf7e973bbe557174b60e2c26c97b44cb91f91ffd4f3a9305a99fca61da4f5723164cc298d3e6eda6c859c727f6708f361f0cd988214d781641eb0a690339ddfe212a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014000ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002041308b09327f3af30b6977edd21b61eb07a6d1b2f405b1f05c353f7691e9b32732ed7015bb5dcc1f0a35ca8526b1e923f46cbf0f0c48f80886158ecdb51b2bcb212a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020041883d35b67977a98cc306945c208c61a858bd5c74a8eb5ad9b80de9154f95a15a84c347f19e0a233824bfa46fa43d4aced394c4842ba106f0ca33742cf8934212a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002020fb30b138c8fcf963e1b919361b6e584e59fd7fd51ca9be6b045459c3f5847083cd9332568e66e86ae86fde4023e696330e89a8787ab65579423485aedd5a59212a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002044674039c2385387a97f6c5e7b7c7dbb0d6dc5c73ab29e578e8e72d781b0cb51bf05cc7ab08e6573e44923d0855fd66560f9075538c4345d90035c18c82badcd222a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201ed2c1bcc4c670389798d4ef6ec0acd9f67325a974dce287dc025873313e4d56b3a05a5d74532eb6ce052c33dbfda360908585e975f1c61d2ec5d69f2a464cb1222a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e549bee931deeed865dc33bcfca8be972b494680eb5f7e74ff868791db762310f149785a2bbfa56dbad617d59b29d6cf153b7b3548300e024e433adc88a8721f222a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014600ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206ca12ae4bdda3d4608b6d942ef2df7d71ecbd0abdaf3e8ab744ccc7fea13da207c605ac971fa32d6001072441c17ce803a09f3dc1155b9a3e5a755c0986f0a1c222a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014700ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e920ac02084885e1a4e72a59b5f0371475833d7ec76fc0291ef3937d605f7355cd7a83985754740cec6ef39e5027a42989e43a226a2b7cbd1bae70762433fc79222a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014800ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002075510805a902a3997b75212dc7d0094ad0aa2a1632034e6e39e8be01bee71443f9b0c8bb02e055c14b65f75290be5372915200dbd2ca0c8235a48aa8e27dd285222a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014900ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fec652b842c171d7872960383c56855ff4e36bf34f3c45d822be45f7c385f355cd97525fb05d611d0edb554abf28085d445f518737c76d62968a6c9df31b91d9232a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014a00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020398f7de06cd6302a82d0319bf41964f24b5d70dc4001e75eaf4241511ed5967accbd5bc72ede119b768845a2f9e12cb5fe23f30c3615ef2e0a6a7d96bbd1ab94232a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014b00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c30d336a3823674fd4c4733b694b95829aacf6fed7dd9e822c809011875b8271c308ae7143c70bb9e461fa75b2eed70373a5c5b47fa1acd2eb6bcbee97b04c36232a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014c00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208a6a474869e481a3c2bb002a03b3b12138c5d072dd88e447dd34620db738d912e33d0578e85eac4b4c8fd06f0fac84ba107f914765849464fb0f344f4ed3b7e9232a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014d00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204d6dca9a612fc0b3e23d130d7dcf8c8a3c9f4b1728d64630447b69f10c18384a58805e2c67375ecf7fbacc53e8eb688a0d6df5b51f1eecfbe31365b66d059130232a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014e00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020cc258ab7cda01fcbaff1c114c304cbd56358a1638736cb83a805a49fe0e10a4eb9c92236da68848ec6fe923d9e3f91075f5e9a041eeb3abb82564c79f39c2bbc232a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03014f00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208150a2437fa0958f63a740e1f5efcd2c15da45a2ee7683acf4107b25b60c67055d8ddadd8ef49b714faf2875ab578a0f39fd5bf25265fd2a0c972d5904256ced242a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015000ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020372f05b8c0f0d35cbfbc3de439ac5298b1e35ed861335152dc573f72498b7b712fb77762eb345818ac384c737ad30b449644b5866d9b13aa4fc93a2840175f77242a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020af73e7e8e30bfd03c2dfb56e8360a41cd825888743fe956cb9529ffd51446953e3d633b5454840d473c24d32087bc1cedd7e152a431b3ff23d9d2d77d30862d6242a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208e4b2c42bb867c9c3a848fb04099e2e946600133b0d4cc05eaee7a9c442bd20844fb0f78643bf5339a9ad27e21d76ada31fe19ce823a98fee543beb9a36ed193242a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002020b9258d1ab83d7e3a58824aeb019c4dc59b99637a3c4e9a3be63021f268a15b384a36785ddd90df47b66adccfc372bb18205b23e7aa2e71c35bf3130a88ab01242a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002085d892581784b0445b8b15c4733e0b825fcdf1b271beb1ec3b98131d896cd95e72f93a0f5460d87f14d840b7592838abbdeabb29f3dd5c88ca72f6e961a5bd73242a2969ffff7f200700000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204740221315b911cdae18f307f02a7f09b2e541fe749cc9541720376335d5fc7787b87fee27cdc419b1cc38dcfb2a0e09009adf6e557f11ff2d818d6a2c464bcb252a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015600ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205929ec90dfa57a951f23d3600f4430a82f3051158b529459198b444a5d4992671a17e454bd08a5303ae8015be10a79d77fe536b4150e79eb2d73e5e9babaab72252a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015700ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201d9d56b57f5df554a346ec52d01018ab4f5a361b210527d04cfe0e3fbce5821d33af4110db477c0e9c1840958291c75f85e394b0c9c55cde554feeb5686848b9252a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015800ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020f7e78a95b3e4db572fdc9fd9db8731262a6a0cb716862bc8bfccb8a7f911ea032f67d51a56c6a277f1d58b8c47a7108fc49ad9149c15d8c42ef414216188313a252a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015900ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000205db43e3a12f4d611018a8eac02ab11ef2e051efb9692c53bab2a00c8e6742f18e9d2896a3967bca2385f8f6d106c82c8fc524d94a368935fc4279016750074bc252a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015a00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002052b5d927c520ffa5fefc891d694e9912782174894ea23448a7ad5401414b877aa405c5d8d095e4b1e57d3d6a59b23dea6cd2b2829ab22aae02484f8df7b04795252a2969ffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015b00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002070af6a6bb91378b72a0e7683f4378f6557622ef9988ff42aa9712610ad4170180d53a889c283d6839a49f31f9d90db4c36a204cde5265daf19b69186a8f840d0262a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015c00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206c3444bd3e78bd81caeb5183a4fd8500dc0f546b2c7b4ae30ca93ab16add580794bcc8434aa14e073d28fb562a931705cd7d4625d4a162fc05aa234d938d714c262a2969ffff7f200600000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015d00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020f3d07275bd06cb971b8cdf946247bb7dd85124042150a83823f41b0a6cbb896bf34e6838d39b67a547d3bd7fc7fa050be6abd1d92f3be443d14f8114f48e1dc0262a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015e00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000202003eab8f3d571c1e9154365a5a886a4fe8eae2c0b7dbe71d870a8a459af956e5a1f2c61f3198ecc9fa4fef1fd59f07c993b742385c79758001c2a721a25c309262a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03015f00ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002015e6b81abc7e28faca3f834d800f300541f75c140d5f5b80b6b15b3897d2994959df6a0c0afa391e97f90d76d46c2a0e07923a9974c6100b957f81ee5ecc339f262a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016000ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020923dce0d0d7457f91f873148cca98d7147761dbd71ed4342e09bfa40902128686c2609750c3cffbc9acc9a16747d00253284c6a3e4ffeea9f87c5a92db976b57262a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016100ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020a09d00ab1f4455d6c19b1c88e6dab435f371f619721210c9d92c4e90daa7f8049dc3bc11a78c7c32bc5e07d8185ef672aa542f1b63f0cd8fb6cd2aaebb682956272a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016200ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fa2fd528f423a5a4f061c1b7a4ba4f853ae3bc6ec582bb1d1b4c194017c8472c822a451f03aea52fc2fd38368a1b545be2d1e19e832718269a233bab0b9ce271272a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016300ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d261f9b942bfd4d48e5b77099e62f35b06f5aa6054512935f012659f378bc96fca12375d74c01877a9ffbf375e8646bdebb81d3cc41390c655ad6cba052417c5272a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016400ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020aa7e67648591cb0ff819d9d0db524bf1db1bfd9c08dd745537b1931dfdf1bf5debab2039b1272167d9bd8d078ac396682c1f7ce5af2778083ee1dc973fc4ddac272a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016500ffffffff0200f2052a01000000160014fcdde0698d0208be119fbd38f14407c89610f1930000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002013d5fa7b241ef3028fe5213c2550bf071f7c6bf9fd21aa83bf8dbdf0fe50711486a9e733575552a7f9020900bd33f353f96a3e9222c3df4933af083037f218a4272a2969ffff7f200700000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016600ffffffff028df2052a0100000016001453cafec6dea84365fb7364cca0eb0a7f671b76fa0000000000000000266a24aa21a9ed7cb2e4c434b0fb2b9a77067c659d5bf113f791fd5adadc1e447c2d1be927008301200000000000000000000000000000000000000000000000000000000000000000000000000200000000010152da139a043b1ab6d83399d190c01417d4d69b5e03b3e813c0eac7a6e5b78c7d0000000000fdffffff02f36ce72901000000160014fa35a62b397f7f370ef24344f28c86e32630959380841e000000000016001401fad90abcd66697e2592164722de4a95ebee16502473044022012e1b4685d8c41f53768e074c892128d31332646a37bfa8edeffef0d087f0a31022059f5e6f618047ecdd0558f445c3dbe984f9c37f76398b57c7409002555e9fc37012103fc33516d8b179656bd3acdf501deef399a028267cf7bdea689b48a2be60c951465000000',
              '000000204233e5c7536c8a79482f13ddba77db1c33a67f556f2eb68a0fe6a0ca8b93021fcd4afc534f169041d8bccc22b85ba7b627a5d9af900d98b5dff9ff9829717e10272a2969ffff7f200200000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016700ffffffff023f05062a0100000016001480e95e027ad313cc946ad5e6ed8fcf7be39b2a6a0000000000000000266a24aa21a9edc5b3e2846ab0e08a772a6eeb81ed02299dd23bae934ddac0b01d71ccfe393eae01200000000000000000000000000000000000000000000000000000000000000000000000000200000000010114266931abf2becf6b4d1a17fce19695c750b9161514b2ec92d482911b3dd5390100000000fdffffff0240420f00000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd012f0f000000000022512063ffee4ea7d51e6cadf9086e286a2527922aaa25b8c53aebf32fa32a0a627f5a024730440220614cd0bba927682189e4bb9527756da3e65b294a0b257c78290ba7ba701291ea022037fb7a5ce4a6aacbbdd0e53d433e47255c2f48fd39070624ede0b82f3ea81b46012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf66000000',
              '000000205af9f309ffaa5c83d2827727be5feb827a9fd48da923c5f4377188370d22cf7a552ac1ce63dfbfffb5bca4d4350e4d1743244d37cce89f3422c285368d270bec282a2969ffff7f200500000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016800ffffffff0200f2052a0100000016001461177ca6a698b8fbe3ea8d38685d1d6ca42794460000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002033df67e2c956b3966323841f7de42590247186dad81fe2db290dae175fbf672c44f7a2f920254a1e51d4ad3cf548cd20e875d89bd214ca0790369008e2cde619282a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016900ffffffff0200f2052a0100000016001461177ca6a698b8fbe3ea8d38685d1d6ca42794460000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c93133dda9375c404d3a04908dd3f8eaedda942edada94f4e091d5369b03d45723afd0e987b53ee66758b34c4b702fb54cf2e68933c764771fcc49ac3c9efd7a282a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016a00ffffffff0200f2052a0100000016001461177ca6a698b8fbe3ea8d38685d1d6ca42794460000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000207ced836eb526720737d97b1174623380f2e5ae93abac0e6613c1f65dfc1b95564dcfaeb0f0fc5a8e27cceb23b6ddb19b3006b50a4c8d0335b34106ed639d23bf282a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016b00ffffffff0200f2052a0100000016001461177ca6a698b8fbe3ea8d38685d1d6ca42794460000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020ff27d0bb955fa79f78722218b37328eaa1d17e035c394d460a13b6816657e33887a33a19ac0e5441992e32ada3a8c25bceab065038d2a604bb8c616f7eacfce3282a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016c00ffffffff0200f2052a0100000016001466d2279b499e9f8544aa534b0c74240724d4731f0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002095c1de4635761802728384d7e488fdd5f7a5dffc3569406a6c68ceef43807c6c7e96819c15ab06d346c25c41e93b34668242b3a512b846432e311abab43e48ba282a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016d00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002089493e6e9cb1123366327ffc4a5d95f71b3bf409a2a470d1c42f216b38039251f9723bd09800b52424ff5dc277cd3b1892a13c00ca8651d597c1bc0b749017e9292a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016e00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020889cda5cf83da865b29b85db73c72d0f6187166eb7570aa1a453b9bc06a0b7165118eb633a0596c730147b9e186349a6c695aeeda1911b854cc39a207e9f1034292a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03016f00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201bc646ea09472bbf095335bd4f07c9d3eabf855d19afad29499a7ad4fa986571135005702717998a8199a31d9aecde153121f5c4424f13a95abb3277708d0415292a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017000ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fd376a7ea9843799c57cbbc4ca41d126015da0ef0964d52db4d229133c392c406255d1fdac56fa556b44777435d0f06a56e9f161e908d08f90e6016773dd0383292a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017100ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020f469c216ebf37bd4d08221ce3ac8749a4d12740104511c2d5b759ce59d4dfc3762eca6bbf8d40b790e3df5e4ae48cfa681c1a1ee6e19a008ad8bebb49d5d5193292a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017200ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204ee782d00a8f9ed354431941d3766c3134a417f4652b105606a40ed288c4465acda2cfba7a4943e45ca85036190fac3c6941988a1067c8be55129e77b6235617292a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017300ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e146e9dadbf6c88cdd5190b707574b26f68f2c31487c026b2af1a2308b55fb47e96146d1021fb9a69041f96b9f9c2151e1cb289308f3997c019d608b3e97c9572a2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017400ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000204dc5d8f42b16d1901ef7f614b9d362d17f5149087844e6ea60efc8faaebc932e748ab8e2acdac4a5dd7f0aad55aa24eb3c573f3ea5824cda7ecf67cfa0a1a93e2a2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017500ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000201f3b3029fe5965bb731244bf07ecac95b1f48b467c9e9e57f35fcc4277e1e07ea8d6e60c3239f6f68e91835d25f8264b98c4f1dae985f5b11cd6a956566cf3e22a2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017600ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000206267df6d3a7fa85e831d7434ae5696fb5ef79e7402ada8ae866cfe871b1516601d9c07c695979ea9fc4a10bd7335f9e72f0b894b3a79297879396389962665852a2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017700ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c3cb8ad194148c24e912ef9c01afbc0f065dc25696f8e231c6de0544c29a722db044e41c37c548c0ae75aab09a1d0ebb8e1253b0a71c8f21e53741700c2f14f72a2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017800ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020af4647a379981bdb7f09e585329bc069a32f02b53e76013c07c6711e5e84ed1e299078707d44c9a8b9b06ea91d513e252aca7cb899a36119866e489e1af588fd2a2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017900ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c4a50c06941ad707f442b50dd9a046237ab41c317b929b2bae027b08686d26799a9d9d658bc540ecdd5880cf3e2200db0e6694039ea8f2f9a3543bbb2fdff5d62b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017a00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000200be7c524fd64c55156ac4fadeef08d18fa876df4da0991e64d54c4ff56a2ed3dd4c43efcf371283f78ebaf6d664cb312b51695627d189000277a3d4000e1a7a62b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017b00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209dab6b15335b9f2b5dd0c7cd39644427e38dd1cb0c769914f784ab52f19e733d92c01b43192fb49db1e1b034c09f2a650b5af0b8dbbb9853dbb641ac621932942b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017c00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b91512f2d642ee8614c981dec8a4cf1c91a4dacf6edae3452c99c61a4ad0835f898157bb45134435b8241eba5f680ceef70fdaa116fbc94f00821a983447b1d62b2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017d00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000200ede25de7aa9496d2126f5d14fa43de9b8ead9b9c7864b809e1a02a2340c8e6dca1c27b558fd54ff86210e31f25a595430a19444c98e1789c2ddd881ee1df85e2b2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017e00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002053168c9e415153e1e4eec9c5ca4527e574781a378d7f183d71b1a9f72d407c6b57156b30467a1990129a1cc3f1e9992833d93ad83b6a26de9b80b8d26029cd552b2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03017f00ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fe2f67a21c5fb3368c994d535153cf1956786328471d5c4a3b422f4edbd520030a35e3058f55d066236e8b538b56855b2e611211e3ad459872c4396a114335d32c2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402800000ffffffff0200f2052a01000000160014756dadeee357fb1bd2831fed608c617935a7d3f80000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020c38b7296cea16583ae5303b5fec99b1ed93467bc34467bf6515703bc7c75fd293e411e4afa1920fad2d48b32e8cd6156e717f28dec46b7ee4462d524c08b46132c2a2969ffff7f200100000002020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402810000ffffffff02cafa052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9edf12ba6ebc4094b290a1c2415f1405af1e4e7250013fa09f5f205dd7edffebcd1012000000000000000000000000000000000000000000000000000000000000000000000000002000000000101e2374b0bdf6af59dafacc6f7345ba9c54bf9ad7ea30a91f555263f5b8a5c22b10000000000ffffffff0176390f0000000000225120eed745804da9784cc203f563efa99ffa54fdf01b137bc964e63c3124070ffbe60400473044022002008a001196f02917cefc5edeaf19fb6e995cd50c6144a3170d38f2f15fb7c3022021110b81af14e41dd416c302bf49f67cb2d0d24f0fe97e36b5d2c1e1d0b9d8230147304402206821eae31b9d275eac7d961180a1b44a827259aea0058e9893f3e5892d2c63d202200e197f0c69f03cd0987638183cabb2735b4574ecc3c83b183c396fa7689e74c20147522102324266de8403b3ab157a09f1f784d587af61831c998c151bcc21bb74c2b2314b2102e3bd38009866c9da8ec4aa99cc4ea9c6c0dd46df15c61ef0ce1f271291714e5752ae00000000',
              '000000209d8e668dfe80e9c99aa9ec882f3a38260cd47f8f02d1f32a5cf61b2285364f5a6dd99d76af5d5e7705f11d418db57359f635cb5857931b534ebc1ed4ecbf7a242c2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402820000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020222e6d5bf2bc8a76cfc8d99802fe81448b9b6a9d4dd0679537f8dad25834f002a343eb2db257363d83f6b9ccd4442ae8e015ce0d79a1caea742ade6ef86fd20f2c2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402830000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020d805aeda34cc15badcf21ae16e355608e33c515ecf94efa0544c15b491b5603a92d840e90e9b3b22a02a8fa19ea1d16566f23506cb6b0fbe6cb54f2258620a592c2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402840000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209071d623a89359dc0fb4e4f9c63957a7684910765edd06eb179973386ca73306e1093ba3e5f75a466cc74d225d5c59c29d0ce1c13d5bc8a19cd239b7ce062eaf2c2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402850000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000200d8f489f9fba77851d80a8a36bd15675f4b28d961a81f7026d1e4988360f0b315fb04b85b1e4507383624069db093e7e5b8a69d6c7e07439b72b5003b189bf1f2d2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402860000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e5b9c786fbb3e62ba569a2feda361416c61d042db42fe33d15a807a0bbb7fb7b7c03482c1876ed23053b06dce2e960d386d85a9030815e76067d5bd5b161cdd72d2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402870000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020fb462753b7b03017fe0ada6b11db6f68fc11f3b768012881727fdfc87560f519ac282dfe89c3423e43fd78e1b40faf01dc43f5e3fc874d649a1d15bd6dfc061f2d2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402880000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000208a62904df35fd035ce8f8a83936a22df01fd6dcd020eef0b8542877736e7f607741ecf33a9829d6e0959bd6ee1de9df8eb079a4c3d6176c991543db7c3504f5d2d2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402890000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020eae3cf91e0b310ef89cce094c88fa37de18c0bf5ecfdfd49816c9220e9480064512867722b564216dd0d6395856cb4e07fae31ef676184116e67debe1acb32262d2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028a0000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000209a85ec738285b6e211f05bffee03d34d1530c414d15dc9957701adb418629c74013bce4e28f37509f3b0587f0279f213b06848abb858c91f62d97bf4a36bb45f2d2a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028b0000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020b4e00771c369819e5b10afde85c41a9d42e07dc876c8205ab69fce7384f6992e7409810c8f412a16ba682ced5a619b1e8ed21777aeb50ea2b984b9f29145d3ed2e2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028c0000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000002021ebac191c482754ee449998fea970d66cea342711b76a06cb5fbc671770b43f2eda2202deb5f5191adc58e981ca3153ef76351d1c46e362bf97d53fe4a3aceb2e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028d0000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020778059c11f1cd754ab638b711623c8e04334ec12657b424eb4ddbcfb0c81f36d7642aae067a088bd34556cfcd3bdb13046b68411314de899884f622c2820f56f2e2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028e0000ffffffff0200f2052a010000001600147715bb754c769314b226ecd3b092759bd0568c350000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000020e059d322a489a8df05b07d4df52b7697802df065c64d8061bf8332ba3f858d750d0cbddeffe282a7a2cd477c98ba91409f12816eb66467bbab9146020762ddfb2e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04028f0000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030ef108d55a9c46403771f14d5be299d479d25f17f593ff2c0e07a8b3eb880b960abafbe9ca2b83aa911e0cdd94dab67ac3482a2d17a8ce6b73af5a2b27e4e59782e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402900000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000306cb2cbf141bf32c99ac6590cc6f943e61001fb0746a54dda3ff9ecf7c6f71c31132185ac4a8c2d52521fb6955ae8fb8ee603dcf7912459928b812cee3d3b543b2e2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402910000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030d40941c8e03a4766368da91c1d23a57e749aca1906357b87c597bd52e45e260e9933da7a58c8552a95195f8c11db446d39a47059c2279d28eb706a69319b2eac2f2a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402920000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030735d7d15708513eefa13ee6a8fe597e4453f608d2b707f9abe5891ac92c0c74faf7e1659e453c32514938201ab78d850d34cc1d7e22e652fd36295cab4ef58832f2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402930000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000003040f09216b6b39a44474384a7c797512d0598e57855a041ae9e1f80275c6b736eb78a7f1920e97cb2eab6ee2aba96cb2e5c073ff195ad5b8e50a538cc18b724212f2a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402940000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000305ee88bc9b5fad404c0eab5bd681d75ab12a8fc37c6b8a01ae6c73727058a37446a3f6879b671fe2035b25f1ee598de766227d0bfecfbe6597c2c84d2b509b5b52f2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402950000ffffffff0200f2052a010000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030b46284bfa8d085d938f2e626871a3be5f9513bec28f3482e1d52737444b0014749ed0492d3a52ddb156fc107f0e23a2d86ee1b88391b2b90c747e44d286b3c002f2a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402960000ffffffff0200f90295000000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030a57cf94f436a430a77fc01cb7bf511dd109446cde8e153f9ab74e423aceb2b23eb82b2cceabd26f017c0910b14c6702280985d908cb1ba5126f70de4a759e2032f2a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402970000ffffffff0200f90295000000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030eb7c194a85046d246db6ab19cbad0c4e2a13f6ddc569395699b7b21b91205173fedbe772d88c62aeb52de8fd3d93b54a2066ecd28477d43d69f5c1ba5c855715302a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402980000ffffffff0200f90295000000001600149fc67ec723509d33ed1062cb3c05d05982286ae60000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000309b821d48a23056898c6e374a0c459a67444aaf80cc0b010a0526c0f095ca172df8f5dd4e96ee3520739cf59758cd5ad7c9bedb068fa6d1298aeb12cb00e1e601302a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402990000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000003033e5a397746d216e920ded9845ba408577b950203e34cce02eb5b25f4347f344c76e3d2a67ee7e6b8e1ea4a81484c6d1f80d559bb653d615fbaa3d54b4f0da2e302a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029a0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000303c81de79f06688d0b0d0de330968e6d5d5be7fddccc027b0c283a9b2bdf1b210b98452d9a49cc635f5fc6ae03fe70b1dea860027d2a5f7175ced89c7ccf7f964302a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029b0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000304a43d63b82a1b3db10eec9bbd741a7d2aadacadfac2af00b416abb1162bf68658ba3e7c09352e688c721e8b7810529036b798838397b3ee28a825fe3054e35a0302a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029c0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000300fc8d0da4064950d128a002c8540cc3d40f79caf1325ed03acde86ba61df076865171ccb978b7acbe14696234c80a7e6871d273562760358a61253807d90db75302a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029d0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030de7b33ebcfbbb09ede0217eef178b66373f94421d4c9d03afc349eaf982a7e5314fc8496255bd0837dc8143c1d8015c65c0520b91bff5d9799bcb40a2ed35f7c312a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029e0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030947578a2848fc31e28d3e00661a4e18ae4ef99b49986eb2b8b71dd2ff1a52f1068d56efa7fb56d5772ecaf6956ebbf496d9d13ce2b35caf3f4683c90f8572394312a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff04029f0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030e285735db6feb930c05a6714ca64dff18bfd96b6790b06975608d18a9ef0e279594c963c27655d3cf6e58913dd479383191ae66f54e8f68442c4606ddc57f4fd312a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a00000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000302bdf9fc675a18080eb932cdf9454de87b79be8d85babacfb3b6206d429de974353eea556483db020c438a2563f52d3e961dc7aa48a9c5290b3592730b4f04e21312a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a10000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000306e3007aa6b8c1e04a9cf7d0070ccfaaef7154d2f9cf39592e6d5f12f8bc4cf7d2b88303e3607a91fee26040e845d3693c6a37162c5b21e6cb5adc024d457204a312a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a20000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '000000307299e2eb4396e21290e69bd1fb5ff893eeef6a21d7313fbb5d6bcdb0844ec36350e102a3ae5022a4c656eb0f5dc52ba9e4749446183027e6597a3c962c162d54312a2969ffff7f200300000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a30000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000003041ec89e67148b47508bf9e9b97993c3a54e69b8681b338dd555429e10c228d724c4c07e512e47bb6dc6193f8443779d0e86995f3eb3c4c865dfab57a4fa6eb68322a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a40000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030543aa4cbd239c15cdd65c250ca9cd00d1c9f68c443d0cd2ca041b9fb7981e9096144a15ce4873abc42632bb1bf92ed4cb80e0192e2c03f44739ee1644ca4184e322a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a50000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '0000003065a0d3572cd40afe5f68b7e9fd088f58a6897c709ad774dde9b0d1798aee2d6465181d5775cf7091b870bf23f26c762363d12ceace7f134f60cf648b00cf1a44322a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a60000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030e2725fe6f67d8b16886761df241072bb0d9a7783bec83fd8859e0d641e1e702fd19a68f4d930d77ecf1ba4eaddc52eb63da5d22b99c68e69d1e8bf84799fb711322a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a70000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030ba921eb097eff8135d946d24037be0b26c994af5b208394077dc77fbb0b26579ff1f5397b7d20832d4328dcf776ae5c85bd005c519b9ae4ea383a802f624e8a8322a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a80000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030279f7381e8c3c2e1b76bbb37f6d463270e995f41600d08b5c753080fc5c04975b65f3d913d25bda5071c1ef3c951794fc8b8bf8b14280b0e27e1cb1dabc7cc5b322a2969ffff7f200200000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402a90000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030eca2849fb05b908f0cad911dc3c56d087e11d8e34ac4dd24c6225418e3afe2607803b465d839615bbd94c4161c27db6c36cc2269abae1639a811993e698abce2332a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402aa0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030d79629b56012c0e8abaaf887c77fc3e9e3605cc6f3fc7359b4052db1094aeb1727659d7d23a5bc4f29228ae40177e9e74b1055e78284240ff6eadcf064ddeda9332a2969ffff7f200100000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ab0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000',
              '00000030f63d658e126edb711843ae25f9338220c40454b10bda980331589a7de993f826ba8519dff5f62e9934166ac349fa38cb29aabf6ae21807e98706f8f8b394aa6c332a2969ffff7f200000000001020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402ac0000ffffffff0200f9029500000000160014b739823522ae9beeda78fb6829478d751fa530de0000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90120000000000000000000000000000000000000000000000000000000000000000000000000']
    bitcoind.restore_blocks(blocks)
    l1, _ = node_factory.get_nodes(2)
    l3 = node_factory.get_node(dbfile='l3-missing-utxo.sqlite3.xz', options={'database-upgrade': True})

    # Fresh nodes do not scan
    assert not l1.daemon.is_in_log("Scanning for missed UTXOs")

    l3.daemon.wait_for_log("Scanning for missed UTXOs from block 89")
    l3.daemon.wait_for_log("lightningd: fixup_scan: block 89 with 1 txs")
    l3.daemon.wait_for_log("lightningd: fixup_scan: block 129 with 2 txs")
    l3.daemon.wait_for_log("lightningd: fixup_scan: block 172 with 1 txs")
    l3.daemon.wait_for_log("Scanning for missed UTXOs finished")

    # Found it?
    assert only_one(l3.db_query(f"SELECT spendheight as spendheight FROM utxoset WHERE blockheight=103 AND txindex=1"))['spendheight'] == 129

    # Restart will NOT invoke scan.
    oldstart_l3 = l3.daemon.logsearch_start
    oldstart_l1 = l1.daemon.logsearch_start
    l1.restart()
    l3.restart()

    time.sleep(5)
    assert not l1.daemon.is_in_log("Scanning for missed UTXOs", start=oldstart_l1)
    assert not l3.daemon.is_in_log("Scanning for missed UTXOs", start=oldstart_l3)
