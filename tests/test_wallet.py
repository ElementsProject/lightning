from bitcoin.rpc import JSONRPCError
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from flaky import flaky  # noqa: F401
from pyln.client import RpcError, Millisatoshi
from utils import (
    only_one, wait_for, sync_blockheight, EXPERIMENTAL_FEATURES,
    VALGRIND, check_coin_moves, TailableProc, scriptpubkey_addr,
    check_utxos_channel
)

import os
import pytest
import subprocess
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
    l1 = node_factory.get_node(random_hsm=True)
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
    with pytest.raises(RpcError):
        l1.rpc.withdraw('not an address', amount)
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, 'not an amount')
    with pytest.raises(RpcError):
        l1.rpc.withdraw(waddr, -amount)
    with pytest.raises(RpcError, match=r'Could not afford'):
        l1.rpc.withdraw(waddr, amount * 100)

    out = l1.rpc.withdraw(waddr, 2 * amount)

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


def test_txprepare(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True)
    addr = chainparams['example_addr']

    # Add some funds to withdraw later: both bech32 and p2sh
    for i in range(5):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
                                   amount / 10**8)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

    prep = l1.rpc.txprepare(outputs=[{addr: Millisatoshi(amount * 3 * 1000)}])
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']
    # 4 inputs, 2 outputs (3 if we have a fee output).
    assert len(decode['vin']) == 4
    assert len(decode['vout']) == 2 if not chainparams['feeoutput'] else 3

    # One output will be correct.
    outnum = [i for i, o in enumerate(decode['vout']) if o['value'] == Decimal(amount * 3) / 10**8][0]

    for i, o in enumerate(decode['vout']):
        if i == outnum:
            assert o['scriptPubKey']['type'] == 'witness_v0_keyhash'
            assert scriptpubkey_addr(o['scriptPubKey']) == addr
        else:
            assert o['scriptPubKey']['type'] in ['witness_v0_keyhash', 'fee']

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
    l1.rpc.txdiscard(prep4['txid'])

    # Try passing in a utxo set
    utxos = [utxo["txid"] + ":" + str(utxo["output"])
             for utxo in l1.rpc.listfunds()["outputs"]][:4]
    prep5 = l1.rpc.txprepare([{addr:
                             Millisatoshi(amount * 3.5 * 1000)}], utxos=utxos)

    # Try passing unconfirmed utxos
    unconfirmed_utxo = l1.rpc.withdraw(l1.rpc.newaddr()["bech32"], 10**5)
    uutxos = [unconfirmed_utxo["txid"] + ":0"]
    with pytest.raises(RpcError, match=r"Could not afford"):
        l1.rpc.txprepare([{addr: Millisatoshi(amount * 3.5 * 1000)}],
                         utxos=uutxos)

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
    l1.rpc.txdiscard(prep5['txid'])
    with pytest.raises(RpcError, match=r"'all'"):
        prep5 = l1.rpc.txprepare([{addr: 'all'}, {addr: 'all'}])

    prep5 = l1.rpc.txprepare([{addr: Millisatoshi(amount * 3 * 500 + 100000)},
                              {addr: Millisatoshi(amount * 3 * 500 - 100000)}])
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

    assert decode['vout'][changenum]['scriptPubKey']['type'] == 'witness_v0_keyhash'


def test_reserveinputs(node_factory, bitcoind, chainparams):
    amount = 1000000
    total_outs = 12
    l1 = node_factory.get_node(feerates=(7500, 7500, 7500, 7500))

    outputs = []
    # Add a medley of funds to withdraw later, bech32 + p2sh-p2wpkh
    for i in range(total_outs // 2):
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                          amount / 10**8)
        outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
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

    outputs = []
    # Add a medley of funds to withdraw later, bech32 + p2sh-p2wpkh
    for i in range(total_outs // 2):
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                          amount / 10**8)
        outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))
        txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
                                          amount / 10**8)
        outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    feerate = '7500perkw'

    # Should get one input, plus some excess
    funding = l1.rpc.fundpsbt(amount // 2, feerate, 0, reserve=False)
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    # We can fuzz this up to 99 blocks back.
    assert psbt['tx']['locktime'] > bitcoind.rpc.getblockcount() - 100
    assert psbt['tx']['locktime'] <= bitcoind.rpc.getblockcount()
    assert len(psbt['tx']['vin']) == 1
    assert funding['excess_msat'] > Millisatoshi(0)
    assert funding['excess_msat'] < Millisatoshi(amount // 2 * 1000)
    assert funding['feerate_per_kw'] == 7500
    assert 'estimated_final_weight' in funding
    assert 'reservations' not in funding

    # This should add 99 to the weight, but otherwise be identical (might choose different inputs though!) except for locktime.
    funding2 = l1.rpc.fundpsbt(amount // 2, feerate, 99, reserve=False, locktime=bitcoind.rpc.getblockcount() + 1)
    psbt2 = bitcoind.rpc.decodepsbt(funding2['psbt'])
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

    funding3 = l1.rpc.fundpsbt(amount // 2, feerate, 0, reserve=False, excess_as_change=True)
    assert funding3['excess_msat'] == Millisatoshi(0)
    # Should have the excess msat as the output value (minus fee for change)
    psbt = bitcoind.rpc.decodepsbt(funding3['psbt'])
    change = Millisatoshi("{}btc".format(psbt['tx']['vout'][funding3['change_outnum']]['value']))
    # The weight should be greater (now includes change output)
    change_weight = funding3['estimated_final_weight'] - funding['estimated_final_weight']
    assert change_weight > 0
    # Check that the amount is ok (equal to excess minus change fee)
    change_fee = Millisatoshi(7500 * change_weight)
    assert funding['excess_msat'] == change + change_fee

    # Should get two inputs.
    psbt = bitcoind.rpc.decodepsbt(l1.rpc.fundpsbt(amount, feerate, 0, reserve=False)['psbt'])
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


def test_utxopsbt(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node()

    outputs = []
    # Add a medley of funds to withdraw later, bech32 + p2sh-p2wpkh
    txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                      amount / 10**8)
    outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))
    txid = bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
                                      amount / 10**8)
    outputs.append((txid, bitcoind.rpc.gettransaction(txid)['details'][0]['vout']))

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == len(outputs))

    fee_val = 7500
    feerate = '{}perkw'.format(fee_val)

    # Explicitly spend the first output above.
    funding = l1.rpc.utxopsbt(amount // 2, feerate, 0,
                              ['{}:{}'.format(outputs[0][0], outputs[0][1])],
                              reserve=False)
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    # We can fuzz this up to 99 blocks back.
    assert psbt['tx']['locktime'] > bitcoind.rpc.getblockcount() - 100
    assert psbt['tx']['locktime'] <= bitcoind.rpc.getblockcount()
    assert len(psbt['tx']['vin']) == 1
    assert funding['excess_msat'] > Millisatoshi(0)
    assert funding['excess_msat'] < Millisatoshi(amount // 2 * 1000)
    assert funding['feerate_per_kw'] == 7500
    assert 'estimated_final_weight' in funding
    assert 'reservations' not in funding

    # This should add 99 to the weight, but otherwise be identical except for locktime.
    start_weight = 99
    funding2 = l1.rpc.utxopsbt(amount // 2, feerate, start_weight,
                               ['{}:{}'.format(outputs[0][0], outputs[0][1])],
                               reserve=False, locktime=bitcoind.rpc.getblockcount() + 1)
    psbt2 = bitcoind.rpc.decodepsbt(funding2['psbt'])
    assert psbt2['tx']['locktime'] == bitcoind.rpc.getblockcount() + 1
    assert psbt2['tx']['vin'] == psbt['tx']['vin']
    if chainparams['elements']:
        # elements includes the fee as an output
        addl_fee = Millisatoshi((fee_val * start_weight + 999) // 1000 * 1000)
        assert psbt2['tx']['vout'][0]['value'] == psbt['tx']['vout'][0]['value'] + addl_fee.to_btc()
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
                               reserve=False,
                               excess_as_change=True)
    assert funding3['excess_msat'] == Millisatoshi(0)
    # Should have the excess msat as the output value (minus fee for change)
    psbt = bitcoind.rpc.decodepsbt(funding3['psbt'])
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
                               reserve=False,
                               excess_as_change=True)
    assert 'change_outnum' not in funding4

    # Should get two inputs (and reserve!)
    funding = l1.rpc.utxopsbt(amount, feerate, 0,
                              ['{}:{}'.format(outputs[0][0], outputs[0][1]),
                               '{}:{}'.format(outputs[1][0], outputs[1][1])])
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
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


def test_sign_and_send_psbt(node_factory, bitcoind, chainparams):
    """
    Tests for the sign + send psbt RPCs
    """
    amount = 1000000
    total_outs = 12
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    l1 = node_factory.get_node(options={'plugin': coin_mvt_plugin},
                               feerates=(7500, 7500, 7500, 7500))
    l2 = node_factory.get_node()
    addr = chainparams['example_addr']
    out_total = Millisatoshi(amount * 3 * 1000)

    # Add a medley of funds to withdraw later, bech32 + p2sh-p2wpkh
    for i in range(total_outs // 2):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
                                   amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == total_outs)

    # Make a PSBT out of our inputs
    funding = l1.rpc.fundpsbt(satoshi=out_total,
                              feerate=7500,
                              startweight=42,
                              reserve=True)
    assert len([x for x in l1.rpc.listfunds()['outputs'] if x['reserved']]) == 4
    psbt = bitcoind.rpc.decodepsbt(funding['psbt'])
    saved_input = psbt['tx']['vin'][0]

    # Go ahead and unreserve the UTXOs, we'll use a smaller
    # set of them to create a second PSBT that we'll attempt to sign
    # and broadcast (to disastrous results)
    l1.rpc.unreserveinputs(funding['psbt'])

    # Re-reserve one of the utxos we just unreserved
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
    for i in range(total_outs // 2):
        bitcoind.rpc.sendtoaddress(l2.rpc.newaddr()['bech32'],
                                   amount / 10**8)
        bitcoind.rpc.sendtoaddress(l2.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
                                   amount / 10**8)
    # Create a PSBT using L2
    bitcoind.generate_block(1)
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == total_outs)
    l2_funding = l2.rpc.fundpsbt(satoshi=out_total,
                                 feerate=7500,
                                 startweight=42,
                                 reserve=True)

    # Try to get L1 to sign it
    with pytest.raises(RpcError, match=r"No wallet inputs to sign"):
        l1.rpc.signpsbt(l2_funding['psbt'])

    # With signonly it will fail if it can't sign it.
    with pytest.raises(RpcError, match=r"is unknown"):
        l1.rpc.signpsbt(l2_funding['psbt'], signonly=[0])

    # Add some of our own PSBT inputs to it
    l1_funding = l1.rpc.fundpsbt(satoshi=out_total,
                                 feerate=7500,
                                 startweight=42,
                                 reserve=True)
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
                                 startweight=42,
                                 reserve=True)
    out_amt = Millisatoshi(l2_funding['excess_msat'])
    output_psbt = bitcoind.rpc.createpsbt([],
                                          [{addr: float((out_total + out_amt).to_btc())}])
    psbt = bitcoind.rpc.joinpsbts([l2_funding['psbt'], output_psbt])
    l2_signed_psbt = l2.rpc.signpsbt(psbt)['signed_psbt']
    l1.rpc.sendpsbt(l2_signed_psbt)

    # Re-try sending the same tx?
    bitcoind.generate_block(1)
    sync_blockheight(bitcoind, [l1])
    # Expect an error here
    with pytest.raises(JSONRPCError, match=r"Transaction already in block chain"):
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
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 1000000000, 'debit': 0, 'tags': ['deposit']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
        {'type': 'chain_mvt', 'credit': 0, 'debit': 1000000000, 'tags': ['withdrawal']},
    ]

    check_coin_moves(l1, 'wallet', wallet_coin_mvts, chainparams)


def test_txsend(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True)
    addr = chainparams['example_addr']

    # Add some funds to withdraw later: both bech32 and p2sh
    for i in range(5):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
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


@unittest.skipIf(TEST_NETWORK != 'regtest', "Fee outputs throw off our output matching logic")
@unittest.skipIf(not EXPERIMENTAL_FEATURES, "Tests annotations which are compiled only with experimental features")
def test_transaction_annotations(node_factory, bitcoind):
    l1, l2, l3 = node_factory.get_nodes(3)
    l1.fundwallet(10**6)

    # We should now have a transaction that gave us the funds in the
    # transactions table...
    outputs = l1.rpc.listfunds()['outputs']
    assert(len(outputs) == 1 and outputs[0]['status'] == 'confirmed')
    out = outputs[0]
    idx = out['output']
    assert(idx in [0, 1] and out['value'] == 10**6)

    # ... and it should have an annotation on the output reading 'deposit'
    txs = l1.rpc.listtransactions()['transactions']
    assert(len(txs) == 1)
    tx = txs[0]
    output = tx['outputs'][idx]
    assert(output['type'] == 'deposit' and output['msat'] == Millisatoshi(1000000000))

    # ... and all other output should be change, and have no annotations
    types = []
    for i, o in enumerate(tx['outputs']):
        if i == idx:
            continue
        if 'type' in o:
            types.append(o['type'])
        else:
            types.append(None)

    assert(set([None]) == set(types))

    ##########################################################################
    # Let's now open a channel. The opener should get the funding transaction
    # annotated as channel open and deposit.
    l1.connect(l2)
    fundingtx = l1.rpc.fundchannel(l2.info['id'], 10**5)

    # We should have one output unreserved, and it should be unconfirmed
    outputs = l1.rpc.listfunds()['outputs']
    assert len(outputs) == 2
    outputs = [o for o in outputs if not o['reserved']]
    assert(len(outputs) == 1 and outputs[0]['status'] == 'unconfirmed')

    # It should also match the funding txid:
    assert(outputs[0]['txid'] == fundingtx['txid'])

    # Confirm the channel and check that the output changed to confirmed
    bitcoind.generate_block(3)
    sync_blockheight(bitcoind, [l1, l2])
    outputs = l1.rpc.listfunds()['outputs']
    assert(len(outputs) == 1 and outputs[0]['status'] == 'confirmed')

    # We should have 2 transactions, the second one should be the funding tx
    # (we are ordering by blockheight and txindex, so that order should be ok)
    txs = l1.rpc.listtransactions()['transactions']
    assert(len(txs) == 2 and txs[1]['hash'] == fundingtx['txid'])

    # Check the annotated types
    types = [o['type'] for o in txs[1]['outputs']]
    changeidx = 0 if types[0] == 'deposit' else 1
    fundidx = 1 - changeidx
    assert(types[changeidx] == 'deposit' and types[fundidx] == 'channel_funding')

    # And check the channel annotation on the funding output
    peers = l1.rpc.listpeers()['peers']
    assert(len(peers) == 1 and len(peers[0]['channels']) == 1)
    scid = peers[0]['channels'][0]['short_channel_id']
    assert(txs[1]['outputs'][fundidx]['channel'] == scid)


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
    l1.daemon.start(stdin=slave_fd, stderr=subprocess.STDOUT,
                    wait_for_initialized=False)
    l1.daemon.wait_for_log(r'Enter hsm_secret password')
    write_all(master_fd, password[2:].encode("utf-8"))
    l1.daemon.wait_for_log(r'Confirm hsm_secret password')
    write_all(master_fd, password[2:].encode("utf-8"))
    assert(l1.daemon.proc.wait(WAIT_TIMEOUT) == HSM_BAD_PASSWORD)
    assert(l1.daemon.is_in_log("Wrong password for encrypted hsm_secret."))

    # Test we can restore the same wallet with the same password
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=False)
    l1.daemon.wait_for_log(r'The hsm_secret is encrypted')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log(r'Confirm hsm_secret password')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log("Server started with public key")
    assert id == l1.rpc.getinfo()["id"]
    l1.stop()

    # We can restore the same wallet with the same password provided through stdin
    l1.daemon.start(stdin=subprocess.PIPE, wait_for_initialized=False)
    l1.daemon.proc.stdin.write(password.encode("utf-8"))
    l1.daemon.proc.stdin.write(password.encode("utf-8"))
    l1.daemon.proc.stdin.flush()
    l1.daemon.wait_for_log("Server started with public key")
    assert id == l1.rpc.getinfo()["id"]


class HsmTool(TailableProc):
    """Helper for testing the hsmtool as a subprocess"""
    def __init__(self, *args):
        self.prefix = "hsmtool"
        TailableProc.__init__(self)
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
    hsmtool = HsmTool("decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd,
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, "A wrong pass\n\n".encode("utf-8"))
    hsmtool.proc.wait(WAIT_TIMEOUT)
    hsmtool.is_in_log(r"Wrong password")

    # Decrypt it with hsmtool
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd,
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    hsmtool = HsmTool("encrypt", hsm_path)
    hsmtool.start(stdin=slave_fd,
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    l1.daemon.start(stdin=slave_fd, stderr=subprocess.STDOUT,
                    wait_for_initialized=False)

    l1.daemon.wait_for_log(r'The hsm_secret is encrypted')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log(r'Confirm hsm_secret password')
    write_all(master_fd, password.encode("utf-8"))
    l1.daemon.wait_for_log("Server started with public key")
    print(node_id, l1.rpc.getinfo()["id"])
    assert node_id == l1.rpc.getinfo()["id"]
    l1.stop()

    # And finally test that we can also decrypt if encrypted with hsmtool
    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool("decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd,
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hsmtool.wait_for_log(r"Enter hsm_secret password:")
    write_all(master_fd, password.encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    l1.daemon.opts.pop("encrypted-hsm")
    l1.daemon.start(stdin=slave_fd, wait_for_initialized=True)
    assert node_id == l1.rpc.getinfo()["id"]

    # We can roundtrip encryption and decryption using a password provided
    # through stdin.
    hsmtool = HsmTool("encrypt", hsm_path)
    hsmtool.start(stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE)
    hsmtool.proc.stdin.write(password.encode("utf-8"))
    hsmtool.proc.stdin.write(password.encode("utf-8"))
    hsmtool.proc.stdin.flush()
    hsmtool.wait_for_log("Successfully encrypted")
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0

    master_fd, slave_fd = os.openpty()
    hsmtool = HsmTool("decrypt", hsm_path)
    hsmtool.start(stdin=slave_fd,
                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    out = subprocess.check_output(cmd_line).decode("utf8").split("\n")
    descriptor = [l for l in out if l.startswith("wpkh(tpub")][0]

    # If we switch wallet, we can't generate address: do so now.
    mine_to_addr = bitcoind.rpc.getnewaddress()

    # Import the descriptor to bitcoind
    try:
        bitcoind.rpc.importmulti([{
            "desc": descriptor,
            # No need to rescan, we'll transact afterward
            "timestamp": "now",
            # The default
            "range": [0, 99]
        }])
    except JSONRPCError:
        # Oh look, a new API!
        # Need watch-only wallet, since descriptor has no privkeys.
        bitcoind.rpc.createwallet("lightningd-ro", True)

        # FIXME: No way to access non-default wallet in python-bitcoinlib
        bitcoind.rpc.unloadwallet("lightningd-tests", True)
        bitcoind.rpc.importdescriptors([{
            "desc": descriptor,
            # No need to rescan, we'll transact afterward
            "timestamp": "now",
            # The default
            "range": [0, 99]
        }])

    # Funds sent to lightningd can be retrieved by bitcoind
    addr = l1.rpc.newaddr()["bech32"]
    txid = l1.rpc.withdraw(addr, 10**3)["txid"]
    bitcoind.generate_block(1, txid, mine_to_addr)
    assert len(bitcoind.rpc.listunspent(1, 1, [addr])) == 1


@unittest.skipIf(VALGRIND, "It does not play well with prompt and key derivation.")
def test_hsmtool_generatehsm(node_factory):
    l1 = node_factory.get_node()
    l1.stop()
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK,
                            "hsm_secret")

    hsmtool = HsmTool("generatehsm", hsm_path)

    # You cannot re-generate an already existing hsm_secret
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE)
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 2
    os.remove(hsm_path)

    # We can generate a valid hsm_secret from a wordlist and a "passphrase"
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd, stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE)
    hsmtool.wait_for_log(r"Select your language:")
    write_all(master_fd, "0\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing "
              "cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    hsmtool.proc.wait(WAIT_TIMEOUT)
    hsmtool.is_in_log(r"New hsm_secret file created")

    # We can start the node with this hsm_secret
    l1.start()


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


@flaky
@unittest.skipIf(VALGRIND, "A big loop is used to check fuzz.")
def test_withdraw_nlocktime_fuzz(node_factory, bitcoind):
    """
    Test that we eventually fuzz nLockTime for withdrawal transactions.
    Marked flaky "just in case" as we fuzz from 0 to 100 with a 10%
    probability.
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

    # Based on BIP-320, but all changed to regtest.
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
    l1.rpc.multiwithdraw(args)["txid"]
