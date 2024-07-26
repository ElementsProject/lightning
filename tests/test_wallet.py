from bitcoin.rpc import JSONRPCError
from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from utils import (
    only_one, wait_for, sync_blockheight,
    VALGRIND, check_coin_moves, TailableProc, scriptpubkey_addr,
    check_utxos_channel
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


def test_txprepare(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(random_hsm=True)
    addr = chainparams['example_addr']

    # Add some funds to withdraw later
    for i in range(10):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
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

    if chainparams['elements']:
        assert decode['vout'][changenum]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    else:
        assert decode['vout'][changenum]['scriptPubKey']['type'] == 'witness_v1_taproot'


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


def test_hsmtool_generatehsm(node_factory):
    l1 = node_factory.get_node(start=False)
    hsm_path = os.path.join(l1.daemon.lightning_dir, TEST_NETWORK,
                            "hsm_secret")

    hsmtool = HsmTool(node_factory.directory, "generatehsm", hsm_path)

    # You cannot re-generate an already existing hsm_secret
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 2
    os.remove(hsm_path)

    # We can generate a valid hsm_secret from a wordlist and a "passphrase"
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Select your language:")
    write_all(master_fd, "0\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing "
              "cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"New hsm_secret file created")

    # Check should pass.
    hsmtool = HsmTool(node_factory.directory, "checkhsm", hsm_path)
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Select your language:")
    write_all(master_fd, "0\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing "
              "cake have wedding\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"OK")

    # Wrong mnemonic will fail.
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Select your language:")
    write_all(master_fd, "0\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 5
    hsmtool.is_in_log(r"resulting hsm_secret did not match")

    # Wrong passphrase will fail.
    master_fd, slave_fd = os.openpty()
    hsmtool.start(stdin=slave_fd)
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase \n".encode("utf-8"))
    hsmtool.wait_for_log(r"Select your language:")
    write_all(master_fd, "0\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing "
              "cake have wedding\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 5
    hsmtool.is_in_log(r"resulting hsm_secret did not match")

    # We can start the node with this hsm_secret
    l1.start()
    assert l1.info['id'] == '02244b73339edd004bc6dfbb953a87984c88e9e7c02ca14ef6ec593ca6be622ba7'


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
    hsmtool.wait_for_log(r"Select your language:")
    write_all(master_fd, "0\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Introduce your BIP39 word list")
    write_all(master_fd, "ritual idle hat sunny universe pluck key alpha wing "
              "cake have wedding\n".encode("utf-8"))
    hsmtool.wait_for_log(r"Enter your passphrase:")
    write_all(master_fd, "This is actually not a passphrase\n".encode("utf-8"))
    assert hsmtool.proc.wait(WAIT_TIMEOUT) == 0
    hsmtool.is_in_log(r"New hsm_secret file created")

    cmd_line = ["tools/hsmtool", "makerune", hsm_path]
    out = subprocess.check_output(cmd_line).decode("utf8").split("\n")[0]

    l1.start()

    # We have to generate a rune now, for commando to even start processing!
    rune = l1.rpc.commando_rune()['rune']
    assert rune == out
