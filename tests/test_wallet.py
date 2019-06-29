from decimal import Decimal
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from flaky import flaky  # noqa: F401
from lightning import RpcError, Millisatoshi
from utils import only_one, wait_for, sync_blockheight

import pytest
import time
import unittest


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
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
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
    bitcoind.generate_block(1)

    # Make sure l2 received the withdrawal.
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) == 1)
    outputs = l2.db_query('SELECT value FROM outputs WHERE status=0;')
    assert only_one(outputs)['value'] == 2 * amount

    # Now make sure an additional two of them were marked as spent
    assert l1.db_query('SELECT COUNT(*) as c FROM outputs WHERE status=2')[0]['c'] == 4

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
    with pytest.raises(RpcError, match=r'Cannot afford transaction'):
        l1.rpc.withdraw(waddr, 'all')

    # Add some funds to withdraw
    for i in range(10):
        l1.bitcoin.rpc.sendtoaddress(addr, amount / 10**8 + 0.01)

    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 10)

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
    l1 = node_factory.get_node(random_hsm=True)

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
    time.sleep(1)

    # The address we detect must match what was paid to.
    output = only_one(l1.rpc.listfunds()['outputs'])
    assert output['address'] == addr


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

    prep = l1.rpc.txprepare([{addr: Millisatoshi(amount * 3 * 1000)}])
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
            assert o['scriptPubKey']['addresses'] == [addr]
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
    assert decode['vout'][0]['scriptPubKey']['addresses'] == [addr]

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
    assert decode['vout'][0]['scriptPubKey']['addresses'] == [addr]

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
    assert decode['vout'][0]['scriptPubKey']['addresses'] == [addr]
    l1.rpc.txdiscard(prep4['txid'])

    # Try passing in a utxo set
    utxos = [utxo["txid"] + ":" + str(utxo["output"]) for utxo in l1.rpc.listfunds()["outputs"]][:4]

    prep5 = l1.rpc.txprepare([{addr:
                             Millisatoshi(amount * 3.5 * 1000)}], utxos=utxos)

    decode = bitcoind.rpc.decoderawtransaction(prep5['unsigned_tx'])
    assert decode['txid'] == prep5['txid']

    # Check that correct utxos are included
    assert len(decode['vin']) == 4
    vins = ["{}:{}".format(v['txid'], v['vout']) for v in decode['vin']]
    for utxo in utxos:
        assert utxo in vins

    # We should have a change output, so this is exact
    assert len(decode['vout']) == 3 if chainparams['feeoutput'] else 2
    assert decode['vout'][1]['value'] == Decimal(amount * 3.5) / 10**8
    assert decode['vout'][1]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert decode['vout'][1]['scriptPubKey']['addresses'] == [addr]

    # Discard prep4 and get all funds again
    l1.rpc.txdiscard(prep5['txid'])
    with pytest.raises(RpcError, match=r'this destination wants all satoshi. The count of outputs can\'t be more than 1'):
        prep5 = l1.rpc.txprepare([{addr: Millisatoshi(amount * 3 * 1000)},
                                  {addr: 'all'}])
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
    assert decode['vout'][outnum1]['scriptPubKey']['addresses'] == [addr]

    assert decode['vout'][outnum2]['scriptPubKey']['type'] == 'witness_v0_keyhash'
    assert decode['vout'][outnum2]['scriptPubKey']['addresses'] == [addr]

    assert decode['vout'][changenum]['scriptPubKey']['type'] == 'witness_v0_keyhash'


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
    assert decode['vout'][changenum]['scriptPubKey']['addresses'][0] in [f['address'] for f in l1.rpc.listfunds()['outputs']]


def test_txprepare_restart(node_factory, bitcoind, chainparams):
    amount = 1000000
    l1 = node_factory.get_node(may_fail=True)
    addr = chainparams['example_addr']

    # Add some funds to withdraw later: both bech32 and p2sh
    for i in range(5):
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr()['bech32'],
                                   amount / 10**8)
        bitcoind.rpc.sendtoaddress(l1.rpc.newaddr('p2sh-segwit')['p2sh-segwit'],
                                   amount / 10**8)
    bitcoind.generate_block(1)
    wait_for(lambda: [o['status'] for o in l1.rpc.listfunds()['outputs']] == ['confirmed'] * 10)

    prep = l1.rpc.txprepare([{addr: 'all'}])
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']
    # All 10 inputs
    assert len(decode['vin']) == 10

    # L1 will forget all about it.
    l1.restart()

    # It goes backwards in blockchain just in case there was a reorg.  Wait.
    wait_for(lambda: [o['status'] for o in l1.rpc.listfunds()['outputs']] == ['confirmed'] * 10)

    with pytest.raises(RpcError, match=r'not an unreleased txid'):
        l1.rpc.txdiscard(prep['txid'])

    prep = l1.rpc.txprepare([{addr: 'all'}])

    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']
    # All 10 inputs
    assert len(decode['vin']) == 10

    # This will also work if we simply kill it.
    l1.restart(clean=False)

    # It goes backwards in blockchain just in case there was a reorg.  Wait.
    wait_for(lambda: [o['status'] for o in l1.rpc.listfunds()['outputs']] == ['confirmed'] * 10)

    # It should have logged this for each output.
    for i in decode['vin']:
        assert l1.daemon.is_in_log('wallet: reserved output {}/{} reset to available'.format(i['txid'], i['vout']))

    prep = l1.rpc.txprepare([{addr: 'all'}])
    decode = bitcoind.rpc.decoderawtransaction(prep['unsigned_tx'])
    assert decode['txid'] == prep['txid']
    # All 10 inputs
    assert len(decode['vin']) == 10
