#!/usr/bin/env python3
"""Test P2TR change outputs with dust limit 330 sat (issue #8395)."""
import unittest
from pyln.testing.fixtures import *  # noqa: F401,F403
from pyln.testing.utils import TEST_NETWORK, wait_for


@unittest.skipIf(TEST_NETWORK == 'liquid-regtest', "P2TR not yet supported on Elements")
def test_p2tr_change_dust_limit(node_factory, bitcoind):

    l1 = node_factory.get_node(feerates=(253, 253, 253, 253))

    addr = l1.rpc.newaddr('p2tr')['p2tr']
    bitcoind.rpc.sendtoaddress(addr, 1.0)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l1.rpc.listfunds()['outputs']) == 1)

    outputs = l1.rpc.listfunds()['outputs']
    assert len(outputs) == 1
    utxo = outputs[0]

    utxo_amount = int(utxo['amount_msat'] / 1000)

    target_amount = utxo_amount - 450

    result = l1.rpc.fundpsbt(
        satoshi=f"{target_amount}sat",
        feerate="253perkw",
        startweight=0,
        excess_as_change=True
    )

    assert 'change_outnum' in result, "Expected change output to be created"

    psbt = bitcoind.rpc.decodepsbt(result['psbt'])

    change_outnum = result['change_outnum']
    if 'tx' in psbt:
        change_output = psbt['tx']['vout'][change_outnum]
        change_amount_btc = float(change_output['value'])
    else:
        change_output = psbt['outputs'][change_outnum]
        change_amount_btc = float(change_output['amount'])

    change_amount_sat = int(change_amount_btc * 100_000_000)

    print(f"Change amount: {change_amount_sat} sat")

    assert change_amount_sat >= 330, f"Change {change_amount_sat} sat should be >= 330 sat"
    assert change_amount_sat <= 546, f"Change {change_amount_sat} sat should be <= 546 sat (for this test)"

    print(f"SUCCESS: P2TR change output of {change_amount_sat} sat created (between 330 and 546 sat)")