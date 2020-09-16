#!/usr/bin/env python3
"""Test plugin for executing the opener v2 protocol
"""
from pyln.client import Plugin, Millisatoshi
from pyln.proto import bech32_decode
from typing import Iterable, List, Optional
from wallycore import psbt_add_output_at, psbt_from_base64, psbt_to_base64, tx_output_init


plugin = Plugin()


def convertbits(data: Iterable[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def get_script(bech_addr):
    hrp, data = bech32_decode(bech_addr)
    # FIXME: verify hrp matches expected network
    wprog = convertbits(data[1:], 5, 8, False)
    wit_ver = data[0]
    if wit_ver > 16:
        raise ValueError("Invalid witness version {}".format(wit_ver[0]))
    return bytes([wit_ver + 0x50 if wit_ver > 0 else wit_ver, len(wprog)] + wprog)


@plugin.method('openchannelv2')
def openchannel_v2(plugin, node_id, amount):
    change_output_weight = (9 + 22) * 4
    funding_output_weight = (9 + 34) * 4
    core_weight = 44
    feerate_val = 2000
    feerate = '{}perkw'.format(feerate_val)

    funding = plugin.rpc.fundpsbt(amount, feerate, funding_output_weight + core_weight)
    psbt_obj = psbt_from_base64(funding['psbt'])

    excess = Millisatoshi(funding['excess_msat'])
    # FIXME: convert feerate ?!
    change_cost = Millisatoshi(change_output_weight * feerate_val // 1000 * 1000)
    dust_limit = Millisatoshi(feerate_val * 1000)
    if excess > (dust_limit + change_cost):
        addr = plugin.rpc.newaddr()['bech32']
        change = excess - change_cost
        output = tx_output_init(int(change.to_satoshi()), get_script(addr))
        psbt_add_output_at(psbt_obj, 0, 0, output)

    resp = plugin.rpc.openchannel_init(node_id, amount,
                                       psbt_to_base64(psbt_obj, 0),
                                       commitment_feerate=feerate,
                                       funding_feerate=feerate)

    # We don't have an updates, so we send update until our peer is also
    # finished
    while not resp['commitments_secured']:
        resp = plugin.rpc.openchannel_update(node_id, resp['psbt'])

    # fixme: pass in array of our input indexes to signonly
    signed = plugin.rpc.signpsbt(resp['psbt'])
    return plugin.rpc.openchannel_signed(node_id, signed['signed_psbt'])


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("df_opener.py initializing")


plugin.run()
