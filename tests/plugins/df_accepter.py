#!/usr/bin/env python3
"""Test plugin for adding inputs/outputs to a dual-funded transaction
"""

from pyln.client import Plugin, Millisatoshi
from pyln.proto import bech32_decode
from typing import Iterable, List, Optional
from wallycore import (
    psbt_add_output_at,
    psbt_find_input_unknown,
    psbt_from_base64,
    psbt_get_input_unknown,
    psbt_get_num_inputs,
    psbt_to_base64,
    tx_output_init,
)

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


def find_feerate(best, their_min, their_max, our_min, our_max):
    if best >= our_min and best <= our_max:
        return best

    if their_max < our_min or their_min > our_max:
        return False

    if best < our_min:
        return our_min

    # best > our_max:
    return our_max


def find_inputs(b64_psbt):
    serial_id_key = bytes.fromhex('fc096c696768746e696e6701')
    psbt = psbt_from_base64(b64_psbt)
    input_idxs = []

    for i in range(psbt_get_num_inputs(psbt)):
        idx = psbt_find_input_unknown(psbt, i, serial_id_key)
        if idx == 0:
            continue
        # returned index is off by one, so 0 can be 'not found'
        serial_bytes = psbt_get_input_unknown(psbt, i, idx - 1)
        serial_id = int.from_bytes(serial_bytes, byteorder='big', signed=False)

        # We're the accepter, so our inputs have odd serials
        if serial_id % 2:
            input_idxs.append(i)

    return input_idxs


@plugin.init()
def init(configuration, options, plugin):
    # this is the max channel size, pre-wumbo
    plugin.max_fund = Millisatoshi((2 ** 24 - 1) * 1000)
    plugin.log('max funding set to {}'.format(plugin.max_fund))


@plugin.method("setacceptfundingmax")
def set_accept_funding_max(plugin, max_sats, **kwargs):
    plugin.max_fund = Millisatoshi(max_sats)

    return {'accepter_max_funding': plugin.max_fund}


@plugin.hook('openchannel2')
def on_openchannel(openchannel2, plugin, **kwargs):
    # We mirror what the peer does, wrt to funding amount ...
    amount = Millisatoshi(openchannel2['their_funding'])
    locktime = openchannel2['locktime']

    if amount > plugin.max_fund:
        plugin.log("amount adjusted from {} to {}".format(amount, plugin.max_fund))
        amount = plugin.max_fund

    if amount == 0:
        plugin.log("accepter_max_funding set to zero")
        return {'result': 'continue'}

    # ...unless they send us totally unacceptable feerates.
    feerate = find_feerate(openchannel2['funding_feerate_best'],
                           openchannel2['funding_feerate_min'],
                           openchannel2['funding_feerate_max'],
                           openchannel2['feerate_our_min'],
                           openchannel2['feerate_our_max'])

    # Their feerate range is out of bounds, we're not going to
    # participate.
    if not feerate:
        plugin.log("Declining to fund, no feerate found.")
        return {'result': 'continue'}

    funding = plugin.rpc.fundpsbt(int(amount.to_satoshi()),
                                  '{}perkw'.format(feerate),
                                  0,  # because we're the accepter!!
                                  reserve=True,
                                  locktime=locktime,
                                  minconf=0,
                                  min_witness_weight=110)
    psbt_obj = psbt_from_base64(funding['psbt'])

    excess = Millisatoshi(funding['excess_msat'])
    change_cost = Millisatoshi(124 * feerate)
    dust_limit = Millisatoshi(253 * 1000)
    if excess > (dust_limit + change_cost):
        addr = plugin.rpc.newaddr()['bech32']
        change = excess - change_cost
        output = tx_output_init(change.to_whole_satoshi(), get_script(addr))
        psbt_add_output_at(psbt_obj, 0, 0, output)

    plugin.log("contributing {} at feerate {}".format(amount, feerate))
    return {'result': 'continue', 'psbt': psbt_to_base64(psbt_obj, 0),
            'accepter_funding_msat': amount,
            'funding_feerate': feerate}


@plugin.hook('openchannel2_changed')
def on_tx_changed(openchannel2_changed, plugin, **kwargs):
    # In this example, we have nothing to add, so we
    # pass back the same psbt that was forwarded in here
    return {'result': 'continue', 'psbt': openchannel2_changed['psbt']}


@plugin.hook('openchannel2_sign')
def on_tx_sign(openchannel2_sign, plugin, **kwargs):
    psbt = openchannel2_sign['psbt']

    # We only sign the ones with our parity of a serial_id
    input_idxs = find_inputs(psbt)
    if len(input_idxs) > 0:
        final_psbt = plugin.rpc.signpsbt(psbt, signonly=input_idxs)['signed_psbt']
    else:
        final_psbt = psbt

    return {'result': 'continue', 'psbt': final_psbt}


plugin.run()
