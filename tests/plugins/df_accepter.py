#!/usr/bin/env python3
"""Test plugin for adding inputs/outputs to a dual-funded transaction
"""

from pyln.client import Plugin, Millisatoshi
from wallycore import (
    psbt_find_input_unknown,
    psbt_from_base64,
    psbt_get_input_unknown,
    psbt_get_num_inputs,
)

plugin = Plugin()


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
    plugin.inflight = {}
    plugin.log('max funding set to {}'.format(plugin.max_fund))


@plugin.method("setacceptfundingmax")
def set_accept_funding_max(plugin, max_sats, **kwargs):
    plugin.max_fund = Millisatoshi(max_sats)

    return {'accepter_max_funding': plugin.max_fund}


def add_inflight(plugin, peerid, chanid, psbt):
    if peerid in plugin.inflight:
        chans = plugin.inflight[peerid]
    else:
        chans = {}
        plugin.inflight[peerid] = chans

    if chanid in chans:
        raise ValueError("channel {} already in flight (peer {})".format(chanid, peerid))
    chans[chanid] = psbt


def cleanup_inflight(plugin, chanid):
    for peer, chans in plugin.inflight.items():
        if chanid in chans:
            psbt = chans[chanid]
            del chans[chanid]
            return psbt
    return None


def cleanup_inflight_peer(plugin, peerid):
    if peerid in plugin.inflight:
        chans = plugin.inflight[peerid]
        for chanid, psbt in chans.items():
            plugin.rpc.unreserveinputs(psbt)
        del plugin.inflight[peerid]


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
    proposed_feerate = openchannel2['funding_feerate_per_kw']
    our_min = openchannel2['feerate_our_min']
    our_max = openchannel2['feerate_our_max']

    # Their feerate range is out of bounds, we're not going to
    # participate.
    if proposed_feerate > our_max or proposed_feerate < our_min:
        plugin.log("Declining to fund, feerate unacceptable.")
        return {'result': 'continue'}

    funding = plugin.rpc.fundpsbt(int(amount.to_satoshi()),
                                  '{}perkw'.format(proposed_feerate),
                                  0,  # because we're the accepter!!
                                  reserve=True,
                                  locktime=locktime,
                                  minconf=0,
                                  min_witness_weight=110,
                                  excess_as_change=True)
    add_inflight(plugin, openchannel2['id'],
                 openchannel2['channel_id'], funding['psbt'])
    plugin.log("contributing {} at feerate {}".format(amount, proposed_feerate))

    return {'result': 'continue', 'psbt': funding['psbt'],
            'accepter_funding_msat': amount}


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

    cleanup_inflight(plugin, openchannel2_sign['channel_id'])
    return {'result': 'continue', 'psbt': final_psbt}


@plugin.subscribe("channel_open_failed")
def on_open_failed(channel_open_failed, plugin, **kwargs):
    channel_id = channel_open_failed['channel_id']
    psbt = cleanup_inflight(plugin, channel_id)
    if psbt:
        plugin.log("failed to open channel {}, unreserving".format(channel_id))
        plugin.rpc.unreserveinputs(psbt)


@plugin.subscribe("disconnect")
def on_peer_disconnect(id, plugin, **kwargs):
    plugin.log("peer {} disconnected, removing inflights".format(id))
    cleanup_inflight_peer(plugin, id)


plugin.run()
