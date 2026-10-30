#!/usr/bin/env python3
"""Accepts a dual-funded open with an input of our own, returning version 0
PSBTs from the hooks, as an external wallet may."""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('openchannel2')
def on_openchannel2(openchannel2, plugin, **kwargs):
    psbt = plugin.rpc.call('fundpsbt', {
        'satoshi': 100000,
        'feerate': '{}perkw'.format(openchannel2['funding_feerate_per_kw']),
        'startweight': 0,
        'min_witness_weight': 110,
        'excess_as_change': True,
        'locktime': openchannel2['locktime'],
        'nonwrapped': True})['psbt']
    return {'result': 'continue',
            'psbt': plugin.rpc.setpsbtversion(psbt, 0)['psbt'],
            'our_funding_msat': 100000 * 1000}


@plugin.hook('openchannel2_sign')
def on_openchannel2_sign(openchannel2_sign, plugin, **kwargs):
    signed = plugin.rpc.signpsbt(openchannel2_sign['psbt'])['signed_psbt']
    return {'result': 'continue',
            'psbt': plugin.rpc.setpsbtversion(signed, 0)['psbt']}


plugin.run()
