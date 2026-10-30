#!/usr/bin/env python3
"""Accepts a dual-funded open with an input of our own, then returns a PSBT
whose outputs sum above max supply from openchannel2_changed."""

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
    return {'result': 'continue', 'psbt': psbt,
            'our_funding_msat': 100000 * 1000}


added = False


@plugin.hook('openchannel2_changed')
def on_openchannel2_changed(openchannel2_changed, plugin, **kwargs):
    global added
    psbt = openchannel2_changed['psbt']
    if not added:
        added = True
        psbt = plugin.rpc.setpsbtversion(psbt, 2)['psbt']
        # Each fits under max supply, so libwally accepts them; 10M + 11M BTC + 1 sat does not.
        psbt = plugin.rpc.addpsbtoutput(1000000000000000, psbt)['psbt']
        psbt = plugin.rpc.addpsbtoutput(1100000000000001, psbt)['psbt']
    return {'result': 'continue', 'psbt': psbt}


plugin.run()
