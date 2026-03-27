#!/usr/bin/env python3
"""Use the openchannel hook to selectively opt-into zeroconf
"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    mindepth = int(plugin.options['zeroconf_mindepth']['value'])

    if openchannel['id'] == plugin.options['zeroconf_allow']['value'] or plugin.options['zeroconf_allow']['value'] == 'any':
        plugin.log(f"This peer is in the zeroconf allowlist, setting mindepth={mindepth}")
        return {'result': 'continue', 'mindepth': mindepth}
    else:
        return {'result': 'continue'}


@plugin.hook('openchannel2')
def on_openchannel2(openchannel2, plugin, **kwargs):
    return on_openchannel(openchannel2, plugin, **kwargs)


plugin.add_option(
    'zeroconf_allow',
    '03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f',
    'A node_id to allow zeroconf channels from',
)

plugin.add_option(
    'zeroconf_mindepth',
    0,
    'Number of confirmations to require from allowlisted peers',
)

plugin.run()
