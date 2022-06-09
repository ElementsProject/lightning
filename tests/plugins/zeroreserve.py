#!/usr/bin/env python3
"""Use the openchannel hook to selectively opt-into zeroconf
"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    plugin.log(repr(openchannel))
    reserve = plugin.options['reserve']['value']

    if reserve is None:
        return {'result': 'continue'}
    else:
        return {'result': 'continue', 'reserve': reserve}


plugin.add_option(
    'reserve',
    None,
    'Absolute reserve to require from peers when accepting channels',
)

plugin.run()
