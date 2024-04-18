#!/usr/bin/env python3
"""Plugin to test openchannel_hook

Will simply accept any channel. Useful fot testing chained hook.
"""

from pyln.client import Plugin
import time

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    delaytime = float(plugin.get_option('delaytime'))
    msg = f'delaying WIRE_ACCEPT_CHANNEL for {delaytime}s'
    plugin.log(msg)
    time.sleep(delaytime)
    return {'result': 'continue'}


@plugin.hook('openchannel2')
def on_openchannel2(openchannel2, plugin, **kwargs):
    delaytime = float(plugin.get_option('delaytime'))
    msg = f'delaying WIRE_ACCEPT_CHANNEL for {delaytime}s'
    plugin.log(msg)
    time.sleep(delaytime)
    return {'result': 'continue'}


plugin.add_option('delaytime', '10', 'How long to hold the WIRE_OPEN_CHANNEL.')
plugin.run()
