#!/usr/bin/env python3
"""Plugin to test openchannel_hook

Will simply reject any channel with message "reject on principle".
Useful fot testing chained hook.
"""

from pyln.client import Plugin
from pyln.testing.utils import env

EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"


plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    msg = "reject on principle"
    plugin.log(msg)
    return {'result': 'reject', 'error_message': msg}


if EXPERIMENTAL_FEATURES:
    @plugin.hook('openchannel2')
    def on_openchannel2(openchannel2, plugin, **kwargs):
        msg = "reject on principle"
        plugin.log(msg)
        return {'result': 'reject', 'error_message': msg}


plugin.run()
