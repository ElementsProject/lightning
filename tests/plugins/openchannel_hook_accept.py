#!/usr/bin/env python3
"""Plugin to test openchannel_hook

Will simply accept any channel. Useful fot testing chained hook.
"""

from pyln.client import Plugin
from pyln.testing.utils import env

plugin = Plugin()


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    msg = "accept on principle"
    plugin.log(msg)
    return {'result': 'continue'}


if EXPERIMENTAL_FEATURES:
    @plugin.hook('openchannel2')
    def on_openchannel2(openchannel2, plugin, **kwargs):
        msg = "accept on principle"
        plugin.log(msg)
        return {'result': 'continue'}


plugin.run()
