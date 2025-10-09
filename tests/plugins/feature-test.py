#!/usr/bin/env python3

from pyln.client import Plugin
import os

# Register a different set feature of feature bits for each location so we can
# later check that they are being passed correctly.
plugin = Plugin(
    dynamic=False,
    init_features=1 << 201,
    node_features=1 << 203,
    invoice_features=1 << 205,
)


@plugin.init()
def init(configuration, options, plugin):
    disable = os.getenv("PLUGIN_DISABLE")
    if disable:
        return {'disable': 'init saying disable'}
    return {}


plugin.run()
