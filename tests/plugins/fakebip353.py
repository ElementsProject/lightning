#!/usr/bin/env python3
"""
This imitates fetchbip353 for testing.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("fetchbip353")
def fetchbip353(plugin, address, **kwargs):
    return {'instructions': [{'offer': plugin.options['bip353offer']['value']}]}


plugin.add_option(
    'bip353offer',
    None,
    "Fake offer to return"
)

plugin.run()
