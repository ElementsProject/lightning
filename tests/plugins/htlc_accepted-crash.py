#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(plugin, **kwargs):
    plugin.log("Crashing on purpose...")
    raise ValueError()


plugin.run()
