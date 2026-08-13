#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("myrpcmethod")
def myrpcmethod(plugin, **kwargs):
    return {}


plugin.run()
