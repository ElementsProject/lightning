#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("getinfo")
def getinfo(plugin, **kwargs):
    return {}


plugin.run()
