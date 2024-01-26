#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("testplug initialized")


@plugin.method("testmethod")
def testmethod(plugin):
    return ("I live.")


plugin.run()
