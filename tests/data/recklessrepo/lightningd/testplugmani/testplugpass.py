#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()

__version__ = 'v1'


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("testplug initialized")


@plugin.method("testmethod")
def testmethod(plugin):
    return ("I live.")


@plugin.method("gettestplugversion")
def gettestplugversion(plugin):
    "to test commit/tag checkout"
    return __version__


plugin.run()
