#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()

__version__ = 'v1'


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("testpluguv initialized")


@plugin.method("uvplugintest")
def uvplugintest(plugin):
    return "I live."


@plugin.method("getuvpluginversion")
def getuvpluginversion(plugin):
    "to test commit/tag checkout"
    return __version__


plugin.run()
