#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("testplugsubdir")
def testplugsubdir(plugin):
    return "I live."


plugin.run()
