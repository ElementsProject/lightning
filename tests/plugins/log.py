#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("printing debug log", level='debug')
    plugin.log("printing info log", level='info')


plugin.run()
