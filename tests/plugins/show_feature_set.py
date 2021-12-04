#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin):
    plugin.feature_set = configuration['feature_set']


@plugin.method('getfeatureset')
def getfeatureset(plugin):
    return plugin.feature_set


plugin.run()
