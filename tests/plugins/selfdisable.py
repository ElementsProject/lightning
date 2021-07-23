#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    return {'disable': 'init saying disable'}


plugin.run()
