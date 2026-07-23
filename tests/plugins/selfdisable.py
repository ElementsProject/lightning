#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    return {'disable': 'init saying disable'}


# plugin.add_option('dummy-option', False, 'does nothing', opt_type='bool')
plugin.run()
