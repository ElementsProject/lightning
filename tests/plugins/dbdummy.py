#! /usr/bin/env python3
'''This plugin is a do-nothing backup plugin which just checks that we
can handle multiple backup plugins.
'''

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('db_write')
def db_write(plugin, **kwargs):
    return {'result': 'continue'}


plugin.run()
