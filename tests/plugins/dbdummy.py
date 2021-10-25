#! /usr/bin/env python3
'''This plugin is used to test we can handle multiple backup plugins, that it
   has some control at shutdown and is correctly killed as last.
'''

from pyln.client import Plugin
from time import sleep
import sys

plugin = Plugin()


@plugin.hook('db_write')
def db_write(plugin, **kwargs):
    return {'result': 'continue'}


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    plugin.log("received shutdown notification")
    # plugins shutdown has timeout of 30s in first call and 5s in 2nd call
    # so only in 2nd call we timeout
    sleep(6)
    sys.exit(0)


# dummy method, should've been removed before JSON RPC is closed
@plugin.method("noop_method")
def handle_dummy_method(plugin, **kwargs):
    pass


plugin.run()
