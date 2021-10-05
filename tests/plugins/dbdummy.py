#! /usr/bin/env python3
'''This plugin is used to test we can handle multiple backup plugins and
that they have some control at shutdown.
'''

from pyln.client import Plugin
from time import sleep
import sys

plugin = Plugin()
shutdown_notifications = 0


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


plugin.run()
