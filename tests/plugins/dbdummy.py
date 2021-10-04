#! /usr/bin/env python3
'''This plugin is used to test we can handle multiple backup plugins and
that they have some control at shutdown.
'''

from pyln.client import Plugin
from time import sleep

plugin = Plugin()
shutdown_notifications = 0


@plugin.hook('db_write')
def db_write(plugin, **kwargs):
    return {'result': 'continue'}


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    global shutdown_notifications
    shutdown_notifications += 1
    plugin.log("received shutdown notification {}".format(shutdown_notifications))
    # don't exit to triggers the 5s timeout


plugin.run()
