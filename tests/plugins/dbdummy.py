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
    if shutdown_notifications > 1:
        sleep(4)    # we have 5s to exit before timeout
        exit(0)


plugin.run()
