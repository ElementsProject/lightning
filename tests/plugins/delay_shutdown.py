#! /usr/bin/env python3
'''This plugin is used to delay the plugin shutdown loop
'''

from pyln.client import Plugin
from time import sleep
import sys

plugin = Plugin()


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    plugin.log("delaying shutdown with 10s")
    sleep(8)
    plugin.log("2s before exit")
    sleep(2)
    sys.exit(0)


plugin.run()
