#! /usr/bin/env python3
'''This plugin is used to delay the plugin shutdown loop
'''

from pyln.client import Plugin
from time import sleep
import sys

plugin = Plugin()


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    delay = int(plugin.get_option('shutdown_delay'))
    plugin.log("delay shutdown with {}".format(delay))
    sleep(delay)
    sys.exit(0)


plugin.add_option('shutdown_delay', 0, '', opt_type='int')
plugin.run()
