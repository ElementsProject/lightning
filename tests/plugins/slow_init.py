#!/usr/bin/env python3
from pyln.client import Plugin
import time

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("slow_init.py initializing {}".format(configuration))
    time.sleep(21)


plugin.run()
