#!/usr/bin/env python3
from pyln.client import Plugin
import os
import time

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("slow_init.py initializing {}".format(configuration))
    time.sleep(int(os.getenv('SLOWINIT_TIME', "0")))


plugin.run()
