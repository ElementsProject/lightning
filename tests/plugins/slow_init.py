#!/usr/bin/env python3
from lightning import Plugin
import time

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("slow_init.py initializing")
    time.sleep(1)


plugin.run()
