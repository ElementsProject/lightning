#!/usr/bin/env python3

from pyln.client import Plugin
import time

plugin = Plugin()


@plugin.method("make_notify")
def make_notify(plugin, request, **kwargs):
    plugin.notify_message(request, "Beginning stage 1")
    for i in range(100):
        plugin.notify_progress(request, i, 100, stage=0, stage_total=2)
        time.sleep(0.01)
    plugin.notify_message(request, "Beginning stage 2", level='debug')
    for i in range(10):
        plugin.notify_progress(request, i, 10, stage=1, stage_total=2)
        time.sleep(0.1)
    return "This worked"


plugin.run()
