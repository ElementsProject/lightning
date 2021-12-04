#!/usr/bin/env python3

from pyln.client import Plugin
import time

plugin = Plugin()


@plugin.method("countdown")
def countdown(count, plugin, request):
    count = int(count)
    for i in range(count):
        time.sleep(0.1)
        request.notify("{}/{}".format(i, count), "INFO")

    return "Done"


plugin.run()
