#!/usr/bin/env python3
from pyln.client import Plugin
import sys


plugin = Plugin()


@plugin.subscribe("*")
def on_any_notification(request, **kwargs):
    plugin.log("notification {}: {}".format(request.method, kwargs))
    if request.method == 'shutdown':
        # A plugin which subscribes to shutdown is expected to exit itself.
        sys.exit(0)


plugin.run()
