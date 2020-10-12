#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()


@plugin.method("call_make_notify")
def call_make_notify(plugin, request, **kwargs):
    plugin.notify_message(request, "Starting notification", level='debug')
    plugin.notify_progress(request, 0, 2)
    plugin.notify_progress(request, 1, 2)
    return plugin.rpc.call('make_notify')


plugin.run()
