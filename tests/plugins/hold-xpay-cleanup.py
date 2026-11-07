#!/usr/bin/env python3
"""Hold xpay's asynchronous layer removal until the test releases it."""
from pyln.client import Plugin

plugin = Plugin()
plugin.cleanups = []


@plugin.async_hook("rpc_command")
def hold_cleanup(request, rpc_command, plugin, **kwargs):
    if rpc_command["method"] == "askrene-remove-layer":
        plugin.cleanups.append(request)
        plugin.log("Holding xpay cleanup")
    else:
        request.set_result({"result": "continue"})


@plugin.method("releasecleanup")
def release_cleanup(plugin):
    """Allow all intercepted layer removals to complete."""
    for request in plugin.cleanups:
        request.set_result({"result": "continue"})
    plugin.cleanups.clear()
    return {}


plugin.run()
