#!/usr/bin/env python3
"""
This plugin is used to test the `rpc_command` hook.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("rpc_command")
def on_rpc_command(plugin, rpc_command, **kwargs):
    request = rpc_command
    if request["method"] == "invoice":
        # Replace part of this command
        request["params"]["description"] = "A plugin modified this description"
        return {"replace": request}
    elif request["method"] == "listfunds":
        # Return a custom result to the command
        return {"return": {"result": ["Custom result"]}}
    elif request["method"] == "sendpay":
        # Don't allow this command to be executed
        return {"return": {"error": {"code": -1, "message": "You cannot do this"}}}
    elif request["method"] == "help":
        request["method"] = "autocleaninvoice"
        return {"replace": request}
    elif request["method"] == "listnodes" and request["params"]:
        # Fetch results and modify
        info = plugin.rpc.call("getinfo")
        info["id"] = request["params"][0]
        return {"return": {"result": info}}
    return {"result": "continue"}


plugin.run()
