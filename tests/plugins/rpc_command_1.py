#!/usr/bin/env python3
"""
This plugin is used to test the chained `rpc_command` hook.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("rpc_command")
def on_rpc_command(plugin, rpc_command, **kwargs):
    request = rpc_command
    if request["method"] == "invoice":
        # Replace part of this command
        request["params"]["description"] = "rpc_command_1 modified this description"
        return {"replace": request}
    elif request["method"] == "listfunds":
        # Return a custom result to the command
        return {"return": {"result": ["Custom rpc_command_1 result"]}}
    elif request["method"] == "help":
        request["method"] = "autocleaninvoice"
        return {"replace": request}
    return {"result": "continue"}


plugin.run()
