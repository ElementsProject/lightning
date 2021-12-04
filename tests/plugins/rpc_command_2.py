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
        request["params"]["description"] = "rpc_command_2 modified this description"
        return {"replace": request}
    elif request["method"] == "sendpay":
        # Don't allow this command to be executed
        return {"return": {"error": {"code": -1,
                                     "message": "rpc_command_2 cannot do this"}}}
    return {"result": "continue"}


plugin.run()
