#!/usr/bin/env python3
"""
This plugin is used to shutdown a node before processing the sendpsbt command
"""
from pyln.client import Plugin
import os
import signal

plugin = Plugin()


@plugin.hook("rpc_command")
def on_rpc_command(plugin, rpc_command, **kwargs):
    request = rpc_command
    if request["method"] == "sendpsbt":
        os.kill(os.getppid(), signal.SIGKILL)

    return {"result": "continue"}


plugin.run()
