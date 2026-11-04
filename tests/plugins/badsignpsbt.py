#!/usr/bin/env python3
"""Plugin which intercepts `signpsbt` and returns the PSBT *unsigned*.

Used to exercise the failure path in txsend after the unreleased tx has
already been removed from txprepare's list.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("rpc_command")
def on_rpc_command(plugin, rpc_command, **kwargs):
    if rpc_command["method"] != "signpsbt":
        return {"result": "continue"}

    params = rpc_command["params"]
    if isinstance(params, dict):
        psbt = params["psbt"]
    else:
        psbt = params[0]

    # Hand back exactly what we were given: no signatures at all.
    return {"return": {"result": {"signed_psbt": psbt}}}


plugin.run()
