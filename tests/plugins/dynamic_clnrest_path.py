#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("dynamic-clnrest-method")
def my_new_method(plugin):
    return {"test-dynamic-clnrest": "success"}


@plugin.method("invalid-nodeid")
def invalid_nodeid(plugin):
    return {"test-invalid-nodeid": "success"}


@plugin.method("capture-route")
def capture_route(plugin, version, capture):
    return {"version": version, "capture": capture}


@plugin.init()
def init(options, configuration, plugin):
    plugin.rpc.call(
        "clnrest-register-path",
        [
            "test/dynamic/clnrest",
            "dynamic-clnrest-method",
            {"method": "pay"},
        ],
    )
    plugin.rpc.call(
        "clnrest-register-path",
        [
            "invalid/nodeid",
            "invalid-nodeid",
            {
                "nodeid": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d"
            },
        ],
    )
    plugin.rpc.call(
        "clnrest-register-path",
        {
            "path": r"v{version}/{capture}/go",
            "rpc_method": "capture-route",
            "rune": {"params": {"amount_msat": 9999}},
        },
    )


plugin.run()
