#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.method('validate-json-rpc')
def validate_json_rpc(plugin, *args, **kwargs):
    return {}


plugin.run()
