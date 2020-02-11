#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.method("utf8")
def echo(plugin, utf8):
    assert '\\u' not in utf8
    return {'utf8': utf8}


plugin.run()
