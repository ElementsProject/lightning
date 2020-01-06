#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.method("helloworld", version=1)
def echo(plugin):
    return "helloworld"


plugin.run()
