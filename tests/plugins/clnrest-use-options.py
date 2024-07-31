#!/usr/bin/env python3
"""Register rest-port to test that we don't "fix" it."""

from pyln.client import Plugin


plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    print(f"rest-port is {plugin.get_option('rest-port')}")


plugin.add_option('rest-port', None, "Parameter to clash with clnrest deprecated one")


plugin.run()
