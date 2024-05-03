#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()

plugin.add_option(
    name="test-dynamic-config",
    description="A config option which can be changed at run-time",
    default="initial",
    dynamic=True)


@plugin.method('dynamic-option-report')
def record_lookup(plugin):
    return {'test-dynamic-config': plugin.get_option('test-dynamic-config')}


plugin.run()
