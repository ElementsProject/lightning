#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()

plugin.add_option(
    name="test-dynamic-config",
    description="A config option which can be changed at run-time",
    default="initial",
    dynamic=True)

plugin.run()
