#!/usr/bin/env python3

from pyln.client import Plugin
import os

plugin = Plugin()


@plugin.method("die")
def die():
    os._exit(1)


plugin.run()
