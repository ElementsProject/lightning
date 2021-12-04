#!/usr/bin/env python3
from pyln.client import Plugin

"""A simple plugin that must come after dep_a, before dep_c.
"""
plugin = Plugin()


@plugin.hook('htlc_accepted', before=['dep_c.py'], after=['dep_a.py'])
def on_htlc_accepted(htlc, plugin, **kwargs):
    print("htlc_accepted called")
    return {'result': 'continue'}


plugin.run()
