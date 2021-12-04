#!/usr/bin/env python3
from pyln.client import Plugin

"""A simple plugin that must come before dep_e.
"""
plugin = Plugin()


@plugin.hook('htlc_accepted', before=['dep_e.py'])
def on_htlc_accepted(htlc, plugin, **kwargs):
    print("htlc_accepted called")
    return {'result': 'continue'}


plugin.run()
