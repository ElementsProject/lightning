#!/usr/bin/env python3
from pyln.client import Plugin

"""A simple plugin that registers an htlc_accepted hook..
"""
plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(htlc, plugin, **kwargs):
    print("htlc_accepted called")
    return {'result': 'continue'}


plugin.run()
