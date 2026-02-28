#!/usr/bin/env python3
"""Simple plugin to log the connected_hook.

"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('peer_connected')
def on_connected(peer, plugin, **kwargs):
    print(f"peer_connected_logger_a {peer['id']} {peer}")
    return {'result': 'continue'}


plugin.run()
