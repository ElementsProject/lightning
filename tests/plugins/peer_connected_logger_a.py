#!/usr/bin/env python3
"""Simple plugin to log the connected_hook.

"""

from pyln.client import Plugin
import os
import time

plugin = Plugin()


@plugin.hook('peer_connected')
def on_connected(peer, plugin, **kwargs):
    print(f"peer_connected_logger_a {peer['id']} {peer}")
    if plugin.get_option("logger_a_sleep") is True:
        # Block until file appears
        while not os.path.exists("unsleep"):
            time.sleep(0.25)
    return {'result': 'continue'}


plugin.add_option("logger_a_sleep", False, 'Block until unsleep file exists', opt_type='bool')
plugin.run()
