#!/usr/bin/env python3
"""Simple plugin to test the connected_hook.

It can mark some node_ids as rejects and it'll check for each
connection if it should be disconnected immediately or if it can
continue.

"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('peer_connected')
def on_connected(peer, plugin, **kwargs):
    if peer['id'] in plugin.reject_ids:
        print("{} is in reject list, disconnecting".format(peer['id']))
        return {'result': 'disconnect', 'error_message': 'You are in reject list'}

    print("{} is allowed".format(peer['id']))
    return {'result': 'continue'}


@plugin.init()
def init(configuration, options, plugin):
    plugin.reject_ids = []


@plugin.method('reject')
def reject(node_id, plugin):
    """Mark a given node_id as reject for future connections.
    """
    print("Rejecting connections from {}".format(node_id))
    plugin.reject_ids.append(node_id)


plugin.run()
