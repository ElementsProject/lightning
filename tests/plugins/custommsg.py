#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('custommsg')
def on_custommsg(peer_id, message, plugin, **kwargs):
    plugin.log("Got a custom message {msg} from peer {peer_id}".format(
        msg=message,
        peer_id=peer_id
    ))
    return {'result': 'continue'}


plugin.run()
