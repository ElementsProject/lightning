#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('custommsg')
def on_custommsg(peer_id, payload, plugin, message=None, **kwargs):
    plugin.log("Got custommessage_b {msg} from peer {peer_id}".format(
        msg=payload,
        peer_id=peer_id
    ))
    return {'result': 'continue'}


plugin.run()
