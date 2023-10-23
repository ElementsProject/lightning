#!/usr/bin/env python3
from pyln.client import Plugin

plugin = Plugin(custom_msgs=[43690])


@plugin.hook('custommsg')
def on_custommsg(peer_id, payload, plugin, message=None, **kwargs):
    plugin.log("Got message {}".format(int(payload[:4], 16)))
    return {'result': 'continue'}


plugin.run()
