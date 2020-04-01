#!/usr/bin/env python3
"""
This plugin is used to test the `onion_message` hook.
"""
from lightning import Plugin

plugin = Plugin()


@plugin.hook("onion_message")
def on_onion_message(plugin, onion_message, **kwargs):
    if 'reply_path' not in onion_message:
        plugin.log("no reply path")
        return

    plugin.rpc.call('sendonionmessage', [onion_message['reply_path']])
    plugin.log("Sent reply via {}".format(onion_message['reply_path']))
    return {"result": "continue"}


plugin.run()
