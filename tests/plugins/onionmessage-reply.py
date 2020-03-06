#!/usr/bin/env python3
"""
This plugin is used to test the `onion_message` hook.
"""
from lightning import Plugin
import subprocess

plugin = Plugin()


@plugin.hook("onion_message")
def on_onion_message(plugin, onion_message, **kwargs):
    onionmsgtool = plugin.get_option('onionmsgtool')

    if 'plaintext' not in onion_message:
        plugin.log("payload:{}".format(onion_message['payload']))
        return

    plaintext = bytearray.fromhex(onion_message['plaintext']).decode()
    plugin.log("plaintext:{}".format(plaintext))

    if 'reply_onion' not in onion_message:
        plugin.log("no reply onion")
        return

    if 'next_node_id' in onion_message:
        nextpeer = onion_message['next_node_id']
    elif 'next_short_channel_id' in onion_message:
        nextpeer = onion_message['next_short_channel_id']
    else:
        plugin.log("No next_node_id or next_short_channel_id?")
        return

    hexmsg = bytes("Acknowledge: {}".format(plaintext), encoding="utf8").hex()
    payload = subprocess.check_output(
        [onionmsgtool, 'encrypt', hexmsg, onion_message['shared_secret']]
    ).decode('ASCII').strip()

    plugin.rpc.call('sendonionmessage', [onion_message['reply_onion'], nextpeer, payload])
    plugin.log("sent reply encrypted using {} ({})".format(onion_message['shared_secret'], payload))
    return {"result": "continue"}


plugin.add_option('onionmsgtool', None, 'Location of the "onionmessage" binary.')
plugin.run()
