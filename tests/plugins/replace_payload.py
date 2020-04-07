#!/usr/bin/env python3
"""Plugin that replaces HTLC payloads.

This feature is important if we want to accept an HTLC tlv field not
accepted by lightningd.
"""


from pyln.client import Plugin
import json
import os
import tempfile
import time

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    # eg. '2902017b04016d0821fff5b6bd5018c8731aa0496c3698ef49f132ef9a3000c94436f4957e79a2f8827b'
    # (but values change depending on pay's randomness!)
    if plugin.replace_payload == 'corrupt_secret':
        if onion['payload'][18] == '0':
            newpayload = onion['payload'][:18] + '1' + onion['payload'][19:]
        else:
            newpayload = onion['payload'][:18] + '0' + onion['payload'][19:]
    else:
        newpayload = plugin.replace_payload
    print("payload was:{}".format(onion['payload']))
    print("payload now:{}".format(newpayload))

    return {'result': 'continue', 'payload': newpayload}


@plugin.method('setpayload')
def setpayload(plugin, payload: bool):
    plugin.replace_payload = payload
    return {}


plugin.run()
