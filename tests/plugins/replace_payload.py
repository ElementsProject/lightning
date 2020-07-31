#!/usr/bin/env python3
"""Plugin that replaces HTLC payloads.

This feature is important if we want to accept an HTLC tlv field not
accepted by lightningd.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    # eg. '2902017b04016d0821fff5b6bd5018c8731aa0496c3698ef49f132ef9a3000c94436f4957e79a2f8827b'
    # (but values change depending on pay's randomness!)
    print("payload was:{}".format(onion['payload']))
    assert onion['payload'][0:2] == '29'

    if plugin.replace_payload == 'corrupt_secret':
        # Note: we don't include length prefix in returned payload, since it doesn't
        # support the pre-TLV legacy form.
        if onion['payload'][18] == '0':
            newpayload = onion['payload'][2:18] + '1' + onion['payload'][19:]
        else:
            newpayload = onion['payload'][2:18] + '0' + onion['payload'][19:]
    else:
        newpayload = plugin.replace_payload
    print("payload was:{}".format(onion['payload']))
    print("payload now:{}".format(newpayload))

    return {'result': 'continue', 'payload': newpayload}


@plugin.method('setpayload')
def setpayload(plugin, payload: bytes):
    plugin.replace_payload = payload
    return {}


plugin.run()
