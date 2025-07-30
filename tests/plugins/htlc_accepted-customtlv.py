#!/usr/bin/env python3
"""A simply plugin that returns a custom tlv stream (byte encoded) to be
attached to a forwarding HTLC.
"""

from pyln.client import Plugin


plugin = Plugin()
custom_tlvs = None


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    if 'extra_tlvs' in htlc:
        print(f"called htlc accepted hook with extra_tlvs: {htlc['extra_tlvs']}")
    print(f'returning continue with custom extra_tlvs: {custom_tlvs}')
    if custom_tlvs:
        return {"result": "continue", "extra_tlvs": custom_tlvs}
    return {"result": "continue"}


@plugin.method("setcustomtlvs")
def setcustomtlvs(plugin, tlvs):
    """Sets the custom tlv to return when receiving an incoming HTLC.
    """
    global custom_tlvs
    print(f'setting custom tlv to {tlvs}')
    custom_tlvs = tlvs


@plugin.init()
def on_init(**kwargs):
    global custom_tlvs
    custom_tlvs = None


plugin.run()
