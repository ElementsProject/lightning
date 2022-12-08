#!/usr/bin/env python3
"""This plugin is used to check that forward_event calls are working correctly.
"""
from pyln.client import Millisatoshi, Plugin

plugin = Plugin(notification_parse_msat=True)


@plugin.init()
def init(configuration, options, plugin):
    plugin.forward_list = []


@plugin.subscribe("forward_event")
def notify_warning(plugin, forward_event):
    # check if pyln-client '_msat' field Millisatoshi replacement works on events
    if type(forward_event['in_msat']) is not Millisatoshi:
        plugin.log(f"pyln-client has not replaced _msat field as it should: {forward_event}")

    # One forward payment may have many notification records for different status,
    # but one forward payment has only one record in 'listforwards' eventrually.
    plugin.log("receive a forward recored, status: {}, payment_hash: {}".format(forward_event['status'], forward_event['payment_hash']))
    plugin.forward_list.append(forward_event)


@plugin.method('listforwards_plugin')
def record_lookup(plugin):
    return {'forwards': plugin.forward_list}


plugin.run()
