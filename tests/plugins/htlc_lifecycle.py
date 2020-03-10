#!/usr/bin/env python3
"""This plugin is used to check htlc lifecycle notifications:
   htlc_offered, htlc_accepted, htlc_settled, htlc_failed
"""
from lightning import Plugin

plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin, **kwargs):
    plugin.log("htlc lifecycle notifications initialized")
    plugin.data = []
    plugin.type = []


@plugin.subscribe("htlc_failed")
def notify_htlc_failed(plugin, htlc_failed, **kwargs):
    plugin.log("htlc_failed received")
    plugin.type.append("htlc_failed")
    plugin.data.append(htlc_failed)


@plugin.subscribe("htlc_settled")
def notify_htlc_settled(plugin, htlc_settled, **kwargs):
    plugin.log("htlc_settled received")
    plugin.type.append("htlc_settled")
    plugin.data.append(htlc_settled)


@plugin.subscribe("htlc_accepted")
def notify_htlc_accepted(plugin, htlc_accepted, **kwargs):
    plugin.log("htlc_accepted received")
    plugin.type.append("htlc_accepted")
    plugin.data.append(htlc_accepted)


@plugin.subscribe("htlc_offered")
def notify_htlc_offered(plugin, htlc, **kwargs):
    plugin.log("htlc_offered received")
    plugin.type.append("htlc_offered")
    plugin.data.append(htlc)


@plugin.method('htlc_plugin')
def record_lookup(plugin):
    return {'type': plugin.type, 'data': plugin.data}


plugin.run()
