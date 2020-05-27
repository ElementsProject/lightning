#!/usr/bin/env python3
"""Plugin to be used to test miscellaneous notifications.

Only used for 'channel_opened' for now.
"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(plugin, options, configuration):
    plugin.log("misc_notifications initialized")


@plugin.subscribe("channel_opened")
def channel_opened(plugin, channel_opened):
    plugin.log("A channel was opened to us by {}, with an amount"
               " of {} and the following funding transaction id: {}"
               .format(channel_opened["id"], channel_opened["amount"],
                       channel_opened["funding_txid"]))


plugin.run()
