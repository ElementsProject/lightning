#!/usr/bin/env python3
"""Plugin to be used to test miscellaneous notifications.
"""

from pyln.client import Plugin
import sys

plugin = Plugin()


@plugin.init()
def init(plugin, options, configuration):
    plugin.log("misc_notifications initialized")


@plugin.subscribe("channel_opened")
def channel_opened(plugin, channel_opened, **kwargs):
    plugin.log("A channel was opened to us by {}, with an amount"
               " of {} and the following funding transaction id: {}"
               .format(channel_opened["id"], channel_opened["amount"],
                       channel_opened["funding_txid"]))


@plugin.subscribe("channel_state_changed")
def channel_state_changed(plugin, channel_state_changed, **kwargs):
    plugin.log("channel_state_changed {}".format(channel_state_changed))


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    # Trigger a db_write during shutdown, db_write plugins should see it
    plugin.log("received shutdown notification")
    plugin.rpc.datastore(key='{}'.format(__file__), string="data written at shutdown", mode="create-or-replace")
    sys.exit(0) # skip the 30s waiting


plugin.run()
