#!/usr/bin/env python3
"""Plugin to be used to test miscellaneous notifications.

Only used for 'channel_opened' for now.
"""

from pyln.client import Plugin
from time import sleep

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
    # Trigger a db_write. If another plugin registered the db_write hook, it
    # should see the data before being shutdown and its hooks unregistered
    plugin.log("received shutdown notification")
    plugin.rpc.datastore(key='{}'.format(__file__), string="data written at shutdown")
    sleep(5)


plugin.run()
