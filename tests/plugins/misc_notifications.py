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
               .format(channel_opened["id"], channel_opened["funding_msat"],
                       channel_opened["funding_txid"]))


@plugin.subscribe("channel_state_changed")
def channel_state_changed(plugin, channel_state_changed, **kwargs):
    plugin.log("channel_state_changed {}".format(channel_state_changed))


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):

    # 'shutdown' notification can be called in two ways, from `plugin stop` or from
    # lightningd's shutdown loop, we test which one by making `getinfo` call
    try:
        plugin.rpc.getinfo()
        plugin.rpc.datastore(key='test', string='Allowed', mode="create-or-append")
        plugin.log("via plugin stop, datastore success")
    except ConnectionRefusedError as e:
        # lightningd shutdown, refusing RPC calls
        plugin.log(str(e))
        sys.exit(0)

    sys.exit(0)


plugin.run()
