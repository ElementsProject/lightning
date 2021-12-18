#!/usr/bin/env python3
"""Plugin to be used to test miscellaneous notifications.
"""

from pyln.client import Plugin, RpcError
import sys
import pytest

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

    # 'shutdown' notification can be called in two ways, from `plugin stop` or from
    # lightningd's shutdown loop, we test which one by making `getinfo` call
    try:
        plugin.rpc.getinfo()
        plugin.rpc.datastore(key='test', string='Allowed', mode="create-or-append")
        plugin.log("via plugin stop, datastore success")
    except RpcError as e:
        if e.error == {'code': -5, 'message': 'lightningd is shutting down'}:
            # JSON RPC is disabled by now, but can do logging
            with pytest.raises(RpcError, match=r'-5.*lightningd is shutting down'):
                plugin.rpc.datastore(key='test', string='Not allowed', mode="create-or-append")
            plugin.log("via lightningd shutdown, datastore failed")
        else:
            raise

    sys.exit(0)


plugin.run()
