#!/usr/bin/env python3

#
# This plugin hooks everything possible
# and slightly slows execution down by sleeping some milliseconds.
#
# rationale: discover thread safetyness issues

from pyln.client import Plugin
import time

RPC_CONTINUE = {'result': 'continue'}

plugin = Plugin()
plugin.delay = 10


def foo():
    time.sleep(plugin.delay / 1000)


@plugin.subscribe("channel_opened")
def on_channel_opened(plugin, channel_opened, **kwargs):
    foo()


@plugin.subscribe("channel_state_changed")
def on_channel_state_changed(plugin, channel_state_changed, **kwargs):
    foo()


@plugin.subscribe("connect")
def on_connect(plugin, id, address, **kwargs):
    foo()


@plugin.subscribe("disconnect")
def on_disconnect(plugin, id, **kwargs):
    foo()


@plugin.subscribe("invoice_payment")
def on_invoice_payment(plugin, invoice_payment, **kwargs):
    foo()


@plugin.subscribe("invoice_creation")
def on_invoice_creation(plugin, invoice_creation, **kwargs):
    foo()


@plugin.subscribe("warning")
def on_warning(plugin, warning, **kwargs):
    foo()


@plugin.subscribe("forward_event")
def on_forward_event(plugin, forward_event, **kwargs):
    foo()


@plugin.subscribe("sendpay_success")
def on_sendpay_success(plugin, sendpay_success, **kwargs):
    foo()


@plugin.subscribe("sendpay_failure")
def on_sendpay_failure(plugin, sendpay_failure, **kwargs):
    foo()


@plugin.subscribe("coin_movement")
def on_coin_movement(plugin, coin_movement, **kwargs):
    foo()


@plugin.subscribe("openchannel_peer_sigs")
def on_openchannel_peer_sigs(plugin, openchannel_peer_sigs, **kwargs):
    foo()


@plugin.hook('db_write')
def on_db_write(writes, data_version, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


@plugin.hook('htlc_accepted')
def on_htlc_accepted(onion, htlc, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


@plugin.hook('commitment_revocation')
def on_commitment_revocation(commitment_txid, penalty_tx, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


@plugin.hook('invoice_payment')
def on_invoice_payment_hook(payment, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


# skip the rpc_command as this would result in deadlocks when using
# plugin functions itself like  getdelay and setdelay
#@plugin.hook('rpc_command')
#def on_rpc_command(rpc_command, plugin, **kwargs):
#    foo()
#    return RPC_CONTINUE


@plugin.hook('custommsg')
def on_custom_msg(payload, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


@plugin.hook('peer_connected')
def on_peer_connected(peer, plugin, **kwargs):
    foo()
    return RPC_CONTINUE


@plugin.method('getdelay')
def get_delay(plugin: Plugin):
    return plugin.delay


@plugin.method('setdelay')
def set_delay(plugin: Plugin, delay: int = 10):
    """ Sets a delay in milliseconds. Default: 10 """
    plugin.delay = int(delay)
    return plugin.delay


@plugin.init()
def init(options, configuration, plugin):
    plugin.log(f"Plugin initialized with delay of {plugin.delay} milliseconds")


plugin.run()
