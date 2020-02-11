#!/usr/bin/env python3
from pyln.client import Plugin
import time

plugin = Plugin()


@plugin.method("hello")
def hello(plugin, name="world"):
    """This is the documentation string for the hello-function.

    It gets reported as the description when registering the function
    as a method with `lightningd`.

    """
    greeting = plugin.get_option('greeting')
    s = '{} {}'.format(greeting, name)
    plugin.log(s)
    return s


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("Plugin helloworld.py initialized")


@plugin.subscribe("connect")
def on_connect(plugin, id, address, **kwargs):
    plugin.log("Received connect event for peer {}".format(id))


@plugin.subscribe("disconnect")
def on_disconnect(plugin, id, **kwargs):
    plugin.log("Received disconnect event for peer {}".format(id))


@plugin.subscribe("invoice_payment")
def on_payment(plugin, invoice_payment, **kwargs):
    plugin.log("Received invoice_payment event for label {}, preimage {},"
               " and amount of {}".format(invoice_payment.get("label"),
                                          invoice_payment.get("preimage"),
                                          invoice_payment.get("msat")))


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, htlc, plugin, **kwargs):
    plugin.log('on_htlc_accepted called')
    time.sleep(20)
    return {'result': 'continue'}


plugin.add_option('greeting', 'Hello', 'The greeting I should use.')
plugin.run()
