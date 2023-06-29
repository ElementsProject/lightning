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


@plugin.method("bye")
def bye(plugin, name, **kwargs):
    """This methods requires {name} to be set by the caller !"""
    return "Bye {}".format(name)


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("Plugin helloworld.py initialized")


@plugin.subscribe("connect")
def on_connect(plugin, connect, **kwargs):
    plugin.log("Received connect event for peer {}".format(connect))


@plugin.subscribe("disconnect")
def on_disconnect(plugin, disconnect, **kwargs):
    plugin.log("Received disconnect event for peer {}".format(disconnect))


@plugin.subscribe("invoice_payment")
def on_payment(plugin, invoice_payment, **kwargs):
    plugin.log("Received invoice_payment event for label {label}, preimage {preimage},"
               " and amount of {msat}".format(**invoice_payment))


@plugin.subscribe("invoice_creation")
def on_invoice_creation(plugin, invoice_creation, **kwargs):
    plugin.log("Received invoice_creation event for label {label}, preimage {preimage},"
               " and amount of {msat}".format(**invoice_creation))


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, htlc, plugin, **kwargs):
    plugin.log('on_htlc_accepted called')
    time.sleep(20)
    return {'result': 'continue'}


plugin.add_option('greeting', 'Hello', 'The greeting I should use.')
plugin.run()
