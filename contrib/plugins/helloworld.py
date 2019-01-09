#!/usr/bin/env python3
from lightning import Plugin
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
def init(options, configuration, plugin):
    plugin.log("Plugin helloworld.py initialized")


@plugin.subscribe("connect")
def on_connect(plugin, id, address):
    plugin.log("Received connect event for peer {}".format(id))


@plugin.subscribe("disconnect")
def on_disconnect(plugin, id):
    plugin.log("Received disconnect event for peer {}".format(id))


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, htlc, plugin):
    plugin.log('on_htlc_accepted called')
    time.sleep(20)
    return {'result': 'continue'}


plugin.add_option('greeting', 'Hello', 'The greeting I should use.')
plugin.run()
