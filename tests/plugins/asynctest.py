#!/usr/bin/env python3
"""This plugin is used to check that async method calls are working correctly.

The plugin registers a method `callme` with an argument. All calls are
stashed away, and are only resolved on the fifth invocation. All calls
will then return the argument of the fifth call.

"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    plugin.requests = []


@plugin.async_method('asyncqueue')
def async_queue(request, plugin):
    plugin.requests.append(request)


@plugin.method('asyncflush')
def async_flush(res, plugin):
    for r in plugin.requests:
        r.set_result(res)


plugin.run()
