#!/usr/bin/env python3
from lightning import Plugin


plugin = Plugin(autopatch=True)


@plugin.method("hello")
def hello(name, plugin):
    """This is the documentation string for the hello-function.

    It gets reported as the description when registering the function
    as a method with `lightningd`.

    """
    greeting = plugin.get_option('greeting')
    s = '{} {}'.format(greeting, name)
    plugin.log(s)
    return s


@plugin.method("init")
def init(options, configuration, plugin):
    plugin.log("Plugin helloworld.py initialized")


plugin.add_option('greeting', 'Hello', 'The greeting I should use.')
plugin.run()
