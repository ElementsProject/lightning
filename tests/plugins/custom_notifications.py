#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.subscribe("custom")
def on_custom_notification(val, plugin, **kwargs):
    plugin.log("Got a custom notification {}".format(val))


@plugin.method("emit")
def emit(plugin):
    """Emit a simple string notification to topic "custom"
    """
    plugin.notify("custom", "Hello world")


plugin.add_notification_topic("custom")
plugin.run()
