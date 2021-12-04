#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.subscribe("custom")
def on_custom_notification(origin, payload, **kwargs):
    plugin.log("Got a custom notification {} from plugin {}".format(payload, origin))


@plugin.method("emit")
def emit(plugin):
    """Emit a simple string notification to topic "custom"
    """
    plugin.notify("custom", "Hello world")


@plugin.method("faulty-emit")
def faulty_emit(plugin):
    """Emit a simple string notification to topic "custom"
    """
    plugin.notify("ididntannouncethis", "Hello world")


@plugin.subscribe("pay_success")
def on_pay_success(origin, payload, **kwargs):
    plugin.log(
        "Got a pay_success notification from plugin {} for payment_hash {}".format(
            origin,
            payload['payment_hash']
        )
    )


@plugin.subscribe("ididntannouncethis")
def on_faulty_emit(origin, payload, **kwargs):
    """We should never receive this as it gets dropped.
    """
    plugin.log("Got the ididntannouncethis event")


plugin.add_notification_topic("custom")
plugin.run()
