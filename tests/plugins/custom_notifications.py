#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.subscribe("custom")
def on_custom_notification(origin, message, **kwargs):
    plugin.log("Got a custom notification {} from plugin {}".format(message, origin))


@plugin.method("emit")
def emit(plugin):
    """Emit a simple string notification to topic "custom"
    """
    plugin.notify("custom", {'message': "Hello world"})


@plugin.method("faulty-emit")
def faulty_emit(plugin):
    """Emit a simple string notification to topic "custom"
    """
    plugin.notify("ididntannouncethis", {'message': "Hello world"})


@plugin.subscribe("pay_success")
def on_pay_success(origin, payment_hash, **kwargs):
    plugin.log(
        "Got a pay_success notification from plugin {} for payment_hash {}".format(
            origin,
            payment_hash
        )
    )


@plugin.subscribe("pay_part_start")
def on_pay_part_start(origin, **kwargs):
    plugin.log("Got pay_part_start: {}".format(kwargs))


@plugin.subscribe("pay_part_end")
def on_pay_part_end(origin, **kwargs):
    plugin.log("Got pay_part_end: {}".format(kwargs))


@plugin.subscribe("ididntannouncethis")
def on_faulty_emit(origin, payload, **kwargs):
    """We should never receive this as it gets dropped.
    """
    plugin.log("Got the ididntannouncethis event")


plugin.add_notification_topic("custom")
plugin.run()
