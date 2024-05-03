#!/usr/bin/env python3
from pyln.client import Plugin, RpcException
from typing import Any, Optional

plugin = Plugin()


@plugin.method('dynamic-option-report')
def record_lookup(plugin):
    return {'test-dynamic-config': plugin.get_option('test-dynamic-config')}


def on_config_change(plugin, config: str, value: Optional[Any]) -> None:
    """Callback method called when a config value is changed.
    """
    plugin.log(f"Setting config {config} to {value}")
    if value == 'bad value':
        raise RpcException("I don't like bad values!")


plugin.add_option(
    name="test-dynamic-config",
    description="A config option which can be changed at run-time",
    default="initial",
    dynamic=True,
    on_change=on_config_change,
)


plugin.run()
