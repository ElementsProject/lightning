#!/usr/bin/env python3
"""Plugin for testing setconfig with multi-value dynamic options (issue #8295)."""
from pyln.client import Plugin, RpcException
from typing import Any, Optional

plugin = Plugin()


@plugin.method('dynamic-multi-report')
def report(plugin):
    """Report current values for the dynamic multi option."""
    return {'test-multi-dynamic': plugin.get_option('test-multi-dynamic')}


def on_config_change(plugin, config: str, value: Optional[Any]) -> None:
    """Callback when config value changes."""
    plugin.log(f"Setting config {config} to {value} (type: {type(value).__name__})")
    if isinstance(value, list):
        for v in value:
            if v == 'reject-me':
                raise RpcException("I don't like reject-me!")
    elif value == 'reject-me':
        raise RpcException("I don't like reject-me!")


plugin.add_option(
    name="test-multi-dynamic",
    description="A multi-value config option which can be changed at run-time",
    default=None,
    multi=True,
    dynamic=True,
    on_change=on_config_change,
)

plugin.run()
