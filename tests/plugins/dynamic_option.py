#!/usr/bin/env python3
from pyln.client import Plugin, RpcException
from typing import Any, Optional

plugin = Plugin()


@plugin.method("dynamic-option-report")
def record_lookup(plugin):
    return {
        "test-dynamic-config": plugin.get_option("test-dynamic-config"),
        "test-dynamic-int": plugin.get_option("test-dynamic-int"),
        "test-dynamic-bool": plugin.get_option("test-dynamic-bool"),
        "test-dynamic-flag": plugin.get_option("test-dynamic-flag"),
    }


def on_config_change(plugin, config: str, value: Optional[Any]) -> None:
    """Callback method called when a config value is changed."""
    plugin.log(f"Setting config {config} to {value}")
    if value == "bad value":
        raise RpcException("I don't like bad values!")


plugin.add_option(
    name="test-dynamic-config",
    description="A config option which can be changed at run-time",
    default="initial",
    dynamic=True,
    on_change=on_config_change,
)

plugin.add_option(
    name="test-dynamic-int",
    description="An int option which can be changed at run-time",
    default=0,
    opt_type="int",
    dynamic=True,
)

plugin.add_option(
    name="test-dynamic-bool",
    description="A bool option which can be changed at run-time",
    default=False,
    opt_type="bool",
    dynamic=True,
)

plugin.add_flag_option(
    name="test-dynamic-flag",
    description="A flag option which can be changed at run-time",
    dynamic=True,
)


plugin.run()
