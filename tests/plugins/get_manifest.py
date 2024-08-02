#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()


@plugin.method("checkmymanifest", clnrest_data={"path": "/path/to/me", "method": "POST"})
def return_this_manifest(plugin, cmd_name: str = None):
    """Returns the manifest of this plugin."""

    name_to_check = cmd_name if cmd_name else "checkmymanifest"

    cmd_manifest = plugin.rpc.help(name_to_check).get("help")

    if cmd_manifest is []:
        raise ValueError(f"Command {name_to_check} not found.")

    return cmd_manifest[0]


@plugin.method("dyncheckmymanifestpost", clnrest_data={"path": "/user/<id>/me", "method": "POST"})
def return_this_dyn_manifest_post(plugin, cmd_name: str = None, id: int = 0):
    """Returns the manifest of this plugin."""

    name_to_check = cmd_name if cmd_name else "dyncheckmymanifestpost"

    cmd_manifest = plugin.rpc.help(name_to_check).get("help")

    if cmd_manifest is []:
        raise ValueError(f"Command {name_to_check} not found.")

    cmd_manifest[0]["dyn_id_post"] = id

    return cmd_manifest[0]


@plugin.method("dyncheckmymanifestget", clnrest_data={"path": "/stats/<id>/me", "method": "GET", "rune": False})
def return_this_dyn_manifest_get(plugin, cmd_name: str = None, id: int = 0):
    """Returns the manifest of this plugin."""

    name_to_check = cmd_name if cmd_name else "dyncheckmymanifestget"

    cmd_manifest = plugin.rpc.help(name_to_check).get("help")

    if cmd_manifest is []:
        raise ValueError(f"Command {name_to_check} not found.")

    cmd_manifest[0]["dyn_id_get"] = id

    return cmd_manifest[0]


@plugin.method("dyncheckmymanifestget2", clnrest_data={"path": "/<cmd_name>/<id>/me", "method": "GET", "rune": False, "content_type": "text/plain"})
def return_this_dyn_manifest_get2(plugin, cmd_name: str = None, id: int = 0):
    """Returns the manifest of this plugin."""

    result = f"{cmd_name} {id}"
    return result


@plugin.method("dyncheckmymanifestget3", clnrest_data={"path": "/stats/to/me", "method": "GET", "rune": False})
def return_this_dyn_manifest_get3(plugin, cmd_name: str = None):
    """Returns the manifest of this plugin."""

    name_to_check = cmd_name if cmd_name else "dyncheckmymanifestget3"

    cmd_manifest = plugin.rpc.help(name_to_check).get("help")

    if cmd_manifest is []:
        raise ValueError(f"Command {name_to_check} not found.")

    return cmd_manifest[0]


plugin.run()
