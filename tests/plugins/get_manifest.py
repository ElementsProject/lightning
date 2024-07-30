#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()

@plugin.method("checkmymanifest", clnrest_data={"path": "/path/to/me", "method": "POST"})
def return_this_manifest(plugin, cmd_name: str =None):
    """Returns the manifest of this plugin."""

    name_to_check = cmd_name if cmd_name else "checkmymanifest"

    cmd_manifest = plugin.rpc.help(name_to_check).get("help")

    if cmd_manifest is []:
        raise ValueError(f"Command {name_to_check} not found.")
    
    return cmd_manifest[0]

plugin.run()
