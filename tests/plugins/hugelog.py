#!/usr/bin/env python3
"""Plugin which emits a single log entry of an arbitrary size.

A log entry is not bounded by anything the daemon controls: a plugin can
hand us a message of any length, and so can any subsystem which logs
attacker-influenced data.  This gives a test a direct way to drive
log_to_files() with an entry far larger than any stack buffer.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("hugelog")
def hugelog(plugin, bytelen):
    """Log one entry of bytelen bytes, on a single line."""
    bytelen = int(bytelen)
    plugin.log("X" * bytelen)
    return {"logged": bytelen}


plugin.run()
