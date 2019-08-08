#!/usr/bin/env python3
"""This plugin is used to check that db_write calls are working correctly.
"""
from lightning import Plugin, RpcError
import sqlite3

plugin = Plugin()
plugin.sqlite_pre_init_cmds = []
plugin.initted = False


@plugin.init()
def init(configuration, options, plugin):
    if not plugin.get_option('dblog-file'):
        raise RpcError("No dblog-file specified")
    plugin.conn = sqlite3.connect(plugin.get_option('dblog-file'),
                                  isolation_level=None)
    plugin.log("replaying pre-init data:")

    plugin.wrap_tx = "BEGIN TRANSACTION;" not in plugin.sqlite_pre_init_cmds

    print(plugin.sqlite_pre_init_cmds)

    if plugin.wrap_tx:
        plugin.conn.execute("BEGIN TRANSACTION;")

    for c in plugin.sqlite_pre_init_cmds:
        if c == "COMMIT;":
            continue
        plugin.conn.execute(c)
        plugin.log("{}".format(c))

    if plugin.wrap_tx:
        plugin.conn.execute("COMMIT;")

    plugin.initted = True
    plugin.log("initialized")


@plugin.hook('db_write')
def db_write(plugin, writes, **kwargs):
    if not plugin.initted:
        plugin.log("deferring {} commands".format(len(writes)))
        plugin.sqlite_pre_init_cmds += writes
    else:
        print(writes)
        if plugin.wrap_tx:
            plugin.conn.execute("BEGIN TRANSACTION;")

        for c in writes:
            plugin.conn.execute(c)
            plugin.log("{}".format(c))

        if plugin.wrap_tx:
            plugin.conn.execute("COMMIT;")

    return True


plugin.add_option('dblog-file', None, 'The db file to create.')
plugin.run()
