lightning-plugin -- Manage plugins with RPC
===========================================

SYNOPSIS
--------

**plugin** *subcommand* [*plugin|directory*] [*options*] ...

DESCRIPTION
-----------

The **plugin** RPC command can be used to control dynamic plugins, i.e. plugins that declared themself 'dynamic' (in getmanifest).

- **subcommand** (string) (one of "start", "stop", "rescan", "startdir", "list"): Determines what action is taken:
   - *subcommand* **start** takes a *path* to an executable as argument and starts it as plugin. *path* may be an absolute path or a path relative to the plugins directory (default *~/.lightning/plugins*). If the plugin is already running and the executable (checksum) has changed, the plugin is killed and restarted except if its an important (or builtin) plugin. If the plugin doesn't complete the 'getmanifest' and 'init' handshakes within 60 seconds, the command will timeout and kill the plugin. Additional *options* may be passed to the plugin, but requires all parameters to be passed as keyword=value pairs using the `-k|--keyword` option which is recommended. For example the following command starts the plugin helloworld.py (present in the plugin directory) with the option greeting set to 'A crazy':
   ``shell.
   lightning-cli -k plugin subcommand=start plugin=helloworld.py greeting='A crazy'.
   ``.
   - *subcommand* **stop** takes a plugin executable *path* or *name* as argument and stops the plugin. If the plugin subscribed to 'shutdown', it may take up to 30 seconds before this command returns. If the plugin is important and dynamic, this will shutdown `lightningd`.
   - *subcommand* **startdir** starts all executables it can find in *directory* (excl. subdirectories) as plugins. Checksum and timeout behavior as in **start** applies.
   - *subcommand* **rescan** starts all plugins in the default plugins directory (default *~/.lightning/plugins*) that are not already running. Checksum and timeout behavior as in **start** applies.
   - *subcommand* **list** lists all running plugins (incl. non-dynamic).
- **plugin** (string, optional): *path* or *name* of a plugin executable to start or stop.
- **directory** (string, optional): *path* of a directory containing plugins.
- **options** (array of strings, optional):
  - (string, optional): *keyword=value* options passed to plugin, can be repeated.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:plugin#1",
  "method": "plugin",
  "params": [
    "list"
  ]
}
{
  "id": "example:plugin#2",
  "method": "plugin",
  "params": {
    "subcommand": "stop",
    "plugin": "fail_htlcs.py"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **command** (string) (one of "start", "stop", "rescan", "startdir", "list"): The subcommand this is responding to.

If **command** is "start", "startdir", "rescan" or "list":
  - **plugins** (array of objects):
    - **name** (string): Full pathname of the plugin.
    - **active** (boolean): Status; plugin completed init and is operational, plugins are configured asynchronously.
    - **dynamic** (boolean): Plugin can be stopped or started without restarting lightningd.

If **command** is "stop":
  - **result** (string): A message saying it successfully stopped.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "command": "list",
  "plugins": [
    {
      "name": "~/lightning/plugins/autoclean",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/chanbackup",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/bcli",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/commando",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/funder",
      "active": true,
      "dynamic": true
    },
    {
      "name": "~/lightning/plugins/topology",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/keysend",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/offers",
      "active": true,
      "dynamic": true
    },
    {
      "name": "~/lightning/plugins/pay",
      "active": true,
      "dynamic": true
    },
    {
      "name": "~/lightning/plugins/txprepare",
      "active": true,
      "dynamic": true
    },
    {
      "name": "~/lightning/plugins/cln-renepay",
      "active": true,
      "dynamic": true
    },
    {
      "name": "~/lightning/plugins/spenderp",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/plugins/sql",
      "active": true,
      "dynamic": true
    },
    {
      "name": "~/lightning/plugins/bookkeeper",
      "active": true,
      "dynamic": false
    },
    {
      "name": "~/lightning/target/debug/examples/cln-plugin-startup",
      "active": true,
      "dynamic": false
    }
  ]
}
{
  "command": "stop",
  "result": "Successfully stopped fail_htlcs.py."
}
```

ERRORS
------

On error, the reason why the action could not be taken upon the plugin is returned.

AUTHOR
------

Antoine Poinsot <<darosior@protonmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-cli(1), lightning-listconfigs(1), [writing plugins][writing plugins]

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[writing plugins]: PLUGINS.md
