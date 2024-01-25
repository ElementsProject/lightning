lightning-plugin -- Manage plugins with RPC
===========================================

SYNOPSIS
--------

**plugin** *subcommand* [plugin|directory] [*options*] ...


DESCRIPTION
-----------

The **plugin** RPC command command can be used to control dynamic plugins,
i.e. plugins that declared themself "dynamic" (in getmanifest).

*subcommand* can be **start**, **stop**, **startdir**, **rescan** or **list** and
determines what action is taken

*plugin* is the *path* or *name* of a plugin executable to start or stop

*directory* is the *path* of a directory containing plugins

*options* are optional *keyword=value* options passed to plugin, can be repeated

*subcommand* **start** takes a *path* to an executable as argument and starts it as plugin.
*path* may be an absolute path or a path relative to the plugins directory (default *~/.lightning/plugins*).
If the plugin is already running and the executable (checksum) has changed, the plugin is
killed and restarted except if its an important (or builtin) plugin.
If the plugin doesn't complete the "getmanifest" and "init" handshakes within 60 seconds,
the command will timeout and kill the plugin.
Additional *options* may be passed to the plugin, but requires all parameters to
be passed as keyword=value pairs using the  `-k|--keyword` option which
is recommended. For example the following command starts the plugin
helloworld.py (present in the plugin directory) with the option
greeting set to 'A crazy':

```
lightning-cli -k plugin subcommand=start plugin=helloworld.py greeting='A crazy'
```

*subcommand* **stop** takes a plugin executable *path* or *name* as argument and stops the plugin.
If the plugin subscribed to "shutdown", it may take up to 30 seconds before this
command returns. If the plugin is important and dynamic, this will shutdown `lightningd`.

*subcommand* **startdir** starts all executables it can find in *directory* (excl. subdirectories)
as plugins. Checksum and timeout behavior as in **start** applies.

*subcommand* **rescan** starts all plugins in the default plugins directory (default *~/.lightning/plugins*)
that are not already running. Checksum and timeout behavior as in **start** applies.

*subcommand* **list** lists all running plugins (incl. non-dynamic)

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **command** (string): the subcommand this is responding to (one of "start", "stop", "rescan", "startdir", "list")

If **command** is "start", "startdir", "rescan" or "list":

  - **plugins** (array of objects):
    - **name** (string): full pathname of the plugin
    - **active** (boolean): status; plugin completed init and is operational, plugins are configured asynchronously.
    - **dynamic** (boolean): plugin can be stopped or started without restarting lightningd

If **command** is "stop":

  - **result** (string): A message saying it successfully stopped

[comment]: # (GENERATE-FROM-SCHEMA-END)

On error, the reason why the action could not be taken upon the
plugin is returned.

SEE ALSO
--------
lightning-cli(1), lightning-listconfigs(1), [writing plugins][writing plugins]

AUTHOR
------

Antoine Poinsot <<darosior@protonmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[writing plugins]: PLUGINS.md
[comment]: # ( SHA256STAMP:83b40cc97b040fc0d7d47ebfda887c7c7ab0f305330978cd8426b6eed01737d2)
