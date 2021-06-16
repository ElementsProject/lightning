lightning-plugin -- Manage plugins with RPC
===========================================

SYNOPSIS
--------

**plugin** command \[parameter\] \[second\_parameter\]

DESCRIPTION
-----------

The **plugin** RPC command allows to manage plugins without having to
restart lightningd. It takes 1 to 3 parameters: a command
(start/stop/startdir/rescan/list) which describes the action to take and
optionally one or two parameters which describes the plugin on which the
action has to be taken.

The *start* command takes a path as the first parameter and will load
the plugin available from this path.  Any additional parameters are
passed to the plugin. It will wait for the plugin to complete the
handshake with `lightningd` for 20 seconds at the most.

The *stop* command takes a plugin name as parameter. It will kill and
unload the specified plugin.

The *startdir* command takes a directory path as first parameter and will
load all plugins this directory contains. It will wait for each plugin to
complete the handshake with `lightningd` for 20 seconds at the most.

The *rescan* command starts all not-already-loaded plugins from the
default plugins directory (by default *~/.lightning/plugins*).

The *list* command will return all the active plugins.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:
- **command** (string): the subcommand this is responding to (one of "start", "stop", "rescan", "startdir", "list")

If **command** is "start", "startdir", "rescan" or "list":
  - **plugins** (array of objects):
    - **name** (string): full pathname of the plugin
    - **active** (boolean): status; since plugins are configured asynchronously, a freshly started plugin may not appear immediately.

If **command** is "stop":
  - **result** (string): A message saying it successfully stopped
[comment]: # (GENERATE-FROM-SCHEMA-END)

On error, the reason why the action could not be taken upon the
plugin is returned.

AUTHOR
------

Antoine Poinsot <<darosior@protonmail.com>> is mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:a14192d703b99bb39ed7a297bcee462a51b9728ad6d6477dd65ad636c0c87c02)
