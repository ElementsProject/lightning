lightning-setconfig -- Dynamically change some config options
=============================================================

SYNOPSIS
--------

**setconfig** *config* [*val*]

DESCRIPTION
-----------

The **setconfig** RPC command allows you set the (dynamic) configuration option named by `config`: options which take a value (as separate from simple flag options) also need a `val` parameter.

This new value will *also* be written at the end of the config file, for persistence across restarts (and any old value commented out).

You can see what options are dynamically adjustable using lightning-listconfigs(7). Note that you can also adjust existing options for stopped plugins; they will have an effect when the plugin is restarted.

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object containing **config** is returned. It is an object containing:

- **config** (string): name of the config variable which was set
- **source** (string): source of configuration setting (`file`:`linenum`)
- **dynamic** (boolean): whether this option is settable via setconfig (always *true*)
- **plugin** (string, optional): the plugin this configuration setting is for
- **set** (boolean, optional): for simple flag options
- **value\_str** (string, optional): for string options
- **value\_msat** (msat, optional): for msat options
- **value\_int** (integer, optional): for integer options
- **value\_bool** (boolean, optional): for boolean options

[comment]: # (GENERATE-FROM-SCHEMA-END)

ERRORS
------

The following error codes may occur:

- -32602: JSONRPC2\_INVALID\_PARAMS, i.e. the parameter is not dynamic, or the val was invalid.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible for this
feature.

SEE ALSO
--------

lightningd-config(5), lightning-listconfigs(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:9acb35e4b599c17e776ed0bf37b2e55022968ca10cb9d467c2e3f1f8e8d88662)
