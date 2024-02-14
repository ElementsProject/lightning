lightning-setconfig -- Dynamically change some config options
=============================================================

SYNOPSIS
--------

**setconfig** *config* [*val*] 

DESCRIPTION
-----------

Command *added* in v23.08.

The **setconfig** RPC command allows you set the (dynamic) configuration option named by `config`: options which take a value (as separate from simple flag options) also need a `val` parameter.

This new value will *also* be written at the end of the config file, for persistence across restarts (and any old value commented out).

You can see what options are dynamically adjustable using lightning- listconfigs(7). Note that you can also adjust existing options for stopped plugins; they will have an effect when the plugin is restarted.

- **config** (string): Name of the config variable which should be set to the value of the variable.
- **val** (one of, optional): Value of the config variable to be set or updated.:
  - (string)
  - (integer)
  - (boolean)

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:setconfig#1",
  "method": "setconfig",
  "params": [
    "autoclean-paidinvoices-age",
    1
  ]
}
{
  "id": "example:setconfig#2",
  "method": "setconfig",
  "params": [
    "test-dynamic-config",
    "changed"
  ]
}
{
  "id": "example:setconfig#3",
  "method": "setconfig",
  "params": {
    "config": "min-capacity-sat",
    "val": 500000
  }
}
```

RETURN VALUE
------------

On success, an object containing **config** is returned. It is an object containing:

- **config** (string): Name of the config variable which was set.
- **source** (string): Source of configuration setting (`file`:`linenum`).
- **dynamic** (boolean) (always *true*): Whether this option is settable via setconfig.
- **plugin** (string, optional): The plugin this configuration setting is for.
- **set** (boolean, optional): For simple flag options.
- **value\_str** (string, optional): For string options.
- **value\_msat** (msat, optional): For msat options.
- **value\_int** (integer, optional): For integer options.
- **value\_bool** (boolean, optional): For boolean options.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "config": {
    "config": "autoclean-paidinvoices-age",
    "value_int": 1,
    "source": "/tmp/ltests-7u_8_rtu/test_autoclean_1/lightning-3/regtest/config:6",
    "plugin": "~/lightning/plugins/autoclean",
    "dynamic": true
  }
}
{
  "config": {
    "config": "test-dynamic-config",
    "value_str": "changed",
    "source": "/tmp/ltests-7u_8_rtu/test_dynamic_option_python_plugin_1/lightning-1/regtest/config:2",
    "plugin": "~/lightning/tests/plugins/dynamic_option.py",
    "dynamic": true
  }
}
{
  "config": {
    "config": "min-capacity-sat",
    "value_int": 500000,
    "source": "/tmp/ltests-nvfdbou2/test_setconfig_1/lightning-2/regtest/config:2",
    "dynamic": true
  }
}
```

ERRORS
------

The following error codes may occur:

- -32602: JSONRPC2\_INVALID\_PARAMS, i.e. the parameter is not dynamic, or the val was invalid.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible for this feature.

SEE ALSO
--------

lightningd-config(5), lightning-listconfigs(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
