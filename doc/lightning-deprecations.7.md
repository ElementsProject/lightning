lightning-deprecations -- Command to enable/disable deprecated APIs
===================================================================

SYNOPSIS
--------

**deprecations** *enable* 

DESCRIPTION
-----------

Command *added* in v24.02.

The **deprecations** RPC command is used to override global config option `allow-deprecated-apis` for further RPC commands on this same connection. This can be useful for developer testing to ensure you don't accidentally rely on deprecated features.

- **enable** (boolean): Flag to enable or disable deprecated APIs. Setting it to `false` will neither accept deprecated parameters or commands, nor output deprecated fields.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:deprecations#1",
  "method": "deprecations",
  "params": {
    "enable": false
  }
}
```

RETURN VALUE
------------

On success, an empty object is returned.

EXAMPLE JSON RESPONSE
---------------------

```json
{}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters.

AUTHOR
------

Rusty Russell <<rusty@blockstream.com>> wrote the initial version of this man page.

SEE ALSO
--------

lightningd-config(5), lightning-notifications(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
