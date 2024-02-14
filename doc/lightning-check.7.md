lightning-check -- Command for verifying parameters
===================================================

SYNOPSIS
--------

**check** *command\_to\_check* 

DESCRIPTION
-----------

The **check** RPC command verifies another command without actually making any changes.

This is guaranteed to be safe, and will do all checks up to the point where something in the system would need to be altered (such as checking that channels are in the right state, peers connected, etc).

It does not guarantee successful execution of the command in all cases. For example, a call to lightning-getroute(7) may still fail to find a route even if checking the parameters succeeds.

- **command\_to\_check** (string): Name of the relevant command.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:check#1",
  "method": "check",
  "params": {
    "command_to_check": "sendpay",
    "route": [
      {
        "amount_msat": 1011,
        "msatoshi": 1011,
        "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
        "delay": 20,
        "channel": "1x1x1"
      },
      {
        "amount_msat": 1000,
        "msatoshi": 1000,
        "id": "035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d",
        "delay": 10,
        "channel": "2x2x2"
      }
    ],
    "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
{
  "id": "example:check#2",
  "method": "check",
  "params": {
    "command_to_check": "dev",
    "subcommand": "slowcmd",
    "msec": 1000
  }
}
{
  "id": "example:check#3",
  "method": "check",
  "params": {
    "command_to_check": "recover",
    "hsmsecret": "6c696768746e696e672d31000000000000000000000000000000000000000000"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **command\_to\_check** (string): The *command\_to\_check* argument.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "command_to_check": "sendpay"
}
{
  "command_to_check": "dev"
}
{
  "command_to_check": "recover"
}
```

AUTHOR
------

Mark Beckwith <<wythe@intrig.com>> and Rusty Russell <<rusty@rustcorp.com.au>> are mainly responsible.

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
