lightning-txsend -- Command to sign and send transaction from txprepare
=======================================================================

SYNOPSIS
--------

**txsend** *txid* 

DESCRIPTION
-----------

The **txsend** RPC command signs and broadcasts a transaction created by *txprepare* RPC command.

- **txid** (txid): The transaction id of the transaction created by `txprepare` rpc command.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:txsend#1",
  "method": "txsend",
  "params": {
    "txid": "c9f59ba6bda8e095bb43ecabfa37de8d5194e5c839b6b63be4e29bceaae483ce"
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **psbt** (string): The completed PSBT representing the signed transaction.
- **tx** (hex): The fully signed transaction.
- **txid** (txid): The transaction id of *tx*.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "tx": "020000000142dc00d81359c3a551e170e3bf5262fa9cacc2eb2e283a10e579491cd86dce4b0000000000fdffffff020000000100000000220020b636f07026ea64952ece5b7620a9337d9ac2321c796a499260994d1b373667504183980000000000225120754a77b503fcba0fd80f0a1a8226ed6764ff9a9d9bb61b485d40d4c9f4be245966000000",
  "txid": "c9f59ba6bda8e095bb43ecabfa37de8d5194e5c839b6b63be4e29bceaae483ce",
  "psbt": "cHNidP8BAgQCAAAAAQMEZgAAAAEEAQEBBQECAQYBAwH7BAIAAAAAAQDeAgAAAAABATRHoQ9tEMHRHpf06v5uTEdjdMk1rccIaA6MNGMipNQWAAAAAAD9////AoCWmAEAAAAAFgAUAfrZCrzWZpfiWSFkci3kqV6+4WXzWm0oAQAAABYAFLnqitWTi465LGxeucwoSAj16NGbAkcwRAIgVtOsUaQaPgH86aW6e6qmJa1xVb8KWvc+HALGosqVVmQCIFi4JU8Gy+vl2a2/frY+71hitYIBB/tjsRP7fpgb8b9TASECHUIV5q1r2ownjOlAFPQASTlZxxNgBvi5O3hCRvajwdJlAAAAAQEfgJaYAQAAAAAWABQB+tkKvNZml+JZIWRyLeSpXr7hZSICA9dFRFyTYmZfIuDZbp52byc/MmDeo5yKdr+gXdJoTdzPRzBEAiBp/HPhg1ObOXqTr5rIjUYLMspGLz+sk1pjD9pjRFzf3wIgWycOB/dQPzwZAK3OXYs269h8o85ucDpdVhH4AyX69a0BIgYD10VEXJNiZl8i4NlunnZvJz8yYN6jnIp2v6Bd0mhN3M8IAfrZCgAAAAABDiBC3ADYE1nDpVHhcOO/UmL6nKzC6y4oOhDleUkc2G3OSwEPBAAAAAABEAT9////AAEDCAAAAAEAAAAAAQQiACC2NvBwJupklS7OW3YgqTN9msIyHHlqSZJgmU0bNzZnUAABAwhBg5gAAAAAAAEEIlEgdUp3tQP8ug/YDwoagibtZ2T/mp2bthtIXUDUyfS+JFkhBycqmiXx/+1S+rBKLMiK6rE1tTcjhWqPFIHCZBf4ipIuCQDVXEk5CwAAAAA="
}
```

ERRORS
------

On failure, an error is reported (from bitcoind), and the inputs from the transaction are unreserved.

- -1: Catchall nonspecific error.

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> is mainly responsible.

SEE ALSO
--------

lightning-txprepare(7), lightning-txdiscard(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
