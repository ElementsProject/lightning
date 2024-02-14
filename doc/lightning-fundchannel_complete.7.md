lightning-fundchannel\_complete -- Command for completing channel establishment
===============================================================================

SYNOPSIS
--------

**fundchannel\_complete** *id* *psbt* 

DESCRIPTION
-----------

`fundchannel_complete` is a lower level RPC command. It allows a user to complete an initiated channel establishment with a connected peer.

Note that the funding transaction MUST NOT be broadcast until after channel establishment has been successfully completed, as the commitment transactions for this channel are not secured until this command successfully completes. Broadcasting transaction before can lead to unrecoverable loss of funds.

- **id** (pubkey): Node id of the remote peer.
- **psbt** (string): Transaction to use for funding (does not need to be signed but must be otherwise complete).

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:fundchannel_complete#1",
  "method": "fundchannel_complete",
  "params": {
    "id": "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59",
    "psbt": "cHNidP8BAIkCAAAAASYd4TeOHEIzrUbbELM2DK0IX09WaXqWsJFlLD455MPPAAAAAAD9////Av///wAAAAAAIgAgW4zTuRTPZ83Y+mJzyTA1PdNkdnNPvZYhAsLfU7kIgM1c8QUpAQAAACJRIH8AZYBKMKON4/oVmJVsVt6zy/+PkBPzziE+LtkuFvWXAAAAAAABAIMCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wJRAP////8CAPIFKgEAAAAWABQ5FIjuMd8ar9WFRV9eGNLF+3RMcAAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAEBHwDyBSoBAAAAFgAUORSI7jHfGq/VhUVfXhjSxft0THAiBgMegIxEPDa2OseVTaV6ANtSwQuoj/j2an7X/Is2EekvWBhhFDNgVAAAgAEAAIAAAACAAAAAAAAAAAAAAAEFIEm9AFgqUlJwbPFtyt3a9dzvb+nAGZiQ3CT1CImhjBFpIQdJvQBYKlJScGzxbcrd2vXc72/pwBmYkNwk9QiJoYwRaRkAYRQzYFYAAIABAACAAAAAgAEAAAAAAAAAAA=="
  }
}
```

RETURN VALUE
------------

On success, an object is returned, containing:

- **channel\_id** (hash): The channel\_id of the resulting channel.
- **commitments\_secured** (boolean) (always *true*): Indication that channel is safe to use.

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "channel_id": "049217e5035a4a60449c6382c445b5c105bd63588d66137ad0511c57a16db6d9",
  "commitments_secured": true
}
```

ERRORS
------

On error the returned object will contain `code` and `message` properties, with `code` being one of the following:

- -32602: If the given parameters are wrong.
- -1: Catchall nonspecific error.
- 305: Peer is not connected.
- 306: Unknown peer id.
- 309: PSBT does not have a unique, correct output to fund the channel.

AUTHOR
------

Lisa Neigut <<niftynei@gmail.com>> is mainly responsible.

SEE ALSO
--------

lightning-connect(7), lightning-fundchannel(7), lightning-multifundchannel(7), lightning-fundchannel\_start(7), lightning-fundchannel\_cancel(7), lightning-openchannel\_init(7), lightning-openchannel\_update(7), lightning-openchannel\_signed(7), lightning-openchannel\_bump(7), lightning-openchannel\_abort(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
