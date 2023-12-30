lightningd-rpc -- Lightning Daemon RPC Protocols
================================================

SYNOPSIS
--------

**~/.lightning/bitcoin/lightning-rpc**

DESCRIPTION
-----------

lightningd(8) communicates via RPC, especially JSONRPC over the UNIX
domain socket (by default **$HOME/.lightning/bitcoin/lightning-rpc**,
but configuable with lightningd-config(5)).


JSON WIRE FORMAT
----------------

JSON RPC is defined at <https://www.jsonrpc.org/specification> and
generally involves writing a JSON request with a unique ID, and
receiving a response containing that ID.

Every response given by lightningd(8) is followed by two '\n'
characters, which should not appear in normal JSON (though plugins may
produce them).  This means efficient code can simply read until it
sees two '\n' characters, and then attempt to parse the JSON (if the
JSON is incomplete, it should continue reading and file a bug).

JSON COMMANDS
-------------

We support "params" as an array (ordered parameters) or a dictionary
(named parameters).  In the array case, JSON "null" is treated as if
the parameter was not specified (if that is allowed).

You should probably prefer named parameters if possible, as they have
generally been shown to be less confusing for complex commands and
more robust when fields are deprecated.

The lightning-cli(1) tool uses ordered parameters by default, but
named parameters if explicitly specified or the first parameter
contains an '='.

JSON IDS
--------

JSON `id` fields in requests are used to match requests and responses.
These used to be simple numbers, but with modern plugins that is deprecated:
we use a specific format, which makes them very useful for debugging
and tracking the cause of commands:

```EBNF
JSONID := IDPART ['/' IDPART]*
IDPART := PREFIX ':' METHOD '#' NUMBER
```

`PREFIX` is cln for the main daemon, cli for lightning-cli, and should
be the plugin name for plugins.  `METHOD` is an internal identifier,
indicating what caused the request: for `cli` it's simply the method
it's invoking, but for plugins it may be the routine which created the
request.  And `NUMBER` ensures uniqueness (it's usually a simple
increment).

Importantly for plugins, incoming requests often trigger outgoing
requests, and for these, the outgoing request id is created by
appending a `/` and another id part into the incoming.  This makes the
chain of responsibility much clearer.  e.g, this shows the JSON `id`
of a `sendrawtransaction` RPC call, and we can tell that lightning-cli
has invoked the `withdraw` command, which lightningd passes through
to the `txprepare` plugin, which called `sendrawtransaction`.

```
cli:withdraw#123/cln:withdraw#7/txprepare:sendpsbt#1/cln:sendrawtransaction#9
```

JSON REPLIES
------------

All JSON replies are wrapped in an object; this allows fields to
be added in future.  You should safely ignore any unknown fields.

Any field name which starts with "warning" is a specific warning, and
should be documented in the commands' manual page.  Each warning field
has an associated human-readable string, but it's redudant, as each
separate warning should have a distinct field name
(e.g. **warning\_offer\_unknown\_currency** and
**warning\_offer\_missing\_description**).

JSON TYPES
----------

The exact specification for (most!) commands is specified in
`doc/schemas/` in the source directory.  This is also used to generate
part of the documentation for each command; the following types are
referred to in addition to simple JSON types:

* `hex`: an even-length string of hexadecimal digits.
* `hash`: a 64-character `hex` which is a sha256 hash.
* `secret`: a 64-character `hex` which is a secret of some kind.
* `u64`: a JSON number without decimal point in the range 0 to 18446744073709551615 inclusive.
* `u32`: a JSON number without decimal point in the range 0 to 4294967295 inclusive.
* `u16`: a JSON number without decimal point in the range 0 to 65535 inclusive.
* `u16`: a JSON number without decimal point in the range 0 to 255 inclusive.
* `pubkey`: a 66-character `hex` which is an SEC-1 encoded secp256k1 point (usually used as a public key).
* `msat`: a `u64` which indicates an amount of millisatoshis.  Deprecated: may also be a string of the number, with "msat" appended.  As an input parameter, lightningd(8) will accept strings with suffixes (see below).
* `txid`: a 64-character `hex` Bitcoin transaction identifier.
* `signature`: a `hex` (144 bytes or less), which is a DER-encoded Bitcoin signature (without any sighash flags appended), 
* `bip340sig`: a 128-character `hex` which is a BIP-340 (Schnorr) signature.
* `point32`: a 64-character `hex` which represents an x-only pubkey.
* `short_channel_id`: a string of form BLOCK "x" TXNUM "x" OUTNUM.
* `short_channel_id_dir`: a `short_channel_id` with "/0" or "/1" appended, indicating the direction between peers.
* `outpoint`: a string containing a `txid` followed by a ":" and an output number (bitcoind uses this form).
* `feerate`: an integer, or a string consisting of a number followed by "perkw" or "perkb".
* `outputdesc`: an object containing onchain addresses as keys, and "all" or a valid `msat` field as values.

The following forms of `msat` are supported as parameters:

- An integer (representing that many millisatoshis), e.g. `10000`
- A string of an integer N and the suffix *msat* (representing N millisatoshis) e.g. `"10000msat"`
- A string of an integer N and the suffix *sat* (representing N times 1000 millisatoshis ) e.g. `"10sat"`
- A string of a number N.M (where M is exactly three digits) and the suffix *sat* (representing N times 1000 plus M millisatoshis) e.g. `"10.000sat"`
- A string of an integer N and the suffix *btc* (representing N times 100000000000 millisatoshis) e.g. `"1btc"`
- A string of a number N.M (where M is exactly eight digits) and the suffix *btc* (representing N times 100000000000 plus M times 1000 millisatoshis) e.g `"0.00000010btc"`
- A string of a number N.M (where M is exactly elevent digits) and the suffix *btc* (representing N times 100000000000 plus M millisatoshis) e.g `"0.00000010000btc"`

JSON NOTIFICATIONS
------------------

Notifications are (per JSONRPC spec) JSON commands without an "id"
field.  They give information about ongoing commands, but you
need to enable them.  See lightning-notifications(7).

FIELD FILTERING
---------------

You can restrict what fields are in the output of any command, by
including a `"filter"` member in your request, alongside the standard
`"method"` and `"params"` fields.

`filter` is a template, with keys indicating what fields are to be
output (values must be `true`).  Only fields which appear in the
template will be output.  For example, here is a normal `result` of
`listtransactions`:

```
"result": {
  "transactions": [
    {
      "hash": "3b15dbc81d6a70abe1e75c1796c3eeba71c3954b7a90dfa67d55c1e989e20dbb",
      "rawtx": "020000000001019db609b099735fada240b82cec9da880b35d7a944065c280b8534cb4e2f5a7e90000000000feffffff0240420f000000000017a914d8b7ebd0ccc80266a97d9a828baf1877032ac6648731aff6290100000017a9142cb0814338091a73b388579b025c34f328dfb7898702473044022060a7ede98390111bc33bb12b09b38ad8e31b2a6fd62e9ce39a165b4c15ed39f8022040537219d42af28be18fd223af7cb2367f2300c9f0eb20dcaf677a96cd23efc7012102b2e79c36f2173bc24754214b6eeecd8dc753afda44f606d6f8c55c60c4d614ac65000000",
      "blockheight": 102,
      "txindex": 1,
      "locktime": 101,
      "version": 2,
      "inputs": [
        {
          "txid": "e9a7f5e2b44c53b880c26540947a5db380a89dec2cb840a2ad5f7399b009b69d",
          "index": 0,
          "sequence": 4294967294
        }
      ],
      "outputs": [
        {
          "index": 0,
          "amount_msat": "1000000000msat",
          "type": "deposit",
          "scriptPubKey": "a914d8b7ebd0ccc80266a97d9a828baf1877032ac66487"
        },
        {
          "index": 1,
          "amount_msat": "4998999857000msat",
          "scriptPubKey": "a9142cb0814338091a73b388579b025c34f328dfb78987"
        }
      ]
    },
    {
      "hash": "3a5ebaae466a9cb69c59553a3100ed545523e7450c32684cbc6bf0b305a6c448",
      "rawtx": "02000000000101bb0de289e9c1557da6df907a4b95c371baeec396175ce7e1ab706a1dc8db153b000000001716001401fad90abcd66697e2592164722de4a95ebee165fdffffff0217a70d0000000000160014c2ccab171c2a5be9dab52ec41b825863024c5466a0860100000000002200205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd0247304402201ce0fef95f6aa0e04a87bdc3083259a8aa7212568f672962d1c3da968daf4f72022041ff4e4e255757c12335e67acde8cf4528c60d4afee45d3f891c81b3a0218c75012103d745445c9362665f22e0d96e9e766f273f3260dea39c8a76bfa05dd2684ddccf66000000",
      "blockheight": 103,
      "txindex": 1,
      "locktime": 102,
      "version": 2,
      "inputs": [
        {
          "txid": "3b15dbc81d6a70abe1e75c1796c3eeba71c3954b7a90dfa67d55c1e989e20dbb",
          "index": 0,
          "sequence": 4294967293
        }
      ],
      "outputs": [
        {
          "index": 0,
          "amount_msat": "894743000msat",
          "type": "deposit",
          "scriptPubKey": "0014c2ccab171c2a5be9dab52ec41b825863024c5466"
        },
        {
          "index": 1,
          "amount_msat": "100000000msat",
          "type": "channel_funding",
          "channel": "103x1x1",
          "scriptPubKey": "00205b8cd3b914cf67cdd8fa6273c930353dd36476734fbd962102c2df53b90880cd"
        }
      ]
    }
  ]
}
```

If we only wanted the output amounts and types, we would create a filter like so:

```
"filter": {"transactions": [{"outputs": [{"amount_msat": true, "type": true}]}]}
```

The result would be:

```
"result": {
  "transactions": [
    {
      "outputs": [
        {
          "amount_msat": "1000000000msat",
          "type": "deposit",
        },
        {
          "amount_msat": "4998999857000msat",
        }
      ]
    },
    {
      "outputs": [
        {
          "amount_msat": "894743000msat",
          "type": "deposit",
        },
        {
          "amount_msat": "100000000msat",
          "type": "channel_funding",
        }
      ]
    }
  ]
}
```

Note: `"filter"` doesn't change the order, just which fields are
printed.  Any fields not explicitly mentioned are omitted from the
output, but plugins which don't support filter (and some routines
doing simple JSON transfers) may ignore `"filter"`, so you should treat
it as an optimazation only).

Note: if you specify an array where an object is specified or vice
versa, the response may include a `warning_parameter_filter` field
which describes the problem.


DEALING WITH FORMAT CHANGES
---------------------------

Fields can be added to the JSON output at any time, but to remove (or,
very rarely) change a field requires a minimum deprecation period of 6
months and two releases.  Usually a new field will be added if one is
deprecated, so both will be present in transition.

To test that you're not using deprecated fields, you can use the
lightningd-config(5) option `allow-deprecated-apis=false`.  You should
only use this in internal tests: it is not recommended that users use
this directly.

The documentation tends to only refer to non-deprecated items, so if
you seen an output field which is not documented, its either a bug
(like that ever happens!) or a deprecated field you should ignore.

DEBUGGING
---------

You can use `log-level=io` to see much of the JSON conversation (in
hex) that occurs.  It's extremely noisy though!

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> wrote this man page, and
much of the configuration language, but many others did the hard work of
actually implementing these options.

SEE ALSO
--------

lightningd-config(5), lightning-notifications(7), lightningd(8)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.
