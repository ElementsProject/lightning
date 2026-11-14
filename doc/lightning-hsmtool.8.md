lightning-hsmtool -- Tool for working with software HSM secrets of lightningd
=============================================================================

SYNOPSIS
--------

```bash
lightning-hsmtool method [ARGUMENTS]...
```

DESCRIPTION
-----------

**lightning-hsmtool** performs various operations on the `hsm_secret`
file used by the software HSM component of **lightningd**.

This can be used to encrypt and decrypt the `hsm_secret` file,
as well as derive secrets used in channel commitments.

METHODS
-------

**encrypt** *hsm\_secret\_path* *password*

  Encrypt the `hsm_secret_path` file so that it can only be decrypted at
**lightningd** startup.
You must give the option **--encrypted-hsm** to **lightningd**.
The password of the `hsm_secret_path` file will be asked whenever you
start **lightningd**.

**decrypt** *hsm\_secret\_path* *password*

  Decrypt the `hsm_secret_path` file that was encrypted with the **encrypt**
method.

**dumpcommitments** *node\_id* *channel\_dbid* *depth* *hsm\_secret\_path* \[*password*\]

  Show the per-commitment secret and point of up to *depth* commitments,
of the specified channel with the specified peer,
identified by the channel database index.
Specify *password* if the `hsm_secret_path` is encrypted.

**dumpcommitments** **--point-only** *node\_id* *channel\_dbid* *commitment\_number* *hsm\_secret\_path*

  Show only the per-commitment point of commitment *commitment\_number*
of the specified channel.
Unlike the form above, this prints no secrets, so the result is safe to
give to the peer of that channel.

**guesstoremote** *p2wpkh* *node\_id* *max\_channel\_dbid* *hsm\_secret\_path* \[*password*\]

  Brute-force the private key to our funds from a remote unilateral close
of a channel, in a case where we have lost all database data except for
our `hsm_secret_path`.
The peer must be the one to close the channel (and the funds will remain
unrecoverable until the channel is closed).
*max\_channel\_dbid* is your own guess on what the *channel\_dbid* was,
or at least the maximum possible value,
and is usually no greater than the number of channels that the node has
ever had.
Specify *password* if the `hsm_secret_path` is encrypted.

**derivetoremote** *node\_id* *channel\_dbid* \[*commitment\_point*\] *hsm\_secret*
  Derive the private key to our funds from a remote unilateral close of a channel.
The peer must be the one to close the channel (and the funds will remain
unrecoverable until the channel is closed).
*channel\_dbid* is the identifier of the channel in the CLN database.
If *commitment\_point* is omitted, then the channel is assumed to have been
negotiated with `option_static_remotekey`;
otherwise, *commitment\_point* is the remote per-commitment point.

**recoverhtlc** *bundle\_path* *destination* *hsm\_secret\_path*

  Sign transactions which spend our HTLC outputs of a commitment
transaction which the peer broadcast after we lost channel state.
In that case **lightningd** logs `Unknown commitment #N, recovering our
funds!`: it recovers our main output, but it cannot find the HTLC outputs
without the peer's per-commitment point.

Nothing is broadcast, and no private key is printed.
Each signed transaction pays the address *destination*, and is printed
with a description of what it spends, so you can check it and then
broadcast it yourself.

*bundle\_path* is a JSON file describing the commitment transaction and
the HTLCs to recover from it:

```json
{
  "version": 1,
  "network": "bitcoin",
  "peer_id": "02...",
  "channel_dbid": 123,
  "remote_htlc_basepoint": "03...",
  "commitment_point": "03...",
  "commitment_tx": "0200...",
  "feerate_perkw": 2500,
  "allow_high_fee": false,
  "htlcs": [
    {"direction": "out", "payment_hash": "...", "cltv_expiry": 952295},
    {"direction": "in", "preimage": "...", "cltv_expiry": 952300}
  ]
}
```

  * *version* is always 1.
  * *network* is the network name, such as `bitcoin`, `testnet4`, `signet`
    or `regtest`.
  * *peer\_id* and *channel\_dbid* are the node id of the peer and the `id`
    of the channel in the `channels` table of our database.
  * *remote\_htlc\_basepoint* is `htlc_basepoint_remote` in the same table.
    The peer knows it too: it is their own HTLC basepoint.
  * *commitment\_point* is the peer's per-commitment point for the
    commitment they broadcast, and only the peer has it.
    A Core Lightning peer can print it, and nothing secret, with
    `lightning-hsmtool dumpcommitments --point-only <our node id> <their
    channel dbid> N <their hsm\_secret>`, where *N* is the number in our
    `Unknown commitment #N` log message.
  * *commitment\_tx* is the hex of the commitment transaction, as printed by
    `bitcoin-cli getrawtransaction`.
  * *feerate\_perkw* is optional, in satoshi per 1000 weight: 250 is
    1 sat/vB.  The default is 2500.
  * *allow\_high\_fee* is optional and defaults to false.  By default,
    recovery refuses a transaction whose fee exceeds one quarter of the
    recovered amount.  Set it to true only after checking the fee.
  * Each of *htlcs* with *direction* `out` is an HTLC which we offered: it
    needs the *payment\_hash* and *cltv\_expiry*, and we take it back once
    it has expired.
    Each with *direction* `in` is an HTLC which the peer offered: it needs
    the *preimage*, and must confirm before the peer takes it back at
    *cltv\_expiry*.  Its *cltv\_expiry* and *payment\_hash* are optional.
    The peer can obtain payment hashes and expiries from `listhtlcs`,
    `listpeerchannels` or its logs.  If neither node retained them, the peer
    can help identify them while decoding the commitment transaction.

The values from our database can be read from a copy of it, for example:

```
sqlite3 lightningd.sqlite3 "SELECT c.id, hex(p.node_id), \
    hex(c.htlc_basepoint_remote) FROM channels c \
    JOIN peers p ON p.id = c.peer_id"
```

A transaction is only signed for an HTLC whose script, rebuilt from the
channel and HTLC values, is paid by an output of *commitment\_tx*: a wrong
value cannot select a different HTLC output.
The destination and fee do affect the signed spend, so check both in the
printed transaction before broadcasting it.
An HTLC without such an output is skipped with a message, and the others
are still recovered.  An HTLC too small to have an output in the
commitment transaction cannot be recovered.
Parts of one payment which have identical scripts are spent by a single
transaction.
Both anchor and non-anchor channels are supported; Elements networks are
not.

**generatehsm** *hsm\_secret\_path* \[*lang* *seed\_phrase*  \[*passphrase*\]\]
  Generates a new hsm\_secret using BIP39.  If lang, seed\_phrase and optional passphrase are not provided they will be prompted for.  *lang* can be "en" (English), "es" (Spanish), "fr" (French), "it" ("Italian"), "jp" (Japanese), "zhs" (Chinese Simplified) or "zht" ("Chinese Traditional"). Note that the seed phrase consists of multiple words, so should be surrounded by quotes.

**checkhsm** *hsm\_secret\_path*
  Checks that hsm\_secret matches a BIP39 passphrase.

**dumponchaindescriptors** \[*--show-secrets*\] *hsm\_secret\_path* \[*network*\]
  Dump output descriptors for our onchain wallet.
This command requires the path to the hsm\_secret containing the wallet seed.
If the flag *--show-secrets* is set the command will show the BIP32 extended private
keys, otherwise the extended public keys will be shown.
The descriptors can be used by external services to be able to generate
addresses for our onchain wallet or to spend those funds
provided that the private keys are visible with *--show-secrets*.
The descriptors can be loaded into a bitcoin-core wallet for example,
using the `importmulti` or `importdescriptors` RPC calls.
If the hsm\_secret was encrypted the command will prompt for a decryption
password.
To generate descriptors using testnet master keys, you may specify *testnet* as
the last parameter. By default, mainnet-encoded keys are generated.

**makerune** *hsm\_secret\_path*
  Make a master rune for this node (with `uniqueid` 0)
This produces the same results as lightning-commando-rune(7) on a fresh node.
You will still need to create a rune once the node starts, if you want commando to work (as it is only activated once it has generated one).

**getsecret** *hsm\_secret\_path* [*id*]
  Extract the secret from the `hsm_secret` file and print it out, for use with `--recover`.  This is usually a 12-word mnemonic, but for pre-v25.12 nodes, a 4-character `id` is needed to generate a BIP-93 formatted HSM secret (e.g. `ad00`): it cannot contain `i`, `o`, or `b`, but can contain digits except `1`.

**getcodexsecret** *hsm\_secret\_path* *id*
  Deprecated alias for getsecret: only works on older (pre-v25.12) nodes.

**getemergencyrecover** *emergency.recover\_path*
  Print out the bech32 encoded emergency.recover file.

**getnodeid** *hsm\_secret\_path*
  Print out the node id that a node using this hsm secret would have: useful for verifying that you are accessing the correct secret!

BUGS
----

You should report bugs on our github issues page, and maybe submit a fix
to gain our eternal gratitude!

AUTHOR
------

ZmnSCPxj [ZmnSCPxj@protonmail.com](mailto:ZmnSCPxj@protonmail.com) wrote the initial version of
this man page, but many others did the hard work of actually implementing **lightning-hsmtool**.

SEE ALSO
--------

lightningd(8), lightningd-config(5)

RESOURCES
---------

Main web site: [https://github.com/ElementsProject/lightning](https://github.com/ElementsProject/lightning)

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.
Main web site: [https://github.com/ElementsProject/lightning](https://github.com/ElementsProject/lightning)
