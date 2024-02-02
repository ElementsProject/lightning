lightningd -- Daemon for running a Lightning Network node
=========================================================

SYNOPSIS
--------

```bash
lightningd [--conf=<config-file>] [OPTIONS]
```

DESCRIPTION
-----------

**lightningd** starts the Core Lightning daemon, which implements a
standards-compliant Lightning Network node.

CONFIGURATION OPTIONS
---------------------

* **--conf**=*FILE*
Specify configuration file. If not an absolute path, will be relative
from the lightning-dir location. Defaults to *config*.

* **--lightning-dir**=*DIR*
Set the directory for the Core Lightning daemon. Defaults to
*$HOME/.lightning*.

MORE OPTIONS
------------

Command line options are mirrored as configuration options in the
configuration file, so `foo` in the configuration file simply becomes
`--foo` on the command line, and `foo=bar` becomes `--foo=bar`.

See lightningd-config(5) for a comprehensive list of all available
options.

LOGGING AND COMMANDING CORE LIGHTNING
-------------------------------------

By default, Core Lightning will log to the standard output.
To log to a specific file, use **--log-file**=*PATH*.
Sending SIGHUP will cause Core Lightning to reopen this file,
for example to do log rotation.

Core Lightning will set up a Unix domain socket for receiving
commands.
By default this will be the file **lightning-rpc** in your
specified **lightning-dir**.
You can use lightning-cli(1) to send commands to Core Lightning
once **lightningd** has started; you need to match the
**--lightning-dir** and **--rpc-file** options between them.

Commands for Core Lightning are described in various manpages
in section 7, with the common prefix **lightning-**.

QUICK START
-----------

First, decide on and create a directory for *lightning-dir*, or just use
the default *$HOME/.lightning*. Then create a *config* file in this
directory containing your configuration.

Your other main preparation would be to set up a mainnet Bitcoin
fullnode, i.e. run a bitcoind(1) instance. The rest of this quick start
guide will assume you are reckless and want to spend real funds on
Lightning: otherwise indicate *network=testnet* in your *config* file explicitly.

Core Lightning needs to communicate with the Bitcoin Core RPC. You can set
this up using *bitcoin-datadir*, *bitcoin-rpcconnect*,
*bitcoin-rpcport*, *bitcoin-rpcuser*, and *bitcoin-rpcpassword* options
in your *config* file.

Finally, just to keep yourself sane, decide on a log file name and
indicate it using *log-file=lightningd.log* in your *config* file. You
might be interested in viewing it periodically as you follow along on
this guide.

Once the **bitcoind** instance is running, start lightningd(8):

    $ lightningd --lightning-dir=$HOME/.lightning --daemon

This starts **lightningd** in the background due to the *--daemon*
option.

Check if things are working:

    $ lightning-cli --lightning-dir=$HOME/.lightning help
    $ lightning-cli --lightning-dir=$HOME/.lightning getinfo

The **getinfo** command in particular will return a *blockheight* field,
which indicates the block height to which **lightningd** has been
synchronized to (this is separate from the block height that your
**bitcoind** has been synchronized to, and will always lag behind
**bitcoind**). You will have to wait until the *blockheight* has reached
the actual blockheight of the Bitcoin network.

Before you can get funds offchain, you need to have some funds onchain
owned by **lightningd** (which has a separate wallet from the
**bitcoind** it connects to). Get an address for **lightningd** via
lightning-newaddr(7) command as below (*--lightning-dir* option has been
elided, specify it if you selected your own *lightning-dir*):

    $ lightning-cli newaddr

This will provide a native SegWit bech32 address. In case all your money
is in services that do not support native SegWit and have to use
P2SH-wrapped addresses, instead use:

    $ lightning-cli newaddr p2sh-segwit

Transfer a small amount of onchain funds to the given address. Check the
status of all your funds (onchain and on-Lightning) via
lightning-listfunds(7):

    $ lightning-cli listfunds

Now you need to look for an arbitrary Lightning node to connect to,
which you can do by using dig(1) and querying *lseed.bitcoinstats.com*:

    $ dig lseed.bitcoinstats.com A

This will give 25 IPv4 addresses, you can select any one of those. You
will also need to learn the corresponding public key, which you can
determine by searching the IP addrss on <https://1ml.com/> . The public
key is a long hex string, like so:
*024772ee4fa461febcef09d5869e1238f932861f57be7a6633048514e3f56644a1*.
(this example public key is not used as of this writing)

After determining a public key, use lightning-connect(7) to connect to
that public key at that IP:

    $ lightning-cli connect $PUBLICKEY $IP

Then open a channel to that node using lightning-fundchannel(7):

    $ lightning-cli fundchannel $PUBLICKEY $SATOSHI

This will require that the funding transaction be confirmed before you
can send funds over Lightning. To track this, use lightning-listpeers(7)
and look at the *state* of the channel:

    $ lightning-cli listpeers $PUBLICKEY

The channel will initially start with a *state* of
*CHANNELD\_AWAITING\_LOCKIN*. You need to wait for the channel *state*
to become *CHANNELD\_NORMAL*, meaning the funding transaction has been
confirmed deeply.

Once the channel *state* is *CHANNELD\_NORMAL*, you can start paying
merchants over Lightning. Acquire a Lightning invoice from your favorite
merchant, and use lightning-pay(7) to pay it:

    $ lightning-cli pay $INVOICE

ERRORS CODE
---

- 1: Generic lightning-cli error
- 10: Error executing subdaemons
- 11: Error locking pidfile (often another lightningd running)
- 20: Generic error related to HSM secret
- 21: HSM secret is encrypted
- 22: Bad password used to decrypt the HSM secred
- 23: Error caused from the I/O operation during a HSM decryption/encryption operation
- 30: Wallet database does not match (network or hsm secret)


BUGS
----

You should report bugs on our github issues page, and maybe submit a fix
to gain our eternal gratitude!

AUTHOR
------

ZmnSCPxj <<ZmnSCPxj@protonmail.com>> wrote the initial version of
this man page, but many others did the hard work of actually
implementing a standards-compliant Lightning Network node
implementation.

SEE ALSO
--------

lightningd-rpc(7),
lightning-listconfigs(7), lightningd-config(5), lightning-cli(1),
lightning-newaddr(7), lightning-listfunds(7), lightning-connect(7),
lightning-fundchannel(7), lightning-listpeers(7), lightning-pay(7),
lightning-hsmtool(8)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.
