lightning-downgrade -- Tool to revert core lightning to an older version
========================================================================

SYNOPSIS
--------

```bash
lightning-downgrade [ARGUMENTS]...
```

DESCRIPTION
-----------

**lightning-downgrade** reverts an upgrade by modifying the `lightningd`
database back the prior version.  `lightningd` must **not** be running
at the time.

A downgrade may not be possible if a new feature has been used that would
be incompatible with an older version.  In this case the downgrade will fail
with a message and nothing will be changed.

Use the latest `lightning-downgrade` to downgrade.  For example, the `v25.12` lightning-downgrade won't know how to downgrade `v26.06`.

All minor versions are compatible, so a downgrade to v25.09 will work
fine with v25.09.1 or v25.09.2, etc.

VERSIONS
--------

* *v25.12*: downgrades to v25.09.

  Downgrade is not possible if `withhold` `true` has been used with `fundchannel_complete`, or if `askrene-bias-node` has been used.

* *v25.09*: downgrade is not supported.

OPTIONS
-------

* **--lightning-dir**=*DIR*

  Set the directory for the lightning daemon we're talking to; defaults to
*$HOME/.lightning*.

* **--conf**=*PATH*

  Sets configuration file (default: **lightning-dir**/*config* ).

* **--network**=*network*
* **--mainnet**
* **--testnet**
* **--testnet4**
* **--signet**
* **--regtest**

  Sets network explicitly.

* **--rpc-file**=*FILE*

  Named pipe to use to talk to lightning daemon: default is
*lightning-rpc* in the lightning directory.

* **wallet**=*DSN*

  Identify the location of the wallet.  See lightningd-config(5) for details.
  
* **--help**/**-h**

  Pretty-print summary of options to standard output and exit.  The format can
be changed using `-F`, `-R`, `-J`, `-H` etc.

* **--version**/**-V**

  Print version number to standard output and exit.


BUGS
----

You should report bugs on our github issues page, and maybe submit a fix
to gain our eternal gratitude!

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> wrote the initial version of **lightning-downgrade** and this man page.

SEE ALSO
--------

lightningd(8), lightningd-config(5)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.
Main web site: <https://github.com/ElementsProject/lightning>
