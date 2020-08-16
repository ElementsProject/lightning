lightningd-config -- Lightning daemon configuration file
========================================================

SYNOPSIS
--------

**~/.lightning/config**

DESCRIPTION
-----------

When lightningd(8) starts up it usually reads a general configuration
file (default: **$HOME/.lightning/config**) then a network-specific
configuration file (default: **$HOME/.lightning/testnet/config**).  This can
be changed: see *--conf* and *--lightning-dir*.

General configuration files are processed first, then network-specific
ones, then command line options: later options override earlier ones
except *addr* options and *log-level* with subsystems, which
accumulate.

*include * followed by a filename includes another configuration file at that
point, relative to the current configuration file.

All these options are mirrored as commandline arguments to
lightningd(8), so *--foo* becomes simply *foo* in the configuration
file, and *--foo=bar* becomes *foo=bar* in the configuration file.

Blank lines and lines beginning with *\#* are ignored.

DEBUGGING
---------

*--help* will show you the defaults for many options; they vary with
network settings so you can specify *--network* before *--help* to see
the defaults for that network.

The lightning-listconfigs(7) command will output a valid configuration
file using the current settings.

OPTIONS
-------

### General options

 **allow-deprecated-apis**=*BOOL*
Enable deprecated options, JSONRPC commands, fields, etc. It defaults to
*true*, but you should set it to *false* when testing to ensure that an
upgrade won’t break your configuration.

 **help**
Print help and exit. Not very useful inside a configuration file, but
fun to put in other’s config files while their computer is unattended.

 **version**
Print version and exit. Also useless inside a configuration file, but
putting this in someone’s config file may convince them to read this man
page.

Bitcoin control options:

 **network**=*NETWORK*
Select the network parameters (*bitcoin*, *testnet*, or *regtest*).
This is not valid within the per-network configuration file.

 **testnet**
Alias for *network=testnet*.

 **signet**
Alias for *network=signet*.

 **mainnet**
Alias for *network=bitcoin*.

 **bitcoin-cli**=*PATH*
The name of *bitcoin-cli* executable to run.

 **bitcoin-datadir**=*DIR*
*-datadir* argument to supply to bitcoin-cli(1).

 **bitcoin-rpcuser**=*USER*
The RPC username for talking to bitcoind(1).

 **bitcoin-rpcpassword**=*PASSWORD*
The RPC password for talking to bitcoind(1).

 **bitcoin-rpcconnect**=*HOST*
The bitcoind(1) RPC host to connect to.

 **bitcoin-rpcport**=*PORT*
The bitcoind(1) RPC port to connect to.

 **bitcoin-retry-timeout**=*SECONDS*
Number of seconds to keep trying a bitcoin-cli(1) command. If the
command keeps failing after this time, exit with a fatal error.

 **rescan**=*BLOCKS*
Number of blocks to rescan from the current head, or absolute
blockheight if negative. This is only needed if something goes badly
wrong.

### Lightning daemon options

 **lightning-dir**=*DIR*
Sets the working directory. All files (except *--conf* and
*--lightning-dir* on the command line) are relative to this.  This
is only valid on the command-line, or in a configuration file specified
by *--conf*.

 **subdaemon**=*SUBDAEMON*:*PATH*
Specifies an alternate subdaemon binary.
Current subdaemons are *channeld*, *closingd*,
*connectd*, *gossipd*, *hsmd*, *onchaind*, and *openingd*.
If the supplied path is relative the subdaemon binary is found in the
working directory. This option may be specified multiple times.

 So, **subdaemon=hsmd:remote_signer** would use a
hypothetical remote signing proxy instead of the standard *lightning_hsmd*
binary.

 **pid-file**=*PATH*
Specify pid file to write to.

 **log-level**=*LEVEL*\[:*SUBSYSTEM*\]
What log level to print out: options are io, debug, info, unusual,
broken.  If *SUBSYSTEM* is supplied, this sets the logging level
for any subsystem containing that string.  Subsystems include:

* *lightningd*: The main lightning daemon
* *database*: The database subsystem
* *wallet*: The wallet subsystem
* *gossipd*: The gossip daemon
* *plugin-manager*: The plugin subsystem
* *plugin-P*: Each plugin, P = plugin path without directory
* *hsmd*: The secret-holding daemon
* *connectd*: The network connection daemon
* *jsonrpc#FD*: Each JSONRPC connection, FD = file descriptor number


  The following subsystems exist for each channel, where N is an incrementing
internal integer id assigned for the lifetime of the channel:
* *openingd-chan#N*: Each opening / idling daemon
* *channeld-chan#N*: Each channel management daemon
* *closingd-chan#N*: Each closing negotiation daemon
* *onchaind-chan#N*: Each onchain close handling daemon


  So, **log-level=debug:plugin** would set debug level logging on all
plugins and the plugin manager.  **log-level=io:chan#55** would set
IO logging on channel number 55 (or 550, for that matter).

 **log-prefix**=*PREFIX*
Prefix for log lines: this can be customized if you want to merge logs
with multiple daemons.

 **log-file**=*PATH*
Log to this file instead of stdout. Sending lightningd(8) SIGHUP will
cause it to reopen this file (useful for log rotation).

 **rpc-file**=*PATH*
Set JSON-RPC socket (or /dev/tty), such as for lightning-cli(1).

 **rpc-file-mode**=*MODE*
Set JSON-RPC socket file mode, as a 4-digit octal number.
Default is 0600, meaning only the user that launched lightningd
can command it.
Set to 0660 to allow users with the same group to access the RPC
as well.

 **daemon**
Run in the background, suppress stdout and stderr.

 **conf**=*PATH*
Sets configuration file, and disable reading the normal general and network
ones. If this is a relative path, it is relative to the starting directory, not
**lightning-dir** (unlike other paths). *PATH* must exist and be
readable (we allow missing files in the default case). Using this inside
a configuration file is invalid.

 **wallet**=*DSN*
Identify the location of the wallet. This is a fully qualified data source
name, including a scheme such as `sqlite3` or `postgres` followed by the
connection parameters.

The default wallet corresponds to the following DSN:

```
--wallet=sqlite3://$HOME/.lightning/bitcoin/lightningd.sqlite3
```

The following is an example of a postgresql wallet DSN:

```
--wallet=postgres://user:pass@localhost:5432/db_name
```

This will connect to a the DB server running on `localhost` port `5432`,
authenticate with username `user` and password `pass`, and then use the
database `db_name`. The database must exist, but the schema will be managed
automatically by `lightningd`.

 **encrypted-hsm**
If set, you will be prompted to enter a password used to encrypt the `hsm_secret`.
Note that once you encrypt the `hsm_secret` this option will be mandatory for
`lightningd` to start.
If there is no `hsm_secret` yet, `lightningd` will create a new encrypted secret.
If you have an unencrypted `hsm_secret` you want to encrypt on-disk, or vice versa,
see lightning-hsmtool(8).

### Lightning node customization options

 **alias**=*NAME*
Up to 32 bytes of UTF-8 characters to tag your node. Completely silly, since
anyone can call their node anything they want. The default is an
NSA-style codename derived from your public key, but "Peter Todd" and
"VAULTERO" are good options, too.

 **rgb**=*RRGGBB*
Your favorite color as a hex code.

 **fee-base**=*MILLISATOSHI*
Default: 1000. The base fee to charge for every payment which passes
through. Note that millisatoshis are a very, very small unit! Changing
this value will only affect new channels and not existing ones. If you
want to change fees for existing channels, use the RPC call
lightning-setchannelfee(7).

 **fee-per-satoshi**=*MILLIONTHS*
Default: 10 (0.001%). This is the proportional fee to charge for every
payment which passes through. As percentages are too coarse, it’s in
millionths, so 10000 is 1%, 1000 is 0.1%. Changing this value will only
affect new channels and not existing ones. If you want to change fees
for existing channels, use the RPC call lightning-setchannelfee(7).

 **min-capacity-sat**=*SATOSHI*
Default: 10000. This value defines the minimal effective channel
capacity in satoshi to accept for channel opening requests. If a peer
tries to open a channel smaller than this, the opening will be rejected.

 **ignore-fee-limits**=*BOOL*
Allow nodes which establish channels to us to set any fee they want.
This may result in a channel which cannot be closed, should fees
increase, but make channels far more reliable since we never close it
due to unreasonable fees.

 **commit-time**=*MILLISECONDS*
How long to wait before sending commitment messages to the peer: in
theory increasing this would reduce load, but your node would have to be
extremely busy node for you to even notice.

### Lightning channel and HTLC options

 **large-channels**
Removes capacity limits for channel creation.  Version 1.0 of the specification
limited channel sizes to 16777215 satoshi.  With this option (which your
node will advertize to peers), your node will accept larger incoming channels
and if the peer supports it, will open larger channels.  Note: this option
is spelled **large-channels** but it's pronounced **wumbo**.

 **watchtime-blocks**=*BLOCKS*
How long we need to spot an outdated close attempt: on opening a channel
we tell our peer that this is how long they’ll have to wait if they
perform a unilateral close.

 **max-locktime-blocks**=*BLOCKS*
The longest our funds can be delayed (ie. the longest
**watchtime-blocks** our peer can ask for, and also the longest HTLC
timeout we will accept). If our peer asks for longer, we’ll refuse to
create a channel, and if an HTLC asks for longer, we’ll refuse it.

 **funding-confirms**=*BLOCKS*
Confirmations required for the funding transaction when the other side
opens a channel before the channel is usable.

 **commit-fee**=*PERCENT*
The percentage of *estimatesmartfee 2/CONSERVATIVE* to use for the commitment
transactions: default is 100.

 **commit-fee-min**=*PERCENT*
 **commit-fee-max**=*PERCENT*
Limits on what onchain fee range we’ll allow when a node opens a channel
with us, as a percentage of *estimatesmartfee 2*. If they’re outside
this range, we abort their opening attempt. Note that **commit-fee-max**
can (should!) be greater than 100.

 **max-concurrent-htlcs**=*INTEGER*
Number of HTLCs one channel can handle concurrently in each direction.
Should be between 1 and 483 (default 30).

 **cltv-delta**=*BLOCKS*
The number of blocks between incoming payments and outgoing payments:
this needs to be enough to make sure that if we have to, we can close
the outgoing payment before the incoming, or redeem the incoming once
the outgoing is redeemed.

 **cltv-final**=*BLOCKS*
The number of blocks to allow for payments we receive: if we have to, we
might need to redeem this on-chain, so this is the number of blocks we
have to do that.

Invoice control options:

 **autocleaninvoice-cycle**=*SECONDS*
Perform cleanup of expired invoices every *SECONDS* seconds, or disable
if 0. Usually unpaid expired invoices are uninteresting, and just take
up space in the database.

 **autocleaninvoice-expired-by**=*SECONDS*
Control how long invoices must have been expired before they are cleaned
(if *autocleaninvoice-cycle* is non-zero).

Payment control options:

 **disable-mpp**
Disable the multi-part payment sending support in the `pay` plugin. By default
the MPP support is enabled, but it can be desirable to disable in situations
in which each payment should result in a single HTLC being forwarded in the
network.

### Networking options

Note that for simple setups, the implicit *autolisten* option does the
right thing: it will try to bind to port 9735 on IPv4 and IPv6, and will
announce it to peers if it seems like a public address.

You can instead use *addr* to override this (eg. to change the port), or
precisely control where to bind and what to announce with the
*bind-addr* and *announce-addr* options. These will **disable** the
*autolisten* logic, so you must specifiy exactly what you want!

 **addr**=*\[IPADDRESS\[:PORT\]\]|autotor:TORIPADDRESS\[:SERVICEPORT\]\[/torport=TORPORT\]|statictor:TORIPADDRESS\[:SERVICEPORT\]\[/torport=TORPORT\]\[/torblob=\[blob\]\]*

Set an IP address (v4 or v6) or automatic Tor address to listen on and
(maybe) announce as our node address.

An empty 'IPADDRESS' is a special value meaning bind to IPv4 and/or
IPv6 on all interfaces, '0.0.0.0' means bind to all IPv4
interfaces, '::' means 'bind to all IPv6 interfaces'.  If 'PORT' is
not specified, 9735 is used.  If we can determine a public IP
address from the resulting binding, the address is announced.

If the argument begins with 'autotor:' then it is followed by the
IPv4 or IPv6 address of the Tor control port (default port 9051),
and this will be used to configure a Tor hidden service for port 9735.
The Tor hidden service will be configured to point to the
first IPv4 or IPv6 address we bind to.

If the argument begins with 'statictor:' then it is followed by the
IPv4 or IPv6 address of the Tor control port (default port 9051),
and this will be used to configure a static Tor hidden service for port 9735.
The Tor hidden service will be configured to point to the
first IPv4 or IPv6 address we bind to and is by default unique to
your nodes id. You can add the text '/torblob=BLOB' followed by up to
64 Bytes of text to generate from this text a v3 onion service
address text unique to the first 32 Byte of this text.
You can also use an postfix '/torport=TORPORT' to select the external
tor binding. The result is that over tor your node is accessible by a port
defined by you and possible different from your local node port assignment

This option can be used multiple times to add more addresses, and
its use disables autolisten.  If necessary, and 'always-use-proxy'
is not specified, a DNS lookup may be done to resolve 'IPADDRESS'
or 'TORIPADDRESS'.

 **bind-addr**=*\[IPADDRESS\[:PORT\]\]|SOCKETPATH*
Set an IP address or UNIX domain socket to listen to, but do not
announce. A UNIX domain socket is distinguished from an IP address by
beginning with a */*.

An empty 'IPADDRESS' is a special value meaning bind to IPv4 and/or
IPv6 on all interfaces, '0.0.0.0' means bind to all IPv4
interfaces, '::' means 'bind to all IPv6 interfaces'.  'PORT' is
not specified, 9735 is used.

This option can be used multiple times to add more addresses, and
its use disables autolisten.  If necessary, and 'always-use-proxy'
is not specified, a DNS lookup may be done to resolve 'IPADDRESS'.

 **announce-addr**=*IPADDRESS\[:PORT\]|TORADDRESS.onion\[:PORT\]*
Set an IP (v4 or v6) address or Tor address to announce; a Tor address
is distinguished by ending in *.onion*. *PORT* defaults to 9735.

Empty or wildcard IPv4 and IPv6 addresses don't make sense here.
Also, unlike the 'addr' option, there is no checking that your
announced addresses are public (e.g. not localhost).

This option can be used multiple times to add more addresses, and
its use disables autolisten.

If necessary, and 'always-use-proxy' is not specified, a DNS
lookup may be done to resolve 'IPADDRESS'.

 **offline**
Do not bind to any ports, and do not try to reconnect to any peers. This
can be useful for maintenance and forensics, so is usually specified on
the command line. Overrides all *addr* and *bind-addr* options.

 **autolisten**=*BOOL*
By default, we bind (and maybe announce) on IPv4 and IPv6 interfaces if
no *addr*, *bind-addr* or *announce-addr* options are specified. Setting
this to *false* disables that.

 **proxy**=*IPADDRESS\[:PORT\]*
Set a socks proxy to use to connect to Tor nodes (or for all connections
if **always-use-proxy** is set).

 **always-use-proxy**=*BOOL*
Always use the **proxy**, even to connect to normal IP addresses (you
can still connect to Unix domain sockets manually). This also disables
all DNS lookups, to avoid leaking information.

 **disable-dns**
Disable the DNS bootstrapping mechanism to find a node by its node ID.

 **enable-autotor-v2-mode**
Try to get a v2 onion address from the Tor service call, default is v3.

 **tor-service-password**=*PASSWORD*
Set a Tor control password, which may be needed for *autotor:* to
authenticate to the Tor control port.

### Lightning Plugins

lightningd(8) supports plugins, which offer additional configuration
options and JSON-RPC methods, depending on the plugin. Some are supplied
by default (usually located in **libexec/c-lightning/plugins/**). If a
**plugins** directory exists under *lightning-dir* that is searched for
plugins along with any immediate subdirectories). You can specify
additional paths too:

 **plugin**=*PATH*
Specify a plugin to run as part of c-lightning. This can be specified
multiple times to add multiple plugins.

 **plugin-dir**=*DIRECTORY*
Specify a directory to look for plugins; all executable files not
containing punctuation (other than *.*, *-* or *\_) in 'DIRECTORY* are
loaded. *DIRECTORY* must exist; this can be specified multiple times to
add multiple directories.

 **clear-plugins**
This option clears all *plugin* and *plugin-dir* options preceeding it,
including the default built-in plugin directory. You can still add
*plugin-dir* and *plugin* options following this and they will have the
normal effect.

 **disable-plugin**=*PLUGIN*
If *PLUGIN* contains a /, plugins with the same path as *PLUGIN* will
not be loaded at startup. Otherwise, no plugin with that base name will
be loaded at startup, whatever directory it is in.  This option is useful for
disabling a single plugin inside a directory.  You can still explicitly
load plugins which have been disabled, using lightning-plugin(7) `start`.

BUGS
----

You should report bugs on our github issues page, and maybe submit a fix
to gain our eternal gratitude!

AUTHOR
------

Rusty Russell &lt;<rusty@rustcorp.com.au>&gt; wrote this man page, and
much of the configuration language, but many others did the hard work of
actually implementing these options.

SEE ALSO
--------

lightning-listconfigs(7) lightning-setchannelfee(7) lightningd(8)
lightning-hsmtool(8)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.
