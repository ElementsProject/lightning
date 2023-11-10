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

Note that some configuration options, marked *dynamic*m can be changed at runtime: see lightning-setconfig(7).

General configuration files are processed first, then network-specific
ones, then command line options: later options override earlier ones
except *addr* options and *log-level* with subsystems, which
accumulate.

`include` followed by a filename includes another configuration file at that
point, relative to the current configuration file.

All these options are mirrored as commandline arguments to
lightningd(8), so `--foo` becomes simply `foo` in the configuration
file, and `--foo=bar` becomes `foo=bar` in the configuration file.

Blank lines and lines beginning with `#` are ignored.

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

* **developer**

  This enables developer mode, allowing developer options and commands to be used.  It also disabled deprecated APIs; use `allow-deprecated-apis=true` to re-enable them.

* **allow-deprecated-apis**=*BOOL*

  Enable deprecated options, JSONRPC commands, fields, etc. It defaults to
*true* outside developer mode, but you should set it to *false* when testing to ensure that an
upgrade won't break your configuration.

* **help**

  Print help and exit. Not very useful inside a configuration file, but
fun to put in other's config files while their computer is unattended.

* **version**

  Print version and exit. Also useless inside a configuration file, but
putting this in someone's config file may convince them to read this man
page.

* **database-upgrade**=*BOOL*

  Upgrades to Core Lightning often change the database: once this is done,
downgrades are not generally possible.  By default, Core Lightning will
exit with an error rather than upgrade, unless this is an official released
version.  If you really want to upgrade to a non-release version, you can
set this to *true* (or *false* to never allow a non-reversible upgrade!).

### Bitcoin control options:

Bitcoin control options:

* **network**=*NETWORK*

  Select the network parameters (*bitcoin*, *testnet*, *signet*, or *regtest*).
This is not valid within the per-network configuration file.

* **mainnet**

  Alias for *network=bitcoin*.

* **regtest**

  Alias for *network=regtest* (added in v23.08)

* **testnet**

  Alias for *network=testnet*.

* **signet**

  Alias for *network=signet*.

* **bitcoin-cli**=*PATH* [plugin `bcli`]

  The name of *bitcoin-cli* executable to run.

* **bitcoin-datadir**=*DIR* [plugin `bcli`]

  *-datadir* argument to supply to bitcoin-cli(1).

* **bitcoin-rpcuser**=*USER* [plugin `bcli`]

  The RPC username for talking to bitcoind(1).

* **bitcoin-rpcpassword**=*PASSWORD* [plugin `bcli`]

  The RPC password for talking to bitcoind(1).

* **bitcoin-rpcconnect**=*HOST* [plugin `bcli`]

  The bitcoind(1) RPC host to connect to.

* **bitcoin-rpcport**=*PORT* [plugin `bcli`]

  The bitcoind(1) RPC port to connect to.

* **bitcoin-retry-timeout**=*SECONDS* [plugin `bcli`]

  Number of seconds to keep trying a bitcoin-cli(1) command. If the
command keeps failing after this time, exit with a fatal error.

* **rescan**=*BLOCKS*

  Number of blocks to rescan from the current head, or absolute
blockheight if negative. This is only needed if something goes badly
wrong.

### Lightning daemon options

* **lightning-dir**=*DIR*

  Sets the working directory. All files (except *--conf* and
*--lightning-dir* on the command line) are relative to this.  This
is only valid on the command-line, or in a configuration file specified
by *--conf*.

* **subdaemon**=*SUBDAEMON*:*PATH*

  Specifies an alternate subdaemon binary.
Current subdaemons are *channeld*, *closingd*,
*connectd*, *gossipd*, *hsmd*, *onchaind*, and *openingd*.
If the supplied path is relative the subdaemon binary is found in the
working directory. This option may be specified multiple times.

  So, **subdaemon=hsmd:remote\_signer** would use a
hypothetical remote signing proxy instead of the standard *lightning\_hsmd*
binary.

* **pid-file**=*PATH*

  Specify pid file to write to.

* **log-level**=*LEVEL*\[:*SUBSYSTEM*\]\[:*PATH*\]

  What log level to print out: options are io, debug, info, unusual,
broken.  If *SUBSYSTEM* is supplied, this sets the logging level
for any subsystem (or *nodeid*) containing that string. If *PATH* is supplied, it means this log-level filter is only applied to that `log-file`, which is useful for creating logs to capture a specific subsystem.  This option may be specified multiple times.
Subsystems include:

  * *lightningd*: The main lightning daemon

  * *database*: The database subsystem

  * *wallet*: The wallet subsystem

  * *gossipd*: The gossip daemon

  * *plugin-manager*: The plugin subsystem

  * *plugin-P*: Each plugin, P = plugin path without directory

  * *hsmd*: The secret-holding daemon

  * *connectd*: The network connection daemon

  * *jsonrpc#FD*: Each JSONRPC connection, FD = file descriptor number


  The following subsystems exist for each channel, where N is an incrementing internal integer id assigned for the lifetime of the channel:

  * *openingd-chan#N*: Each opening / idling daemon

  * *channeld-chan#N*: Each channel management daemon

  * *closingd-chan#N*: Each closing negotiation daemon

  * *onchaind-chan#N*: Each onchain close handling daemon


  So, **log-level=debug:plugin** would set debug level logging on all
plugins and the plugin manager.  **log-level=io:chan#55** would set
IO logging on channel number 55 (or 550, for that matter).
**log-level=debug:024b9a1fa8:/tmp/024b9a1fa8.debug.log** would set debug logging for that channel only on the **log-file=/tmp/024b9a1fa8.debug.log** (or any node id containing that string).

* **log-prefix**=*PREFIX*

  Prefix for all log lines: this can be customized if you want to merge logs
with multiple daemons.  Usually you want to include a space at the end of *PREFIX*,
as the timestamp follows immediately.

* **log-file**=*PATH*

  Log to this file (instead of stdout).  If you specify this more than once
you'll get more than one log file: **-** is used to mean stdout.  Sending
lightningd(8) SIGHUP will cause it to reopen each file (useful for log
rotation).

* **log-timestamps**=*BOOL*

  Set this to false to turn off timestamp prefixes (they will still appear
in crash log files).

* **rpc-file**=*PATH*

  Set JSON-RPC socket (or /dev/tty), such as for lightning-cli(1).

* **rpc-file-mode**=*MODE*

  Set JSON-RPC socket file mode, as a 4-digit octal number.
Default is 0600, meaning only the user that launched lightningd
can command it.
Set to 0660 to allow users with the same group to access the RPC
as well.

* **daemon**

  Run in the background, suppress stdout and stderr.  Note that you need
to specify **log-file** for this case.

* **conf**=*PATH*

  Sets configuration file, and disable reading the normal general and network
ones. If this is a relative path, it is relative to the starting directory, not
**lightning-dir** (unlike other paths). *PATH* must exist and be
readable (we allow missing files in the default case). Using this inside
a configuration file is invalid.

* **wallet**=*DSN*

  Identify the location of the wallet. This is a fully qualified data source
name, including a scheme such as `sqlite3` or `postgres` followed by the
connection parameters.

  The default wallet corresponds to the following DSN:
  `--wallet=sqlite3://$HOME/.lightning/bitcoin/lightningd.sqlite31`

  For the `sqlite3` scheme, you can specify a single backup database file
by separating it with a `:` character, like so:
  `--wallet=sqlite3://$HOME/.lightning/bitcoin/lightningd.sqlite3:/backup/lightningd.sqlite3`

  The following is an example of a postgresql wallet DSN:

  `--wallet=postgres://user:pass@localhost:5432/db_name`

  This will connect to a DB server running on `localhost` port `5432`,
authenticate with username `user` and password `pass`, and then use the
database `db_name`. The database must exist, but the schema will be managed
automatically by `lightningd`.

* **bookkeeper-dir**=*DIR* [plugin `bookkeeper`]

  Directory to keep the accounts.sqlite3 database file in.
Defaults to lightning-dir.

* **bookkeeper-db**=*DSN* [plugin `bookkeeper`]

  Identify the location of the bookkeeper data. This is a fully qualified data source
name, including a scheme such as `sqlite3` or `postgres` followed by the
connection parameters.
Defaults to `sqlite3://accounts.sqlite3` in the `bookkeeper-dir`.

* **encrypted-hsm**

 If set, you will be prompted to enter a password used to encrypt the `hsm_secret`.
Note that once you encrypt the `hsm_secret` this option will be mandatory for
`lightningd` to start.
If there is no `hsm_secret` yet, `lightningd` will create a new encrypted secret.
If you have an unencrypted `hsm_secret` you want to encrypt on-disk, or vice versa,
see lightning-hsmtool(8).

* **grpc-port**=*portnum* [plugin `cln-grpc`]

  The port number for the GRPC plugin to listen for incoming
connections; default is not to activate the plugin at all.

### Lightning node customization options

* **recover**=*hsmsecret*

  Restore the node from a 32-byte secret encoded as either a codex32 secret string or a 64-character hex string: this will fail if the `hsm_secret` file exists.  Your node will start the node in offline mode, for manual recovery.  The secret can be extracted from the `hsm_secret` using hsmtool(8).

* **alias**=*NAME*

  Up to 32 bytes of UTF-8 characters to tag your node. Completely silly, since
anyone can call their node anything they want. The default is an
NSA-style codename derived from your public key, but "Peter Todd" and
"VAULTERO" are good options, too.

* **rgb**=*RRGGBB*

  Your favorite color as a hex code.

* **fee-base**=*MILLISATOSHI*

  Default: 1000. The base fee to charge for every payment which passes
through. Note that millisatoshis are a very, very small unit! Changing
this value will only affect new channels and not existing ones. If you
want to change fees for existing channels, use the RPC call
lightning-setchannel(7).

* **fee-per-satoshi**=*MILLIONTHS*

  Default: 10 (0.001%). This is the proportional fee to charge for every
payment which passes through. As percentages are too coarse, it's in
millionths, so 10000 is 1%, 1000 is 0.1%. Changing this value will only
affect new channels and not existing ones. If you want to change fees
for existing channels, use the RPC call lightning-setchannel(7).

* **min-capacity-sat**=*SATOSHI* [*dynamic*]

  Default: 10000. This value defines the minimal effective channel
capacity in satoshi to accept for channel opening requests. This will
reject any opening of a channel which can't pass an HTLC of least this
value.  Usually this prevents a peer opening a tiny channel, but it
can also prevent a channel you open with a reasonable amount and the peer
requesting such a large reserve that the capacity of the channel
falls below this.

* **ignore-fee-limits**=*BOOL*

  Allow nodes which establish channels to us to set any fee they want.
This may result in a channel which cannot be closed, should fees
increase, but make channels far more reliable since we never close it
due to unreasonable fees.  Note that this can be set on a per-channel
basis with lightning-setchannel(7).

* **commit-time**=*MILLISECONDS*

  How long to wait before sending commitment messages to the peer: in
theory increasing this would reduce load, but your node would have to be
extremely busy node for you to even notice.

* **force-feerates**==*VALUES*

  Networks like regtest and testnet have unreliable fee estimates: we
usually treat them as the minimum (253 sats/kw) if we can't get them.
This allows override of one or more of our standard feerates (see
lightning-feerates(7)).  Up to 5 values, separated by '/' can be
provided: if fewer are provided, then the final value is used for the
remainder.  The values are in per-kw (roughly 1/4 of bitcoind's per-kb
values), and the order is "opening", "mutual\_close", "unilateral\_close",
"delayed\_to\_us", "htlc\_resolution", and "penalty".

  You would usually put this option in the per-chain config file, to avoid
setting it on Bitcoin mainnet!  e.g. `~rusty/.lightning/regtest/config`.

* **htlc-minimum-msat**=*MILLISATOSHI*

  Default: 0. Sets the minimal allowed HTLC value for newly created channels.
If you want to change the `htlc_minimum_msat` for existing channels, use the
RPC call lightning-setchannel(7).

* **htlc-maximum-msat**=*MILLISATOSHI*

  Default: unset (no limit). Sets the maximum allowed HTLC value for newly created
channels. If you want to change the `htlc_maximum_msat` for existing channels,
use the RPC call lightning-setchannel(7).

* **announce-addr-discovered**=*BOOL*

  Explicitly control the usage of discovered public IPs in `node_announcement` updates.
  Default: 'auto' - Only if we don't have anything else to announce.
  Note: You also need to open TCP port 9735 on your router towords your node.
  Note: Will always be disabled if you use 'always-use-proxy'.

* **announce-addr-discovered-port**=*PORT*
  Sets the public TCP port to use for announcing dynamically discovered IPs.
  If unset, this defaults to the selected networks lightning port,
  which is 9735 on mainnet.

### Lightning channel and HTLC options

* **large-channels** (deprecated in v23.11)

  As of v23.11, this is the default (and thus, the option is ignored).  Previously if you didn't specify this, channel sizes were limited to 16777215 satoshi.  Note: this option is spelled **large-channels** but it's pronounced **wumbo**.

* **watchtime-blocks**=*BLOCKS*

  How long we need to spot an outdated close attempt: on opening a channel
we tell our peer that this is how long they'll have to wait if they
perform a unilateral close.

* **max-locktime-blocks**=*BLOCKS*

  The longest our funds can be delayed (ie. the longest
**watchtime-blocks** our peer can ask for, and also the longest HTLC
timeout we will accept). If our peer asks for longer, we'll refuse to
create a channel, and if an HTLC asks for longer, we'll refuse it.

* **funding-confirms**=*BLOCKS*

  Confirmations required for the funding transaction when the other side
opens a channel before the channel is usable.

* **commit-fee**=*PERCENT*

  The percentage of *estimatesmartfee 2/CONSERVATIVE* to use for the commitment
transactions: default is 100.

* **commit-feerate-offset**=*INTEGER*

  The additional feerate a channel opener adds to their preferred feerate to
lessen the odds of a disconnect due to feerate disagreement (default 5).

* **max-concurrent-htlcs**=*INTEGER*

  Number of HTLCs one channel can handle concurrently in each direction.
Should be between 1 and 483 (default 30).

* **max-dust-htlc-exposure-msat**=*MILLISATOSHI*

  Option which limits the total amount of sats to be allowed as dust on a channel.

* **cltv-delta**=*BLOCKS*

  The number of blocks between incoming payments and outgoing payments:
this needs to be enough to make sure that if we have to, we can close
the outgoing payment before the incoming, or redeem the incoming once
the outgoing is redeemed.

* **cltv-final**=*BLOCKS*

  The number of blocks to allow for payments we receive: if we have to, we
might need to redeem this on-chain, so this is the number of blocks we
have to do that.

* **accept-htlc-tlv-type**=*types*

  Normally HTLC onions which contain unknown even fields are rejected.
This option specifies that this type is to be accepted, and ignored.  Can be
specified multuple times. (Added in v23.08).

* **min-emergency-msat**=*msat*

  This is the amount of funds to keep in the wallet to close anchor channels (which don't carry their own transaction fees).  It defaults to 25000sat, and is only maintained if there are any anchor channels (or, when opening an anchor channel).  This amount may be insufficient for multiple closes at once, however.
  

### Cleanup control options:

* **autoclean-cycle**=*SECONDS* [plugin `autoclean`, *dynamic*]

  Perform search for things to clean every *SECONDS* seconds (default
3600, or 1 hour, which is usually sufficient).

* **autoclean-succeededforwards-age**=*SECONDS* [plugin `autoclean`, *dynamic*]

  How old successful forwards (`settled` in listforwards `status`) have to be before deletion (default 0, meaning never).

* **autoclean-failedforwards-age**=*SECONDS* [plugin `autoclean`, *dynamic*]

  How old failed forwards (`failed` or `local_failed` in listforwards `status`) have to be before deletion (default 0, meaning never).

* **autoclean-succeededpays-age**=*SECONDS* [plugin `autoclean`, *dynamic*]

  How old successful payments (`complete` in listpays `status`) have to be before deletion (default 0, meaning never).

* **autoclean-failedpays-age**=*SECONDS* [plugin `autoclean`, *dynamic*]

  How old failed payment attempts (`failed` in listpays `status`) have to be before deletion (default 0, meaning never).

* **autoclean-paidinvoices-age**=*SECONDS* [plugin `autoclean`, *dynamic*]

  How old invoices which were paid (`paid` in listinvoices `status`) have to be before deletion (default 0, meaning never).

* **autoclean-expiredinvoices-age**=*SECONDS* [plugin `autoclean`, *dynamic*]

  How old invoices which were not paid (and cannot be) (`expired` in listinvoices `status`) before deletion (default 0, meaning never).

Note: prior to v22.11, forwards for channels which were closed were
not easily distinguishable.  As a result, autoclean may delete more
than one of these at once, and then suffer failures when it fails to
delete the others.

### Payment and invoice control options:

* **disable-mpp** [plugin `pay`]

  Disable the multi-part payment sending support in the `pay` plugin. By default
the MPP support is enabled, but it can be desirable to disable in situations
in which each payment should result in a single HTLC being forwarded in the
network.

* **invoices-onchain-fallback**

  Add a (taproot) fallback address to invoices produced by the `invoice`
command, so they invoices can also be paid onchain.

### Networking options

Note that for simple setups, the implicit *autolisten* option does the
right thing: for the mainnet (bitcoin) network it will try to bind to
port 9735 on IPv4 and IPv6, and will announce it to peers if it seems
like a public address (and other default ports for other networks,
as described below).

Core Lightning also support IPv4/6 address discovery behind NAT routers.
If your node detects an new public address, it will update its announcement.
For this to work you need to forward the default TCP port 9735 to your node.
IP discovery is only active if no other addresses are announced.

You can instead use *addr* to override this (eg. to change the port), or
precisely control where to bind and what to announce with the
*bind-addr* and *announce-addr* options. These will **disable** the
*autolisten* logic, so you must specifiy exactly what you want!

* **addr**=*\[IPADDRESS\[:PORT\]\]|autotor:TORIPADDRESS\[:SERVICEPORT\]\[/torport=TORPORT\]|statictor:TORIPADDRESS\[:SERVICEPORT\]\[/torport=TORPORT\]\[/torblob=\[blob\]\]|HOSTNAME\[:PORT\]*

  Set an IP address (v4 or v6) or automatic Tor address to listen on and
(maybe) announce as our node address.

  An empty 'IPADDRESS' is a special value meaning bind to IPv4 and/or
IPv6 on all interfaces, '0.0.0.0' means bind to all IPv4
interfaces, '::' means 'bind to all IPv6 interfaces' (if you want to
specify an IPv6 address *and* a port, use `[]` around the IPv6
address, like `[::]:9750`).
  If 'PORT' is not specified, the default port 9735 is used for mainnet
(testnet: 19735, signet: 39735, regtest: 19846).
If we can determine a public IP address from the resulting binding,
the address is announced.

  If the argument begins with 'autotor:' then it is followed by the
IPv4 or IPv6 address of the Tor control port (default port 9051),
and this will be used to configure a Tor hidden service for port 9735
in case of mainnet (bitcoin) network whereas other networks (testnet,
signet, regtest) will set the same default ports they use for non-Tor
addresses (see above).
The Tor hidden service will be configured to point to the
first IPv4 or IPv6 address we bind to and is by default unique to
your node's id.

  If the argument begins with 'statictor:' then it is followed by the
IPv4 or IPv6 address of the Tor control port (default port 9051),
and this will be used to configure a static Tor hidden service.
You can add the text '/torblob=BLOB' followed by up to
64 Bytes of text to generate from this text a v3 onion service
address text unique to the first 32 Byte of this text.
You can also use an postfix '/torport=TORPORT' to select the external
tor binding. The result is that over tor your node is accessible by a port
defined by you and possibly different from your local node port assignment.

  This option can be used multiple times to add more addresses, and
its use disables autolisten.  If necessary, and 'always-use-proxy'
is not specified, a DNS lookup may be done to resolve `HOSTNAME` or `TORIPADDRESS'`.

  If `HOSTNAME` was given that resolves to a local interface, the daemon
will bind to that interface.

* **bind-addr**=*\[IPADDRESS\[:PORT\]\]|SOCKETPATH|HOSTNAME\[:PORT\]*

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

  If a HOSTNAME was given and `always-use-proxy` is not specified,
a DNS lookup may be done to resolve it and bind to a local interface (if found).

* **announce-addr**=*IPADDRESS\[:PORT\]|TORADDRESS.onion\[:PORT\]|dns:HOSTNAME\[:PORT\]*

  Set an IP (v4 or v6) address or Tor address to announce; a Tor address
is distinguished by ending in *.onion*. *PORT* defaults to 9735.

  Empty or wildcard IPv4 and IPv6 addresses don't make sense here.
Also, unlike the 'addr' option, there is no checking that your
announced addresses are public (e.g. not localhost).

  This option can be used multiple times to add more addresses, and
its use disables autolisten.

  Since v23.058, the `dns:` prefix can be used to indicate that this hostname and port should be announced as a DNS hostname entry.  Please note that most mainnet nodes do not yet use, read or propagate this information correctly.

* **announce-addr-dns**=*BOOL* (deprecated in v23.08)

  When set to *true* (default is *false*), prefixes all `HOSTNAME` in **announce-addr** with `dns:`.

* **offline**

  Do not bind to any ports, and do not try to reconnect to any peers. This
can be useful for maintenance and forensics, so is usually specified on
the command line. Overrides all *addr* and *bind-addr* options.

* **autolisten**=*BOOL*

  By default, we bind (and maybe announce) on IPv4 and IPv6 interfaces if
no *addr*, *bind-addr* or *announce-addr* options are specified. Setting
this to *false* disables that.

* **proxy**=*IPADDRESS\[:PORT\]*

  Set a socks proxy to use to connect to Tor nodes (or for all connections
if **always-use-proxy** is set).  The port defaults to 9050 if not specified.

* **always-use-proxy**=*BOOL*

  Always use the **proxy**, even to connect to normal IP addresses (you
can still connect to Unix domain sockets manually). This also disables
all DNS lookups, to avoid leaking information.

* **disable-dns**

  Disable the DNS bootstrapping mechanism to find a node by its node ID.

* **tor-service-password**=*PASSWORD*

  Set a Tor control password, which may be needed for *autotor:* to
authenticate to the Tor control port.

* **clnrest-port**=*PORT* [plugin `clnrest.py`]

  Sets the REST server port to listen to (3010 is common).  If this is not specified, the clnrest.py plugin will be disabled.

* **clnrest-protocol**=*PROTOCOL* [plugin `clnrest.py`]

  Specifies the REST server protocol. Default is HTTPS.

* **clnrest-host**=*HOST* [plugin `clnrest.py`]

  Defines the REST server host. Default is 127.0.0.1.

* **clnrest-certs**=*PATH*  [plugin `clnrest.py`]

  Defines the path for HTTPS cert & key. Default path is same as RPC file path to utilize gRPC's client certificate. If it is missing at the configured location, new identity (`client.pem` and `client-key.pem`) will be generated.

* **clnrest-cors-origins**=*CORSORIGINS*  [plugin `clnrest.py`]

  Define multiple origins which are allowed to share resources on web pages to a domain different from the one that served the web page. Default is `*` which allows all origins.

* **clnrest-csp**=*CSPOLICY*  [plugin `clnrest.py`]

  Creates a whitelist of trusted content sources that can run on a webpage and helps mitigate the risk of attacks. Default CSP is `default-src 'self'; font-src 'self'; img-src 'self' data:; frame-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';`.

### Lightning Plugins

lightningd(8) supports plugins, which offer additional configuration
options and JSON-RPC methods, depending on the plugin. Some are supplied
by default (usually located in **libexec/c-lightning/plugins/**). If a
**plugins** directory exists under *lightning-dir* that is searched for
plugins along with any immediate subdirectories). You can specify
additional paths too:

* **plugin**=*PATH*

  Specify a plugin to run as part of Core Lightning. This can be specified
multiple times to add multiple plugins.  Note that unless plugins themselves
specify ordering requirements for being called on various hooks, plugins will
be ordered by commandline, then config file.

* **plugin-dir**=*DIRECTORY*

  Specify a directory to look for plugins; all executable files not
containing punctuation (other than *.*, *-* or *\_) in 'DIRECTORY* are
loaded. *DIRECTORY* must exist; this can be specified multiple times to
add multiple directories.  The ordering of plugins within a directory
is currently unspecified.

* **clear-plugins**

  This option clears all *plugin*, *important-plugin*, and *plugin-dir* options
preceeding it,
including the default built-in plugin directory. You can still add
*plugin-dir*, *plugin*, and *important-plugin* options following this
and they will have the normal effect.

* **disable-plugin**=*PLUGIN*

  If *PLUGIN* contains a /, plugins with the same path as *PLUGIN* will
not be loaded at startup. Otherwise, no plugin with that base name will
be loaded at startup, whatever directory it is in.  This option is useful for
disabling a single plugin inside a directory.  You can still explicitly
load plugins which have been disabled, using lightning-plugin(7) `start`.

* **important-plugin**=*PLUGIN*

  Speciy a plugin to run as part of Core Lightning.
This can be specified multiple times to add multiple plugins.
Plugins specified via this option are considered so important, that if the
plugin stops for any reason (including via lightning-plugin(7) `stop`),
Core Lightning will also stop running.
This way, you can monitor crashes of important plugins by simply monitoring
if Core Lightning terminates.
Built-in plugins, which are installed with lightningd(8), are automatically
considered important.

### Experimental Options

Experimental options are subject to breakage between releases: they
are made available for advanced users who want to test proposed
features.

* **experimental-onion-messages**

  Specifying this enables sending, forwarding and receiving onion messages,
which are in draft status in the [bolt][bolt] specifications (PR #759).
This is automatically enabled by `experimental-offers`.

* **experimental-offers**

  Specifying this enables the `offers` and `fetchinvoice` plugins and
corresponding functionality, which are in draft status ([bolt][bolt] #798) as [bolt12][bolt12], as well as `experimental-onion-messages`.

* **fetchinvoice-noconnect**

  Specifying this prevents `fetchinvoice` and `sendinvoice` from
trying to connect directly to the offering node as a last resort.

* **experimental-shutdown-wrong-funding**

  Specifying this allows the `wrong_funding` field in _shutdown: if a
remote node has opened a channel but claims it used the incorrect txid
(and the channel hasn't been used yet at all) this allows them to
negotiate a clean shutdown with the txid they offer ([#4421][pr4421]).

* **experimental-dual-fund**

  Specifying this enables support for the dual funding protocol ([bolt][bolt] #851),
allowing both parties to contribute funds to a channel. The decision
about whether to add funds or not to a proposed channel is handled
automatically by a plugin that implements the appropriate logic for
your needs. The default behavior is to not contribute funds.

* **experimental-splicing**

  Specifying this enables support for the splicing protocol ([bolt][bolt] #863),
allowing both parties to dynamically adjust the size a channel. These changes
can be built interactively using PSBT and combined with other channel actions
including dual fund, additional channel splices, or generic transaction activity.
The operations will be bundled into a single transaction. The channel will remain
active while awaiting splice confirmation, however you can only spend the smaller
of the prior channel balance and the new one.

* **experimental-websocket-port**=*PORT* (deprecated in v23.08)

  Specifying this enables support for accepting incoming WebSocket
connections on that port, on any IPv4 and IPv6 addresses you listen
to ([bolt][bolt] #891).  The normal protocol is expected to be sent over WebSocket binary
frames once the connection is upgraded.

  You should use `bind=ws::<portnum>` instead to create a WebSocket listening port.

* **experimental-peer-storage**

  Specifying this option means we will store up to 64k of encrypted
data for our peers, and give them our (encrypted!) backup data to
store as well, based on a protocol similar to [bolt][bolt] #881.

* **experimental-quiesce**

  Specifying this option advertizes `option_quiesce`.  Not very useful
by itself, except for testing.

* **experimental-upgrade-protocol**

  Specifying this option means we send (and allow receipt of) a simple
protocol to update channel types.  At the moment, we only support setting
`option_static_remotekey` to ancient channels.  The peer must also support
this option.


* **experimental-anchors**

  Specifying this option turns on the `option_anchors_zero_fee_htlc_tx`
feature, meaning we can open anchor-based channels.  This will become
the default for new channels in future, after more testing.  Anchor-based
channels use larger commitment transactions, with the trade-off that they
don't have to use a worst-case fee, but can bump the commitment transaction
if it's needed.  Note that this means that we need to keep
some funds aside: see `min-emergency-msat`.

BUGS
----

You should report bugs on our github issues page, and maybe submit a fix
to gain our eternal gratitude!

AUTHOR
------

Rusty Russell <<rusty@rustcorp.com.au>> wrote this man page, and
much of the configuration language, but many others did the hard work of
actually implementing these options.

SEE ALSO
--------

lightning-listconfigs(7) lightning-setchannel(7) lightningd(8)
lightning-hsmtool(8)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

COPYING
-------

Note: the modules in the ccan/ directory have their own licenses, but
the rest of the code is covered by the BSD-style MIT license.

[bolt]: https://github.com/lightning/bolts
[bolt12]: https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md
[pr4421]: https://github.com/ElementsProject/lightning/pull/4421
