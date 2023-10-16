---
title: "Configuring your node"
slug: "configuration"
excerpt: "Choose from a variety of configuration options as per your needs."
hidden: false
createdAt: "2022-11-18T14:32:13.821Z"
updatedAt: "2023-02-21T13:26:18.280Z"
---
`lightningd` can be configured either by passing options via the command line, or via a configuration file.

## Using a configuration file

To use a configuration file, create a file named `config` within your top-level lightning directory or network subdirectory (eg. `~/.lightning/config` or `~/.lightning/bitcoin/config`).

When `lightningd` starts up it usually reads a general configuration file (default: `$HOME/.lightning/config`) then a network-specific configuration file (default: `$HOME/.lightning/testnet/config`).  This can be changed using `--conf` and `--lightning-dir`.

> 📘 
> 
> General configuration files are processed first, then network-specific ones, then command line options: later options override earlier ones except _addr_ options and _log-level_ with subsystems, which accumulate.

`include` followed by a filename includes another configuration file at that point, relative to the current configuration file.

All options listed below are mirrored as commandline arguments to lightningd(, so `--foo` becomes simply `foo` in the configuration file, and `--foo=bar` becomes `foo=bar` in the configuration file.

Blank lines and lines beginning with `#` are ignored.

## Debugging

`--help` will show you the defaults for many options; they vary with network settings so you can specify `--network` before `--help` to see the defaults for that network.

The [`lightning-listconfigs`](ref:lightning-listconfigs) command will output a valid configuration file using the current settings.

## Options

### General options

- **allow-deprecated-apis**=_BOOL_

    Enable deprecated options, JSONRPC commands, fields, etc. It defaults to  
  _true_, but you should set it to _false_ when testing to ensure that an  
  upgrade won't break your configuration.

- **help**

    Print help and exit. Not very useful inside a configuration file, but  
  fun to put in other's config files while their computer is unattended.

- **version**

    Print version and exit. Also useless inside a configuration file, but  
  putting this in someone's config file may convince them to read this man  
  page.

- **database-upgrade**=_BOOL_

    Upgrades to Core Lightning often change the database: once this is done,  
  downgrades are not generally possible.  By default, Core Lightning will  
  exit with an error rather than upgrade, unless this is an official released  
  version.  If you really want to upgrade to a non-release version, you can  
  set this to _true_ (or _false_ to never allow a non-reversible upgrade!).

### Bitcoin control options:

**network**=_NETWORK_

- Select the network parameters (_bitcoin_, _testnet_, _signet_, or _regtest_).  
  This is not valid within the per-network configuration file.

- **mainnet**

  Alias for _network=bitcoin_.

- **testnet**

  Alias for _network=testnet_.

- **signet**

  Alias for _network=signet_.

- **bitcoin-cli**=_PATH_ [plugin `bcli`]

  The name of _bitcoin-cli_ executable to run.

- **bitcoin-datadir**=_DIR_ [plugin `bcli`]

  _-datadir_ argument to supply to bitcoin-cli(1).

- **bitcoin-rpcuser**=_USER_ [plugin `bcli`]

  The RPC username for talking to bitcoind(1).

- **bitcoin-rpcpassword**=_PASSWORD_ [plugin `bcli`]

  The RPC password for talking to bitcoind(1).

- **bitcoin-rpcconnect**=_HOST_ [plugin `bcli`]

  The bitcoind(1) RPC host to connect to.

- **bitcoin-rpcport**=_PORT_ [plugin `bcli`]

  The bitcoind(1) RPC port to connect to.

- **bitcoin-retry-timeout**=_SECONDS_ [plugin `bcli`]

  Number of seconds to keep trying a bitcoin-cli(1) command. If the  
  command keeps failing after this time, exit with a fatal error.

- **rescan**=_BLOCKS_

  Number of blocks to rescan from the current head, or absolute  
  blockheight if negative. This is only needed if something goes badly  
  wrong.

### Lightning daemon options

- **lightning-dir**=_DIR_

  Sets the working directory. All files (except _--conf_ and  
  _--lightning-dir_ on the command line) are relative to this.  This  
  is only valid on the command-line, or in a configuration file specified  
  by _--conf_.

- **subdaemon**=_SUBDAEMON_:_PATH_

  Specifies an alternate subdaemon binary.  
  Current subdaemons are _channeld_, _closingd_,  
  _connectd_, _gossipd_, _hsmd_, _onchaind_, and _openingd_.  
  If the supplied path is relative the subdaemon binary is found in the  
  working directory. This option may be specified multiple times.

  So, **subdaemon=hsmd:remote\_signer** would use a  
  hypothetical remote signing proxy instead of the standard _lightning\_hsmd_  
  binary.

- **pid-file**=_PATH_

  Specify pid file to write to.

- **log-level**=_LEVEL_\[:_SUBSYSTEM_\]

  What log level to print out: options are io, debug, info, unusual, broken.  If _SUBSYSTEM_ is supplied, this sets the logging level for any subsystem (or _nodeid_) containing that string. This option may be specified multiple times. Subsystems include:

  - _lightningd_: The main lightning daemon

  - _database_: The database subsystem

  - _wallet_: The wallet subsystem

  - _gossipd_: The gossip daemon

  - _plugin-manager_: The plugin subsystem

  - _plugin-P_: Each plugin, P = plugin path without directory

  - _hsmd_: The secret-holding daemon

  - _connectd_: The network connection daemon

  - _jsonrpc#FD_: Each JSONRPC connection, FD = file descriptor number

  The following subsystems exist for each channel, where N is an incrementing internal integer id assigned for the lifetime of the channel:

  - _openingd-chan#N_: Each opening / idling daemon

  - _channeld-chan#N_: Each channel management daemon

  - _closingd-chan#N_: Each closing negotiation daemon

  - _onchaind-chan#N_: Each onchain close handling daemon

  So, **log-level=debug:plugin** would set debug level logging on all plugins and the plugin manager.  **log-level=io:chan#55** would set IO logging on channel number 55 (or 550, for that matter).

  **log-level=debug:024b9a1fa8** would set debug logging for that channel (or any node id containing that string).

- **log-prefix**=_PREFIX_

  Prefix for all log lines: this can be customized if you want to merge logs with multiple daemons.  Usually you want to include a space at the end of _PREFIX_, as the timestamp follows immediately.

- **log-file**=_PATH_

  Log to this file (instead of stdout).  If you specify this more than once you'll get more than one log file: **-** is used to mean stdout.  Sending lightningd(8) SIGHUP will cause it to reopen each file (useful for log rotation).

- **log-timestamps**=_BOOL_

  Set this to false to turn off timestamp prefixes (they will still appear in crash log files).

- **rpc-file**=_PATH_

  Set JSON-RPC socket (or /dev/tty), such as for lightning-cli.

- **rpc-file-mode**=_MODE_

  Set JSON-RPC socket file mode, as a 4-digit octal number.  
  Default is 0600, meaning only the user that launched lightningd can command it.  
  Set to 0660 to allow users with the same group to access the RPC as well.

- **daemon**

  Run in the background, suppress stdout and stderr.  Note that you need to specify **log-file** for this case.

- **conf**=_PATH_

  Sets configuration file, and disable reading the normal general and network ones. If this is a relative path, it is relative to the starting directory, not **lightning-dir** (unlike other paths). _PATH_ must exist and be readable (we allow missing files in the default case). Using this inside a configuration file is invalid.

- **wallet**=_DSN_

  Identify the location of the wallet. This is a fully qualified data source name, including a scheme such as `sqlite3` or `postgres` followed by the connection parameters.

  The default wallet corresponds to the following DSN:  
    `--wallet=sqlite3://$HOME/.lightning/bitcoin/lightningd.sqlite31`

  For the `sqlite3` scheme, you can specify a single backup database file by separating it with a `:` character, like so:  `--wallet=sqlite3://$HOME/.lightning/bitcoin/lightningd.sqlite3:/backup/lightningd.sqlite3`

  The following is an example of a postgresql wallet DSN:

    `--wallet=postgres://user:pass@localhost:5432/db_name`

  This will connect to a DB server running on `localhost` port `5432`, authenticate with username `user` and password `pass`, and then use the database `db_name`. The database must exist, but the schema will be managed automatically by `lightningd`.

- **bookkeeper-dir**=_DIR_ [plugin `bookkeeper`]

  Directory to keep the accounts.sqlite3 database file in. Defaults to lightning-dir.

- **bookkeeper-db**=_DSN_ [plugin `bookkeeper`]

  Identify the location of the bookkeeper data. This is a fully qualified data source name, including a scheme such as `sqlite3` or `postgres` followed by the connection parameters. Defaults to `sqlite3://accounts.sqlite3` in the `bookkeeper-dir`.

- **encrypted-hsm**  
  If set, you will be prompted to enter a password used to encrypt the `hsm_secret`.  
  Note that once you encrypt the `hsm_secret` this option will be mandatory for  
  `lightningd` to start.  
  If there is no `hsm_secret` yet, `lightningd` will create a new encrypted secret.  
  If you have an unencrypted `hsm_secret` you want to encrypt on-disk, or vice versa,  
  see [`lightning-hsmtool`](ref:lightning-hsmtool).

- **grpc-port**=_portnum_ [plugin `cln-grpc`]

  The port number for the GRPC plugin to listen for incoming connections; default is not to activate the plugin at all.

### Lightning node customization options

- **alias**=_NAME_

  Up to 32 bytes of UTF-8 characters to tag your node. Completely silly, since anyone can call their node anything they want. The default is an NSA-style codename derived from your public key, but "Peter Todd" and "VAULTERO" are good options, too.

- **rgb**=_RRGGBB_

  Your favorite color as a hex code.

- **fee-base**=_MILLISATOSHI_

  Default: 1000. The base fee to charge for every payment which passes through. Note that millisatoshis are a very, very small unit! Changing this value will only affect new channels and not existing ones. If you want to change fees for existing channels, use the RPC call [`lightning-setchannel`](ref:lightning-setchannel).

- **fee-per-satoshi**=_MILLIONTHS_

  Default: 10 (0.001%). This is the proportional fee to charge for every payment which passes through. As percentages are too coarse, it's in millionths, so 10000 is 1%, 1000 is 0.1%. Changing this value will only affect new channels and not existing ones. If you want to change fees for existing channels, use the RPC call [`lightning-setchannel`](ref:lightning-setchannel).

- **min-capacity-sat**=_SATOSHI_

  Default: 10000. This value defines the minimal effective channel capacity in satoshi to accept for channel opening requests. This will reject any opening of a channel which can't pass an HTLC of least this value.  Usually this prevents a peer opening a tiny channel, but it  
  can also prevent a channel you open with a reasonable amount and the peer requesting such a large reserve that the capacity of the channel falls below this.

- **ignore-fee-limits**=_BOOL_

  Allow nodes which establish channels to us to set any fee they want. This may result in a channel which cannot be closed, should fees increase, but make channels far more reliable since we never close it due to unreasonable fees.

- **commit-time**=_MILLISECONDS_

  How long to wait before sending commitment messages to the peer: in theory increasing this would reduce load, but your node would have to be extremely busy node for you to even notice.

- **force-feerates**==_VALUES_

  Networks like regtest and testnet have unreliable fee estimates: we usually treat them as the minimum (253 sats/kw) if we can't get them.  
  This allows override of one or more of our standard feerates (see [`lightning-feerates`](ref:lightning-feerates)).  Up to 5 values, separated by '/' can be provided: if fewer are provided, then the final value is used for the remainder.  The values are in per-kw (roughly 1/4 of bitcoind's per-kb values), and the order is "opening", "mutual_close", "unilateral_close", "delayed_to_us", "htlc_resolution", and "penalty".

  You would usually put this option in the per-chain config file, to avoid setting it on Bitcoin mainnet!  e.g. `~rusty/.lightning/regtest/config`.

- **htlc-minimum-msat**=_MILLISATOSHI_

  Default: 0. Sets the minimal allowed HTLC value for newly created channels.  
  If you want to change the `htlc_minimum_msat` for existing channels, use the RPC call [`lightning-setchannel`](ref:lightning-setchannel).

- **htlc-maximum-msat**=_MILLISATOSHI_

  Default: unset (no limit). Sets the maximum allowed HTLC value for newly created channels. If you want to change the `htlc_maximum_msat` for existing channels, use the RPC call [`lightning-setchannel`](ref:lightning-setchannel).

- **disable-ip-discovery**

  Turn off public IP discovery to send `node_announcement` updates that contain the discovered IP with TCP port 9735 as announced address. If unset and you open TCP port 9735 on your router towards your node, your node will remain connectable on changing IP addresses.  Note: Will always be disabled if you use 'always-use-proxy'.

### Lightning channel and HTLC options

- **watchtime-blocks**=_BLOCKS_

  How long we need to spot an outdated close attempt: on opening a channel we tell our peer that this is how long they'll have to wait if they perform a unilateral close.

- **max-locktime-blocks**=_BLOCKS_

  The longest our funds can be delayed (ie. the longest **watchtime-blocks** our peer can ask for, and also the longest HTLC timeout we will accept). If our peer asks for longer, we'll refuse to create a channel, and if an HTLC asks for longer, we'll refuse it.

- **funding-confirms**=_BLOCKS_

  Confirmations required for the funding transaction when the other side opens a channel before the channel is usable.

- **commit-fee**=_PERCENT_ [plugin `bcli`]

  The percentage of _estimatesmartfee 2/CONSERVATIVE_ to use for the commitment  
  transactions: default is 100.

- **max-concurrent-htlcs**=_INTEGER_

  Number of HTLCs one channel can handle concurrently in each direction.  
  Should be between 1 and 483 (default 30).

- **max-dust-htlc-exposure-msat**=_MILLISATOSHI_

  Option which limits the total amount of sats to be allowed as dust on a channel.

- **cltv-delta**=_BLOCKS_

  The number of blocks between incoming payments and outgoing payments: this needs to be enough to make sure that if we have to, we can close the outgoing payment before the incoming, or redeem the incoming once the outgoing is redeemed.

- **cltv-final**=_BLOCKS_

  The number of blocks to allow for payments we receive: if we have to, we might need to redeem this on-chain, so this is the number of blocks we have to do that.

- **accept-htlc-tlv-types**=_types_

  Normally HTLC onions which contain unknown even fields are rejected.  
  This option specifies that these (comma-separated) types are to be  
  accepted, and ignored.

### Cleanup control options:

- **autoclean-cycle**=_SECONDS_ [plugin `autoclean`]

  Perform search for things to clean every _SECONDS_ seconds (default 3600, or 1 hour, which is usually sufficient).

- **autoclean-succeededforwards-age**=_SECONDS_ [plugin `autoclean`]

  How old successful forwards (`settled` in listforwards `status`) have to be before deletion (default 0, meaning never).

- **autoclean-failedforwards-age**=_SECONDS_ [plugin `autoclean`]

  How old failed forwards (`failed` or `local_failed` in listforwards `status`) have to be before deletion (default 0, meaning never).

- **autoclean-succeededpays-age**=_SECONDS_ [plugin `autoclean`]

  How old successful payments (`complete` in listpays `status`) have to be before deletion (default 0, meaning never).

- **autoclean-failedpays-age**=_SECONDS_ [plugin `autoclean`]

  How old failed payment attempts (`failed` in listpays `status`) have to be before deletion (default 0, meaning never).

- **autoclean-paidinvoices-age**=_SECONDS_ [plugin `autoclean`]

  How old invoices which were paid (`paid` in listinvoices `status`) have to be before deletion (default 0, meaning never).

- **autoclean-expiredinvoices-age**=_SECONDS_ [plugin `autoclean`]

  How old invoices which were not paid (and cannot be) (`expired` in listinvoices `status`) before deletion (default 0, meaning never).

Note: prior to v22.11, forwards for channels which were closed were not easily distinguishable.  As a result, autoclean may delete more than one of these at once, and then suffer failures when it fails to delete the others.

### Payment control options:

- **disable-mpp** [plugin `pay`]

  Disable the multi-part payment sending support in the `pay` plugin. By default the MPP support is enabled, but it can be desirable to disable in situations in which each payment should result in a single HTLC being forwarded in the network.

### Networking options

Note that for simple setups, the implicit _autolisten_ option does the right thing: for the mainnet (bitcoin) network it will try to bind to port 9735 on IPv4 and IPv6, and will announce it to peers if it seems like a public address (and other default ports for other networks, as described below).

Core Lightning also support IPv4/6 address discovery behind NAT routers. If your node detects an new public address, it will update its announcement. For this to work you need to forward the default TCP port 9735 to your node. IP discovery is only active if no other addresses are announced.

You can instead use _addr_ to override this (eg. to change the port), or precisely control where to bind and what to announce with the _bind-addr_ and _announce-addr_ options. These will **disable** the _autolisten_ logic, so you must specifiy exactly what you want!

- **addr**=_\[IPADDRESS[:PORT]]|autotor:TORIPADDRESS[:SERVICEPORT][/torport=TORPORT]|statictor:TORIPADDRESS[:SERVICEPORT]\[/torport=TORPORT]\[/torblob=[blob]]|DNS[:PORT]_

  Set an IP address (v4 or v6) or automatic Tor address to listen on and (maybe) announce as our node address.

  An empty 'IPADDRESS' is a special value meaning bind to IPv4 and/or IPv6 on all interfaces, '0.0.0.0' means bind to all IPv4 interfaces, '::' means 'bind to all IPv6 interfaces' (if you want to specify an IPv6 address _and_ a port, use `[]` around the IPv6 address, like `[::]:9750`).  
  If 'PORT' is not specified, the default port 9735 is used for mainnet (testnet: 19735, signet: 39735, regtest: 19846). If we can determine a public IP address from the resulting binding,  
  the address is announced.

  If the argument begins with 'autotor:' then it is followed by the IPv4 or IPv6 address of the Tor control port (default port 9051), and this will be used to configure a Tor hidden service for port 9735 in case of mainnet (bitcoin) network whereas other networks (testnet,  
  signet, regtest) will set the same default ports they use for non-Tor addresses (see above).  
  The Tor hidden service will be configured to point to the first IPv4 or IPv6 address we bind to and is by default unique to your node's id.

  If the argument begins with 'statictor:' then it is followed by the IPv4 or IPv6 address of the Tor control port (default port 9051), and this will be used to configure a static Tor hidden service.  
  You can add the text '/torblob=BLOB' followed by up to 64 Bytes of text to generate from this text a v3 onion service address text unique to the first 32 Byte of this text. You can also use an postfix '/torport=TORPORT' to select the external tor binding. The result is that over tor your node is accessible by a port defined by you and possibly different from your local node port assignment.

This option can be used multiple times to add more addresses, and its use disables autolisten.  If necessary, and 'always-use-proxy' is not specified, a DNS lookup may be done to resolve 'DNS' or 'TORIPADDRESS'.

If a 'DNS' hostname was given that resolves to a local interface, the daemon will bind to that interface: if **announce-addr-dns** is true then it will also announce that as type 'DNS' (rather than announcing the IP address).

- **bind-addr**=_\[IPADDRESS[:PORT]]|SOCKETPATH|DNS[:PORT]|DNS[:PORT]_

  Set an IP address or UNIX domain socket to listen to, but do not announce. A UNIX domain socket is distinguished from an IP address by beginning with a _/_.

  An empty 'IPADDRESS' is a special value meaning bind to IPv4 and/or IPv6 on all interfaces, '0.0.0.0' means bind to all IPv4 interfaces, '::' means 'bind to all IPv6 interfaces'.  'PORT' is  
  not specified, 9735 is used.

  This option can be used multiple times to add more addresses, and its use disables autolisten.  If necessary, and 'always-use-proxy' is not specified, a DNS lookup may be done to resolve 'IPADDRESS'.

  If a 'DNS' hostname was given and 'always-use-proxy' is not specified, a lookup may be done to resolve it and bind to a local interface (if found).

- **announce-addr**=_IPADDRESS\[:PORT\]|TORADDRESS.onion\[:PORT\]|DNS\[:PORT\]_

  Set an IP (v4 or v6) address or Tor address to announce; a Tor address is distinguished by ending in _.onion_. _PORT_ defaults to 9735.

  Empty or wildcard IPv4 and IPv6 addresses don't make sense here.  
  Also, unlike the 'addr' option, there is no checking that your announced addresses are public (e.g. not localhost).

  This option can be used multiple times to add more addresses, and its use disables autolisten.

  Since v22.11 'DNS' hostnames can be used for announcement: see **announce-addr-dns**.

- **announce-addr-dns**=_BOOL_

  Set to _true_ (default is \_false), this so that names given as arguments to **addr** and \_announce-addr\*\* are published in node announcement messages as names, rather than IP addresses.  Please note that most mainnet nodes do not yet use, read or propagate this information correctly.

- **offline**

  Do not bind to any ports, and do not try to reconnect to any peers. This can be useful for maintenance and forensics, so is usually specified on the command line. Overrides all _addr_ and _bind-addr_ options.

- **autolisten**=_BOOL_

  By default, we bind (and maybe announce) on IPv4 and IPv6 interfaces if no _addr_, _bind-addr_ or _announce-addr_ options are specified. Setting this to _false_ disables that.

- **proxy**=_IPADDRESS\[:PORT\]_

  Set a socks proxy to use to connect to Tor nodes (or for all connections if **always-use-proxy** is set).  The port defaults to 9050 if not specified.

- **always-use-proxy**=_BOOL_

  Always use the **proxy**, even to connect to normal IP addresses (you can still connect to Unix domain sockets manually). This also disables all DNS lookups, to avoid leaking information.

- **disable-dns**

  Disable the DNS bootstrapping mechanism to find a node by its node ID.

- **tor-service-password**=_PASSWORD_

  Set a Tor control password, which may be needed for _autotor:_ to authenticate to the Tor control port.

### Lightning Plugins

`lightningd` supports plugins, which offer additional configuration options and JSON-RPC methods, depending on the plugin. Some are supplied by default (usually located in **libexec/c-lightning/plugins/**). If a **plugins** directory exists under _lightning-dir_ that is searched for  
plugins along with any immediate subdirectories). You can specify additional paths too:

- **plugin**=_PATH_

  Specify a plugin to run as part of Core Lightning. This can be specified multiple times to add multiple plugins.  Note that unless plugins themselves specify ordering requirements for being called on various hooks, plugins will be ordered by commandline, then config file.

- **plugin-dir**=_DIRECTORY_

  Specify a directory to look for plugins; all executable files not containing punctuation (other than _._, _-_ or _\_) in 'DIRECTORY_ are loaded. _DIRECTORY_ must exist; this can be specified multiple times to add multiple directories.  The ordering of plugins within a directory is currently unspecified.

- **clear-plugins**

  This option clears all _plugin_, _important-plugin_, and _plugin-dir_ options preceeding it, including the default built-in plugin directory. You can still add _plugin-dir_, _plugin_, and _important-plugin_ options following this and they will have the normal effect.

- **disable-plugin**=_PLUGIN_

  If _PLUGIN_ contains a /, plugins with the same path as _PLUGIN_ will not be loaded at startup. Otherwise, no plugin with that base name will be loaded at startup, whatever directory it is in.  This option is useful for disabling a single plugin inside a directory.  You can still explicitly load plugins which have been disabled, using [lightning-plugin](ref:lightning-plugin) `start`.

- **important-plugin**=_PLUGIN_

  Specify a plugin to run as part of Core Lightning.  
  This can be specified multiple times to add multiple plugins.  
  Plugins specified via this option are considered so important, that if the plugin stops for any reason (including via [lightning-plugin](ref:lightning-plugin) `stop`), Core Lightning will also stop running.  
  This way, you can monitor crashes of important plugins by simply monitoring if Core Lightning terminates.  
  Built-in plugins, which are installed with lightningd, are automatically considered important.

### Experimental Options

Experimental options are subject to breakage between releases: they are made available for advanced users who want to test proposed features. When the build is configured _without_ `--enable-experimental-features`, below options are available but disabled by default.  
Supported features can be listed with `lightningd --list-features-only`

A build _with_ `--enable-experimental-features` flag hard-codes some of below options as enabled, ignoring their command line flag. It may also add support for even more features. The safest way to determine the active configuration is by checking `listconfigs` or by looking at `our_features` (bits) in `getinfo`.

- **experimental-onion-messages**

  Specifying this enables sending, forwarding and receiving onion messages, which are in draft status in the [bolt](https://github.com/lightning/bolts) specifications (PR #759). A build with `--enable-experimental-features` usually enables this via  
  experimental-offers, see below.

- **experimental-offers**

  Specifying this enables the `offers` and `fetchinvoice` plugins and corresponding functionality, which are in draft status [bolt](https://github.com/lightning/bolts)#798 as [bolt12](https://github.com/rustyrussell/lightning-rfc/blob/guilt/offers/12-offer-encoding.md).  
  A build with `--enable-experimental-features` enables this permanently and usually  
  enables experimental-onion-messages as well.

- **fetchinvoice-noconnect**

  Specifying this prevents `fetchinvoice` and `sendinvoice` from trying to connect directly to the offering node as a last resort.

- **experimental-shutdown-wrong-funding**

  Specifying this allows the `wrong_funding` field in \_shutdown: if a remote node has opened a channel but claims it used the incorrect txid (and the channel hasn't been used yet at all) this allows them to negotiate a clean shutdown with the txid they offer #[4421](https://github.com/ElementsProject/lightning/pull/4421).

- **experimental-dual-fund**

  Specifying this enables support for the dual funding protocol ([bolt](https://github.com/lightning/bolts) #851), allowing both parties to contribute funds to a channel. The decision about whether to add funds or not to a proposed channel is handled automatically by a plugin that implements the appropriate logic for your needs. The default behavior is to not contribute funds.

- **experimental-websocket-port**=_PORT_

  Specifying this enables support for accepting incoming WebSocket connections on that port, on any IPv4 and IPv6 addresses you listen to ([bolt](https://github.com/lightning/bolts) #891).  The normal protocol is expected to be sent over WebSocket binary frames once the connection is upgraded.
