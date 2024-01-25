lightning-listconfigs -- Command to list all configuration options.
================================================================

SYNOPSIS
--------

**listconfigs** [*config*]

DESCRIPTION
-----------

*config* (optional) is a configuration option name to restrict return.

The **listconfigs** RPC command to list all configuration options, or with *config* only one.

The returned values reflect the current configuration, including
showing default values (`dev-` options are not shown unless specified as *config* explicitly).

Note: as plugins can add options, not all configuration settings are
listed here!  The format of each entry is as follows:

- **source** (string): source of configuration setting (`file`:`linenum`)
- **dynamic** (boolean, optional): true if this option is settable via setconfig
- **plugin** (string, optional): set if this is from a plugin

Depending on the option type, exactly one of the following is present:

- **set** (boolean, optional): for simple flag options
- **value\_str** (string, optional): for string options
- **value\_msat** (msat, optional): for msat options
- **value\_int** (integer, optional): for integer options
- **value\_bool** (boolean, optional): for boolean options

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": 82,
  "method": "listconfigs",
  "params": {
    "config": "network"
  }
}
```

RETURN VALUE
------------

[comment]: # (GENERATE-FROM-SCHEMA-START)
On success, an object is returned, containing:

- **configs** (object, optional) *(added v23.08)*:
  - **conf** (object, optional):
    - **value\_str** (string): field from cmdline
    - **source** (string): source of configuration setting (always "cmdline")
  - **developer** (object, optional) *(added v23.08)*:
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **clear-plugins** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **disable-mpp** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
    - **plugin** (string, optional): plugin which registered this configuration setting
  - **mainnet** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **regtest** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **signet** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **testnet** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **important-plugin** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **plugin** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **plugin-dir** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **lightning-dir** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **network** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default (can also be changed by `testnet`, `signet`, `regtest` options!)
    - **source** (string): source of configuration setting
  - **allow-deprecated-apis** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **rpc-file** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **disable-plugin** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **always-use-proxy** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **daemon** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **wallet** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **large-channels** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-dual-fund** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-splicing** (object, optional) *(added v23.08)*:
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-onion-messages** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-offers** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-shutdown-wrong-funding** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-websocket-port** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **experimental-peer-storage** (object, optional) *(added v23.02)*:
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **experimental-anchors** (object, optional) *(added v23.08)*:
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **database-upgrade** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **rgb** (object, optional):
    - **value\_str** (hex): field from config or cmdline, or default (always 6 characters)
    - **source** (string): source of configuration setting
  - **alias** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **pid-file** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **ignore-fee-limits** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **watchtime-blocks** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **max-locktime-blocks** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **funding-confirms** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **cltv-delta** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **cltv-final** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **commit-time** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **fee-base** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **rescan** (object, optional):
    - **value\_int** (integer): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **fee-per-satoshi** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **max-concurrent-htlcs** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **htlc-minimum-msat** (object, optional):
    - **value\_msat** (msat): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **htlc-maximum-msat** (object, optional):
    - **value\_msat** (msat): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **max-dust-htlc-exposure-msat** (object, optional):
    - **value\_msat** (msat): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **min-capacity-sat** (object, optional):
    - **value\_int** (u64): field from config or cmdline, or default
    - **source** (string): source of configuration setting
    - **dynamic** (boolean, optional): Can this be set by setconfig() (always *true*)
  - **addr** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **announce-addr** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **bind-addr** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **offline** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **autolisten** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **proxy** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **disable-dns** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **announce-addr-discovered** (object, optional) *(added v23.02)*:
    - **value\_str** (string): field from config or cmdline, or default (one of "true", "false", "auto")
    - **source** (string): source of configuration setting
  - **announce-addr-discovered-port** (object, optional) *(added v23.02)*:
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **encrypted-hsm** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **rpc-file-mode** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **log-level** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **log-prefix** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **log-file** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **log-timestamps** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **force-feerates** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **subdaemon** (object, optional):
    - **values\_str** (array of strings):
      - field from config or cmdline
    - **sources** (array of strings):
      - source of configuration setting
  - **fetchinvoice-noconnect** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline
    - **source** (string): source of configuration setting
  - **accept-htlc-tlv-types** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **tor-service-password** (object, optional):
    - **value\_str** (string): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **announce-addr-dns** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **require-confirmed-inputs** (object, optional):
    - **value\_bool** (boolean): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **commit-fee** (object, optional):
    - **value\_int** (u64): field from config or cmdline, or default
    - **source** (string): source of configuration setting
  - **commit-feerate-offset** (object, optional):
    - **value\_int** (u32): field from config or cmdline, or default
    - **source** (string): source of configuration setting
- **# version** (string, optional): Special field indicating the current version **deprecated, removal in v24.05**
- **plugins** (array of objects, optional) **deprecated, removal in v24.05**:
  - **path** (string): Full path of the plugin
  - **name** (string): short name of the plugin
  - **options** (object, optional): Specific options set for this plugin:
- **important-plugins** (array of objects, optional) **deprecated, removal in v24.05**:
  - **path** (string): Full path of the plugin
  - **name** (string): short name of the plugin
  - **options** (object, optional): Specific options set for this plugin:
- **conf** (string, optional): `conf` field from cmdline, or default **deprecated, removal in v24.05**
- **lightning-dir** (string, optional): `lightning-dir` field from config or cmdline, or default **deprecated, removal in v24.05**
- **network** (string, optional): `network` field from config or cmdline, or default **deprecated, removal in v24.05**
- **allow-deprecated-apis** (boolean, optional): `allow-deprecated-apis` field from config or cmdline, or default **deprecated, removal in v24.05**
- **rpc-file** (string, optional): `rpc-file` field from config or cmdline, or default **deprecated, removal in v24.05**
- **disable-plugin** (array of strings, optional) **deprecated, removal in v24.05**:
  - `disable-plugin` field from config or cmdline
- **bookkeeper-dir** (string, optional): `bookkeeper-dir` field from config or cmdline, or default **deprecated, removal in v24.05**
- **bookkeeper-db** (string, optional): `bookkeeper-db` field from config or cmdline, or default **deprecated, removal in v24.05**
- **always-use-proxy** (boolean, optional): `always-use-proxy` field from config or cmdline, or default **deprecated, removal in v24.05**
- **daemon** (boolean, optional): `daemon` field from config or cmdline, or default **deprecated, removal in v24.05**
- **wallet** (string, optional): `wallet` field from config or cmdline default **deprecated, removal in v24.05**
- **large-channels** (boolean, optional): `large-channels` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-dual-fund** (boolean, optional): `experimental-dual-fund` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-splicing** (boolean, optional): `experimental-splicing` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-onion-messages** (boolean, optional): `experimental-onion-messages` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-offers** (boolean, optional): `experimental-offers` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-shutdown-wrong-funding** (boolean, optional): `experimental-shutdown-wrong-funding` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-websocket-port** (u16, optional): `experimental-websocket-port` field from config or cmdline, or default **deprecated, removal in v24.05**
- **experimental-peer-storage** (boolean, optional): `experimental-peer-storage` field from config or cmdline, or default **deprecated, removal in v24.05** *(added v23.02)*
- **experimental-quiesce** (boolean, optional): `experimental-quiesce` field from config or cmdline, or default **deprecated, removal in v24.05** *(added v23.08)*
- **experimental-upgrade-protocol** (boolean, optional): `experimental-upgrade-protocol` field from config or cmdline, or default **deprecated, removal in v24.05** *(added v23.08)*
- **invoices-onchain-fallback** (boolean, optional): `invoices-onchain-fallback` field from config or cmdline, or default *(added v23.11)*
- **database-upgrade** (boolean, optional): `database-upgrade` field from config or cmdline **deprecated, removal in v24.05**
- **rgb** (hex, optional): `rgb` field from config or cmdline, or default (always 6 characters) **deprecated, removal in v24.05**
- **alias** (string, optional): `alias` field from config or cmdline, or default **deprecated, removal in v24.05**
- **pid-file** (string, optional): `pid-file` field from config or cmdline, or default **deprecated, removal in v24.05**
- **ignore-fee-limits** (boolean, optional): `ignore-fee-limits` field from config or cmdline, or default **deprecated, removal in v24.05**
- **watchtime-blocks** (u32, optional): `watchtime-blocks` field from config or cmdline, or default **deprecated, removal in v24.05**
- **max-locktime-blocks** (u32, optional): `max-locktime-blocks` field from config or cmdline, or default **deprecated, removal in v24.05**
- **funding-confirms** (u32, optional): `funding-confirms` field from config or cmdline, or default **deprecated, removal in v24.05**
- **cltv-delta** (u32, optional): `cltv-delta` field from config or cmdline, or default **deprecated, removal in v24.05**
- **cltv-final** (u32, optional): `cltv-final` field from config or cmdline, or default **deprecated, removal in v24.05**
- **commit-time** (u32, optional): `commit-time` field from config or cmdline, or default **deprecated, removal in v24.05**
- **fee-base** (u32, optional): `fee-base` field from config or cmdline, or default **deprecated, removal in v24.05**
- **rescan** (integer, optional): `rescan` field from config or cmdline, or default **deprecated, removal in v24.05**
- **fee-per-satoshi** (u32, optional): `fee-per-satoshi` field from config or cmdline, or default **deprecated, removal in v24.05**
- **max-concurrent-htlcs** (u32, optional): `max-concurrent-htlcs` field from config or cmdline, or default **deprecated, removal in v24.05**
- **htlc-minimum-msat** (msat, optional): `htlc-minimum-msat` field from config or cmdline, or default **deprecated, removal in v24.05**
- **htlc-maximum-msat** (msat, optional): `htlc-maximum-msat` field from config or cmdline, or default **deprecated, removal in v24.05**
- **max-dust-htlc-exposure-msat** (msat, optional): `max-dust-htlc-exposure-mast` field from config or cmdline, or default **deprecated, removal in v24.05**
- **min-capacity-sat** (u64, optional): `min-capacity-sat` field from config or cmdline, or default **deprecated, removal in v24.05**
- **addr** (string, optional): `addr` field from config or cmdline (can be more than one) **deprecated, removal in v24.05**
- **announce-addr** (string, optional): `announce-addr` field from config or cmdline (can be more than one) **deprecated, removal in v24.05**
- **bind-addr** (string, optional): `bind-addr` field from config or cmdline (can be more than one) **deprecated, removal in v24.05**
- **offline** (boolean, optional): `true` if `offline` was set in config or cmdline **deprecated, removal in v24.05**
- **autolisten** (boolean, optional): `autolisten` field from config or cmdline, or default **deprecated, removal in v24.05**
- **proxy** (string, optional): `proxy` field from config or cmdline, or default **deprecated, removal in v24.05**
- **disable-dns** (boolean, optional): `true` if `disable-dns` was set in config or cmdline **deprecated, removal in v24.05**
- **announce-addr-discovered** (string, optional): `true`/`false`/`auto` depending on how `announce-addr-discovered` was set in config or cmdline **deprecated, removal in v24.05** *(added v23.02)*
- **announce-addr-discovered-port** (integer, optional): Sets the announced TCP port for dynamically discovered IPs. **deprecated, removal in v24.05** *(added v23.02)*
- **encrypted-hsm** (boolean, optional): `true` if `encrypted-hsm` was set in config or cmdline **deprecated, removal in v24.05**
- **rpc-file-mode** (string, optional): `rpc-file-mode` field from config or cmdline, or default **deprecated, removal in v24.05**
- **log-level** (string, optional): `log-level` field from config or cmdline, or default **deprecated, removal in v24.05**
- **log-prefix** (string, optional): `log-prefix` field from config or cmdline, or default **deprecated, removal in v24.05**
- **log-file** (string, optional): `log-file` field from config or cmdline, or default **deprecated, removal in v24.05**
- **log-timestamps** (boolean, optional): `log-timestamps` field from config or cmdline, or default **deprecated, removal in v24.05**
- **force-feerates** (string, optional): force-feerate configuration setting, if any **deprecated, removal in v24.05**
- **subdaemon** (string, optional): `subdaemon` fields from config or cmdline if any (can be more than one) **deprecated, removal in v24.05**
- **fetchinvoice-noconnect** (boolean, optional): `fetchinvoice-noconnect` fields from config or cmdline, or default **deprecated, removal in v24.05**
- **accept-htlc-tlv-types** (string, optional): `accept-htlc-tlv-types` field from config or cmdline, or not present **deprecated, removal in v24.05**
- **tor-service-password** (string, optional): `tor-service-password` field from config or cmdline, if any **deprecated, removal in v24.05**
- **dev-allowdustreserve** (boolean, optional): Whether we allow setting dust reserves **deprecated, removal in v24.05**
- **announce-addr-dns** (boolean, optional): Whether we put DNS entries into node\_announcement **deprecated, removal in v24.05** *(added v22.11.1)*
- **require-confirmed-inputs** (boolean, optional): Request peers to only send confirmed inputs (dual-fund only) **deprecated, removal in v24.05**
- **developer** (boolean, optional): Whether developer mode is enabled *(added v23.08)*
- **commit-fee** (u64, optional): The percentage of the 6-block fee estimate to use for commitment transactions **deprecated, removal in v24.05** *(added v23.05)*
- **min-emergency-msat** (msat, optional): field from config or cmdline, or default *(added v23.08)*
- **commit-feerate-offset** (u32, optional): additional commitment feerate applied by channel owner *(added v23.11)*

[comment]: # (GENERATE-FROM-SCHEMA-END)


On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or field with *config* name doesn't exist.

EXAMPLE JSON RESPONSE
---------------------

```json
{
   "# version": "v0.9.0-1",
   "lightning-dir": "/media/vincent/Maxtor/sanboxTestWrapperRPC/lightning_dir_dev",
   "network": "testnet",
   "allow-deprecated-apis": true,
   "rpc-file": "lightning-rpc",
   "plugins": [
      {
         "path": "/home/vincent/Github/plugins/sauron/sauron.py",
         "name": "sauron.py",
         "options": {
            "sauron-api-endpoint": "http://blockstream.info/testnet/api/",
            "sauron-tor-proxy": ""
         }
      },
      {
         "path": "/home/vincent/Github/reckless/reckless.py",
         "name": "reckless.py"
      }
   ],
   "important-plugins": [
      {
         "path": "/home/vincent/Github/lightning/lightningd/../plugins/autoclean",
         "name": "autoclean",
         "options": {
            "autocleaninvoice-cycle": null,
            "autocleaninvoice-expired-by": null
         }
      },
      {
         "path": "/home/vincent/Github/lightning/lightningd/../plugins/fundchannel",
         "name": "fundchannel"
      },
      {
         "path": "/home/vincent/Github/lightning/lightningd/../plugins/keysend",
         "name": "keysend"
      },
      {
         "path": "/home/vincent/Github/lightning/lightningd/../plugins/pay",
         "name": "pay",
         "options": {
            "disable-mpp": false
         }
      }
   ],
   "important-plugin": "/home/vincent/Github/lightning/lightningd/../plugins/autoclean",
   "important-plugin": "/home/vincent/Github/lightning/lightningd/../plugins/fundchannel",
   "important-plugin": "/home/vincent/Github/lightning/lightningd/../plugins/keysend",
   "important-plugin": "/home/vincent/Github/lightning/lightningd/../plugins/pay",
   "plugin": "/home/vincent/Github/plugins/sauron/sauron.py",
   "plugin": "/home/vincent/Github/reckless/reckless.py",
   "disable-plugin": [
      "bcli"
   ],
   "always-use-proxy": false,
   "daemon": "false",
   "wallet": "sqlite3:///media/vincent/Maxtor/sanboxTestWrapperRPC/lightning_dir_dev/testnet/lightningd.sqlite3",
   "wumbo": true,
   "rgb": "03ad98",
   "alias": "BRUCEWAYN-TES-DEV",
   "pid-file": "/media/vincent/Maxtor/sanboxTestWrapperRPC/lightning_dir_dev/lightningd-testne...",
   "ignore-fee-limits": true,
   "watchtime-blocks": 6,
   "max-locktime-blocks": 2016,
   "funding-confirms": 1,
   "commit-fee-min": 0,
   "commit-fee-max": 0,
   "cltv-delta": 6,
   "cltv-final": 10,
   "commit-time": 10,
   "fee-base": 1,
   "rescan": 30,
   "fee-per-satoshi": 10,
   "max-concurrent-htlcs": 483,
   "min-capacity-sat": 10000,
   "addr": "autotor:127.0.0.1:9051",
   "bind-addr": "127.0.0.1:9735",
   "announce-addr": "fp463inc4w3lamhhduytrwdwq6q6uzugtaeapylqfc43agrdnnqsheyd.onion:9735",
   "offline": "false",
   "autolisten": true,
   "proxy": "127.0.0.1:9050",
   "disable-dns": "false",
   "encrypted-hsm": false,
   "rpc-file-mode": "0600",
   "log-level": "DEBUG",
   "log-prefix": "lightningd",
}

```

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page, but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-getinfo(7), lightningd-config(5)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>

[comment]: # ( SHA256STAMP:cbd485cba5ad5295f6d47bb612b2ce51ad94f07f3bbf2e1db4cd9f5d45ecb6e3)
