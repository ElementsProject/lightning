lightning-listconfigs -- Command to list all configuration options.
===================================================================

SYNOPSIS
--------

**listconfigs** [*config*] 

DESCRIPTION
-----------

The **listconfigs** RPC command to list all configuration options, or with *config* only one.

- **config** (string, optional): Configuration option name to restrict return.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": "example:listconfigs#1",
  "method": "listconfigs",
  "params": {
    "config": "network"
  }
}
{
  "id": "example:listconfigs#2",
  "method": "listconfigs",
  "params": {
    "config": null
  }
}
{
  "id": "example:listconfigs#3",
  "method": "listconfigs",
  "params": {
    "config": "experimental-dual-fund"
  }
}
```

RETURN VALUE
------------

The returned values reflect the current configuration, including showing default values (`dev-` options are not shown unless specified as *config* explicitly).

Note: as plugins can add options, not all configuration settings are listed here! The format of each entry is as follows:

- **source** (string): source of configuration setting (`file`:`linenum`)
- **dynamic** (boolean, optional): true if this option is settable via setconfig
- **plugin** (string, optional): set if this is from a plugin

Depending on the option type, exactly one of the following is present:

- **set** (boolean, optional): for simple flag options
- **value\_str** (string, optional): for string options
- **value\_msat** (msat, optional): for msat options
- **value\_int** (integer, optional): for integer options
- **value\_bool** (boolean, optional): for boolean options
On success, an object is returned, containing:

- **configs** (object, optional) *(added v23.08)*:
  - **conf** (object, optional):
    - **value\_str** (string): Field from cmdline.
    - **source** (string) (always "cmdline"): Source of configuration setting.
  - **developer** (object, optional) *(added v23.08)*:
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **clear-plugins** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **disable-mpp** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
    - **plugin** (string, optional): Plugin which registered this configuration setting.
  - **mainnet** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **regtest** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **signet** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **testnet** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **important-plugin** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **plugin** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **plugin-dir** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **lightning-dir** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **network** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default (can also be changed by `testnet`, `signet`, `regtest` options!).
    - **source** (string): Source of configuration setting.
  - **allow-deprecated-apis** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **rpc-file** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **disable-plugin** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **always-use-proxy** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **daemon** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **wallet** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **large-channels** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-dual-fund** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-splicing** (object, optional) *(added v23.08)*:
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-onion-messages** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-offers** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-shutdown-wrong-funding** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-websocket-port** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **experimental-peer-storage** (object, optional) *(added v23.02)*:
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **experimental-anchors** (object, optional) *(added v23.08)*:
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **database-upgrade** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **rgb** (object, optional):
    - **value\_str** (hex) (always 6 characters): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **alias** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **pid-file** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **ignore-fee-limits** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **watchtime-blocks** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **max-locktime-blocks** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **funding-confirms** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **cltv-delta** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **cltv-final** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **commit-time** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **fee-base** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **rescan** (object, optional):
    - **value\_int** (integer): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **fee-per-satoshi** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **max-concurrent-htlcs** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **htlc-minimum-msat** (object, optional):
    - **value\_msat** (msat): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **htlc-maximum-msat** (object, optional):
    - **value\_msat** (msat): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **max-dust-htlc-exposure-msat** (object, optional):
    - **value\_msat** (msat): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **min-capacity-sat** (object, optional):
    - **value\_int** (u64): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
    - **dynamic** (boolean, optional) (always *true*): Can this be set by setconfig().
  - **addr** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **announce-addr** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **bind-addr** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **offline** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **autolisten** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **proxy** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **disable-dns** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **announce-addr-discovered** (object, optional) *(added v23.02)*:
    - **value\_str** (string) (one of "true", "false", "auto"): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **announce-addr-discovered-port** (object, optional) *(added v23.02)*:
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **encrypted-hsm** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **rpc-file-mode** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **log-level** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **log-prefix** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **log-file** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **log-timestamps** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **force-feerates** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **subdaemon** (object, optional):
    - **values\_str** (array of strings):
      - (string, optional): Field from config or cmdline.
    - **sources** (array of strings):
      - (string, optional): Source of configuration setting.
  - **fetchinvoice-noconnect** (object, optional):
    - **set** (boolean): `true` if set in config or cmdline.
    - **source** (string): Source of configuration setting.
  - **accept-htlc-tlv-types** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **tor-service-password** (object, optional):
    - **value\_str** (string): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **announce-addr-dns** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **require-confirmed-inputs** (object, optional):
    - **value\_bool** (boolean): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **commit-fee** (object, optional):
    - **value\_int** (u64): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
  - **commit-feerate-offset** (object, optional):
    - **value\_int** (u32): Field from config or cmdline, or default.
    - **source** (string): Source of configuration setting.
- **# version** (string, optional): Special field indicating the current version. **deprecated in v23.08, removed after v24.02**
- **plugins** (array of objects, optional) **deprecated in v23.08, removed after v24.02**:
  - **path** (string): Full path of the plugin.
  - **name** (string): Short name of the plugin.
  - **options** (object, optional): Specific options set for this plugin.:
- **important-plugins** (array of objects, optional) **deprecated in v23.08, removed after v24.02**:
  - **path** (string): Full path of the plugin.
  - **name** (string): Short name of the plugin.
  - **options** (object, optional): Specific options set for this plugin.:
- **conf** (string, optional): `conf` field from cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **lightning-dir** (string, optional): `lightning-dir` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **network** (string, optional): `network` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **allow-deprecated-apis** (boolean, optional): `allow-deprecated-apis` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **rpc-file** (string, optional): `rpc-file` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **disable-plugin** (array of strings, optional) **deprecated in v23.08, removed after v24.02**:
  - (string, optional): `disable-plugin` field from config or cmdline.
- **bookkeeper-dir** (string, optional): `bookkeeper-dir` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **bookkeeper-db** (string, optional): `bookkeeper-db` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **always-use-proxy** (boolean, optional): `always-use-proxy` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **daemon** (boolean, optional): `daemon` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **wallet** (string, optional): `wallet` field from config or cmdline default. **deprecated in v23.08, removed after v24.02**
- **large-channels** (boolean, optional): `large-channels` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-dual-fund** (boolean, optional): `experimental-dual-fund` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-splicing** (boolean, optional): `experimental-splicing` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-onion-messages** (boolean, optional): `experimental-onion-messages` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-offers** (boolean, optional): `experimental-offers` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-shutdown-wrong-funding** (boolean, optional): `experimental-shutdown-wrong-funding` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-websocket-port** (u16, optional): `experimental-websocket-port` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **experimental-peer-storage** (boolean, optional): `experimental-peer-storage` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02** *(added v23.02)*
- **experimental-quiesce** (boolean, optional): `experimental-quiesce` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02** *(added v23.08)*
- **experimental-upgrade-protocol** (boolean, optional): `experimental-upgrade-protocol` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02** *(added v23.08)*
- **invoices-onchain-fallback** (boolean, optional): `invoices-onchain-fallback` field from config or cmdline, or default. *(added v23.11)*
- **database-upgrade** (boolean, optional): `database-upgrade` field from config or cmdline. **deprecated in v23.08, removed after v24.02**
- **rgb** (hex, optional) (always 6 characters): `rgb` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **alias** (string, optional): `alias` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **pid-file** (string, optional): `pid-file` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **ignore-fee-limits** (boolean, optional): `ignore-fee-limits` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **watchtime-blocks** (u32, optional): `watchtime-blocks` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **max-locktime-blocks** (u32, optional): `max-locktime-blocks` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **funding-confirms** (u32, optional): `funding-confirms` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **cltv-delta** (u32, optional): `cltv-delta` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **cltv-final** (u32, optional): `cltv-final` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **commit-time** (u32, optional): `commit-time` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **fee-base** (u32, optional): `fee-base` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **rescan** (integer, optional): `rescan` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **fee-per-satoshi** (u32, optional): `fee-per-satoshi` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **max-concurrent-htlcs** (u32, optional): `max-concurrent-htlcs` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **htlc-minimum-msat** (msat, optional): `htlc-minimum-msat` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **htlc-maximum-msat** (msat, optional): `htlc-maximum-msat` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **max-dust-htlc-exposure-msat** (msat, optional): `max-dust-htlc-exposure-mast` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **min-capacity-sat** (u64, optional): `min-capacity-sat` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **addr** (string, optional): `addr` field from config or cmdline (can be more than one). **deprecated in v23.08, removed after v24.02**
- **announce-addr** (string, optional): `announce-addr` field from config or cmdline (can be more than one). **deprecated in v23.08, removed after v24.02**
- **bind-addr** (string, optional): `bind-addr` field from config or cmdline (can be more than one). **deprecated in v23.08, removed after v24.02**
- **offline** (boolean, optional): `true` if `offline` was set in config or cmdline. **deprecated in v23.08, removed after v24.02**
- **autolisten** (boolean, optional): `autolisten` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **proxy** (string, optional): `proxy` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **disable-dns** (boolean, optional): `true` if `disable-dns` was set in config or cmdline. **deprecated in v23.08, removed after v24.02**
- **announce-addr-discovered** (string, optional): `true`/`false`/`auto` depending on how `announce-addr-discovered` was set in config or cmdline. **deprecated in v23.08, removed after v24.02** *(added v23.02)*
- **announce-addr-discovered-port** (integer, optional): Sets the announced TCP port for dynamically discovered IPs. **deprecated in v23.08, removed after v24.02** *(added v23.02)*
- **encrypted-hsm** (boolean, optional): `true` if `encrypted-hsm` was set in config or cmdline. **deprecated in v23.08, removed after v24.02**
- **rpc-file-mode** (string, optional): `rpc-file-mode` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **log-level** (string, optional): `log-level` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **log-prefix** (string, optional): `log-prefix` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **log-file** (string, optional): `log-file` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **log-timestamps** (boolean, optional): `log-timestamps` field from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **force-feerates** (string, optional): Force-feerate configuration setting, if any. **deprecated in v23.08, removed after v24.02**
- **subdaemon** (string, optional): `subdaemon` fields from config or cmdline if any (can be more than one). **deprecated in v23.08, removed after v24.02**
- **fetchinvoice-noconnect** (boolean, optional): `fetchinvoice-noconnect` fields from config or cmdline, or default. **deprecated in v23.08, removed after v24.02**
- **accept-htlc-tlv-types** (string, optional): `accept-htlc-tlv-types` field from config or cmdline, or not present. **deprecated in v23.08, removed after v24.02**
- **tor-service-password** (string, optional): `tor-service-password` field from config or cmdline, if any. **deprecated in v23.08, removed after v24.02**
- **dev-allowdustreserve** (boolean, optional): Whether we allow setting dust reserves. **deprecated in v23.08, removed after v24.02**
- **announce-addr-dns** (boolean, optional): Whether we put DNS entries into node\_announcement. **deprecated in v23.08, removed after v24.02** *(added v22.11.1)*
- **require-confirmed-inputs** (boolean, optional): Request peers to only send confirmed inputs (dual-fund only). **deprecated in v23.08, removed after v24.02**
- **developer** (boolean, optional): Whether developer mode is enabled. *(added v23.08)*
- **commit-fee** (u64, optional): The percentage of the 6-block fee estimate to use for commitment transactions. **deprecated in v23.08, removed after v24.02** *(added v23.05)*
- **min-emergency-msat** (msat, optional): Field from config or cmdline, or default. *(added v23.08)*
- **commit-feerate-offset** (u32, optional): Additional commitment feerate applied by channel owner. *(added v23.11)*

EXAMPLE JSON RESPONSE
---------------------

```json
{
  "#version": "v0.9.0-1",
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
  "important-plugin": "/home/vincent/Github/lightning/lightningd/../plugins/pay",
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
  "log-prefix": "lightningd"
}
{
  "configs": {
    "developer": {
      "set": true,
      "source": "cmdline"
    },
    "lightning-dir": {
      "value_str": "/tmp/ltests-giwf5tc7/test_plugin_start_1/lightning-1/",
      "source": "cmdline"
    },
    "network": {
      "value_str": "regtest",
      "source": "cmdline"
    },
    "testnet": {
      "set": false,
      "source": "default"
    },
    "signet": {
      "set": false,
      "source": "default"
    },
    "mainnet": {
      "set": false,
      "source": "default"
    },
    "regtest": {
      "set": false,
      "source": "default"
    },
    "rpc-file": {
      "value_str": "lightning-rpc",
      "source": "default"
    },
    "allow-deprecated-apis": {
      "value_bool": false,
      "source": "cmdline"
    },
    "plugin": {
      "values_str": [
        "~/lightning/target/debug/examples/cln-plugin-startup"
      ],
      "sources": [
        "cmdline"
      ]
    },
    "plugin-dir": {
      "values_str": [],
      "sources": []
    },
    "clear-plugins": {
      "set": false,
      "source": "default"
    },
    "disable-plugin": {
      "values_str": [],
      "sources": []
    },
    "important-plugin": {
      "values_str": [],
      "sources": []
    },
    "always-use-proxy": {
      "value_bool": false,
      "source": "default"
    },
    "daemon": {
      "set": false,
      "source": "default"
    },
    "experimental-dual-fund": {
      "set": false,
      "source": "default"
    },
    "experimental-splicing": {
      "set": false,
      "source": "default"
    },
    "experimental-onion-messages": {
      "set": false,
      "source": "default"
    },
    "experimental-offers": {
      "set": false,
      "source": "default"
    },
    "experimental-shutdown-wrong-funding": {
      "set": false,
      "source": "default"
    },
    "experimental-peer-storage": {
      "set": false,
      "source": "default"
    },
    "experimental-quiesce": {
      "set": false,
      "source": "default"
    },
    "experimental-anchors": {
      "set": false,
      "source": "default"
    },
    "rgb": {
      "value_str": "0266e4",
      "source": "default"
    },
    "alias": {
      "value_str": "JUNIORBEAM-1-102-g7549e10-modded",
      "source": "default"
    },
    "pid-file": {
      "value_str": "/tmp/ltests-giwf5tc7/test_plugin_start_1/lightning-1/lightningd-regtest.pid",
      "source": "default"
    },
    "ignore-fee-limits": {
      "value_bool": false,
      "source": "cmdline"
    },
    "watchtime-blocks": {
      "value_int": 5,
      "source": "cmdline"
    },
    "max-locktime-blocks": {
      "value_int": 2016,
      "source": "default"
    },
    "funding-confirms": {
      "value_int": 1,
      "source": "default"
    },
    "require-confirmed-inputs": {
      "value_bool": false,
      "source": "default"
    },
    "cltv-delta": {
      "value_int": 6,
      "source": "cmdline"
    },
    "cltv-final": {
      "value_int": 5,
      "source": "cmdline"
    },
    "commit-time": {
      "value_int": 10,
      "source": "default"
    },
    "fee-base": {
      "value_int": 1,
      "source": "default"
    },
    "rescan": {
      "value_int": 1,
      "source": "cmdline"
    },
    "fee-per-satoshi": {
      "value_int": 10,
      "source": "default"
    },
    "htlc-minimum-msat": {
      "value_msat": 0,
      "source": "default"
    },
    "htlc-maximum-msat": {
      "value_msat": 18446744073709552000,
      "source": "default"
    },
    "max-concurrent-htlcs": {
      "value_int": 483,
      "source": "default"
    },
    "max-dust-htlc-exposure-msat": {
      "value_msat": 50000000,
      "source": "default"
    },
    "min-capacity-sat": {
      "value_int": 10000,
      "source": "default",
      "dynamic": true
    },
    "addr": {
      "values_str": [
        "127.0.0.1:33157"
      ],
      "sources": [
        "cmdline"
      ]
    },
    "bind-addr": {
      "values_str": [],
      "sources": []
    },
    "announce-addr": {
      "values_str": [],
      "sources": []
    },
    "announce-addr-discovered": {
      "value_str": "auto",
      "source": "default"
    },
    "announce-addr-discovered-port": {
      "value_int": 19846,
      "source": "default"
    },
    "offline": {
      "set": false,
      "source": "default"
    },
    "autolisten": {
      "value_bool": false,
      "source": "default"
    },
    "accept-htlc-tlv-type": {
      "values_int": [],
      "sources": []
    },
    "disable-dns": {
      "set": true,
      "source": "cmdline"
    },
    "encrypted-hsm": {
      "set": false,
      "source": "default"
    },
    "rpc-file-mode": {
      "value_str": "0600",
      "source": "default"
    },
    "commit-fee": {
      "value_int": 100,
      "source": "default"
    },
    "commit-feerate-offset": {
      "value_int": 5,
      "source": "default"
    },
    "min-emergency-msat": {
      "value_msat": 25000000,
      "source": "default"
    },
    "subdaemon": {
      "values_str": [],
      "sources": []
    },
    "experimental-upgrade-protocol": {
      "set": false,
      "source": "default"
    },
    "invoices-onchain-fallback": {
      "set": false,
      "source": "default"
    },
    "log-level": {
      "value_str": "debug",
      "source": "cmdline"
    },
    "log-timestamps": {
      "value_bool": true,
      "source": "default"
    },
    "log-prefix": {
      "value_str": "lightningd-1 ",
      "source": "cmdline"
    },
    "log-file": {
      "values_str": [
        "-",
        "/tmp/ltests-giwf5tc7/test_plugin_start_1/lightning-1/log"
      ],
      "sources": [
        "cmdline",
        "cmdline"
      ]
    },
    "dev-no-plugin-checksum": {
      "set": true,
      "source": "cmdline"
    },
    "dev-no-reconnect": {
      "set": true,
      "source": "cmdline"
    },
    "dev-fail-on-subdaemon-fail": {
      "set": true,
      "source": "cmdline"
    },
    "dev-bitcoind-poll": {
      "value_int": 1,
      "source": "cmdline"
    },
    "dev-fast-gossip": {
      "set": true,
      "source": "cmdline"
    },
    "renepay-debug-mcf": {
      "set": false,
      "source": "default",
      "plugin": "~/lightning/plugins/cln-renepay"
    },
    "renepay-debug-payflow": {
      "set": false,
      "source": "default",
      "plugin": "~/lightning/plugins/cln-renepay"
    },
    "test-option": {
      "value_int": 31337,
      "source": "cmdline",
      "plugin": "~/lightning/target/debug/examples/cln-plugin-startup"
    },
    "bitcoin-datadir": {
      "value_str": "/tmp/ltests-giwf5tc7/test_plugin_start_1/lightning-1/",
      "source": "cmdline",
      "plugin": "~/lightning/plugins/bcli"
    },
    "bitcoin-rpcuser": {
      "value_str": "rpcuser",
      "source": "cmdline",
      "plugin": "~/lightning/plugins/bcli"
    },
    "bitcoin-rpcpassword": {
      "value_str": "rpcpass",
      "source": "cmdline",
      "plugin": "~/lightning/plugins/bcli"
    },
    "bitcoin-rpcport": {
      "value_int": 51309,
      "source": "cmdline",
      "plugin": "~/lightning/plugins/bcli"
    },
    "disable-mpp": {
      "set": false,
      "source": "default",
      "plugin": "~/lightning/plugins/pay"
    }
  }
}
{
  "configs": {
    "experimental-dual-fund": {
      "set": false,
      "source": "default"
    }
  }
}
```

ERRORS
------

On failure, one of the following error codes may be returned:

- -32602: Error in given parameters or field with *config* name doesn't exist.

AUTHOR
------

Vincenzo Palazzo <<vincenzo.palazzo@protonmail.com>> wrote the initial version of this man page,
but many others did the hard work of actually implementing this rpc command.

SEE ALSO
--------

lightning-getinfo(7), lightningd-config(5)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
