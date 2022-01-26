lightning-listconfigs -- Command to list all configuration options.
================================================================

SYNOPSIS
--------

**listconfigs** [*config*]

DESCRIPTION
-----------

The **listconfigs** RPC command to list all configuration options, or with *config*, just that one.

The returned values reflect the current configuration, including
showing default values (`dev-` options are not shown).

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
- **# version** (string, optional): Special field indicating the current version
- **plugins** (array of objects, optional):
  - **path** (string): Full path of the plugin
  - **name** (string): short name of the plugin
  - **options** (object, optional): Specific options set for this plugin:
- **important-plugins** (array of objects, optional):
  - **path** (string): Full path of the plugin
  - **name** (string): short name of the plugin
  - **options** (object, optional): Specific options set for this plugin:
- **conf** (string, optional): `conf` field from cmdline, or default
- **lightning-dir** (string, optional): `lightning-dir` field from config or cmdline, or default
- **network** (string, optional): `network` field from config or cmdline, or default
- **allow-deprecated-apis** (boolean, optional): `allow-deprecated-apis` field from config or cmdline, or default
- **rpc-file** (string, optional): `rpc-file` field from config or cmdline, or default
- **disable-plugin** (array of strings, optional):
  - `disable-plugin` field from config or cmdline
- **always-use-proxy** (boolean, optional): `always-use-proxy` field from config or cmdline, or default
- **daemon** (boolean, optional): `daemon` field from config or cmdline, or default
- **wallet** (string, optional): `wallet` field from config or cmdline, or default
- **large-channels** (boolean, optional): `large-channels` field from config or cmdline, or default
- **experimental-dual-fund** (boolean, optional): `experimental-dual-fund` field from config or cmdline, or default
- **experimental-onion-messages** (boolean, optional): `experimental-onion-messages` field from config or cmdline, or default
- **experimental-offers** (boolean, optional): `experimental-offers` field from config or cmdline, or default
- **experimental-shutdown-wrong-funding** (boolean, optional): `experimental-shutdown-wrong-funding` field from config or cmdline, or default
- **experimental-websocket-port** (u16, optional): `experimental-websocket-port` field from config or cmdline, or default
- **rgb** (hex, optional): `rgb` field from config or cmdline, or default (always 6 characters)
- **alias** (string, optional): `alias` field from config or cmdline, or default
- **pid-file** (string, optional): `pid-file` field from config or cmdline, or default
- **ignore-fee-limits** (boolean, optional): `ignore-fee-limits` field from config or cmdline, or default
- **watchtime-blocks** (u32, optional): `watchtime-blocks` field from config or cmdline, or default
- **max-locktime-blocks** (u32, optional): `max-locktime-blocks` field from config or cmdline, or default
- **funding-confirms** (u32, optional): `funding-confirms` field from config or cmdline, or default
- **cltv-delta** (u32, optional): `cltv-delta` field from config or cmdline, or default
- **cltv-final** (u32, optional): `cltv-final` field from config or cmdline, or default
- **commit-time** (u32, optional): `commit-time` field from config or cmdline, or default
- **fee-base** (u32, optional): `fee-base` field from config or cmdline, or default
- **rescan** (integer, optional): `rescan` field from config or cmdline, or default
- **fee-per-satoshi** (u32, optional): `fee-per-satoshi` field from config or cmdline, or default
- **max-concurrent-htlcs** (u32, optional): `max-concurrent-htlcs` field from config or cmdline, or default
- **max-dust-htlc-exposure-msat** (msat, optional): `max-dust-htlc-exposure-mast` field from config or cmdline, or default
- **min-capacity-sat** (u64, optional): `min-capacity-sat` field from config or cmdline, or default
- **addr** (string, optional): `addr` field from config or cmdline (can be more than one)
- **announce-addr** (string, optional): `announce-addr` field from config or cmdline (can be more than one)
- **bind-addr** (string, optional): `bind-addr` field from config or cmdline (can be more than one)
- **offline** (boolean, optional): `true` if `offline` was set in config or cmdline
- **autolisten** (boolean, optional): `autolisten` field from config or cmdline, or default
- **proxy** (string, optional): `proxy` field from config or cmdline, or default
- **disable-dns** (boolean, optional): `true` if `disable-dns` was set in config or cmdline
- **encrypted-hsm** (boolean, optional): `true` if `encrypted-hsm` was set in config or cmdline
- **rpc-file-mode** (string, optional): `rpc-file-mode` field from config or cmdline, or default
- **log-level** (string, optional): `log-level` field from config or cmdline, or default
- **log-prefix** (string, optional): `log-prefix` field from config or cmdline, or default
- **log-file** (string, optional): `log-file` field from config or cmdline, or default
- **log-timestamps** (boolean, optional): `log-timestamps` field from config or cmdline, or default
- **force-feerates** (string, optional): force-feerate configuration setting, if any
- **subdaemon** (string, optional): `subdaemon` fields from config or cmdline if any (can be more than one)
- **fetchinvoice-noconnect** (boolean, optional): `featchinvoice-noconnect` fileds from config or cmdline, or default
- **tor-service-password** (string, optional): `tor-service-password` field from config or cmdline, if any

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
   "wumbo": false,
   "wumbo": false,
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
   "enable-autotor-v2-mode": "false",
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
[comment]: # ( SHA256STAMP:59b197ad256bd701744ed5aa9f663166e48ef6320cf3a1538af0bd855daa3186)
