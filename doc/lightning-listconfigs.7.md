lightning-listconfigs -- Command to list all configuration options.
================================================================

SYNOPSIS
--------

**listconfigs** \[config\]

DESCRIPTION
-----------

The **listconfigs** RPC command to list all configuration options, or with *config*, just that one.

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

On success, an object is returned with members reflecting the
corresponding lightningd-config(5) options which were specified in
the configuration file(s) and command line.

Additional members include:

- *# version*: Version of lightningd software that is currently running.
- *plugins*: A array of the non-important plugin currently running. Each object contains the following members:
   - *path*: Path of the plugin executable.
   - *name*: The plugin name.
   - *options*: A object that contains all options accepted from command line or configuration file, if the plugin has opitions
- *important-plugins*: An array of the important plugins currently running. Each object contains the same members as the *plugin* array.

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
