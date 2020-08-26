lightning-listconfigs -- Command to list all configuration options.
================================================================

SYNOPSIS
--------

**listconfigs** \[config\]

DESCRIPTION
-----------

The **listconfigs** teh RPC command to list all configuration options, or with *config*, just that one.

EXAMPLE JSON REQUEST
--------------------

```json
{
  "id": 82,
  "method": "listconfigs",
  "params": {}
}
```

RETURN VALUE
------------

On success, an object with the following proprieties is returned:

- *# version*: A string that rappresents the version of node.
- *lightning-di*: A string that rappresents the work dir of the node.
- *network*: A string that rappresents the network (e.g: bitcoin).
- *allow-deprecated-apis*: A boolean value that rappresent if the deprecated api are avaible on the node.
- *rpc-file*: A string that rappresent the location of the rpc file.
- *plugins*: A array that rappresent the no important plugin registered. Each object contains the following proprieties:
   - *path*: A string that rappresent the path of plugin.
   - *name*: A string that rappresent the name of plugin.
   - *options*: A object that contains all options accepted from comand line, if the plugin accepted parameters from command line.
- *important-plugins*: An array that rappresent all important pluging registered to the node. Each object contains the same proprieties of *plugin* array.
- *disable-plugin*: An array of string that rappresent the name of plugin disabled.
- *always-use-proxy*: A boolean value that rappresent if the node utilize always the proxy.
- *daemon*: A boolean value is the node have the daemon propriety enabled.
- *wallet*: A string that rappresent the location of wallet with database url convention.
- *wumbo*: A boolean value that rappresent the value of wumbo propriety.
- *rgb*: A string that rappresent the color of the node.
- *alias*: A string that rappresent the alias of the node.
- *pid-file*: A string that rappresent the location of the pid file.
- *ignore-fee-limits*: A boolean value that rappresent is the node ignore the fee limit.
- *watchtime-blocks*: An integer that rappresent the watchtime of the blocks.
- *max-locktime-blocks*: A integer that rappresent that max locktime for blocks.
- *funding-confirms*: An integer that rappresent the number of funding transaction confermation.
- *commit-fee-min*: A integer that rappresent the minimum commit fee.
- *commit-fee-max*: A integer that rappresent the maximum commit fee.
- *cltv-delta*: An integer that rappresent the value of cltv delta.
- *cltv-final*: An integer that rappresent the value of cltv final.
- *commit-time*: An integer that rappresent the value of commit time.
- *fee-base*: A integer that rappresent the value of fee base.
- *rescan*: A integer that rappresent the number of block that the node must rescan before to run.
- *fee-per-satoshi*: An integer that rappresent the fee for satoshi.
- *max-concurrent-htlcs*: A integer that rappresent the number of HTLCs one channel can handle concurrently in each direction.
- *min-capacity-sat*: A integer that rappresent the minimal effective channel capacity in satoshi to accept for channel opening requests.
- *addr*: A string that rappresent the address where the node are listen.
- *bind-addr*: A string that rappresent the address or UNIX domine socket where the node are listen.
- *announce-addr*: A string that rappresent the address where the node is annunced.
- *offline*: A boolean value that rappresent if the node is offline.
- *autolisten*: A boolean value that rappresent if the autolisten is enabled.
- *proxy*: A string that rappresent the proxy address.
- *disable-dns*: A boolean value that rappresent if the dns is disabled.
- *enable-autotor-v2-mode*: A boolean value that rappresent if the Tor v2 is enabled.
- *encrypted-hsm*: A boolean value that rappresent if the wallet is encrypted. 
- *rpc-file-mode*: A string that rappresent the value rpc-file-mode.
- *log-level*: A string that rappresent the level of log.
- *log-prefix*: A string that rappresent the log prefix.
On failure, one of the following error codes may be returned:

- -32602. Error in given parameters or field with *config* name doesn't exist.

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

lightning-getinfo(7)

RESOURCES
---------

Main web site: <https://github.com/ElementsProject/lightning>
