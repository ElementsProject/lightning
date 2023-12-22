---
title: "Wallet recovery"
slug: "recovery"
excerpt: "Learn about various recovery methods."
hidden: false
---


## Recovery


### Using `emergency.recover`

  - Copy the valid binary formatted `hsm_secret` into `$LIGHTNINGDIR` directory
  - Copy the latest `emergency.recover` backup file into the `$LIGHTNINGDIR` before starting up the node
  - Start `lightningd`
  - Run `lightning-cli emergencyrecover` (RPC command)[https://docs.corelightning.org/reference/lightning-emergencyrecover] to recover all the channels on the node
  - Wait until your peer force closes the channel and the node would automatically sweep the funds. This could take some time


### Using `--recover` flag

  - Copy the latest `emergency.recover` backup file into the `$LIGHTNINGDIR` before starting up the node
  - Start `lightningd --recover=<codex32secret>`. It will automatically generate your node's hsm_secret using the codex32 secret
  - The node will initiate in offline mode. As a result, it won't establish connections with peers automatically
  - Restart `lightningd`
  - Run `lightning-cli emergencyrecover` (RPC command)[https://docs.corelightning.org/reference/lightning-emergencyrecover] to recover all the channels on the node


> 🚧 
>
> **Only** recover from database if you are sure that it is **latest**.
>
> Snapshot-style backups of the lightningd database is **discouraged**, as _any_ loss of state may result in permanent loss of funds. 
>
> See the  [penalty mechanism](https://github.com/lightning/bolts/blob/master/05-onchain.md#revoked-transaction-close-handling) for more details.


### Using database

If you already have **latest** wallet backup and hsm_secret, it is technically not recovery. It is similar to restarting your lightning node.

  - Copy the DB backup `lightningd.sqlite3` from your NFS backup directory into `$LIGHTNINGDIR` directory
  - Either copy the valid binary formatted `hsm_secret` into `$LIGHTNINGDIR` directory and start `lightningd`
  - Or start lightningd with recover flag (`lightningd --recover=<codex32secret>`)
  - Note that `emergency.recover` backup file is not required here but you can copy it into `$LIGHTNINGDIR` directory (if exists)
