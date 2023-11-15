---
title: "Backup and recovery"
slug: "backup-and-recovery"
excerpt: "Learn the various backup and recovery options available for your Core Lightning node."
hidden: false
createdAt: "2022-11-18T16:28:17.292Z"
updatedAt: "2023-04-22T12:51:49.775Z"
---

In Lightning, since _you_ are the only one storing all your financial information, you **_cannot_** recover this financial information from anywhere else.This means that on Lightning, **you have to** responsibly back up your financial information yourself, using various processes and automation.

The discussion below assumes that you know the location of your `$LIGHTNINGDIR`, and you know the directory structure within. By default your `$LIGHTNINGDIR` will be `~/.lightning/${COIN}`. For example, if you are running `--mainnet`, `$LIGHTNINGDIR` will be  `~/.lightning/bitcoin`.


## Backup

Core Lightning has an internal bitcoin wallet and you can backup three main components from the wallet:
- HSM Secret: On-chain funds are backed up via the HD wallet seed, stored in byte-form as hsm_secret
- Static Channel: Lightning channel states to recover are stored in a file named `emergency.recover`
- Database: Detailed information for funds locked in channels are stored in the database


### HSM Secret Backup


> 📘 Who should do this:
> 
> Everyone.


> 🚧 
> 
> Recovery of the `hsm_secret` is sufficient to recover any onchain funds.
> 
> Recovery of the `hsm_secret` is necessary, but insufficient, to recover any in-channel funds.  
>
> The `hsm_secret` is highly confidential, and its loss could lead to the theft of your funds. Therefore, it is crucial to ensure that 
it is kept in a secure location.


The `hsm_secret` is created when you first create the node, and does not change. Thus, a one-time backup of `hsm_secret` is sufficient. 
It should be noted down a few times on a piece of paper, in either hexadecimal or codex32 format, as described below:


#### Hex Format

The secret is just 32 bytes, and can be converted into hexadecimal digits like below:

```shell
cd $LIGHTNINGDIR
xxd hsm_secret
```

To convert above hex back into the binary `hsm_secret` (32 bytes format) for recovery, you can re-enter the hexdump into a text file and use `xxd`:

```
cat > hsm_secret_hex.txt <<HEX
00: 30cc f221 94e1 7f01 cd54 d68c a1ba f124
10: e1f3 1d45 d904 823c 77b7 1e18 fd93 1676
HEX
xxd -r hsm_secret_hex.txt > hsm_secret
chmod 0400 hsm_secret
```


#### Codex32 Format

Run `tools/hsmtool getcodexsecret <hsm/secret/path> <id>` to get the `hsm_secret` in codex32 format.

Example `tools/hsmtool getcodexsecret ~/.lightning/bitcoin/hsm_secret adt0`.

`hsm/secret/path` in the above command is `$LIGHTNINGDIR/hsm_secret`, and
`id` is any 4 character string used to identify this secret. It **cannot** contain `i`, `o`, or `b`, but **can** contain all digits except `1`.

Click [here](doc:hsm-secret) to learn more about other cool hsm methods.


### Static Channel Backup


> 📘 Who should do this:
> 
> Those who already have at least one channel.


> 🚧 
>
> It's important to note that static channel recovery requires cooperation with peers and should only be used as a last resort to retrieve coins that are stuck in a channel. 


This feature allows users to get the static channel backup in the form of `emergency.recover` file located in the `$LIGHTNINGDIR`. 

This file gets updated each time you open a new channel. Therefore, it's recommended that you backup this file whenever a new channel is opened.


### Database Backup


> 📘 Who should do this:
> 
> Casual users.


> 🚧 
>
> Snapshot-style backups of the lightningd database is **discouraged**, as _any_ loss of state may result in permanent loss of funds. 
>
> See the  [penalty mechanism](https://github.com/lightning/bolts/blob/master/05-onchain.md#revoked-transaction-close-handling) for more information on why any amount of state-loss results in fund loss.


lightningd also stores detailed information of funds locked in Lightning Network channels in a database. This database is required for on-going channel updates as well as channel closure. There is no single-seed backup for funds locked in channels. 

Real-time database replication is the recommended approach to backing up node data. Tools for replication are currently in active development, using the db write plugin hook.

Click [here](doc:advanced-db-backup) to learn more about advanced DB backup methods.
