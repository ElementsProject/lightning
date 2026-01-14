---
title: Backup your wallet
slug: backup
content:
  excerpt: Learn the various backup options available for your Core Lightning node.
privacy:
  view: public
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


#### Mnemonic Format (v25.12+)

Starting with Core Lightning v25.12, new nodes are created with a BIP39 12-word mnemonic phrase as their root secret. By default, **no passphrase is used**. You can optionally protect your mnemonic with a passphrase for additional security by starting `lightningd` with the `--hsm-passphrase` option.

**Backing up your mnemonic:**

The **best way to back up your mnemonic** is to use `lightning-hsmtool getsecret`:

```shell
lightning-hsmtool getsecret $LIGHTNINGDIR/hsm_secret
```

This will output your 12-word mnemonic. Write it down on paper and store it securely. **Important:** If you used a passphrase when creating your node, you must back it up separately along with your mnemonic, as both are required to recover your funds.

**Alternative: Creating your own mnemonic before first start**

If you prefer to use your own mnemonic instead of having `lightningd` generate a random one, create the `hsm_secret` manually before starting your node for the first time:

```shell
lightning-hsmtool generatehsm $LIGHTNINGDIR/hsm_secret
```

This will prompt you to enter your mnemonic (12 words) and an optional passphrase. If you choose to use a passphrase, you must start `lightningd` with the `--hsm-passphrase` option to provide it.

**Alternative: Using `exposesecret`**

If your node was already created (with a randomly-generated mnemonic) and you did **not** use a passphrase (`--hsm-passphrase`), you can extract the mnemonic using the `exposesecret` RPC command:

```shell
lightning-cli exposesecret passphrase=<your-exposesecret-passphrase>
```

Note: This requires setting `exposesecret-passphrase` in your config. This is a separate security measure for the `exposesecret` command itself, not related to the HSM passphrase. **`exposesecret` does not work if your `hsm_secret` uses a passphrase** - it only works with non-passphrase-protected secrets.

**Recovery with mnemonic:**

For v25.12+ nodes, you can use the `recover` RPC command to recover directly from your mnemonic:

```shell
lightning-cli recover hsmsecret="word1 word2 word3 ... word12"
```

Alternatively, you can manually recreate the `hsm_secret` file using `lightning-hsmtool generatehsm`:

```shell
lightning-hsmtool generatehsm $LIGHTNINGDIR/hsm_secret
```

The command will prompt you to:
1. Enter your backed-up mnemonic words (12 words, separated by spaces)
2. Enter your passphrase (if you used one, or press Enter if you didn't)

Then start `lightningd` normally (with `--hsm-passphrase` if you used a passphrase).


#### Readable Format

Run `tools/lightning-hsmtool getsecret <hsm/secret/path>` to get the `hsm_secret` in readable format. For v25.12+ nodes, this returns the 12-word mnemonic. For older nodes, you will get a codex32 string instead, and must supply a four-letter id to attach to it, like so:

Example for newer nodes: `tools/lightning-hsmtool getsecret ~/.lightning/bitcoin/hsm_secret`

Example for older nodes: `tools/lightning-hsmtool getsecret ~/.lightning/bitcoin/hsm_secret adt0`.

`hsm/secret/path` in the above command is `$LIGHTNINGDIR/hsm_secret`, and
`id` is any 4 character string used to identify this secret. It **cannot** contain `i`, `o`, or `b`, but **can** contain all digits except `1`.

**Recovery with codex32 (legacy nodes):**

Legacy nodes can recover using the `recover` RPC command with a codex32 secret:

```shell
lightning-cli recover hsmsecret=<codex32secret>
```

Click [here](doc:hsm-secret) to learn more about other cool hsm methods.


#### Legacy Formats (Pre-v25.12)

For nodes created before v25.12, the `hsm_secret` was stored as a 32-byte binary file. These can be backed up in hexadecimal format:


##### Hex Format

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
