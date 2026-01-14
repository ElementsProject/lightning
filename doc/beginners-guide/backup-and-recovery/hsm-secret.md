---
title: HSM Secret
slug: hsm-secret
content:
  excerpt: Learn about various cool HSM secret methods.
privacy:
  view: public
---


## Mnemonic-Based HSM Secrets (v25.12+)

Starting with Core Lightning v25.12, new nodes are automatically created with a BIP39 12-word mnemonic phrase as their root secret. This provides a more user-friendly backup method compared to the previous 32-byte binary format.


### Automatic HSM Secret Creation

When you first start `lightningd` (v25.12+), it will automatically generate a random BIP39 mnemonic and create the `hsm_secret` file **without a passphrase**. No prompts are shown during this process.

If you want to add a passphrase for additional security, start `lightningd` with the `--hsm-passphrase` option:

```shell
lightningd --hsm-passphrase
```

This will prompt you to enter a passphrase (and confirm it) before creating the `hsm_secret`. The passphrase becomes part of the BIP39 seed derivation process, providing an additional security factor. If you use a passphrase, you must use `--hsm-passphrase` every time you start `lightningd`.


### Creating HSM Secret with Your Own Mnemonic

If you want to use your own mnemonic (instead of a randomly generated one), create the `hsm_secret` manually using the `lightning-hsmtool generatehsm` command before starting `lightningd`. If you did `make install` then `hsmtool` is installed as [`lightning-hsmtool`](ref:lightning-hsmtool), else you can find it in the `tools/` directory of the build directory.

```shell
lightning-hsmtool generatehsm $LIGHTNINGDIR/hsm_secret
```

The command will prompt you interactively in the command line:
1. Enter your BIP39 mnemonic phrase (12 words, separated by spaces)
2. Enter an optional passphrase (you can press Enter to skip adding a passphrase)

The passphrase provides additional security by adding entropy to the seed derivation process according to BIP39. 

You can regenerate the same `hsm_secret` file using the same BIP39 words and passphrase, which you can back up on paper. **Important:** If you use a passphrase, you must back it up separately along with your mnemonic, as both are required to recover your funds.


### Extract Mnemonic for Backup

If your `hsm_secret` does **not** use a passphrase, you can extract your mnemonic using the `exposesecret` RPC command (requires setting `exposesecret-passphrase` in your config):

```shell
lightning-cli exposesecret passphrase=<your-exposesecret-passphrase>
```

This returns your mnemonic phrase, which you can then write down and store securely.

**Important:** `exposesecret` does not work with passphrase-protected `hsm_secret` files. If you used `--hsm-passphrase` when creating your node, you must have backed up your mnemonic during the `generatehsm` step.


## Legacy HSM Secret Formats (Pre-v25.12)

For nodes created before v25.12, the `hsm_secret` was stored as a 32-byte binary file. These legacy formats are still supported for backward compatibility.


### Encrypt Legacy HSM Secret

You can encrypt a legacy `hsm_secret` content (which is used to derive the HD wallet's master key):
- either by passing the `--hsm-passphrase` startup argument (this replaced the deprecated `--encrypted-hsm` option in v25.12)
- or by using the `encrypt` method from `/tools/lightning-hsmtool`. 

If you encrypt your legacy `hsm_secret`, you will have to pass the `--hsm-passphrase` startup option to `lightningd`. Once your `hsm_secret` is encrypted, you **will not** be able to access your funds without your password, so please beware with your password management. Also, beware of not feeling too safe with an encrypted `hsm_secret`: unlike for `bitcoind` where the wallet encryption can restrict the usage of some RPC command, `lightningd` always needs to access keys from the wallet which is thus **not locked** (yet), even with an encrypted BIP32 master seed.


### Decrypt Legacy HSM Secret

You can unencrypt an encrypted legacy `hsm_secret` using the `lightning-hsmtool` with the `decrypt` method.

```shell
lightning-hsmtool decrypt ${LIGHTNINGDIR}/hsm_secret
```
