---
title: HSM Secret
slug: hsm-secret
content:
  excerpt: Learn about various cool HSM secret methods.
privacy:
  view: public
---


## Generate HSM Secret

If you are deploying a new node that has no funds and channels yet, you can generate BIP39 words using any process, and create the `hsm_secret` using the `lightning-hsmtool generatehsm` command. If you did `make install` then `hsmtool` is installed as [`lightning-hsmtool`](ref:lightning-hsmtool), else you can find it in the `tools/` directory of the build directory.

```shell
lightning-hsmtool generatehsm hsm_secret
```

Then enter the BIP39 words, plus an optional passphrase. Then copy the `hsm_secret` to `${LIGHTNINGDIR}`

You can regenerate the same `hsm_secret` file using the same BIP39 words, which again, you can back up on paper.


## Encrypt HSM Secret

You can encrypt the `hsm_secret` content (which is used to derive the HD wallet's master key):
- either by passing the `--encrypted-hsm` startup argument
- or by using the `encrypt` method from `/tools/lightning-hsmtool`. 

If you encrypt your `hsm_secret`, you will have to pass the `--encrypted-hsm` startup option to `lightningd`. Once your `hsm_secret` is encrypted, you **will not** be able to access your funds without your password, so please beware with your password management. Also, beware of not feeling too safe with an encrypted `hsm_secret`: unlike for `bitcoind` where the wallet encryption can restrict the usage of some RPC command, `lightningd` always needs to access keys from the wallet which is thus **not locked** (yet), even with an encrypted BIP32 master seed.


## Decrypt HSM Secret

You can unencrypt an encrypted `hsm_secret` using the `lightning-hsmtool` with the `decrypt` method.

```shell
lightning-hsmtool decrypt ${LIGHTNINGDIR}/hsm_secret
```
