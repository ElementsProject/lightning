---
title: "Securing keys"
slug: "securing-keys"
hidden: false
createdAt: "2022-11-18T16:28:08.529Z"
updatedAt: "2023-01-31T13:52:27.300Z"
---
You can encrypt the `hsm_secret` content (which is used to derive the HD wallet's master key) by passing the `--encrypted-hsm` startup argument, or by using the `hsmtool` (which you can find in the `tool/` directory at the root of [Core Lightning repository](https://github.com/ElementsProject/lightning)) with the `encrypt` method. You can unencrypt an encrypted `hsm_secret` using the `hsmtool` with the `decrypt` method.

If you encrypt your `hsm_secret`, you will have to pass the `--encrypted-hsm` startup option to `lightningd`. Once your `hsm_secret` is encrypted, you **will not** be able to access your funds without your password, so please beware with your password management. Also, beware of not feeling too safe with an encrypted `hsm_secret`: unlike for `bitcoind` where the wallet encryption can restrict the usage of some RPC command, `lightningd` always needs to access keys from the wallet which is thus **not locked** (yet), even with an encrypted BIP32 master seed.