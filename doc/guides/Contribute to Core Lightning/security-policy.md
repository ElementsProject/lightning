---
title: "Security policy"
slug: "security-policy"
excerpt: "Learn how to responsibly report a security issue."
hidden: false
createdAt: "2022-12-09T09:58:38.899Z"
updatedAt: "2023-02-21T15:15:57.281Z"
---
## Supported Versions

We have a 3 month release cycle, and the last two versions are supported.

## Reporting a Vulnerability

To report security issues, send an email to rusty `at` rustcorp.com.au, or security `at` blockstream.com (not for support).

## Signatures For Releases

The following keys may be used to communicate sensitive information to  
developers, and to validate signatures on releases:

| Name             | Fingerprint                                        |
| ---------------- | -------------------------------------------------- |
| Rusty Russell    | 15EE 8D6C AB0E 7F0C F999  BFCB D920 0E6C D1AD B8F1 |
| Christian Decker | B731 AAC5 21B0 1385 9313  F674 A26D 6D9F E088 ED58 |
| Lisa Neigut      | 30DE 693A E0DE 9E37 B3E7  EB6B BFF0 F678 10C1 EED1 |
| Alex Myers       | 0437 4E42 789B BBA9 462E  4767 F3BF 63F2 7474 36AB |

You can import a key by running the following command with that individual’s fingerprint: `gpg --keyserver hkps://keys.openpgp.org --recv-keys "<fingerprint>"`. Ensure that you put quotes around fingerprints containing spaces.