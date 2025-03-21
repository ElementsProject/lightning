# Security Policy

## Supported Versions

We have a 3 month release cycle, and the last two versions are supported.

## Reporting a Vulnerability

To report security vulnerabilities, please send an email to one of the following addresses:
- `rusty@rustcorp.com.au`
- `security@blockstream.com`

Note: These email addresses are exclusively for vulnerability reporting.

For all other inquiries/communication, please refer to the [Reach Out to Us](https://github.com/ElementsProject/lightning?tab=readme-ov-file#reach-out-to-us) section in our README.

## Signatures For Releases

The following keys may be used to communicate sensitive information to
developers, and to validate signatures on releases:

| Name | Email | Fingerprint |
|------|-------|-------------|
| Blockstream Security Reporting | `security@blockstream.com` | 1176 542D A98E 71E1 3372  2EF7 4AC8 CC88 6844 A2D6 |
| Rusty Russell | `rusty@rustcorp.com.au` | 15EE 8D6C AB0E 7F0C F999  BFCB D920 0E6C D1AD B8F1 |
| Christian Decker | `decker@blockstream.com` | B731 AAC5 21B0 1385 9313  F674 A26D 6D9F E088 ED58 |
| Lisa Neigut | `niftynei@gmail.com` | 30DE 693A E0DE 9E37 B3E7  EB6B BFF0 F678 10C1 EED1 |
| Alex Myers | `alex@endothermic.dev` | 0437 4E42 789B BBA9 462E  4767 F3BF 63F2 7474 36AB |
| Peter Neuroth | `pet.v.ne@gmail.com` | 653B 19F3 3DF7 EFF3 E9D1  C94C C3F2 1EE3 87FF 4CD2 |
| Shahana Farooqui | `sfarooqui@blockstream.com` | FE13 58EB 7793 51DB 24E5  555A A327 573C 9758 9BF5 |
| Blockstream CLN Release | `cln@blockstream.com` | 616C 52F9 9D06 12B2 A151  B107 4129 A994 AA7E 9852 |

You can import a key by running the following command with that individual’s fingerprint: 
`gpg --keyserver hkps://keys.openpgp.org --recv-keys "<fingerprint>"`. 
Ensure that you put quotes around fingerprints containing spaces.
