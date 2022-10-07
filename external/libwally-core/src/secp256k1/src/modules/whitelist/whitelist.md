Address Whitelisting Module
===========================

This module implements a scheme by which members of some group, having fixed
signing keys, can prove control of an arbitrary other key without associating
their own identity (only that they belong to the group) to the new key. The
application is to patch ring-signature-like behaviour onto systems such as
Bitcoin or PGP which do not directly support this.

We refer to such delegation as "whitelisting" because we expect it to be used
to build a dynamic whitelist of authorized keys.

For example, imagine a private sidechain with a fixed membership set but
stronger privacy properties than Bitcoin. When moving coins from this system
to Bitcoin, it is desirable that the destination Bitcoin addresses be provably
in control of some user of the sidechain. This prevents malicious or erroneous
behaviour on the sidechain, which can likely be resolved by its participants,
from translating to theft on the wider Bitcoin network, which is irreversible.

### Unused Schemes and Design Rationale

#### Direct Signing

An obvious scheme for such delegation is to simply have participants sign the
key they want to whitelist. To avoid revealing their specific identity, they
could use a ring signature. The problem with this is that it really only proves
that a participant *signed off* on a key, not that they control it. Thus any
security failure that allows text substitution could be used to subvert this
and redirect coins to an attacker-controlled address.

#### Signing with Difference-of-Keys

A less obvious scheme is to have a participant sign an arbitrary message with
the sum of her key `P` and the whitelisted key `W`. Such a signature with the key
`P + W` proves knowledge of either (a) discrete logarithms of both `P` and `W`;
or (b) neither. This makes directly attacking participants' signing schemes much
harder, but allows an attacker to whitelist arbitrary "cancellation" keys by
computing `W` as the difference between an attacker-controlled key and `P`.
Because to spend the funds the attacker must produce a signature with `W`, the
coins will be unspendable until attacker and the legitimate participant owning
`P` cooperate.

In an important sense, this "cancellation" attack is a good thing: it enables
*offline delegation*. That is, the key `P` does not need to be available at the
time of delegation. Instead, participants could choose `S = P + W`, sign with
this to delegate, and only later compute the discrete logarithm of `W = P - S`.
This allows `P` to be in cold storage or be otherwise inaccessible, improving
the overall system security.

#### Signing with Tweaked-Difference-of-Keys

A modification of this scheme, which prevents this "cancellation" attack, is to
instead have participants sign some message with the key `P + H(W)W`, for `H`
some random-oracle hash that maps group elements to scalars. This key, and its
discrete logarithm, cannot be known until after `W` is chosen, so `W` cannot
be selected as the difference between it and `P`. (Note that `P` could still
be some chosen difference; however `P` is a fixed key and must be verified
out-of-band to have come from a legitimate participant anyway.)

This scheme is almost what we want, but it no longer supports offline
delegation. However, we can get this back by introducing a new key, `P'`,
and signing with the key `P + H(W + P')(W + P')`. This gives us the best
of both worlds: `P'` does not need to be online to delegate, allowing it
to be securely stored and preventing real-time attacks; `P` does need to
be online, but its compromise only allows an attacker to whitelist keys he does
not control alone.

### Our Scheme

Our scheme works as follows: each participant `i` chooses two keys, `P_i` and `Q_i`.
We refer to `P_i` as the "online key" and `Q_i` as the "offline key". To whitelist
a key `W`, the participant computes the key `L_j = P_j + H(W + Q_j)(W + Q_j)` for
every participant `j`. Then she will know the discrete logarithm of `L_i` for her
own `i`.

Next, she signs a message containing every `P_i` and `Q_i` as well as `W` with
a ring signature over all the keys `L_j`. This proves that she knows the discrete
logarithm of some `L_i` (though it is zero-knowledge which one), and therefore
knows:
1. The discrete logarithms of all of `W`, `P_i` and `Q_i`; or
2. The discrete logarithm of `P_i` but of *neither* `W` nor `Q_i`.
In other words, compromise of the online key `P_i` allows an attacker to whitelist
"cancellation keys" for which the attacker alone does not know the discrete logarithm;
to whitelist an attacker-controlled key, he must compromise both `P_i` and `Q_i`. This is difficult
because by design, only the sum `S = W + Q_i` is used when signing; then by choosing
`S` freely, a participant can delegate without the secret key to `Q_i` ever being online.
(Later, when she wants to actually use `W`, she will need to compute its key as the
difference between `S` and `Q_i`; but this can be done offline and much later
and with more expensive security requirements.)

The message to be signed contains all public keys to prevent a class of attacks
centered around choosing keys to match pre-computed signatures. In our proposed
use case, whitelisted keys already must be computed before they are signed, and
the remaining public keys are verified out-of-band when setting up the system,
so there is no direct benefit to this. We do it only to reduce fragility and
increase safety of unforeseen uses.

Having to access the offline key `Q_i` to compute the secret to the sum `W +
Q_i` for every authorization is onerous.  Instead, if the whitelisted keys are
created using
[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
unhardened derivation, the sum can be computed on an online machine. In order
to achieve that, the offline key `Q_j` is set to the negated last hardened
BIP32 derived parent key (typically, the public key corresponding to the xpub).
As a result `W + Q_i = I_L*G` where `I_L` is the public tweak used
to derive `W` and can be easily computed online using the extended public key
and the derivation path.
