# Release Announce for 0.6
## a.k.a. "I Accidentally The Smart Contract"

The long wait is over: the c-lightning team is excited to announce the 0.6 release of
[c-lightning][clightning], an important milestone for the project. This complete rewrite of the previous implementation is the first fully specification-compliant release of c-lightning. It migrates away from the protocol used while designing the specification and toward a new architecture that is modular and extensible, to better adapt to your needs and your infrastructure.

## New Features

While there are far too many new features in the 0.6 release to list, the following are the most interesting and impactful:

 - __Lightweight nodes__: Previous releases required a full `bitcoind` node
   running alongside c-lightning, to provide access to the Bitcoin network. This release still requires the `bitcoin-cli` utility to be present, but it
   can now talk to remote nodes as well, including some lightweight nodes such
   as [`spruned`][spruned]. This makes it possible to run a c-lightning node on
   Raspberry Pis as well as other low-powered devices.
 - The __gossip protocol__ has been updated to use a more lightweight bandwidth mechanism that
   asks for specific information, rather than exchanging full network
   Views as the previous release did. This is particular important for low-powered and mobile devices that
   would otherwise spend a lot of bandwidth and energy downloading and
   verifying information they already have.
 - __API stability__: The c-lightning
   JSON-RPC interface and supporting libraries have been redesigned in order to minimize
   changes in future releases. This API stability should make it easy for other
   projects to build on top of c-lightning because we will support this version of
   the API for the foreseeable future, maintaining backward compatibility,
   should we introduce any changes.
 - __Wallet and sync__: c-lightning now includes a full-fledged wallet that
   manages both on-chain and off-chain funds. There is no more raw
   transaction handling! All funds are automatically tracked and returned to the
   internal wallet as soon as possible, with no user interaction required. In
   addition the blockchain tracking now maintains an internal view of the blockchain, ending long blockchain rescans.
 - __TOR support__: c-lightning now supports connecting to nodes over the
   TOR network, auto-registering as a hidden service, and accepting
   incoming connections over TOR.
 - The __payment logic__ has undergone a major overhaul to support automatic retries
   for routing failures, randomization of route selection, and better feedback about
   the current state of a payment.
 - And as always: performance, performance, performance.

## Flexibility through Modularity

The c-lightning architecture is based on a number of independent communicating
processes, each with its own responsibilities. This allows better integration into
your infrastructure and better adaptation to your needs. Two
daemons that are global for all channels,`gossipd` and `hsmd`, are of particular note because of their modular design

`gossipd` manages a local view of the network and is tasked with finding a path
from the source of a payment to its destination. The default implementation
attempts to find a route with reasonable tradeoffs between fees, timeouts, and
stability. It also obfuscates the route by selecting randomly among a
number of candidate routes and tweaking the amounts and timeouts in order to
conceal the endpoints of a payment.  The default implementation can easily be
switched out if you have particular routing requirements or want to
enforce a specific routing policy, such as always selecting the route with the lowest
timeouts or the lowest fees.

`hsmd` manages all operations that touch cryptographic materials and controls
the funds in the channel. It is the sole subsystem that has access to the node's
private key. This means that other subsystems do not hold any private
information and must communicate with the `hsmd` daemon to sign or decrypt
anything. Centralizing the cryptographic operations in this manner reduces the
surface that needs to be secured and opens up a number of interesting
applications. While the default `hsmd` implementation already provides good
security through process separation and the ability to further secure it via OS
level security, e.g., SELinux and AppArmor, it can be easily replaced with an implementation that talks to a physical HSM. Replacing the `hsmd`
implementation furthermore allows headless operation, e.g., running a
c-lightning node at home, with a paired mobile app managing the private keys
and initiating payments or creating invoices.

This separation of c-lightning functionality into multiple daemons is not only a big
improvement in flexibility, but also a robust improvement to node security, as it ensures that an attacker cannot directly
interface with anything that touches the private keys. Each subsystem
independently verifies the consistency of the internal state, disconnecting a
peer and killing its process if any inconsistency is detected. The multi-daemon
architecture also enables the use of Docker, SELinux and AppArmor to lock down
what information each daemon can access and what actions they can perform.

## What's Next?

Our work with c-lightning is far from done; we are constantly working on
[features][features] and [enhancements][enhancements], as well as improvements to
performance, stability and usability. Didn’t find your favorite feature? Have
some feedback that might be helpful? Why not file an [issue on
Github][gh-issue], drop us a line on the [mailing list][ml], or [contact us on
IRC][irc].

In parallel we are also contributing to the advancement of the Lightning specification
itself and are actively researching what the next iteration of the protocol could
look like through initiatives like our [eltoo][eltoo] proposal and upstream
Bitcoin proposals such as [`SIGHASH_NOINPUT`][sighash-noinput].

We'd like to thank the many contributors who have not only contributed code to
c-lightning, but also those who were #reckless enough to test and give feedback
about what works and what could be improved. And finally, we'd like to thank the
other Lightning Network teams, ACINQ and Lightning Labs, as well as all individual contributors
that pitched in to make the Lightning Network community such a pleasant, collaborative and open
environment!

[spruned]: https://github.com/gdassori/spruned
[clightning]: https://github.com/ElementsProject/lightning
[features]: https://github.com/ElementsProject/lightning/issues?q=is%3Aissue+is%3Aopen+label%3Afeature
[enhancements]: https://github.com/ElementsProject/lightning/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement
[irc]: irc://c-lightning@irc.freenode.net
[ml]: mailto:c-lightning@lists.ozlabs.org
[gh-issue]: https://github.com/ElementsProject/lightning/issues/new
[sighash-noinput]: https://github.com/bitcoin/bips/blob/master/bip-0118.mediawiki
[eltoo]: https://blockstream.com/2018/04/30/eltoo-next-lightning.html


