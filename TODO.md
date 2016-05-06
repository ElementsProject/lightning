# Looking for things to hack on? #

I've marked things as simple if you want something easy to work on!

## Cleanups ##

* Wean off openssl's -lcrypto
  * (simple) use libsodium for all RNG
  * (simple) use libbase58

* Remove our specific libsecp256k1 in secp256k1/ and use the installed one.
  * Implement `sig_valid`, using `secp256k1_ecdsa_signature_normalize`
  * Use `secp256k1_ecdsa_signature_parse_compact`/`_serialize_compact` in `signature_to_proto`

## Minor improvements ##

* Make `json_get_params` fail if unknown parameters are specified by user.
* Print backtrace in `log_crash`
* Support locktime in blocks in `accept_pkt_open`, `accept_pkt_htlc_add`, `commit_tx_depth`
* When unpacking a packet, reject any with an unknown odd-numbered field as per BOLT #2.
* Provide details (string) when a command fails because state() returns CMD_FAIL
* logging: add `log_struct()` for common structs.
* Limit total number of peers in `new_peer`, or at least in `peer_connected_in`.
* logging: add IO logging for peers.
* Add `history` RPC command which shows all prior commit txs.
* Improve `getpeers` to show status of peers when connecting, DNS lookups etc.
* Add pings to protocol
  * Timeout a peer if they don't respond in a given time (eg. 2 pings)
* Add timers to drop peer if we approach timeout for HTLCs and they're still
uncommitted to closing it (see BOLT #2 "Risks With HTLC Timeouts").

## Testing: ##

* Add more unit tests in bitcoin/test.
* Test more scenarios with daemon/test/test.sh
* Implement compile-time crypto-free mode
  * Implement canned conversation files for fuzz testing (eg AFL).
* Write canned input/output test cases for various conversations, and
  include them in a form suitable for other implementations to test.

## Major improvements: ##

* Track fee estimation for each new block.
  * (MAJOR) Implement fee renegotiation acceptance.
  * (MAJOR) Implement fee renegotiation as fee rate changes.

* Don't fail funding if fees insufficient, fall back as per BOLT #2.

* (MAJOR) Do proper close, still allowing ongoing HTLCs to resolve.

* (MAJOR) Implement reconnection.
* Save preimages in shachain.
  * (MAJOR) Implement persistence.
* (MAJOR) Implement onion
  * (MAJOR) Implement routing
  * (MAJOR) Implement failure messages

## Other ##

* Grep for other FIXMEs and fix one :)
* Look on https://github.com/ElementsProject/lightning/issues

Happy hacking!<br>
Rusty.
