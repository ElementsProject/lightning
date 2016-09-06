# Looking for things to hack on? #

## Cleanups ##

* Remove our specific libsecp256k1 in secp256k1/ and use the installed one.

## Minor improvements ##

* Make `json_get_params` fail if unknown parameters are specified by user.
* Print backtrace in `log_crash`
* When unpacking a packet, reject any with an unknown odd-numbered field as per BOLT #2.
* Limit total number of peers in `new_peer`, or at least in `peer_connected_in`.
* logging: add IO logging for peers.
* Add `history` RPC command which shows all prior commit txs.
* Improve `getpeers` to show status of peers when connecting, DNS lookups etc.
* Add pings to protocol
  * Timeout a peer if they don't respond in a given time (eg. 2 pings)

## Testing: ##

* Add more unit tests in bitcoin/test and daemon/test
* Test more scenarios with daemon/test/test.sh, and split it up.
* Implement compile-time crypto-free mode
  * Implement canned conversation files for fuzz testing (eg AFL).
* Write canned input/output test cases for various conversations, and
  include them in a form suitable for other implementations to test.

## Major improvements: ##

* (MAJOR) Implement onion
  * (MAJOR) Implement failure message encryption

## Other ##

* Grep for other FIXMEs and fix one :)
* Look on https://github.com/ElementsProject/lightning/issues

Happy hacking!<br>
Rusty.
