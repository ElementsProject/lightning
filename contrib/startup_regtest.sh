#!/bin/sh

## Short script to startup two local nodes with
## bitcoind, all running on regtest

## Should be called by source since it sets aliases

if [ -z "$PATH_TO_LIGHTNING" ]
then
	echo "\$PATH_TO_LIGHTNING not set"
	return
fi

if [ -z "$PATH_TO_BITCOIN" ]
then
	echo "\$PATH_TO_BITCOIN not set"
	return
fi

mkdir -p /tmp/l1-regtest /tmp/l2-regtest

# Node one config
cat << 'EOF' > /tmp/l1-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l1-regtest/log
addr=localhost:6060
EOF

cat << 'EOF' > /tmp/l2-regtest/config
network=regtest
daemon
log-level=debug
log-file=/tmp/l2-regtest/log
addr=localhost:9090
EOF

# Start bitcoind in the background
bitcoind -daemon -regtest

# Start the lightning nodes
"$PATH_TO_LIGHTNING/lightningd/lightningd" --lightning-dir=/tmp/l1-regtest
"$PATH_TO_LIGHTNING/lightningd/lightningd" --lightning-dir=/tmp/l2-regtest

alias l1-cli='$PATH_TO_LIGHTNING/cli/lightning-cli --lightning-dir=/tmp/l1-regtest'
alias l2-cli='$PATH_TO_LIGHTNING/cli/lightning-cli --lightning-dir=/tmp/l2-regtest'
alias bt-cli='bitcoin-cli -regtest'

cleanup_lightning() {
	test ! -f /tmp/l1-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l1-regtest/lightningd-regtest.pid)" && \
		rm /tmp/l1-regtest/lightningd-regtest.pid)
	test ! -f /tmp/l2-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l2-regtest/lightningd-regtest.pid)" && \
		rm /tmp/l2-regtest/lightningd-regtest.pid)
	test ! -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_BITCOIN/regtest/bitcoind.pid")" && \
		rm "$PATH_TO_BITCOIN/regtest/bitcoind.pid")
	unalias l1-cli
	unalias l2-cli
	unalias bt-cli
	unset -f cleanup_lightning
}
