#!/bin/sh

## Short script to startup some local nodes with
## bitcoind, all running on regtest
## Makes it easier to test things out, by hand.

## Should be called by source since it sets aliases
##
##  First load this file up.
##
##  $ source contrib/startup_regtest.sh
##
##  Start up the nodeset
##
##  $ start_ln 3
##
##  Let's connect the nodes.
##
##  $ l2-cli getinfo | jq .id
##    "02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb"
##  $ l2-cli getinfo | jq .binding[0].port
##    9090
##  $ l1-cli connect 02b96b03e42d9126cb5228752c575c628ad09bdb7a138ec5142bbca21e244ddceb@localhost:9090
##    {
##      "id" : "030b02fc3d043d2d47ae25a9306d98d2abb7fc9bee824e68b8ce75d6d8f09d5eb7"
##    }
##
##  When you're finished, clean up or stop
##
##  $ stop_ln  # stops the services, keeps the aliases
##  $ cleanup_ln # stops and cleans up aliases
##

# Do the Right Thing if we're currently in top of srcdir.
if [ -z "$PATH_TO_LIGHTNING" ] && [ -x cli/lightning-cli ] && [ -x lightningd/lightningd ]; then
	PATH_TO_LIGHTNING=$(pwd)
fi

if [ -z "$PATH_TO_LIGHTNING" ]; then
	# Already installed maybe?  Prints
	# shellcheck disable=SC2039
	type lightning-cli || return
	# shellcheck disable=SC2039
	type lightningd || return
	LCLI=lightning-cli
	LIGHTNINGD=lightningd
else
	LCLI="$PATH_TO_LIGHTNING"/cli/lightning-cli
	LIGHTNINGD="$PATH_TO_LIGHTNING"/lightningd/lightningd
	# This mirrors "type" output above.
	echo lightning-cli is "$LCLI"
	echo lightningd is "$LIGHTNINGD"
fi

if [ -z "$PATH_TO_BITCOIN" ]; then
	if [ -d "$HOME/.bitcoin" ]; then
		PATH_TO_BITCOIN="$HOME/.bitcoin"
	else
		echo "\$PATH_TO_BITCOIN not set to a .bitcoin dir?" >&2
		return
	fi
fi

start_ln() {
	# Start bitcoind in the background
	test -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		bitcoind -regtest -txindex -fallbackfee=0.00000253 -daemon

	# Wait for it to start.
	while ! bitcoin-cli -regtest ping 2> /tmp/null; do echo "awaiting bitcoind..." && sleep 1; done

	# Kick it out of initialblockdownload if necessary
	if bitcoin-cli -regtest getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		bitcoin-cli -regtest generatetoaddress 1 "$(bitcoin-cli -regtest getnewaddress)" > /dev/null
	fi

	if [ -z "$1" ]
	then
		node_count=2
	else
		node_count=$1
	fi
	if [ "$node_count" -gt 100 ]; then
		node_count=100
	fi

	LN_NODES=$node_count

	for i in $(seq $node_count); do
		socket=$(( 7070 + i * 101))
		mkdir -p "/tmp/l$i-regtest"
		# Node config
		cat <<- EOF > "/tmp/l$i-regtest/config"
		network=regtest
		log-level=debug
		log-file=/tmp/l$i-regtest/log
		addr=localhost:$socket
		EOF

		# Start the lightning nodes
		test -f "/tmp/l$i-regtest/lightningd-regtest.pid" || \
			"$LIGHTNINGD" "--lightning-dir=/tmp/l$i-regtest" --daemon
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-cli="$LCLI --lightning-dir=/tmp/l$i-regtest"
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-log="less /tmp/l$i-regtest/log"
	done

	alias bt-cli='bitcoin-cli -regtest'
	# Give a hint.
	echo "Commands: "
	for i in $(seq $node_count); do
		echo "	l$i-cli, l$i-log,"
	done
	echo "	bt-cli, stop_ln, cleanup_ln"
}

stop_ln() {
	if [ -n "$LN_NODES" ]
	then
		for i in $(seq $LN_NODES); do
			test ! -f "/tmp/l$i-regtest/lightningd-regtest.pid" || \
				(kill "$(cat "/tmp/l$i-regtest/lightningd-regtest.pid")"; \
				rm "/tmp/l$i-regtest/lightningd-regtest.pid")
			unalias "l$i-cli"
			unalias "l$i-log"
		done
	fi

	test ! -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_BITCOIN/regtest/bitcoind.pid")"; \
		rm "$PATH_TO_BITCOIN/regtest/bitcoind.pid")

	unset LN_NODES
	unalias bt-cli
}
