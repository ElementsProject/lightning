#!/bin/sh

## Short script to startup two local nodes with
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
##  $ start_ln
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

mkdir -p /tmp/l1-regtest /tmp/l2-regtest

# Node one config
cat << 'EOF' > /tmp/l1-regtest/config
network=regtest
log-level=debug
log-file=/tmp/l1-regtest/log
addr=localhost:6060
EOF

cat << 'EOF' > /tmp/l2-regtest/config
network=regtest
log-level=debug
log-file=/tmp/l2-regtest/log
addr=localhost:9090
EOF

alias l1-cli='$LCLI --lightning-dir=/tmp/l1-regtest'
alias l2-cli='$LCLI --lightning-dir=/tmp/l2-regtest'
alias bt-cli='bitcoin-cli -regtest'
alias l1-log='less /tmp/l1-regtest/log'
alias l2-log='less /tmp/l2-regtest/log'

start_ln() {
	# Start bitcoind in the background
	test -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		bitcoind -daemon -regtest -txindex

	# Wait for it to start.
	while ! bt-cli ping 2> /dev/null; do sleep 1; done

	# Kick it out of initialblockdownload if necessary
	if bt-cli getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		bt-cli generatetoaddress 1 "$(bt-cli getnewaddress)" > /dev/null
	fi

	# Start the lightning nodes
	test -f /tmp/l1-regtest/lightningd-regtest.pid || \
		"$LIGHTNINGD" --lightning-dir=/tmp/l1-regtest &
	test  -f /tmp/l2-regtest/lightningd-regtest.pid || \
		"$LIGHTNINGD" --lightning-dir=/tmp/l2-regtest &

	# Give a hint.
	echo "Commands: l1-cli, l2-cli, l[1|2]-log, bt-cli, stop_ln, cleanup_ln"
}

stop_ln() {
	test ! -f /tmp/l1-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l1-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l1-regtest/lightningd-regtest.pid)
	test ! -f /tmp/l2-regtest/lightningd-regtest.pid || \
		(kill "$(cat /tmp/l2-regtest/lightningd-regtest.pid)"; \
		rm /tmp/l2-regtest/lightningd-regtest.pid)
	test ! -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_BITCOIN/regtest/bitcoind.pid")"; \
		rm "$PATH_TO_BITCOIN/regtest/bitcoind.pid")
}

cleanup_ln() {
	stop_ln
	unalias l1-cli
	unalias l2-cli
	unalias bt-cli
	unalias l1-log
	unalias l2-log
	unset -f start_ln
	unset -f stop_ln
	unset -f cleanup_ln
}
