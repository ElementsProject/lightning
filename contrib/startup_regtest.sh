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
##  Let's connect the nodes. The `connect a b` command connects node a to b.
##
##  $ connect 1 2
##  {
##    "id" : "030b02fc3d043d2d47ae25a9306d98d2abb7fc9bee824e68b8ce75d6d8f09d5eb7"
##  }
##
##  When you're finished, clean up or stop
##
##  $ stop_ln
##  $ destroy_ln # clean up the lightning directories
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
	elif [ -d "$HOME/Library/Application Support/Bitcoin/" ]; then
		PATH_TO_BITCOIN="$HOME/Library/Application Support/Bitcoin/"
	else
		echo "\$PATH_TO_BITCOIN not set to a .bitcoin dir?" >&2
		return
	fi
fi

start_nodes() {
	if [ -z "$1" ]; then
		node_count=2
	else
		node_count=$1
	fi
	if [ "$node_count" -gt 100 ]; then
		node_count=100
	fi
	if [ -z "$2" ]; then
		network=regtest
	else
		network=$2
	fi
	# This supresses db syncs, for speed.
	if type eatmydata >/dev/null 2>&1; then
	    EATMYDATA=eatmydata
	else
	    EATMYDATA=
	fi

	LN_NODES=$node_count

	for i in $(seq "$node_count"); do
		socket=$(( 7070 + i * 101))
		mkdir -p "/tmp/l$i-$network"
		# Node config
		cat <<- EOF > "/tmp/l$i-$network/config"
		network=$network
		log-level=debug
		log-file=/tmp/l$i-$network/log
		addr=localhost:$socket
		allow-deprecated-apis=false
		EOF

		# If we've configured to use developer, add dev options
		if $LIGHTNINGD --help | grep -q dev-fast-gossip; then
			cat <<- EOF >> "/tmp/l$i-$network/config"
			developer
			dev-fast-gossip
			dev-bitcoind-poll=5
			experimental-dual-fund
			experimental-splicing
			experimental-offers
			funder-policy=match
			funder-policy-mod=100
			funder-min-their-funding=10000
			funder-per-channel-max=100000
			funder-fuzz-percent=0
			lease-fee-base-sat=2sat
			lease-fee-basis=50
			invoices-onchain-fallback
			EOF
		fi


		# Start the lightning nodes
		test -f "/tmp/l$i-$network/lightningd-$network.pid" || \
			$EATMYDATA "$LIGHTNINGD" "--network=$network" "--lightning-dir=/tmp/l$i-$network" "--bitcoin-datadir=$PATH_TO_BITCOIN" "--database-upgrade=true" &
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-cli="$LCLI --lightning-dir=/tmp/l$i-$network"
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-log="less /tmp/l$i-$network/log"
	done

	if [ -z "$EATMYDATA" ]; then
	    echo "WARNING: eatmydata not found: install it for faster testing"
	fi
	# Give a hint.
	echo "Commands: "
	for i in $(seq "$node_count"); do
		echo "	l$i-cli, l$i-log,"
	done
}

start_ln() {
	# Start bitcoind in the background
	test -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		bitcoind -datadir="$PATH_TO_BITCOIN" -regtest -txindex -fallbackfee=0.00000253 -daemon

	# Wait for it to start.
	while ! bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest ping 2> /tmp/null; do echo "awaiting bitcoind..." && sleep 1; done

	# Check if default wallet exists
	if ! bitcoin-cli -datadir=$PATH_TO_BITCOIN -regtest listwalletdir | jq -r '.wallets[] | .name' | grep -wqe 'default' ; then
		# wallet dir does not exist, create one
		echo "Making \"default\" bitcoind wallet."
		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest createwallet default >/dev/null 2>&1
	fi

	# Check if default wallet is loaded
	if ! bitcoin-cli -datadir=$PATH_TO_BITCOIN -regtest listwallets | jq -r '.[]' | grep -wqe 'default' ; then
		echo "Loading \"default\" bitcoind wallet."
		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest loadwallet default >/dev/null 2>&1
	fi

	# Kick it out of initialblockdownload if necessary
	if bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest generatetoaddress 1 "$(bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest getnewaddress)" > /dev/null
	fi

	alias bt-cli='bitcoin-cli -datadir=$PATH_TO_BITCOIN -regtest'

	if [ -z "$1" ]; then
		nodes=2
	else
		nodes="$1"
	fi
	start_nodes "$nodes" regtest
	echo "	bt-cli, stop_ln, fund_nodes"
}

ensure_bitcoind_funds() {

	if [ -z "$ADDRESS" ]; then
		ADDRESS=$(bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest "$WALLET" getnewaddress)
	fi

	balance=$(bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest "$WALLET" getbalance)

	if [ 1 -eq "$(echo "$balance"'<1' | bc -l)" ]; then

		printf "%s" "Mining into address " "$ADDRESS""... "

		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest generatetoaddress 100 "$ADDRESS" > /dev/null

		echo "done."
	fi
}

fund_nodes() {
	WALLET="default"
	NODES=""

	for var in "$@"; do
		case $var in
			-w=*|--wallet=*)
				WALLET="${var#*=}"
				;;
			*)
				NODES="${NODES:+${NODES} }${var}"
				;;
		esac
	done

	if [ -z "$NODES" ]; then
		NODES=$(seq "$node_count")
	fi

	WALLET="-rpcwallet=$WALLET"

	ADDRESS=$(bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest "$WALLET" getnewaddress)

	ensure_bitcoind_funds

	echo "bitcoind balance:" "$(bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest "$WALLET" getbalance)"

	last_node=""

	echo "$NODES" | while read -r i; do

		if [ -z "$last_node" ]; then
			last_node=$i
			continue
		fi

		node1=$last_node
		node2=$i
		last_node=$i

		L2_NODE_ID=$($LCLI -F --lightning-dir=/tmp/l"$node2"-regtest getinfo | sed -n 's/^id=\(.*\)/\1/p')
		L2_NODE_PORT=$($LCLI -F --lightning-dir=/tmp/l"$node2"-regtest getinfo | sed -n 's/^binding\[0\].port=\(.*\)/\1/p')

		$LCLI -H --lightning-dir=/tmp/l"$node1"-regtest connect "$L2_NODE_ID"@localhost:"$L2_NODE_PORT" > /dev/null

		L1_WALLET_ADDR=$($LCLI -F --lightning-dir=/tmp/l"$node1"-regtest newaddr | sed -n 's/^bech32=\(.*\)/\1/p')

		ensure_bitcoind_funds

		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest "$WALLET" sendtoaddress "$L1_WALLET_ADDR" 1 > /dev/null

		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest generatetoaddress 1 "$ADDRESS" > /dev/null

		printf "%s" "Waiting for lightning node funds... "

		while ! $LCLI -F --lightning-dir=/tmp/l"$node1"-regtest listfunds | grep -q "outputs"
		do
			sleep 1
		done

		echo "found."

		printf "%s" "Funding channel from node " "$node1" " to node " "$node2"". "

		$LCLI --lightning-dir=/tmp/l"$node1"-regtest fundchannel "$L2_NODE_ID" 1000000 > /dev/null

		bitcoin-cli -datadir="$PATH_TO_BITCOIN" -regtest generatetoaddress 6 "$ADDRESS" > /dev/null

		printf "%s" "Waiting for confirmation... "

		while ! $LCLI -F --lightning-dir=/tmp/l"$node1"-regtest listchannels | grep -q "channels"
		do
			sleep 1
		done

		echo "done."

	done
}

stop_nodes() {
	network=${1:-regtest}
	if [ -n "$LN_NODES" ]; then
		for i in $(seq "$LN_NODES"); do
			test ! -f "/tmp/l$i-$network/lightningd-$network.pid" || \
				(kill "$(cat "/tmp/l$i-$network/lightningd-$network.pid")"; \
				rm "/tmp/l$i-$network/lightningd-$network.pid")
			unalias "l$i-cli"
			unalias "l$i-log"
		done
	fi
}

stop_ln() {
	stop_nodes "$@"
	test ! -f "$PATH_TO_BITCOIN/regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_BITCOIN/regtest/bitcoind.pid")"; \
		rm "$PATH_TO_BITCOIN/regtest/bitcoind.pid")

	unset LN_NODES
	unalias bt-cli
}

destroy_ln() {
	network=${1:-regtest}
	rm -rf /tmp/l[0-9]*-"$network"
}

start_elem() {
	if [ -z "$PATH_TO_ELEMENTS" ]; then
		if [ -d "$HOME/.elements" ]; then
			PATH_TO_ELEMENTS="$HOME/.elements"
		else
			echo "\$PATH_TO_ELEMENTS not set to a .elements dir" >&2
			return
		fi
	fi

	test -f "$PATH_TO_ELEMENTS/liquid-regtest/bitcoin.pid" || \
		elementsd -chain=liquid-regtest -printtoconsole -logtimestamps -nolisten -validatepegin=0 -con_blocksubsidy=5000000000 -daemon

	# Wait for it to start.
	while ! elements-cli -chain=liquid-regtest ping 2> /tmp/null; do echo "awaiting elementsd..." && sleep 1; done

	# Kick it out of initialblockdownload if necessary
	if elements-cli -chain=liquid-regtest getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		elements-cli -chain=liquid-regtest generatetoaddress 1 "$(elements-cli -chain=liquid-regtest getnewaddress)" > /dev/null
	fi
	alias et-cli='elements-cli -chain=liquid-regtest'

	if [ -z "$1" ]; then
		nodes=2
	else
		nodes="$1"
	fi
	start_nodes "$nodes" liquid-regtest
	echo "	et-cli, stop_elem"
}


stop_elem() {
	stop_nodes "$1" liquid-regtest
	test ! -f "$PATH_TO_ELEMENTS/liquid-regtest/bitcoind.pid" || \
		(kill "$(cat "$PATH_TO_ELEMENTS/liquid-regtest/bitcoind.pid")"; \
		rm "$PATH_TO_ELEMENTS/liquid-regtest/bitcoind.pid")

	unset LN_NODES
	unalias et-cli
}

connect() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		printf "usage: connect 1 2\n"
	else
		to=$($LCLI --lightning-dir="/tmp/l$2-$network" -F getinfo | grep '^\(id\|binding\[0\]\.\(address\|port\)\)' | cut -d= -f2- | tr '\n' ' ' | (read -r ID ADDR PORT; echo "$ID@${ADDR}:$PORT"))
		$LCLI --lightning-dir="/tmp/l$1-$network" connect "$to"
	fi
}

echo Useful commands:
echo "  start_ln 3: start three nodes, l1, l2, l3"
echo "  connect 1 2: connect l1 and l2"
echo "  fund_nodes: connect all nodes with channels, in a row"
echo "  stop_ln: shutdown"
echo "  destroy_ln: remove ln directories"
