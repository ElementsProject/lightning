#! /bin/sh
# Query bitcoind to get (first) unspent output to spend.

set -e

. `dirname $0`/vars.sh
INIT=$1

case $STYLE in
    alpha)
	# This is a one-shot in alpha, it seems.
	$CLI setgenerate true
	;;
    bitcoin)
	# Initially we need 100 blocks so coinbase matures, giving us funds.
	if [ -n "$INIT" ]; then
	    $CLI generate 101
	else
	    $CLI generate 1
	fi
	;;
esac
