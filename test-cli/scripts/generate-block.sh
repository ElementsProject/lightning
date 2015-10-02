#! /bin/sh
# Generate a block.

set -e

. `dirname $0`/vars.sh
INIT=$1

case $STYLE in
    alpha)
	# This is a one-shot in alpha, it seems.
	$CLI setgenerate true
	# Avoid median time bug by generating 11 blocks
	if [ -n "$INIT" ]; then
	    for i in `seq 11`; do $CLI setgenerate true; done
	fi
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
