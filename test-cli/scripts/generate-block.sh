#! /bin/sh
# Query bitcoind to get (first) unspent output to spend.

set -e

. `dirname $0`/vars.sh

case $STYLE in
    alpha)
	# This is a one-shot in alpha, it seems.
	$CLI setgenerate true
	;;
    bitcoin)
	$CLI generate 1
	;;
esac
