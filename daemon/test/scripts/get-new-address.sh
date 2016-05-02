#! /bin/sh

# Alpha defaults to confidential addresses.  We don't handle those (yet?)
# so extract the unconfidential address.
set -e

. `dirname $0`/vars.sh

case $STYLE in
    alpha)
	A=`$CLI getnewaddress`
	$CLI validateaddress $A | sed -n 's/.*"unconfidential" : "\([A-Za-z0-9]*\)".*/\1/p'
	;;
    bitcoin)
	$CLI getnewaddress
	;;
esac
