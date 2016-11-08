#! /bin/sh -e

. `dirname $0`/vars.sh

[ ! -f $DATADIR/regtest/bitcoind.pid ] || BITCOIN_PID=`cat $DATADIR/regtest/bitcoind.pid`

$CLI stop
sleep 1 # Make sure socket is closed.

# Now make sure it's dead.
if [ -n "$BITCOIN_PID" ]; then kill -9 $BITCOIN_PID 2>/dev/null || true; fi
