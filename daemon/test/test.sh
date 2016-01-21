#! /bin/sh -e

# We steal the test-cli scripts.
cd test-cli

. scripts/vars.sh

scripts/setup.sh

DIR1=/tmp/lightning.$$.1
DIR2=/tmp/lightning.$$.2

LCLI1="../daemon/lightning-cli --lightning-dir=$DIR1"
LCLI2="../daemon/lightning-cli --lightning-dir=$DIR2"

trap "echo Results in $DIR1 and $DIR2" EXIT
mkdir $DIR1 $DIR2
../daemon/lightningd --log-level=debug --lightning-dir=$DIR1 > $DIR1/output &
../daemon/lightningd --log-level=debug --lightning-dir=$DIR2 > $DIR2/output &

i=0
while ! $LCLI1 getlog | grep Hello; do
    sleep 1
    i=$(($i + 1))
    if [ $i -gt 10 ]; then
	echo Failed to start daemon 1 >&2
	exit 1
    fi
done

while ! $LCLI2 getlog | grep 'listener on port'; do
    sleep 1
    i=$(($i + 1))
    if [ $i -gt 10 ]; then
	echo Failed to start daemon 2 >&2
	exit 1
    fi
done

PORT2=`$LCLI2 getlog | sed -n 's/.*on port \([0-9]*\).*/\1/p'`

$LCLI1 connect localhost $PORT2 999999
sleep 1

# Expect them to be waiting for anchor.
$LCLI1 getpeers | grep STATE_OPEN_WAITING_OURANCHOR
$LCLI2 getpeers | grep STATE_OPEN_WAITING_THEIRANCHOR

# Now make it pass anchor.
$CLI generate 3

# FIXME: Speed this up!
sleep 30

$LCLI1 getpeers | grep STATE_NORMAL_HIGHPRIO
$LCLI2 getpeers | grep STATE_NORMAL_LOWPRIO

$LCLI1 stop
$LCLI2 stop
scripts/shutdown.sh

trap "rm -rf $DIR1 $DIR2" EXIT

