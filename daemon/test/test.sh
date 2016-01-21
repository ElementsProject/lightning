#! /bin/sh -ex

# We steal the test-cli scripts.
cd test-cli

. scripts/vars.sh

scripts/setup.sh

DIR1=/tmp/lightning.$$.1
DIR2=/tmp/lightning.$$.2

REDIR1="$DIR1/output"
REDIR2="$DIR2/output"

if [ x"$1" = x"--valgrind" ]; then
    PREFIX1="valgrind --vgdb-error=1"
    PREFIX2="valgrind --vgdb-error=1"
    REDIR1="/dev/tty"
    REDIR2="/dev/tty"
    shift
elif [ x"$1" = x"--gdb1" ]; then
    PREFIX1="gdb --args -ex run"
    REDIR1="/dev/tty"
    shift
elif [ x"$1" = x"--gdb2" ]; then
    PREFIX2="gdb --args -ex run"
    REDIR2="/dev/tty"
    shift
fi

LCLI1="../daemon/lightning-cli --lightning-dir=$DIR1"
LCLI2="../daemon/lightning-cli --lightning-dir=$DIR2"

check_status()
{
    us_pay=$1
    us_fee=$2
    us_htlcs="$3"
    them_pay=$4
    them_fee=$5
    them_htlcs="$6"

    if $LCLI1 getpeers | tr -s '\012\011 ' ' ' | fgrep -q '"channel" : { "us" : { "pay" : '$us_pay', "fee" : '$us_fee', "htlcs" : [ '"$us_htlcs"'] }, "them" : { "pay" : '$them_pay', "fee" : '$them_fee', "htlcs" : [ '"$them_htlcs"'] } }'; then :; else
	echo Cannot find peer1: '"channel" : { "us" : { "pay" : '$us_pay', "fee" : '$us_fee', "htlcs" : [ '"$us_htlcs"'] }, "them" : { "pay" : '$them_pay', "fee" : '$them_fee', "htlcs" : [ '"$them_htlcs"'] } }' >&2
	$LCLI1 getpeers | tr -s '\012\011 ' ' ' >&2
	return 1
    fi

    if $LCLI2 getpeers | tr -s '\012\011 ' ' ' | fgrep -q '"channel" : { "us" : { "pay" : '$them_pay', "fee" : '$them_fee', "htlcs" : [ '"$them_htlcs"'] }, "them" : { "pay" : '$us_pay', "fee" : '$us_fee', "htlcs" : [ '"$us_htlcs"'] } }'; then :; else
	echo Cannot find peer2: '"channel" : { "us" : { "pay" : '$them_pay', "fee" : '$them_fee', "htlcs" : [ '"$them_htlcs"'] }, "them" : { "pay" : '$us_pay', "fee" : '$us_fee', "htlcs" : [ '"$us_htlcs"'] } }' >&2
	$LCLI2 getpeers | tr -s '\012\011 ' ' ' >&2
	return 1
    fi
}

all_ok()
{
    scripts/shutdown.sh

    trap "rm -rf $DIR1 $DIR2" EXIT
    exit 0
}
    
trap "echo Results in $DIR1 and $DIR2" EXIT
mkdir $DIR1 $DIR2
$PREFIX1 ../daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR1 > $REDIR1 &
$PREFIX2 ../daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR2 > $REDIR2 &

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

ID1=`$LCLI1 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'`
ID2=`$LCLI2 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'`

PORT2=`$LCLI2 getlog | sed -n 's/.*on port \([0-9]*\).*/\1/p'`

$LCLI1 connect localhost $PORT2 999999
sleep 2

# Expect them to be waiting for anchor.
$LCLI1 getpeers | grep STATE_OPEN_WAITING_OURANCHOR
$LCLI2 getpeers | grep STATE_OPEN_WAITING_THEIRANCHOR

if [ "x$1" = x"--timeout-anchor" ]; then
    # Timeout before anchor committed.
    TIME=$((`date +%s` + 7200 + 3 * 1200 + 1))

    # This will crash in a moment.
    $LCLI1 dev-mocktime $TIME

    # This will crash immediately
    if $LCLI2 dev-mocktime $TIME >&2; then
	echo Node2 did not crash >&2
	exit 1
    fi

    sleep 1

    # Check crash logs
    if [ ! -f $DIR1/crash.log ]; then
	echo Node1 did not crash >&2
	exit 1
    fi
    if [ ! -f $DIR2/crash.log ]; then
	echo Node2 did not crash >&2
	exit 1
    fi

    fgrep 'Entered error state STATE_ERR_ANCHOR_TIMEOUT' $DIR2/crash.log
    all_ok
fi
    

# Now make it pass anchor.
$CLI generate 3

# They poll every second, so give them time to process.
sleep 2

$LCLI1 getpeers | grep STATE_NORMAL_HIGHPRIO
$LCLI2 getpeers | grep STATE_NORMAL_LOWPRIO

check_status 949999000 50000000 "" 0 0 ""

EXPIRY=$(( $(date +%s) + 1000))
SECRET=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd
RHASH=`$LCLI1 dev-rhash $SECRET | sed 's/.*"\([0-9a-f]*\)".*/\1/'`
$LCLI1 newhtlc $ID2 1000000 $EXPIRY $RHASH

# Check channel status
check_status 948999000 50000000 '{ "msatoshis" : 1000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' 0 0 ""

$LCLI2 fulfillhtlc $ID1 $SECRET

# We've transferred the HTLC amount to 2, who now has to pay fees.
check_status 949999000 49000000 "" 0 1000000 ""

# A new one, at 10x the amount.
$LCLI1 newhtlc $ID2 10000000 $EXPIRY $RHASH

# Check channel status
check_status 939999000 49000000 '{ "msatoshis" : 10000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' 0 1000000 ""

$LCLI2 failhtlc $ID1 $RHASH

# Back to how we were before.
check_status 949999000 49000000 "" 0 1000000 ""

# Same again, but this time it expires.
$LCLI1 newhtlc $ID2 10000000 $EXPIRY $RHASH

# Check channel status
check_status 939999000 49000000 '{ "msatoshis" : 10000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' 0 1000000 ""

# Make sure node1 accepts the expiry packet.
$LCLI1 dev-mocktime $(($EXPIRY))

# This should make node2 send it.
$LCLI2 dev-mocktime $(($EXPIRY + 31))
sleep 1

# Back to how we were before.
check_status 949999000 49000000 "" 0 1000000 ""

$LCLI1 close $ID2

sleep 1

# They should be waiting for close.
$LCLI1 getpeers | tr -s '\012\011 ' ' ' | fgrep '"STATE_CLOSE_WAIT_CLOSE"'
$LCLI2 getpeers | tr -s '\012\011 ' ' ' | fgrep '"STATE_CLOSE_WAIT_CLOSE"'

# Give it 99 blocks.
$CLI generate 99

# Make sure they saw it!
$LCLI1 dev-mocktime $(($EXPIRY + 32))
$LCLI2 dev-mocktime $(($EXPIRY + 32))
sleep 1
$LCLI1 getpeers | tr -s '\012\011 ' ' ' | fgrep '"STATE_CLOSE_WAIT_CLOSE"'
$LCLI2 getpeers | tr -s '\012\011 ' ' ' | fgrep '"STATE_CLOSE_WAIT_CLOSE"'

# Now the final one.
$CLI generate 1
TIME=$(($EXPIRY + 33))
$LCLI1 dev-mocktime $TIME
$LCLI2 dev-mocktime $TIME
sleep 1

$LCLI1 getpeers | tr -s '\012\011 ' ' ' | fgrep '"peers" : [ ]'
$LCLI2 getpeers | tr -s '\012\011 ' ' ' | fgrep '"peers" : [ ]'

$LCLI1 stop
$LCLI2 stop

all_ok
