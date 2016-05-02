#! /bin/sh -e

# Wherever we are, we want to be in daemon/test dir.
cd `git rev-parse --show-toplevel`/daemon/test

. scripts/vars.sh

scripts/setup.sh

DIR1=/tmp/lightning.$$.1
DIR2=/tmp/lightning.$$.2

REDIR1="$DIR1/output"
REDIR2="$DIR2/output"
REDIRERR1="$DIR1/errors"
REDIRERR2="$DIR2/errors"
FGREP="fgrep -q"

# We inject 0.01 bitcoin, but then fees (estimatefee fails and we use a
# fee rate as per the close tx).
AMOUNT=995940000

# Default fee rate per kb.
FEE_RATE=200000

# Fee in millisatoshi if we have no htlcs (note rounding to make it even)
NO_HTLCS_FEE=$((338 * $FEE_RATE / 2000 * 2000))
ONE_HTLCS_FEE=$(( (338 + 32) * $FEE_RATE / 2000 * 2000))
EXTRA_FEE=$(($ONE_HTLCS_FEE - $NO_HTLCS_FEE))

# Always use valgrind.
PREFIX="valgrind -q --error-exitcode=7"

while [ $# != 0 ]; do
    case x"$1" in
	x"--valgrind-vgdb")
	    PREFIX="valgrind --vgdb-error=1"
	    REDIR1="/dev/tty"
	    REDIRERR1="/dev/tty"
	    REDIR2="/dev/tty"
	    REDIRERR2="/dev/tty"
	    ;;
	x"--gdb1")
	    GDB1=1
	    ;;
	x"--gdb2")
	    GDB2=1
	    ;;
	x"--timeout-anchor")
	    TIMEOUT_ANCHOR=1
	    ;;
	x"--verbose")
	    VERBOSE=1
	    ;;
	*)
	    echo Unknown arg "$1" >&2
	    exit 1
    esac
    shift
done

LCLI1="../lightning-cli --lightning-dir=$DIR1"
LCLI2="../lightning-cli --lightning-dir=$DIR2"

if [ -n "$VERBOSE" ]; then
    FGREP="fgrep"
else
    # Suppress command output.
    exec >/dev/null
fi

lcli1()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI1 "$@" >&2
    fi
    $LCLI1 "$@"
}

lcli2()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI2 "$@" >&2
    fi
    $LCLI2 "$@"
}

check_status_single()
{
    lcli="$1"
    us_pay=$2
    us_fee=$3
    us_htlcs="$4"
    them_pay=$5
    them_fee=$6
    them_htlcs="$7"

    if $lcli getpeers | tr -s '\012\011 ' ' ' | $FGREP '"our_amount" : '$us_pay', "our_fee" : '$us_fee', "their_amount" : '$them_pay', "their_fee" : '$them_fee', "our_htlcs" : [ '"$us_htlcs"'], "their_htlcs" : [ '"$them_htlcs"']'; then :; else
	echo Cannot find $lcli output: '"our_amount" : '$us_pay', "our_fee" : '$us_fee', "their_amount" : '$them_pay', "their_fee" : '$them_fee', "our_htlcs" : [ '"$us_htlcs"'], "their_htlcs" : [ '"$them_htlcs"']' >&2
	$lcli getpeers | tr -s '\012\011 ' ' ' >&2
	return 1
    fi
}

check_status()
{
    us_pay=$1
    us_fee=$2
    us_htlcs="$3"
    them_pay=$4
    them_fee=$5
    them_htlcs="$6"

    check_status_single lcli1 "$us_pay" "$us_fee" "$us_htlcs" "$them_pay" "$them_fee" "$them_htlcs" 
    check_status_single lcli2 "$them_pay" "$them_fee" "$them_htlcs" "$us_pay" "$us_fee" "$us_htlcs"
}

check_staged()
{
    lcli="$1"
    num_htlcs="$2"

    if $lcli getpeers | tr -s '\012\011 ' ' ' | $FGREP '"staged_changes" : '$num_htlcs; then :; else
	echo Cannot find $lcli output: '"staged_changes" : '$num_htlcs >&2
	$lcli getpeers | tr -s '\012\011 ' ' ' >&2
	return 1
    fi
}

check_tx_spend()
{
    $CLI generate 1
    if [ $($CLI getblock $($CLI getbestblockhash) | grep -c '^    "') -gt 1 ]; then
	:
    else
	echo "Block didn't include tx:" >&2
	$CLI getblock $($CLI getbestblockhash) >&2
	exit 1
    fi
}

check_peerstate()
{
    if $1 getpeers | $FGREP -w $2; then :
    else
	echo "$1" not in state "$2": >&2
	$1 getpeers >&2
	exit 1
    fi
}

check_no_peers()
{
    if $1 getpeers | tr -s '\012\011 ' ' ' | $FGREP '"peers" : [ ]'; then :
    else
	echo "$1" still has peers: >&2
	$1 getpeers >&2
	exit 1
    fi
}
    
all_ok()
{
    # Look for valgrind errors.
    if grep ^== $DIR1/errors; then exit 1; fi
    if grep ^== $DIR2/errors; then exit 1; fi
    scripts/shutdown.sh

    trap "rm -rf $DIR1 $DIR2" EXIT
    exit 0
}

trap "echo Results in $DIR1 and $DIR2 >&2; cat $DIR1/errors $DIR2/errors >&2" EXIT
mkdir $DIR1 $DIR2
if [ -n "$GDB1" ]; then
    echo Press return once you run: gdb --args daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR1 --bitcoin-datadir=$DATADIR
    read REPLY
else
    $PREFIX ../lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR1 --bitcoin-datadir=$DATADIR > $REDIR1 2> $REDIRERR1 &
fi

if [ -n "$GDB2" ]; then
    echo Press return once you run: gdb --args daemon/lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR2 --bitcoin-datadir=$DATADIR
    read REPLY
else
    $PREFIX ../lightningd --log-level=debug --bitcoind-poll=1 --min-expiry=900 --lightning-dir=$DIR2 --bitcoin-datadir=$DATADIR > $REDIR2 2> $REDIRERR2 &
fi

i=0
while ! $LCLI1 getlog 2>/dev/null | $FGREP Hello; do
    sleep 1
    i=$(($i + 1))
    if [ $i -gt 10 ]; then
	echo Failed to start daemon 1 >&2
	exit 1
    fi
done

while ! $LCLI2 getlog 2>/dev/null | $FGREP 'listener on port'; do
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

# Make a payment into a P2SH for anchor.
P2SHADDR=`$LCLI1 newaddr | sed -n 's/{ "address" : "\(.*\)" }/\1/p'`
TXID=`$CLI sendtoaddress $P2SHADDR 0.01`
TX=`$CLI getrawtransaction $TXID`

lcli1 connect localhost $PORT2 $TX
sleep 5

# Expect them to be waiting for anchor.
check_peerstate lcli1 STATE_OPEN_WAITING_OURANCHOR
check_peerstate lcli2 STATE_OPEN_WAITING_THEIRANCHOR

if [ -n "$TIMEOUT_ANCHOR" ]; then
    # Anchor gets 1 commit.
    check_tx_spend

    # Timeout before anchor committed deep enough.
    TIME=$((`date +%s` + 7200 + 3 * 1200 + 1))

    lcli1 dev-mocktime $TIME

    # This will crash immediately
    if $LCLI2 dev-mocktime $TIME 2> /dev/null; then
	echo Node2 did not crash >&2
	exit 1
    fi
    $FGREP 'Entered error state STATE_ERR_ANCHOR_TIMEOUT' $DIR2/crash.log

    sleep 2

    # It should send out commit tx.
    check_peerstate lcli1 STATE_CLOSE_WAIT_OURCOMMIT

    # Generate a block (should include commit tx)
    check_tx_spend
   
    # Now "wait" for 1 day, which is what node2 asked for on commit.
    TIME=$(($TIME + 24 * 60 * 60))
    lcli1 dev-mocktime $TIME

    # Move bitcoind median time as well, so CSV moves.
    $CLI setmocktime $TIME
    $CLI generate 6
    
    # Due to laziness, we trigger by block generation.
    TIME=$(($TIME + 1))
    lcli1 dev-mocktime $TIME
    sleep 2

    # Sometimes it skips poll because it's busy.  Do it again.
    TIME=$(($TIME + 1))
    lcli1 dev-mocktime $TIME
    sleep 2
    
    check_peerstate lcli1 STATE_CLOSE_WAIT_SPENDOURS
    
    # Now it should have spent the commit tx.
    check_tx_spend

    # 99 more blocks pass...
    $CLI generate 99
    TIME=$(($TIME + 1))
    lcli1 dev-mocktime $TIME
    sleep 5

    # Considers it all done now.
    check_no_peers lcli1

    lcli1 stop
    all_ok
fi
    
# Now make it pass anchor (should be in first block, then two more to bury it)
check_tx_spend
$CLI generate 2

# They poll every second, so give them time to process.
sleep 2

check_peerstate lcli1 STATE_NORMAL
check_peerstate lcli2 STATE_NORMAL

A_AMOUNT=$(($AMOUNT - $NO_HTLCS_FEE))
A_FEE=$NO_HTLCS_FEE
B_AMOUNT=0
B_FEE=0
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

EXPIRY=$(( $(date +%s) + 1000))
SECRET=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd
RHASH=`lcli1 dev-rhash $SECRET | sed 's/.*"\([0-9a-f]*\)".*/\1/'`
lcli1 newhtlc $ID2 1000000 $EXPIRY $RHASH

# Nothing should have changed!
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""
# But 2 should register a staged htlc.
check_staged lcli2 1

# Now commit it.
lcli1 commit $ID2

# Node 1 hasn't got it committed, but node2 should have told it to stage.
check_status_single lcli1 $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""
check_staged lcli1 1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - 1000000))
A_FEE=$(($A_FEE + $EXTRA_FEE))

# Node 2 has it committed.
check_status_single lcli2 $B_AMOUNT $B_FEE "" $A_AMOUNT $A_FEE '{ "msatoshis" : 1000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } '

# Now node2 gives commitment to node1.
lcli2 commit $ID1
check_status $A_AMOUNT $A_FEE '{ "msatoshis" : 1000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

lcli2 fulfillhtlc $ID1 $SECRET
lcli2 commit $ID1
lcli1 commit $ID2

# We've transferred the HTLC amount to 2, who now has to pay fees,
# so no net change for A who saves on fees.
B_FEE=1000000
# With no HTLCs, extra fee no longer required.
A_FEE=$(($A_FEE - $EXTRA_FEE - $B_FEE))
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + 1000000))

check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# A new one, at 10x the amount.
lcli1 newhtlc $ID2 10000000 $EXPIRY $RHASH
lcli1 commit $ID2
lcli2 commit $ID1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - 10000000))
A_FEE=$(($A_FEE + $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE '{ "msatoshis" : 10000000, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

lcli2 failhtlc $ID1 $RHASH
lcli2 commit $ID1
lcli1 commit $ID2

# Back to how we were before.
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + 10000000))
A_FEE=$(($A_FEE - $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Same again, but this time it expires.
lcli1 newhtlc $ID2 10000001 $EXPIRY $RHASH
lcli1 commit $ID2
lcli2 commit $ID1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - 10000001))
A_FEE=$(($A_FEE + $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE '{ "msatoshis" : 10000001, "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

# Make sure node1 accepts the expiry packet.
lcli1 dev-mocktime $(($EXPIRY))

# This should make node2 send it.
lcli2 dev-mocktime $(($EXPIRY + 31))
lcli2 commit $ID1
lcli1 commit $ID2
sleep 1

# Back to how we were before.
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + 10000001))
A_FEE=$(($A_FEE - $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

lcli1 close $ID2

sleep 1

# They should be waiting for close.
check_peerstate lcli1 STATE_CLOSE_WAIT_CLOSE
check_peerstate lcli2 STATE_CLOSE_WAIT_CLOSE

# Give it 99 blocks.
$CLI generate 99

# Make sure they saw it!
lcli1 dev-mocktime $(($EXPIRY + 32))
lcli2 dev-mocktime $(($EXPIRY + 32))
sleep 5
check_peerstate lcli1 STATE_CLOSE_WAIT_CLOSE
check_peerstate lcli2 STATE_CLOSE_WAIT_CLOSE

# Now the final one.
$CLI generate 1
TIME=$(($EXPIRY + 33))
lcli1 dev-mocktime $TIME
lcli2 dev-mocktime $TIME
sleep 2

check_no_peers lcli1
check_no_peers lcli2

lcli1 stop
lcli2 stop

all_ok
