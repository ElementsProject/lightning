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

# Always use valgrind if available.
[ -n "$NO_VALGRIND" ] || PREFIX="valgrind -q --error-exitcode=7"

while [ $# != 0 ]; do
    case x"$1" in
	x"--valgrind-vgdb")
	    [ -n "$NO_VALGRIND" ] || PREFIX="valgrind --vgdb-error=1"
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
	x"--dump-onchain")
	    DUMP_ONCHAIN=1
	    ;;
	x"--steal")
	    STEAL=1
	    ;;
	x"--manual-commit")
	    MANUALCOMMIT=1
	    ;;
	x"--normal")
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

# Usage: <cmd to test>...
check()
{
    local i=0
    while ! eval "$@"; do
	# Try making time pass for the nodes (if on mocktime), then sleeping.
	if [ -n "$MOCKTIME" ]; then 
	    MOCKTIME=$(($MOCKTIME + 1))
	    # Some tests kill nodes, so ignore failure here.
	    lcli1 dev-mocktime $MOCKTIME > /dev/null 2>&1 || true
	    lcli2 dev-mocktime $MOCKTIME > /dev/null 2>&1 || true
	fi
	sleep 1
	i=$(($i + 1))
	if [ $i = 20 ]; then
	    return 1
	fi
    done
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

    if check "$lcli getpeers | tr -s '\012\011\" ' ' ' | $FGREP \"our_amount : $us_pay, our_fee : $us_fee, their_amount : $them_pay, their_fee : $them_fee, our_htlcs : [ $us_htlcs], their_htlcs : [ $them_htlcs]\""; then :; else
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
    what="$2"
    num_htlcs="$3"

    if check "$lcli getpeers | tr -s '\012\011\" ' ' ' | $FGREP ${what}_'staged_changes : '$num_htlcs"; then :; else
	echo Cannot find $lcli output: '"'${what}_'staged_changes" : '$num_htlcs >&2
	$lcli getpeers | tr -s '\012\011 ' ' ' >&2
	return 1
    fi
}

check_tx_spend()
{
    if check "$CLI getrawmempool | $FGREP '\"'"; then :;
    else
	echo "No tx in mempool:" >&2
	$CLI getrawmempool >&2
	exit 1
    fi
}

check_peerstate()
{
    if check "$1 getpeers | $FGREP -w $2"; then :
    else
	echo "$1" not in state "$2": >&2
	$1 getpeers >&2
	exit 1
    fi
}

check_peerconnected()
{
    if check "$1 getpeers | tr -s '\012\011\" ' ' ' | $FGREP -w 'connected : '$2"; then :
    else
	echo "$1" not connected "$2": >&2
	$1 getpeers >&2
	exit 1
    fi
}

check_no_peers()
{
    if check "$1 getpeers | tr -s '\012\011\" ' ' ' | $FGREP 'peers : [ ]'"; then :
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

if [ -n "$MANUALCOMMIT" ]; then
    # Aka. never. 
    COMMIT_TIME=1h
else
    COMMIT_TIME=10ms
fi

cat > $DIR1/config <<EOF
log-level=debug
bitcoind-poll=1s
min-expiry=900
bitcoin-datadir=$DATADIR
locktime=600
commit-time=$COMMIT_TIME
EOF

cat > $DIR2/config <<EOF
log-level=debug
bitcoind-poll=1s
min-expiry=900
bitcoin-datadir=$DATADIR
locktime=600
commit-time=$COMMIT_TIME
EOF

if [ -n "$GDB1" ]; then
    echo Press return once you run: gdb --args daemon/lightningd --lightning-dir=$DIR1 >&2
    read REPLY
else
    $PREFIX ../lightningd --lightning-dir=$DIR1 > $REDIR1 2> $REDIRERR1 &
fi

if [ -n "$GDB2" ]; then
    echo Press return once you run: gdb --args daemon/lightningd --lightning-dir=$DIR2 >&2
    read REPLY
else
    $PREFIX ../lightningd --lightning-dir=$DIR2 > $REDIR2 2> $REDIRERR2 &
fi

if ! check "$LCLI1 getlog 2>/dev/null | $FGREP Hello"; then
    echo Failed to start daemon 1 >&2
    exit 1
fi

if ! check "$LCLI2 getlog 2>/dev/null | $FGREP Hello"; then
    echo Failed to start daemon 2 >&2
    exit 1
fi

ID1=`$LCLI1 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'`
ID2=`$LCLI2 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'`

PORT2=`$LCLI2 getlog | sed -n 's/.*on port \([0-9]*\).*/\1/p'`

# Make a payment into a P2SH for anchor.
P2SHADDR=`$LCLI1 newaddr | sed -n 's/{ "address" : "\(.*\)" }/\1/p'`
TXID=`$CLI sendtoaddress $P2SHADDR 0.01`
TX=`$CLI getrawtransaction $TXID`
$CLI generate 1

lcli1 connect localhost $PORT2 $TX

# Expect them to be waiting for anchor.
check_peerstate lcli1 STATE_OPEN_WAITING_OURANCHOR
check_peerstate lcli2 STATE_OPEN_WAITING_THEIRANCHOR

if [ -n "$TIMEOUT_ANCHOR" ]; then
    # Check anchor emitted, not mined deep enough.
    check_tx_spend lcli1
    $CLI generate 2

    # Timeout before anchor committed.
    MOCKTIME=$((`date +%s` + 7200 + 3 * 1200 + 1))

    lcli1 dev-mocktime $MOCKTIME

    # This will crash immediately
    if $LCLI2 dev-mocktime $MOCKTIME 2> /dev/null; then
	echo Node2 did not crash >&2
	exit 1
    fi
    $FGREP 'Entered error state STATE_ERR_ANCHOR_TIMEOUT' $DIR2/crash.log

    # Node1 should be disconnected.
    check_peerconnected lcli1 false
    
    # It should send out commit tx; mine it.
    check_tx_spend lcli1
    $CLI generate 1

    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_OUR_UNILATERAL

    # Now "wait" for 1 day, which is what node2 asked for on commit.
    MOCKTIME=$(($MOCKTIME + 24 * 60 * 60 - 1))
    lcli1 dev-mocktime $MOCKTIME

    # Move bitcoind median time as well, so CSV moves.
    $CLI setmocktime $MOCKTIME
    $CLI generate 6

    # Now it should have spent the commit tx.
    check_tx_spend lcli1

    # 100 blocks pass...
    $CLI generate 100
    MOCKTIME=$(($MOCKTIME + 1))
    lcli1 dev-mocktime $MOCKTIME

    # Considers it all done now.
    check_no_peers lcli1

    lcli1 stop
    all_ok
fi

# Now make it pass anchor (should be in mempool: three blocks bury it)
check_tx_spend lcli1
$CLI generate 3

check_peerstate lcli1 STATE_NORMAL
check_peerstate lcli2 STATE_NORMAL

A_AMOUNT=$(($AMOUNT - $NO_HTLCS_FEE))
A_FEE=$NO_HTLCS_FEE
B_AMOUNT=0
B_FEE=0
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# This is 10,000 satoshi, so not dust!
HTLC_AMOUNT=10000000

EXPIRY=$(( $(date +%s) + 1000))
SECRET=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd
RHASH=`lcli1 dev-rhash $SECRET | sed 's/.*"\([0-9a-f]*\)".*/\1/'`
lcli1 newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH

if [ -n "$MANUALCOMMIT" ]; then
    # Nothing should have changed!
    check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""
    # But they should register a staged htlc.
    check_staged lcli2 local 1
    check_staged lcli1 remote 1

    # Now commit it.
    lcli1 commit $ID2

    # Node 1 hasn't got it committed, but node2 should have told it to stage.
    check_status_single lcli1 $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""
    check_staged lcli1 local 1
    check_staged lcli2 remote 1

    # Check channel status
    A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
    A_FEE=$(($A_FEE + $EXTRA_FEE))

    # Node 2 has it committed.
    check_status_single lcli2 $B_AMOUNT $B_FEE "" $A_AMOUNT $A_FEE '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } '

    # Now node2 gives commitment to node1.
    lcli2 commit $ID1
else
    A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
    A_FEE=$(($A_FEE + $EXTRA_FEE))
fi

# Both should have committed tx.
check_status $A_AMOUNT $A_FEE '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

if [ -n "$STEAL" ]; then
    $LCLI1 dev-signcommit $ID2 >&2
    STEAL_TX=`$LCLI1 dev-signcommit $ID2 | cut -d\" -f4`
fi

if [ -n "$DUMP_ONCHAIN" ]; then
    # make node1 disconnect with node2.
    lcli1 dev-disconnect $ID2
    check_peerconnected lcli1 false

    # lcli1 should have sent out commitment tx
    check_peerstate lcli1 STATE_ERR_BREAKDOWN
    check_tx_spend lcli1

    # Mine it.
    $CLI generate 1
    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_OUR_UNILATERAL
    check_peerstate lcli2 STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL

    # both still know about htlc
    check_status $A_AMOUNT $A_FEE '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

    # Move bitcoind's time so CSV timeout has expired.
    $CLI setmocktime $((`date +%s` + 600))
    $CLI generate 6

    # Now, lcli1 should spend its own output.
    check_tx_spend lcli1
    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_OUR_UNILATERAL

    # Move bitcoind's time so HTLC has expired.
    $CLI setmocktime $(($EXPIRY + 1))
    $CLI generate 6

    # lcli1 should have gotten HTLC back.
    check_tx_spend lcli1

    # Now, after 100 blocks, should all be concluded.
    $CLI generate 100

    # Both consider it all done now.
    check_no_peers lcli1

    lcli1 stop
    all_ok
fi
    
lcli2 fulfillhtlc $ID1 $SECRET
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2

# We've transferred the HTLC amount to 2, who now has to pay fees,
# so no net change for A who saves on fees.
B_FEE=$HTLC_AMOUNT
# With no HTLCs, extra fee no longer required.
A_FEE=$(($A_FEE - $EXTRA_FEE - $B_FEE))
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + $HTLC_AMOUNT))

check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# A new one, at 10x the amount.
HTLC_AMOUNT=100000000

lcli1 newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
A_FEE=$(($A_FEE + $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

lcli2 failhtlc $ID1 $RHASH
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2

# Back to how we were before.
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + $HTLC_AMOUNT))
A_FEE=$(($A_FEE - $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Same again, but this time it expires.
HTLC_AMOUNT=10000001
lcli1 newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
A_FEE=$(($A_FEE + $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

# Make sure node1 accepts the expiry packet.
MOCKTIME=$(($EXPIRY))
lcli1 dev-mocktime $MOCKTIME

# This should make node2 send it.
MOCKTIME=$(($MOCKTIME + 31))
lcli2 dev-mocktime $MOCKTIME
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2

# Back to how we were before.
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + $HTLC_AMOUNT))
A_FEE=$(($A_FEE - $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

if [ -n "$STEAL" ]; then
    # Send out old commit tx from peer 1.
    $CLI sendrawtransaction $STEAL_TX
    $CLI generate 1

    # Node1 should get really upset; node2 should steal the transaction.
    check_peerstate lcli1 STATE_ERR_INFORMATION_LEAK
    check_peerstate lcli2 STATE_CLOSE_ONCHAIN_CHEATED
    check_tx_spend lcli2

    # Give it 100 blocks.
    $CLI generate 100

    check_no_peers lcli2

    lcli1 stop
    lcli2 stop
    
    all_ok
fi

# First, give more money to node2, so it can offer HTLCs.
EXPIRY=$(($MOCKTIME + 1000))
HTLC_AMOUNT=100000000
lcli1 newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1

check_status $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE)) $(($A_FEE + $EXTRA_FEE)) '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $B_AMOUNT $B_FEE ""

lcli2 fulfillhtlc $ID1 $SECRET
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2

# Both now pay equal fees.
A_FEE=$(($NO_HTLCS_FEE / 2))
B_FEE=$(($NO_HTLCS_FEE / 2))
# We transferred 10000000 before, and $HTLC_AMOUNT now.
A_AMOUNT=$(($AMOUNT - 10000000 - $HTLC_AMOUNT - $A_FEE))
B_AMOUNT=$((10000000 + $HTLC_AMOUNT - $B_FEE))

check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Now, two HTLCs at once, one from each direction.
# Both sides can afford this.
HTLC_AMOUNT=1000000
lcli1 newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH
SECRET2=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfe
RHASH2=`lcli1 dev-rhash $SECRET2 | sed 's/.*"\([0-9a-f]*\)".*/\1/'`
lcli2 newhtlc $ID1 $HTLC_AMOUNT $EXPIRY $RHASH2
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2

check_status $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE)) $(($A_FEE + $EXTRA_FEE)) '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH'" } ' $(($B_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE)) $(($B_FEE + $EXTRA_FEE)) '{ "msatoshis" : '$HTLC_AMOUNT', "expiry" : { "second" : '$EXPIRY' }, "rhash" : "'$RHASH2'" } '

lcli2 failhtlc $ID1 $RHASH
lcli1 fulfillhtlc $ID2 $SECRET2
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 commit $ID1

# We transferred amount from B to A.
A_AMOUNT=$(($A_AMOUNT + $HTLC_AMOUNT))
B_AMOUNT=$(($B_AMOUNT - $HTLC_AMOUNT))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

lcli1 close $ID2

# They should be waiting for close.
check_peerstate lcli1 STATE_CLOSE_WAIT_CLOSE
check_peerstate lcli2 STATE_CLOSE_WAIT_CLOSE

$CLI generate 1

check_peerstate lcli1 STATE_CLOSE_ONCHAIN_MUTUAL
check_peerstate lcli2 STATE_CLOSE_ONCHAIN_MUTUAL

# Give it 99 blocks.
$CLI generate 98

# Make sure they saw it!
check_peerstate lcli1 STATE_CLOSE_ONCHAIN_MUTUAL
check_peerstate lcli2 STATE_CLOSE_ONCHAIN_MUTUAL

# Now the final one.
$CLI generate 1

check_no_peers lcli1
check_no_peers lcli2

lcli1 stop
lcli2 stop

all_ok
