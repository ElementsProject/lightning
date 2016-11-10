#! /bin/sh -e

# Wherever we are, we want to be in daemon/test dir.
cd `git rev-parse --show-toplevel`/daemon/test

. scripts/vars.sh
. scripts/helpers.sh

# Bash variables for in-depth debugging.
#set -vx
#export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

STYLE=${1:-normal}
shift

parse_cmdline 3 "$@"
case x"$STYLE" in
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
    x"--mutual-close-with-htlcs")
	CLOSE_WITH_HTLCS=1
	;;
    x"--different-fee-rates")
	DIFFERENT_FEES=1
	;;
    x"--normal")
	;;
    *)
	echo Unknown arg "$STYLE" >&2
	exit 1
	;;
esac

setup_lightning 3

if [ -n "$DIFFERENT_FEES" ]; then
    # Simply override default fee (estimatefee fails on regtest anyway)
    DEFAULT_FEE_RATE2=50000
    # We use 5x fee rate for commits, by defailt.
    FEE_RATE2=$(($DEFAULT_FEE_RATE2 * 5))
    echo "default-fee-rate=$DEFAULT_FEE_RATE2" >> $DIR2/config
fi

if [ -n "$MANUALCOMMIT" ]; then
    # Aka. never.
    echo 'commit-time=1h' >> $DIR1/config
    echo 'commit-time=1h' >> $DIR2/config
    echo 'commit-time=1h' >> $DIR3/config
fi

start_lightningd 3

# Check IDs match logs
[ `$LCLI1 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'` = $ID1 ]
[ `$LCLI2 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'` = $ID2 ]
[ $NUM_LIGHTNINGD = 2 ] || [ `$LCLI3 getlog | sed -n 's/.*"ID: \([0-9a-f]*\)".*/\1/p'` = $ID3 ]

# Make sure they see it (for timeout we need to know what height they were)
BLOCKHEIGHT=`$CLI getblockcount`
check '[ `get_info_field "$LCLI1" blockheight` = $BLOCKHEIGHT ]'
check '[ `get_info_field "$LCLI2" blockheight` = $BLOCKHEIGHT ]'

# Prevent anchor broadcast if we want to test timeout.
if [ -n "$TIMEOUT_ANCHOR" ]; then
    lcli1 dev-broadcast false
fi
lcli1 connect localhost $PORT2 $FUND_INPUT_TX &

# Expect them to be waiting for anchor, and ack from other side.
check_peerstate lcli1 STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE
check_peerstate lcli2 STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE

DO_RECONNECT=$RECONNECT

if [ -n "$TIMEOUT_ANCHOR" ]; then
    # Blocks before anchor committed (100 to hit chain, 1 to reach depth)
    $CLI generate 100

    # Still waiting.
    check_peerstate lcli1 STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE
    check_peerstate lcli2 STATE_OPEN_WAIT_ANCHORDEPTH_AND_THEIRCOMPLETE

    # Make sure whichever times out first doesn't tell the other.
    lcli1 dev-output $ID2 false
    lcli2 dev-output $ID1 false
    $CLI generate 1

    # Node1 should have gone into STATE_ERR_ANCHOR_TIMEOUT.
    check "lcli1 getlog debug | $FGREP STATE_ERR_ANCHOR_TIMEOUT"

    # Don't try to reconnect any more if we are.
    if [ x"$RECONNECT" = xreconnect ]; then DO_RECONNECT=""; fi
    NO_PEER2=1
    
    # Now let them send errors if they're still trying.
    lcli2 dev-output $ID1 true || true
    lcli1 dev-output $ID2 true || true

    # Peer 2 should give up, and have forgotten all about it.
    check "lcli2 getlog debug | $FGREP STATE_CLOSED"
    check_no_peers lcli2

    # Node1 should be disconnected.
    check_peerconnected lcli1 false

    # Now let node1 broadcast anchor and unilateral close belatedly!
    lcli1 dev-broadcast true

    # Now mine that transaction so they see it.
    $CLI generate 1

    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_OUR_UNILATERAL

    # Now move bitcoind 1 day, which is what node2 asked for on commit.
    # Get current time from last block (works if we run this twice).
    CURTIME=$($CLI getblock $($CLI getblockhash $(($BLOCKHEIGHT + 100))) | sed -n 's/ "time": \([0-9]*\),/\1/p')
    $CLI setmocktime $(($CURTIME + 24 * 60 * 60))

    # Move average so CSV moves.
    $CLI generate 6

    # Now it should have spent the commit tx.
    check_tx_spend

    # 100 blocks pass
    $CLI generate 100

    # Considers it all done now.
    check_no_peers lcli1

    lcli1 stop
    lcli2 stop
    all_ok
fi

# Now make it pass anchor (should be in mempool: one block to bury it)
check_tx_spend
$CLI generate 1

check_peerstate lcli1 STATE_NORMAL
check_peerstate lcli2 STATE_NORMAL

# We turn off routing failure for the moment.
lcli1 dev-routefail false
lcli2 dev-routefail false

if [ -n "$DIFFERENT_FEES" ]; then 
    # This is 100,000 satoshi, so covers fees.
    HTLC_AMOUNT=100000000

    # Asymmetry, since fee rates different.
    NO_HTLCS_FEE2=$((338 * $FEE_RATE2 / 2000 * 2000))
    ONE_HTLCS_FEE2=$(( (338 + 32) * $FEE_RATE2 / 2000 * 2000))

    A_AMOUNT1=$(($AMOUNT - $NO_HTLCS_FEE))
    A_FEE1=$NO_HTLCS_FEE
    A_AMOUNT2=$(($AMOUNT - $NO_HTLCS_FEE2))
    A_FEE2=$NO_HTLCS_FEE2
    B_AMOUNT=0
    B_FEE=0
    
    check_status_single lcli1 $A_AMOUNT1 $A_FEE1 "" $B_AMOUNT $B_FEE "" 
    check_status_single lcli2 $B_AMOUNT $B_FEE "" $(($A_AMOUNT2)) $(($A_FEE2)) ""

    EXPIRY=$(( $(blockheight) + 10))
    SECRET=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd
    RHASH=`lcli1 dev-rhash $SECRET | sed 's/.*"\([0-9a-f]*\)".*/\1/'`
    HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`
    [ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
    [ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
    check_status_single lcli2 0 0 "" $(($AMOUNT - $HTLC_AMOUNT - $ONE_HTLCS_FEE2)) $(($ONE_HTLCS_FEE2)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : RCVD_ADD_ACK_REVOCATION } "
    lcli2 dev-fulfillhtlc $ID1 $HTLCID $SECRET
    [ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
    [ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

    check_status_single lcli1 $(($AMOUNT - $HTLC_AMOUNT - $NO_HTLCS_FEE / 2)) $(($NO_HTLCS_FEE / 2)) "" $(($HTLC_AMOUNT - $NO_HTLCS_FEE / 2)) $(($NO_HTLCS_FEE / 2)) ""
    check_status_single lcli2 $(($HTLC_AMOUNT - $NO_HTLCS_FEE2 / 2)) $(($NO_HTLCS_FEE2 / 2)) "" $(($AMOUNT - $HTLC_AMOUNT - $NO_HTLCS_FEE2 / 2)) $(($NO_HTLCS_FEE2 / 2)) ""

    # FIXME: reactivate feechanges!
    # # Change fee rate on node2 to same as node1.
    # lcli2 dev-feerate 40000
    # $CLI generate 1
    # [ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
    # [ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

    # check_status $(($AMOUNT - $HTLC_AMOUNT - $NO_HTLCS_FEE / 2)) $(($NO_HTLCS_FEE / 2)) "" $(($HTLC_AMOUNT - $NO_HTLCS_FEE / 2)) $(($NO_HTLCS_FEE / 2)) "" 

    # # Change back.
    # lcli2 dev-feerate 50000
    # $CLI generate 1
    # [ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
    # [ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

    # check_status_single lcli1 $(($AMOUNT - $HTLC_AMOUNT - $NO_HTLCS_FEE / 2)) $(($NO_HTLCS_FEE / 2)) "" $(($HTLC_AMOUNT - $NO_HTLCS_FEE / 2)) $(($NO_HTLCS_FEE / 2)) ""
    # check_status_single lcli2 $(($HTLC_AMOUNT - $NO_HTLCS_FEE2 / 2)) $(($NO_HTLCS_FEE2 / 2)) "" $(($AMOUNT - $HTLC_AMOUNT - $NO_HTLCS_FEE2 / 2)) $(($NO_HTLCS_FEE2 / 2)) ""

    lcli1 close $ID2
    # Make sure they notice it.
    check_peerstate lcli1 STATE_MUTUAL_CLOSING
    check_peerstate lcli2 STATE_MUTUAL_CLOSING
    $CLI generate 1
    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_MUTUAL
    check_peerstate lcli2 STATE_CLOSE_ONCHAIN_MUTUAL
    # Give it 10 blocks ie "forever"
    $CLI generate 10
    check_no_peers lcli1
    check_no_peers lcli2

    lcli1 stop
    lcli2 stop

    all_ok
fi

A_AMOUNT=$(($AMOUNT - $NO_HTLCS_FEE))
A_FEE=$NO_HTLCS_FEE
B_AMOUNT=0
B_FEE=0
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# This is 10,000 satoshi, so not dust!
HTLC_AMOUNT=10000000

EXPIRY=$(( $(blockheight) + 10))
SECRET=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfd
RHASH=`lcli1 dev-rhash $SECRET | sed 's/.*"\([0-9a-f]*\)".*/\1/'`

HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`

if [ -n "$MANUALCOMMIT" ]; then
    # They should register a staged htlc.
    check_status $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_HTLC } " $B_AMOUNT $B_FEE ""

    # Now commit it.
    lcli1 dev-commit $ID2

    # Node 1 hasn't got it committed, but node2 should have told it to stage.
    check_status_single lcli1 $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : RCVD_ADD_REVOCATION } " $B_AMOUNT $B_FEE ""

    # Check channel status
    A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
    A_FEE=$(($A_FEE + $EXTRA_FEE))

    # Node 2 has it committed.
    check_status_single lcli2 $B_AMOUNT $B_FEE "" $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_REVOCATION } "

    # There should be no "both committed" here yet
    if lcli1 getlog debug | $FGREP "Both committed"; then
	echo "Node1 thinks they are both committed";
	exit 1
    fi
    if lcli2 getlog debug | $FGREP "Both committed"; then
	echo "Node2 thinks they are both committed";
	exit 1
    fi

    # Now node2 gives commitment to node1.
    lcli2 dev-commit $ID1

    # After revocation, they should know they're both committed.
    check lcli1 "getlog debug | $FGREP 'Both committed to ADD of our HTLC'"
    check lcli2 "getlog debug | $FGREP 'Both committed to ADD of their HTLC'"
else
    A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
    A_FEE=$(($A_FEE + $EXTRA_FEE))
fi

# Both should have committed tx.
check_status $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } " $B_AMOUNT $B_FEE ""

if [ -n "$STEAL" ]; then
    STEAL_TX=`$LCLI1 dev-signcommit $ID2 | cut -d\" -f4`
fi

if [ -n "$DUMP_ONCHAIN" ]; then
    # make node1 disconnect with node2.
    lcli1 dev-disconnect $ID2
    check_peerconnected lcli1 false

    # lcli1 should have sent out commitment tx
    check_peerstate lcli1 STATE_ERR_BREAKDOWN
    check_tx_spend

    # Mine it.
    $CLI generate 1
    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_OUR_UNILATERAL
    check_peerstate lcli2 STATE_CLOSE_ONCHAIN_THEIR_UNILATERAL

    # both still know about htlc
    check_status $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } " $B_AMOUNT $B_FEE ""

    # Generate 6 blocks so CSV timeout has expired.
    $CLI generate 6

    # Now, lcli1 should spend its own output.
    check_tx_spend
    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_OUR_UNILATERAL

    while [ $(blockheight) != $EXPIRY ]; do
	$CLI generate 1
    done

    # lcli1 should have gotten HTLC back.
    check_tx_spend

    # Now, after 10 blocks, should all be concluded.
    $CLI generate 10

    # Both consider it all done now.
    check_no_peers lcli1

    lcli1 stop
    all_ok
fi
    
lcli2 dev-fulfillhtlc $ID1 $HTLCID $SECRET
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

# Without manual commit, this check is racy.
if [ -n "$MANUALCOMMIT" ]; then
    if lcli1 getlog debug | $FGREP 'Both committed to FULFILL'; then
	echo "Node1 thinks they are both committed";
	exit 1
    fi
    if lcli2 getlog debug | $FGREP 'Both committed to FULFILL'; then
	echo "Node2 thinks they are both committed";
	exit 1
    fi
fi
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

# If we're very slow, manually committed above, and we're restarting,
# we may restart *after* this and thus not see it in the log.
[ "$RECONNECT$MANUALCOMMIT" = restart1 ] || check lcli1 "getlog debug | $FGREP 'Both committed to FULFILL of our HTLC'"
check lcli2 "getlog debug | $FGREP 'Both committed to FULFILL of their HTLC'"

# We've transferred the HTLC amount to 2, who now has to pay fees,
# so no net change for A who saves on fees.
B_FEE=$HTLC_AMOUNT
# With no HTLCs, extra fee no longer required.
A_FEE=$(($A_FEE - $EXTRA_FEE - $B_FEE))
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + $HTLC_AMOUNT))

check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# A new one, at 10x the amount.
HTLC_AMOUNT=100000000

HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
A_FEE=$(($A_FEE + $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } " $B_AMOUNT $B_FEE ""

lcli2 dev-failhtlc $ID1 $HTLCID 695
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

# Back to how we were before.
A_AMOUNT=$(($A_AMOUNT + $EXTRA_FEE + $HTLC_AMOUNT))
A_FEE=$(($A_FEE - $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Same again, but this time it expires.
HTLC_AMOUNT=10000001
HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

# Check channel status
A_AMOUNT=$(($A_AMOUNT - $EXTRA_FEE - $HTLC_AMOUNT))
A_FEE=$(($A_FEE + $EXTRA_FEE))
check_status $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } " $B_AMOUNT $B_FEE ""

# Make sure node1 accepts the expiry packet.
while [ $(blockheight) != $EXPIRY ]; do
    $CLI generate 1
done

# This should make node2 send it.
$CLI generate 1

if [ -n "$MANUALCOMMIT" ]; then
    check_status $A_AMOUNT $A_FEE "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : RCVD_REMOVE_HTLC } " $B_AMOUNT $B_FEE ""

    lcli2 dev-commit $ID1
    lcli1 dev-commit $ID2
fi

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
    check_tx_spend

    # Give it "forever" blocks.
    $CLI generate 10

    check_no_peers lcli2

    lcli1 stop
    lcli2 stop
    
    all_ok
fi

# First, give more money to node2, so it can offer HTLCs.
EXPIRY=$(( $(blockheight) + 10))
HTLC_AMOUNT=100000000
HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

check_status $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE)) $(($A_FEE + $EXTRA_FEE)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } " $B_AMOUNT $B_FEE ""

lcli2 dev-fulfillhtlc $ID1 $HTLCID $SECRET
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

# Both now pay equal fees.
A_FEE=$(($NO_HTLCS_FEE / 2))
B_FEE=$(($NO_HTLCS_FEE / 2))
# We transferred 10000000 before, and $HTLC_AMOUNT now.
A_AMOUNT=$(($AMOUNT - 10000000 - $HTLC_AMOUNT - $A_FEE))
B_AMOUNT=$((10000000 + $HTLC_AMOUNT - $B_FEE))

check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Two failures crossover
SECRET2=1de08917a61cb2b62ed5937d38577f6a7bfe59c176781c6d8128018e8b5ccdfe
RHASH2=`lcli1 dev-rhash $SECRET2 | sed 's/.*"\([0-9a-f]*\)".*/\1/'`

# This means B will *just* afford it (but can't cover increased fees)
HTLC_AMOUNT=$(($B_AMOUNT - $EXTRA_FEE / 2))
HTLCID=`lcli2 dev-newhtlc $ID1 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`
# Make sure that's committed, in case lcli1 restarts.
lcli2 dev-commit $ID1 >/dev/null || true

HTLCID2=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH2 | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

# A covers the extra part of the fee.
check_status $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE - $EXTRA_FEE / 2)) $(($A_FEE + $EXTRA_FEE + $EXTRA_FEE / 2)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH2 , state : SENT_ADD_ACK_REVOCATION } " 0 $(($B_FEE + $EXTRA_FEE / 2)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : RCVD_ADD_ACK_REVOCATION } "

# Fail both, to reset.
lcli1 dev-failhtlc $ID2 $HTLCID 830
lcli2 dev-failhtlc $ID1 $HTLCID2 829

[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Now, two HTLCs at once, one from each direction.
# Both sides can afford this.
HTLC_AMOUNT=1000000
HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`
HTLCID2=`lcli2 dev-newhtlc $ID1 $HTLC_AMOUNT $EXPIRY $RHASH2 | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

check_status $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE)) $(($A_FEE + $EXTRA_FEE)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } " $(($B_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE)) $(($B_FEE + $EXTRA_FEE)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH2 , state : RCVD_ADD_ACK_REVOCATION } "

if [ -n "$CLOSE_WITH_HTLCS" ]; then
    # Now begin close
    lcli1 close $ID2

    # They should be waiting for it to clear up.
    check_peerstate lcli1 STATE_SHUTDOWN
    check_peerstate lcli2 STATE_SHUTDOWN

    # Fail one, still waiting.
    lcli2 dev-failhtlc $ID1 $HTLCID 800
    check_peerstate lcli1 STATE_SHUTDOWN
    check_peerstate lcli2 STATE_SHUTDOWN

    # Fulfill the other causes them to actually complete the close.
    lcli1 dev-fulfillhtlc $ID2 $HTLCID2 $SECRET2
    check_peerstate lcli1 STATE_MUTUAL_CLOSING
    check_peerstate lcli2 STATE_MUTUAL_CLOSING

    $CLI generate 1

    check_peerstate lcli1 STATE_CLOSE_ONCHAIN_MUTUAL
    check_peerstate lcli2 STATE_CLOSE_ONCHAIN_MUTUAL

    # Give it "forever" blocks.
    $CLI generate 9

    check_no_peers lcli1
    check_no_peers lcli2

    lcli1 stop
    lcli2 stop
    
    all_ok
fi

lcli1 dev-fulfillhtlc $ID2 $HTLCID2 $SECRET2
lcli2 dev-failhtlc $ID1 $HTLCID 849
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

# We transferred amount from B to A.
A_AMOUNT=$(($A_AMOUNT + $HTLC_AMOUNT))
B_AMOUNT=$(($B_AMOUNT - $HTLC_AMOUNT))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Now, test making more changes before receiving commit reply.
DO_RECONNECT=""
lcli2 dev-output $ID1 false
HTLCID=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH | extract_id`

# Make sure node1 sends commit (in the background, since it will block!)
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2 &

if [ -n "$MANUALCOMMIT" ]; then
    # node2 will consider this committed.
    check_status_single lcli2 $(($B_AMOUNT - $EXTRA_FEE/2)) $(($B_FEE + $EXTRA_FEE/2)) "" $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE/2)) $(($A_FEE + $EXTRA_FEE/2)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_REVOCATION } "
else
    # It will start committing by itself
    check_status_single lcli2 $(($B_AMOUNT - $EXTRA_FEE/2)) $(($B_FEE + $EXTRA_FEE/2)) "" $(($A_AMOUNT - $HTLC_AMOUNT - $EXTRA_FEE/2)) $(($A_FEE + $EXTRA_FEE/2)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_COMMIT } "
fi

# node1 will still be awaiting node2's revocation reply.
check_status_single lcli1 $(($A_AMOUNT)) $(($A_FEE)) "{ msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_COMMIT } " $B_AMOUNT $B_FEE ""

# Now send another offer, and enable node2 output.
HTLCID2=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH2 | extract_id`
lcli2 dev-output $ID1 true

[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

DO_RECONNECT=$RECONNECT

# Both sides should be committed to htlcs
# We open-code check_status here: HTLCs could be in either order.
check_balance_single lcli1 $(($A_AMOUNT - $HTLC_AMOUNT*2 - $EXTRA_FEE)) $(($A_FEE + $EXTRA_FEE)) $(($B_AMOUNT - $EXTRA_FEE)) $(($B_FEE + $EXTRA_FEE))
check_balance_single lcli2 $(($B_AMOUNT - $EXTRA_FEE)) $(($B_FEE + $EXTRA_FEE)) $(($A_AMOUNT - $HTLC_AMOUNT*2 - $EXTRA_FEE)) $(($A_FEE + $EXTRA_FEE))

# Once both balances are correct, this should be right.
lcli1 getpeers | tr -s '\012\011" ' ' ' | $FGREP "our_htlcs : [ { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION }, { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH2 , state : SENT_ADD_ACK_REVOCATION } ], their_htlcs : [ ]" || lcli1 getpeers | tr -s '\012\011" ' ' ' | $FGREP "our_htlcs : [ { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH2 , state : SENT_ADD_ACK_REVOCATION }, { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : SENT_ADD_ACK_REVOCATION } ], their_htlcs : [ ]"

lcli2 getpeers | tr -s '\012\011" ' ' ' | $FGREP "our_htlcs : [ ], their_htlcs : [ { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : RCVD_ADD_ACK_REVOCATION }, { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH2 , state : RCVD_ADD_ACK_REVOCATION } ]" || lcli2 getpeers | tr -s '\012\011" ' ' ' | $FGREP "our_htlcs : [ ], their_htlcs : [ { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH2 , state : RCVD_ADD_ACK_REVOCATION }, { msatoshi : $HTLC_AMOUNT, expiry : { block : $EXPIRY }, rhash : $RHASH , state : RCVD_ADD_ACK_REVOCATION } ]"

# Just for once, reconnect/restart node 2.
case "$RECONNECT" in
    reconnect)
	echo RECONNECTING NODE2
	$LCLI2 dev-reconnect $ID1 >/dev/null
	sleep 1
	;;
    restart)
	echo RESTARTING NODE2
	$LCLI2 -- dev-restart $LIGHTNINGD2 >/dev/null 2>&1 || true
	if ! check "$LCLI2 getlog 2>/dev/null | fgrep -q Hello"; then
	    echo "Node2 dev-restart failed!">&2
	    exit 1
	fi
	;;
esac

if ! check "$LCLI2 getpeers | tr -s '\012\011\" ' ' ' | fgrep -q 'connected : true'"; then
    echo "Failed to reconnect!">&2
    exit 1
fi

# Node2 collects the HTLCs.
lcli2 dev-fulfillhtlc $ID1 $HTLCID $SECRET
lcli2 dev-fulfillhtlc $ID1 $HTLCID2 $SECRET2

[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

# We transferred 2 * amount from A to B.
A_AMOUNT=$(($A_AMOUNT - $HTLC_AMOUNT * 2))
B_AMOUNT=$(($B_AMOUNT + $HTLC_AMOUNT * 2))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

# Now, use automatic payment redemption
lcli1 dev-routefail true
lcli2 dev-routefail true
RHASH3=`lcli2 invoice $HTLC_AMOUNT RHASH3 | sed 's/.*"\([0-9a-f]*\)".*/\1/'`

lcli2 listinvoice
[ "`lcli2 listinvoice | tr -s '\012\011\" ' ' '`" = "[ { label : RHASH3 , rhash : $RHASH3 , msatoshi : $HTLC_AMOUNT, complete : false } ] " ]

HTLCID3=`lcli1 dev-newhtlc $ID2 $HTLC_AMOUNT $EXPIRY $RHASH3 | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

# We transferred amount from A to B.
A_AMOUNT=$(($A_AMOUNT - $HTLC_AMOUNT))
B_AMOUNT=$(($B_AMOUNT + $HTLC_AMOUNT))
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

[ "`lcli2 listinvoice | tr -s '\012\011\" ' ' '`" = "[ { label : RHASH3 , rhash : $RHASH3 , msatoshi : $HTLC_AMOUNT, complete : true } ] " ]

# Now, failed payment (didn't pay enough)
RHASH4=`lcli2 invoice $HTLC_AMOUNT RHASH4 | sed 's/.*"\([0-9a-f]*\)".*/\1/'`

# Shouldn't have this already.
if lcli2 getlog | $FGREP 'Short payment for'; then exit 1; fi

# Test listinvoice with both, or subset (either order possible!)
INVOICES=`lcli2 listinvoice | tr -s '\012\011\" ' ' '`
[ "$INVOICES" = "[ { label : RHASH3 , rhash : $RHASH3 , msatoshi : $HTLC_AMOUNT, complete : true }, { label : RHASH4 , rhash : $RHASH4 , msatoshi : $HTLC_AMOUNT, complete : false } ] " ] || [ "$INVOICES" = "[ { label : RHASH4 , rhash : $RHASH4 , msatoshi : $HTLC_AMOUNT, complete : false }, { label : RHASH3 , rhash : $RHASH3 , msatoshi : $HTLC_AMOUNT, complete : true } ] " ]
[ "`lcli2 listinvoice RHASH3 | tr -s '\012\011\" ' ' '`" = "[ { label : RHASH3 , rhash : $RHASH3 , msatoshi : $HTLC_AMOUNT, complete : true } ] " ]
[ "`lcli2 listinvoice RHASH4 | tr -s '\012\011\" ' ' '`" = "[ { label : RHASH4 , rhash : $RHASH4 , msatoshi : $HTLC_AMOUNT, complete : false } ] " ]

HTLCID4=`lcli1 dev-newhtlc $ID2 $(($HTLC_AMOUNT - 1)) $EXPIRY $RHASH4 | extract_id`
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2
[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1

[ ! -n "$MANUALCOMMIT" ] || lcli2 dev-commit $ID1
[ ! -n "$MANUALCOMMIT" ] || lcli1 dev-commit $ID2

check lcli2 "getlog | $FGREP 'Short payment for'"
check_status $A_AMOUNT $A_FEE "" $B_AMOUNT $B_FEE ""

lcli2 delinvoice RHASH4
if lcli2 delinvoice RHASH3 >/dev/null; then
    echo "Should not be able to delete completed invoice!" >&2
    exit 1
fi

if [ ! -n "$MANUALCOMMIT" ]; then
    # Test routing to a third node.
    P2SHADDR2=`$LCLI2 newaddr | sed -n 's/{ "address" : "\(.*\)" }/\1/p'`
    TXID2=`$CLI sendtoaddress $P2SHADDR2 0.01`
    TX2=`$CLI getrawtransaction $TXID2`
    $CLI generate 1

    lcli2 connect localhost $PORT3 $TX2 &
    check_tx_spend
    $CLI generate 1

    # Make sure it's STATE_NORMAL.
    check_peerstate lcli3 STATE_NORMAL

    # More than enough to cover commit fees.
    HTLC_AMOUNT=100000000

    # Tell node 1 about the 2->3 route.
    # Add to config in case we are restaring.
    echo "add-route=$ID2/$ID3/546000/10/36/36" >> $DIR1/config
    lcli1 dev-add-route $ID2 $ID3 546000 10 36 36
    RHASH5=`lcli3 invoice $HTLC_AMOUNT RHASH5 | sed 's/.*"\([0-9a-f]*\)".*/\1/'`

    # Get route.
    ROUTE=`lcli1 getroute $ID3 $HTLC_AMOUNT 1`
    ROUTE=`echo $ROUTE | sed 's/^{ "route" : \(.*\) }$/\1/'`

    # Try wrong hash.
    if lcli1 sendpay "$ROUTE" $RHASH4; then
	echo Paid with wrong hash? >&2
	exit 1
    fi

    # Try underpaying.
    PAID=`echo "$ROUTE" | sed -n 's/.*"msatoshi" : \([0-9]*\),.*/\1/p'`
    UNDERPAY=`echo "$ROUTE" | sed "s/: $PAID,/: $(($PAID - 1)),/"`
    if lcli1 sendpay "$UNDERPAY" $RHASH5; then
	echo Paid with too little? >&2
	exit 1
    fi

    # If restarting, make sure node3 remembers incoming payment.
    if [ "$RECONNECT" = restart ]; then
	$LCLI3 -- dev-restart $LIGHTNINGD3 >/dev/null 2>&1 || true
	if ! check "$LCLI3 getpeers 2>/dev/null | tr -s '\012\011\" ' ' ' | fgrep -q 'connected : true'"; then
	    echo "Failed to reconnect!">&2
	    exit 1
	fi
    fi
    
    [ "`lcli3 listinvoice RHASH5 | tr -s '\012\011\" ' ' '`" = "[ { label : RHASH5 , rhash : $RHASH5 , msatoshi : $HTLC_AMOUNT, complete : false } ] " ]
    # Pay correctly.
    lcli1 sendpay "$ROUTE" $RHASH5

    # Node 3 should end up with that amount (minus 1/2 tx fee)
    # Note that it is delayed a little, since node2 fulfils as soon as fulfill
    # starts.
    check lcli3 "getpeers | $FGREP \"\\\"our_amount\\\" : $(($HTLC_AMOUNT - $NO_HTLCS_FEE / 2))\""

    # If restarting, make sure node3 remembers completed payment.
    if [ "$RECONNECT" = restart ]; then
	echo RESTARTING NODE3
	$LCLI3 -- dev-restart $LIGHTNINGD3 >/dev/null 2>&1 || true
	if ! check "$LCLI3 getpeers 2>/dev/null | tr -s '\012\011\" ' ' ' | fgrep -q 'connected : true'"; then
	    echo "Failed to reconnect!">&2
	    exit 1
	fi
    fi

    [ "`lcli3 listinvoice RHASH5 | tr -s '\012\011\" ' ' '`" = "[ { label : RHASH5 , rhash : $RHASH5 , msatoshi : $HTLC_AMOUNT, complete : true } ] " ]

    [ "`lcli3 waitinvoice | tr -s '\012\011\" ' ' '`" = "{ label : RHASH5 , rhash : $RHASH5 , msatoshi : $HTLC_AMOUNT } " ]

    # Can't pay twice (try from node2)
    ROUTE2=`lcli2 getroute $ID3 $HTLC_AMOUNT 1`
    ROUTE2=`echo $ROUTE2 | sed 's/^{ "route" : \(.*\) }$/\1/'`
    if lcli2 sendpay "$ROUTE2" $RHASH5; then
	echo "Paying twice worked?" >&2
	exit 1
    fi

    lcli3 close $ID2

    # Re-send should be a noop (doesn't matter that node3 is down!)
    lcli1 sendpay "$ROUTE" $RHASH5

    # Re-send to different id or amount should complain.
    SHORTROUTE=`echo "$ROUTE" | sed 's/, { "id" : .* }//' | sed 's/"msatoshi" : [0-9]*,/"msatoshi" : '$HTLC_AMOUNT,/`
    lcli1 sendpay "$SHORTROUTE" $RHASH5 | $FGREP "already succeeded to $ID3"
    lcli1 sendpay "$UNDERPAY" $RHASH5 | $FGREP "already succeeded with amount $HTLC_AMOUNT"

    # Now node2 should fail to route.
    if lcli1 sendpay "$ROUTE" $RHASH4 | $FGREP "failed: error code 404 node $ID2 reason Unknown peer"; then : ;
    else
	echo "Pay to node3 didn't give 404" >&2
	exit 1
    fi

    # Now node1 should fail to route (route deleted)
    if lcli1 getroute $ID3 $HTLC_AMOUNT 1 | $FGREP "no route found"; then : ;
    else
	echo "Pay to node3 didn't fail instantly second time" >&2
	exit 1
    fi
fi

lcli1 close $ID2

# They should be negotiating the close.
check_peerstate lcli1 STATE_MUTUAL_CLOSING
check_peerstate lcli2 STATE_MUTUAL_CLOSING

$CLI generate 1

check_peerstate lcli1 STATE_CLOSE_ONCHAIN_MUTUAL
check_peerstate lcli2 STATE_CLOSE_ONCHAIN_MUTUAL

# Give it forever-1 blocks.
$CLI generate 8

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
