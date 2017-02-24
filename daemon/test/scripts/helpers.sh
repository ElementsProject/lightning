#! /bin/sh
# Sourced by test script.

# Takes the number of lightningd's we're going to start (2 or 3), then args
parse_cmdline()
{
    NUM_LIGHTNINGD=$1
    shift

    DIR1=/tmp/lightning.$$.1
    DIR2=/tmp/lightning.$$.2
    REDIR1="$DIR1/output"
    REDIR2="$DIR2/output"
    REDIRERR1="$DIR1/errors"
    REDIRERR2="$DIR2/errors"

    if [ $NUM_LIGHTNINGD = 3 ]; then
	DIR3=/tmp/lightning.$$.3
	REDIR3="$DIR3/output"
	REDIRERR3="$DIR3/errors"
    fi

    while [ $# != 0 ]; do
	case x"$1" in
	    x"--valgrind-vgdb")
		[ -n "$NO_VALGRIND" ] || PREFIX="$PREFIX --vgdb-error=1"
		REDIR1="/dev/tty"
		REDIRERR1="/dev/tty"
		REDIR2="/dev/tty"
		REDIRERR2="/dev/tty"
		if [ $NUM_LIGHTNINGD = 3 ]; then
		    REDIR3="/dev/tty"
		    REDIRERR3="/dev/tty"
		fi
		;;
	    x"--gdb1")
		GDB1=1
		;;
	    x"--gdb2")
		GDB2=1
		;;
	    x"--gdb3")
		GDB3=1
		if [ $NUM_LIGHTNINGD -lt 3 ]; then
		    echo "$1" invalid with only 2 lightning daemons >&2
		    exit 1
		fi
		;;
	    x"--gdb1="*)
		DAEMON1_EXTRA=--dev-debugger=${1#--gdb1=}
		;;
	    x"--gdb2="*)
		DAEMON2_EXTRA=--dev-debugger=${1#--gdb2=}
		;;
	    x"--reconnect")
		RECONNECT=reconnect
		;;
	    x"--restart")
		RECONNECT=restart
		;;
	    x"--crash")
		CRASH_ON_FAIL=1
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

    if [ -n "$VERBOSE" ]; then
	FGREP="fgrep"
    else
	FGREP="fgrep -q"
	# Suppress command output.
	exec >/dev/null
    fi
}

failed()
{
    if [ -n "$CRASH_ON_FAIL" ]; then
	$LCLI1 dev-crash 2>/dev/null || true
	$LCLI2 dev-crash 2>/dev/null || true
	echo -n Crash results in $DIR1 and $DIR2 >&2
	if [ -n "$LCLI3" ]; then
	    $LCLI3 dev-crash 2>/dev/null || true
	    echo and $DIR3 >&2
	else
	    echo >&2
	fi
    fi
    cat $DIR1/errors $DIR2/errors $DIR3/errors 2>/dev/null || true
    exit 1
}

setup_lightning()
{
    NUM_LIGHTNINGD=$1

    LCLI1="../lightning-cli --lightning-dir=$DIR1"
    LCLI2="../lightning-cli --lightning-dir=$DIR2"
    [ $NUM_LIGHTNINGD = 2 ] || LCLI3="../lightning-cli --lightning-dir=$DIR3"

    trap failed EXIT
    mkdir $DIR1 $DIR2
    [ $NUM_LIGHTNINGD = 2 ] || mkdir $DIR3

    cat > $DIR1/config <<EOF
disable-irc
log-level=debug
bitcoind-regtest
bitcoind-poll=5s
deadline-blocks=5
min-htlc-expiry=6
bitcoin-datadir=$DATADIR
locktime-blocks=6
EOF

    cp $DIR1/config $DIR2/config
    [ $NUM_LIGHTNINGD = 2 ] || cp $DIR1/config $DIR3/config

    # Find a free TCP port.
    echo port=`findport 4000 $VARIANT` >> $DIR2/config
    [ $NUM_LIGHTNINGD = 2 ] || echo port=`findport 4010 $VARIANT` >> $DIR3/config
}

# Use DIR REDIR REDIRERR GDBFLAG BINARY EXTRAARGS
start_one_lightningd()
{
    # Need absolute path for re-exec testing.
    local CMD
    CMD="$(readlink -f `pwd`/../../$5) --lightning-dir=$1"
    if [ -n "$4" ]; then
	echo Press return once you run: gdb --args $CMD $6 >&2

	read REPLY
    else
	CMD="$PREFIX $CMD"
	$CMD $6 > $2 2> $3 &
    fi
    echo $CMD $6
}

start_lightningd()
{
    NUM_LIGHTNINGD=$1
    BINARY=${2:-daemon/lightningd}

    # If bitcoind not already running, start it.
    if ! $CLI getinfo >/dev/null 2>&1; then
	echo Starting bitcoind...
	scripts/setup.sh
	SHUTDOWN_BITCOIN=scripts/shutdown.sh
    else
	SHUTDOWN_BITCOIN=/bin/true
    fi

    LIGHTNINGD1=`start_one_lightningd $DIR1 $REDIR1 $REDIRERR1 "$GDB1" $BINARY $DAEMON1_EXTRA`
    LIGHTNINGD2=`start_one_lightningd $DIR2 $REDIR2 $REDIRERR2 "$GDB2" $BINARY $DAEMON2_EXTRA`
    [ $NUM_LIGHTNINGD = 2 ] || LIGHTNINGD3=`start_one_lightningd $DIR3 $REDIR3 $REDIRERR3 "$GDB3" $BINARY`

    if ! check "$LCLI1 getlog 2>/dev/null | $FGREP Hello"; then
	echo Failed to start daemon 1 >&2
	exit 1
    fi

    if ! check "$LCLI2 getlog 2>/dev/null | $FGREP Hello"; then
	echo Failed to start daemon 2 >&2
	exit 1
    fi

    if [ $NUM_LIGHTNINGD = 3 ] && ! check "$LCLI3 getlog 2>/dev/null | $FGREP Hello"; then
	echo Failed to start daemon 3 >&2
	exit 1
    fi

    # Version should match binary version
    GETINFO_VERSION=`$LCLI1 getinfo | sed -n 's/.*"version" : "\([^"]*\)".*/\1/p'`
    LCLI_VERSION=$($LCLI1 --version | head -n1)
    LDAEMON_VERSION=$($LIGHTNINGD1 --version | head -n1)
    if [ $GETINFO_VERSION != $LCLI_VERSION -o $GETINFO_VERSION != $LDAEMON_VERSION ]; then
	echo Wrong versions: getinfo gave $GETINFO_VERSION, cli gave $LCLI_VERSION, daemon gave $LDAEMON_VERSION >&2
	exit 1
    fi

    ID1=`get_info_field "$LCLI1" id`
    ID2=`get_info_field "$LCLI2" id`
    [ $NUM_LIGHTNINGD = 2 ] || ID3=`get_info_field "$LCLI3" id`

    PORT2=`get_info_field "$LCLI2" port`
    [ $NUM_LIGHTNINGD = 2 ] || PORT3=`get_info_field "$LCLI3" port`
}

fund_lightningd()
{
    # Make a payment into a P2SH for anchor.
    P2SHADDR=`$LCLI1 newaddr | sed -n 's/{ "address" : "\(.*\)" }/\1/p'`
    FUND_INPUT_TXID=`$CLI sendtoaddress $P2SHADDR 0.01`
    FUND_INPUT_TX=`$CLI getrawtransaction $FUND_INPUT_TXID`

    # Mine it so check_tx_spend doesn't see it (breaks some tests).
    $CLI generate 1
}

lcli1()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI1 "$@" >&2
    fi
    # Make sure we output if it fails; we need to capture it otherwise.
    if ! OUT=`$LCLI1 "$@"`; then
	echo "$OUT"
	return 1
    fi
    echo "$OUT"
    if [ -n "$DO_RECONNECT" ]; then
	case "$1" in
	    # Don't restart on every get* command.
	    get*)
	    ;;
	    dev-disconnect)
	    ;;
	    stop)
	    ;;
	    *)
		case "$RECONNECT" in
		    reconnect)
			[ -z "$VERBOSE" ] || echo RECONNECTING >&2
			$LCLI1 dev-reconnect $ID2 >/dev/null
			;;
		    restart)
			[ -z "$VERBOSE" ] || echo RESTARTING >&2
			$LCLI1 -- dev-restart $LIGHTNINGD1 >/dev/null 2>&1 || true
			if ! check "$LCLI1 getlog 2>/dev/null | fgrep -q Hello"; then
			    echo "dev-restart failed!">&2
			    exit 1
			fi
			;;
		esac
		# Wait for reconnect (if peer2 still there)
		if [ -z "$NO_PEER2" ] && ! check "$LCLI1 getpeers | tr -s '\012\011\" ' ' ' | fgrep -q 'connected : true'"; then
		    echo "Failed to reconnect!">&2
		    exit 1
		fi

		if [ "$1" = "dev-newhtlc" ]; then
		    # It might have gotten committed, or might be forgotten.
		    ID=`echo "$OUT" | extract_id`
		    if ! htlc_exists "$LCLI1" $2 $ID; then
			if [ -z "$VERBOSE" ]; then
			    $LCLI1 "$@" >/dev/null 2>&1 || true
			else
			    echo "Rerunning $LCLI1 $@" >&2
			    $LCLI1 "$@" >&2 || true
			fi
		    fi
		    # Make sure it's confirmed before we run next command,
		    # in case *that* restarts (unless manual commit)
		    [ -n "$MANUALCOMMIT" ] || check ! htlc_is_state \'"$LCLI1"\' $2 $ID SENT_ADD_HTLC
		# Removals may also be forgotten.
		elif [ "$1" = "fulfillhtlc" -o "$1" = "failhtlc" ]; then
		    ID="$3"
		    if htlc_is_state "$LCLI1" $2 $ID RCVD_ADD_ACK_REVOCATION; then
			if [ -z "$VERBOSE" ]; then
			    $LCLI1 "$@" >/dev/null 2>&1 || true
			else
			    echo "Rerunning $LCLI1 $@" >&2
			    $LCLI1 "$@" >&2 || true
			fi
			# Make sure it's confirmed before we run next command,
			# in case *that* restarts.
			[ -n "$MANUALCOMMIT" ] || check ! htlc_is_state \'"$LCLI1"\' $2 $ID SENT_REMOVE_HTLC
		    fi
		fi
		;;
	esac
    fi
}

lcli2()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI2 "$@" >&2
    fi
    $LCLI2 "$@"
}

lcli3()
{
    if [ -n "$VERBOSE" ]; then
	echo $LCLI3 "$@" >&2
    fi
    $LCLI3 "$@"
}

all_ok()
{
    # Look for valgrind errors.
    if grep ^== $DIR1/errors; then exit 1; fi
    if grep ^== $DIR2/errors; then exit 1; fi
    [ $NUM_LIGHTNINGD = 2 ] || if grep ^== $DIR3/errors; then exit 1; fi

    # Look for unknown logging types.
    if grep "UNKNOWN TYPE" $DIR1/output >&2; then exit 1; fi
    if grep "UNKNOWN TYPE" $DIR2/output >&2; then exit 1; fi
    [ $NUM_LIGHTNINGD = 2 ] || if grep "UNKNOWN TYPE" $DIR3/output >&2; then exit 1; fi
    $SHUTDOWN_BITCOIN

    trap "rm -rf $DIR1 $DIR2 $DIR3" EXIT
    exit 0
}

# If result is in quotes, those are stripped.  Spaces in quotes not handled
get_field()
{
    tr -s '\012\011" ' ' ' | sed 's/.* '$1' : \([^, }]*\).*/\1/'
}    

# If result is in quotes, those are stripped.  Spaces in quotes not handled
get_info_field()
{
    $1 getinfo | tr -s '\012\011" ' ' ' | sed 's/.* '$2' : \([^, }]*\).*/\1/'
}    
    
# Peer $1 -> $2's htlc $3 is in state $4
htlc_is_state()
{
    if [ $# != 4 ]; then echo "htlc_is_state got $# ARGS: $@" >&2; exit 1; fi
    $1 gethtlcs $2 true | tr -s '\012\011\" ' ' ' | $FGREP "id : $3, state : $4 ," >&2
}

# Peer $1 -> $2's htlc $3 exists
htlc_exists()
{
    $1 gethtlcs $2 true | tr -s '\012\011\" ' ' ' | $FGREP "id : $3," >&2
}

blockheight()
{
    $CLI getblockcount
}

# Usage: <cmd to test>...
check()
{
    local i=0
    while ! eval "$@"; do
	sleep 1
	i=$(($i + 1))
	if [ $i = 60 ]; then
	    return 1
	fi
    done
}

check_balance_single()
{
    lcli="$1"
    us_pay=$2
    us_fee=$3
    them_pay=$4
    them_fee=$5

    if check "$lcli getpeers | tr -s '\012\011\" ' ' ' | $FGREP \"our_amount : $us_pay, our_fee : $us_fee, their_amount : $them_pay, their_fee : $them_fee,\""; then :; else
	echo Cannot find $lcli output: "our_amount : $us_pay, our_fee : $us_fee, their_amount : $them_pay, their_fee : $them_fee," >&2
	$lcli getpeers | tr -s '\012\011" ' ' ' >&2
	return 1
    fi
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

    check_balance_single "$lcli" $us_pay $us_fee $them_pay $them_fee

    if check "$lcli getpeers | tr -s '\012\011\" ' ' ' | $FGREP \"our_htlcs : [ $us_htlcs], their_htlcs : [ $them_htlcs]\""; then :; else
	echo Cannot find $lcli output: "our_htlcs : [ $us_htlcs], their_htlcs : [ $them_htlcs]" >&2
	$lcli getpeers | tr -s '\012\011" ' ' ' >&2
	return 1
    fi
}

# SEND_ -> RCVD_ and RCVD_ -> SEND_
swap_status()
{
    echo "$@" | sed -e 's/state : RCVD_/@@/g' -e 's/state : SENT_/state : RCVD_/g' -e 's/@@/state : SENT_/g'
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
    check_status_single lcli2 "$them_pay" "$them_fee" "`swap_status \"$them_htlcs\"`" "$us_pay" "$us_fee" "`swap_status \"$us_htlcs\"`"
}

check_tx_spend()
{
    local FAIL
    FAIL=0
    if [ $# = 1 ]; then
	check "$CLI getrawmempool | $FGREP $1" || FAIL=1
    else
	check "$CLI getrawmempool | $FGREP '\"'" || FAIL=1
    fi
    if [ $FAIL = 1 ]; then
	echo "No tx $1 in mempool:" >&2
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

extract_id()
{
    XID=`tr -s '\012\011\" ' ' ' | sed -n 's/{ id : \([0-9]*\) }/\1/p'`
    case "$XID" in
	[0-9]*)
	    echo $XID;;
	*)
	    return 1;;
    esac
}
