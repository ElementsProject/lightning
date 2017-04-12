# Sourced by other scripts

# Bash variables for in-depth debugging.
#set -vx
#export PS4='+(${BASH_SOURCE}:${LINENO}): ${FUNCNAME[0]:+${FUNCNAME[0]}(): }'

# Suppress sync if we can, for speedup.
if which eatmydata >/dev/null; then EATMYDATA=eatmydata; fi

DATADIR=/tmp/bitcoin-lightning$VARIANT
CLI="bitcoin-cli -datadir=$DATADIR"
REGTESTDIR=regtest
DAEMON="$EATMYDATA bitcoind -datadir=$DATADIR"

PREFIX=$EATMYDATA

# Always use valgrind if available (unless NO_VALGRIND=1 set)
if which valgrind >/dev/null; then :; else NO_VALGRIND=1; fi
[ -n "$NO_VALGRIND" ] || PREFIX="$EATMYDATA valgrind -q $VG_TRACE_CHILDREN --trace-children-skip=*bitcoin-cli* --error-exitcode=7"

# We inject 0.01 bitcoin, but then fees (estimatefee fails and we use a
# fee rate as per the default).
AMOUNT=991880000

# Default fee rate per kb.
FEE_RATE=200000

# Fee in millisatoshi if we have no htlcs (note rounding to make it even)
NO_HTLCS_FEE=$((338 * $FEE_RATE / 2000 * 2000))
ONE_HTLCS_FEE=$(( (338 + 32) * $FEE_RATE / 2000 * 2000))
EXTRA_FEE=$(($ONE_HTLCS_FEE - $NO_HTLCS_FEE))

findport()
{
    PORT=$1
    # Give two ports per variant.
    if [ x"$2" != x ]; then PORT=$(($PORT + $2 * 2)); fi
    while netstat -ntl | grep -q ":$PORT "; do PORT=$(($PORT + 1)); done
    echo $PORT
}
