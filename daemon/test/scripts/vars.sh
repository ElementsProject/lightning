# Sourced by other scripts

# Suppress sync if we can, for speedup.
if which eatmydata >/dev/null; then EATMYDATA=eatmydata; fi

DATADIR=/tmp/bitcoin-lightning$VARIANT
CLI="bitcoin-cli -datadir=$DATADIR"
REGTESTDIR=regtest
DAEMON="$EATMYDATA bitcoind -datadir=$DATADIR"

PREFIX=$EATMYDATA

# Always use valgrind if available (unless NO_VALGRIND=1 set)
if which valgrind >/dev/null; then :; else NO_VALGRIND=1; fi
[ -n "$NO_VALGRIND" ] || PREFIX="$EATMYDATA valgrind -q --error-exitcode=7"

findport()
{
    PORT=$1
    # Give two ports per variant.
    if [ x"$2" != x ]; then PORT=$(($PORT + $2 * 2)); fi
    while netstat -ntl | grep -q ":$PORT "; do PORT=$(($PORT + 1)); done
    echo $PORT
}
