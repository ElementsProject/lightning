# Sourced by other scripts

# Suppress sync if we can, for speedup.
if which eatmydata >/dev/null; then EATMYDATA=eatmydata; fi

STYLE=bitcoin
DATADIR=/tmp/bitcoin-lightning
CLI="bitcoin-cli -datadir=$DATADIR"
REGTESTDIR=regtest
DAEMON="$EATMYDATA bitcoind -datadir=$DATADIR"

findport()
{
    PORT=$1
    while netstat -ntl | grep -q ":$PORT "; do PORT=$(($PORT + 1)); done
    echo $PORT
}
#PREFIX="valgrind --vgdb-error=1"
