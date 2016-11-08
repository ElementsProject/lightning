# Sourced by other scripts

STYLE=bitcoin
DATADIR=/tmp/bitcoin-lightning
CLI="bitcoin-cli -datadir=$DATADIR"
REGTESTDIR=regtest
DAEMON="bitcoind -datadir=$DATADIR"

findport()
{
    PORT=$1
    while netstat -ntl | grep -q ":$PORT "; do PORT=$(($PORT + 1)); done
    echo $PORT
}
#PREFIX="valgrind --vgdb-error=1"
