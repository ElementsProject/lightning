# Sourced by other scripts

STYLE=bitcoin
DATADIR=/tmp/bitcoin-lightning
CLI="bitcoin-cli -datadir=$DATADIR"
REGTESTDIR=regtest
DAEMON="bitcoind -datadir=$DATADIR"
if grep ^FEATURES ../Makefile | cut -d'#' -f1 | grep -q BIP68; then
	SEQ_ENFORCEMENT=true
else
	SEQ_ENFORCEMENT=false
fi

findport()
{
    PORT=$1
    while netstat -ntl | grep -q ":$PORT "; do PORT=$(($PORT + 1)); done
    echo $PORT
}
#PREFIX="valgrind --vgdb-error=1"
