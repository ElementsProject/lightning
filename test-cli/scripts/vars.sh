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

#PREFIX="valgrind --vgdb-error=1"
