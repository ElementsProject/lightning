# Sourced by other scripts

if grep -q ^FEATURES.*ALPHA ../Makefile; then
    STYLE=alpha
    DATADIR=/tmp/alpha-lightning
    REGTESTDIR=alpharegtest
    CLI="alpha-cli -datadir=$DATADIR"
    DAEMON="alphad -datadir=$DATADIR"
    SEQ_ENFORCEMENT=true
else
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
fi

#PREFIX="valgrind --vgdb-error=1"
