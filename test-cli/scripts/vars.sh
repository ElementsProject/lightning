# Sourced by other scripts

if grep -q ^FEATURES.*ALPHA ../Makefile; then
    STYLE=alpha
    DATADIR=$HOME/.alpha
    REGTESTDIR=alpharegtest
    CLI="alpha-cli -datadir=$DATADIR -regtest -testnet=0"
    DAEMON="alphad -datadir=$DATADIR"
    SEQ_ENFORCEMENT=true
else
    STYLE=bitcoin
    CLI="bitcoin-cli -regtest"
    DATADIR=$HOME/.bitcoin
    REGTESTDIR=regtest
    DAEMON="bitcoind -regtest"
    if grep ^FEATURES ../Makefile | cut -d'#' -f1 | grep -q BIP68; then
	SEQ_ENFORCEMENT=true
    else
	SEQ_ENFORCEMENT=false
    fi
fi

#PREFIX="valgrind --vgdb-error=1"
