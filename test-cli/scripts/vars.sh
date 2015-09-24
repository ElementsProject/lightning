# Sourced by other scripts

if grep -q ^FEATURES.*ALPHA ../Makefile; then
    STYLE=alpha
    DATADIR=$HOME/.alpha
    REGTESTDIR=alpharegtest
    CLI="alpha-cli -datadir=$DATADIR -regtest -testnet=0"
    DAEMON="alphad -datadir=$DATADIR"
else
    STYLE=bitcoin
    CLI="bitcoin-cli -regtest"
    DATADIR=$HOME/.bitcoin
    REGTESTDIR=regtest
    DAEMON="bitcoind -regtest"
fi

#PREFIX="valgrind --vgdb-error=1"
