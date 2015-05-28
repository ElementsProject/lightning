#! /bin/sh
# Query bitcoind to get (first) unspent output to spend.

###
# Nobody should *EVER* write code like this.  EVER!!
###

set -e

if [ n"$1" = n--privkey ]; then
    KEY=1
    shift
fi
NUM=1
if [ $# = 1 ]; then
    NUM=$1
    shift
fi
    
if [ $# -gt 0 ]; then
    echo "Usage: getinput.sh [--privkey] [INPUT-INDEX]"
    exit 1
fi

if [ -n "$KEY" ]; then
    ADDR=`bitcoin-cli -testnet listunspent | sed -n 's/^        "address" : "\([0-9a-zA-Z]*\)",$/\1/p' | tail -n +$NUM | head -n1`
    bitcoin-cli dumpprivkey $ADDR
else
    TXID=`bitcoin-cli -testnet listunspent | sed -n 's/^        "txid" : "\([0-9a-f]*\)",$/\1/p' | tail -n +$NUM | head -n1`
    OUTNUM=`bitcoin-cli -testnet listunspent | sed -n 's/^        "vout" : \([0-9]*\),$/\1/p' | tail -n +$NUM | head -n1`
    AMOUNT=`bitcoin-cli -testnet listunspent | sed -n 's/^        "amount" : \([0-9.]*\),$/\1/p' | tail -n +$NUM | head -n1 | tr -d . | sed 's/^0*//'`
    SCRIPT=`bitcoin-cli -testnet listunspent | sed -n 's/^        "scriptPubKey" : "\([0-9a-f]*\)",$/\1/p' | tail -n +$NUM | head -n1`

    echo $TXID/$OUTNUM/$AMOUNT/$SCRIPT
fi
