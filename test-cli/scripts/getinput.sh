#! /bin/sh
# Query bitcoind to get (first) unspent output to spend.

###
# Nobody should *EVER* write code like this.  EVER!!
###
set -e

. `dirname $0`/vars.sh

NUM=1
if [ $# = 1 ]; then
    NUM=$1
    shift
fi
    
if [ $# -gt 0 ]; then
    echo "Usage: getinput.sh [INPUT-INDEX]"
    exit 1
fi

TXID=`$CLI listunspent | sed -n 's/^ *"txid" *: *"\([0-9a-f]*\)",$/\1/p' | tail -n +$NUM | head -n1`
OUTNUM=`$CLI listunspent | sed -n 's/^ *"vout" *: *\([0-9]*\),$/\1/p' | tail -n +$NUM | head -n1`
AMOUNT=`$CLI listunspent | sed -n 's/^ *"amount" *: *\([0-9.]*\),$/\1/p' | tail -n +$NUM | head -n1 | tr -d . | sed 's/^0*//'`
SCRIPT=`$CLI listunspent | sed -n 's/^ *"scriptPubKey" *: *"\([0-9a-f]*\)",$/\1/p' | tail -n +$NUM | head -n1`
ADDR=`$CLI listunspent | sed -n 's/^ *"address" *: *"\([0-9a-zA-Z]*\)",$/\1/p' | tail -n +$NUM | head -n1`
PRIVKEY=`$CLI dumpprivkey $ADDR`

echo $TXID/$OUTNUM/$AMOUNT/$SCRIPT/$PRIVKEY
