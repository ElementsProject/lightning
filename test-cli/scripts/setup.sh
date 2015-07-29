#! /bin/sh -e

. `dirname $0`/vars.sh

if $CLI getinfo 2>/dev/null; then
    echo $DAEMON already running >&2
    exit 1
fi

# Start clean
rm -rf $DATADIR/$REGTESTDIR

$DAEMON &
i=0
while ! $CLI getinfo >/dev/null 2>&1; do
    if [ $i -gt 30 ]; then
	echo $DAEMON start failed? >&1
	exit 1
    fi
    sleep 1
    i=$(($i + 1))
done
    
scripts/generate-block.sh init

A1=`scripts/get-new-address.sh`
TX=`$CLI sendmany "" "{ \"$A1\":10 }"`
scripts/generate-block.sh

# Find the inputs number corresponding to that 10 btc out
echo "Argument to test.sh:"
for i in $(seq 1 $($CLI listunspent | grep -c txid) ); do scripts/getinput.sh $i | grep -q "$TX.*/1000000000/" && echo -n "$i "; done
echo
