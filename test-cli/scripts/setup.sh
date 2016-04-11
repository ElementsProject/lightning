#! /bin/sh -e

. `dirname $0`/vars.sh

if $CLI getinfo 2>/dev/null; then
    echo $DAEMON already running >&2
    exit 1
fi

# Start clean
rm -rf $DATADIR
mkdir $DATADIR

# Create appropriate config file so cmdline matches.
cat > $DATADIR/bitcoin.conf <<EOF
regtest=1
testnet=0
EOF

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
TX=`$CLI sendmany "" "{ \"$A1\":0.01 }"`
scripts/generate-block.sh
