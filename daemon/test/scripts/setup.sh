#! /bin/sh -e

. `dirname $0`/vars.sh

VERSION=$(`dirname $0`/../../lightning-cli --version | head -n1)
[ $VERSION = `git describe --always --dirty` ] || (echo Wrong version $VERSION >&2; exit 1)

# Start clean
rm -rf $DATADIR
mkdir $DATADIR

# Find a free port (racy, but hey)
PORT=`findport 18332 $VARIANT`
RPCPORT=`findport $(($PORT + 1))`

# Create appropriate config file so cmdline matches.
cat > $DATADIR/bitcoin.conf <<EOF
regtest=1
testnet=0
rpcport=$RPCPORT
port=$PORT
EOF

$DAEMON &
i=0
while ! $CLI getinfo >/dev/null 2>&1; do
    if [ $i -gt 60 ]; then
	echo $DAEMON start failed? >&1
	exit 1
    fi
    sleep 1
    i=$(($i + 1))
done

# Make sure they have segwit support!
if $CLI getblockchaininfo | grep -q '"segwit"'; then :
else
    echo This bitcoind does not have segwit support. >&2
    echo Please install a recent one >&2
    exit 1
fi

`dirname $0`/generate-block.sh init

A1=$($CLI getnewaddress)
TX=`$CLI sendmany "" "{ \"$A1\":0.01 }"`
`dirname $0`/generate-block.sh
