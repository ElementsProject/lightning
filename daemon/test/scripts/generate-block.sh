#! /bin/sh
# Generate a block.

set -e

. `dirname $0`/vars.sh
INIT=$1

# Initially we need 100 blocks so coinbase matures, giving us funds.
if [ -n "$INIT" ]; then
    # To activate segwit via BIP9, we need at least 432 blocks!
    $CLI generate 432 > /dev/null
    if $CLI getblockchaininfo | tr -s '\012\011 ' ' ' | grep -q '"segwit": { "status": "active",'; then :
    else
	echo "Segwit not activated after 432 blocks?" >&2
	$CLI getblockchaininfo >&2
	exit 1
    fi
else
    $CLI generate 1 > /dev/null
fi
