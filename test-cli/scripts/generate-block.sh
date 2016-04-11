#! /bin/sh
# Generate a block.

set -e

. `dirname $0`/vars.sh
INIT=$1

# Initially we need 100 blocks so coinbase matures, giving us funds.
if [ -n "$INIT" ]; then
    $CLI generate 101
else
    $CLI generate 1
fi
