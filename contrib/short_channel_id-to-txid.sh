#! /bin/sh

set -e

if [ "$#" != 1 ]; then
    echo Usage: "$0" "short:channel:id" >&2
    echo Uses bitcoin-cli to extract the actual txid >&2
    exit 1
fi

BLOCK=$(echo "$1" | cut -d: -f1)
TXNUM=$(echo "$1" | cut -d: -f2)

bitcoin-cli getblock "$(bitcoin-cli getblockhash "$BLOCK")" true | grep '^    "' | head -n "$((TXNUM + 1))" | tail -n 1 | tr -dc '0-9a-f\n'

