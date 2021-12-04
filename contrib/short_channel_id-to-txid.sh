#! /bin/sh

set -e

if [ "$#" != 1 ]
then
    echo Usage: "$0" "shortchannelid (e.g. 532046x1702x0 or 532046:1702:0)" >&2
    echo Uses bitcoin-cli to extract the actual txid >&2
    exit 1
fi

# Try to segment using both x and : as delimiters (compatibility with the old shortchannelid standard)
BLOCK=$(echo "$1" | cut -dx -f1)
TXNUM=$(echo "$1" | cut -dx -f2)

if [ "$BLOCK" = "$1" ] && [ "$TXNUM" = "$1" ]
then
    BLOCK=$(echo "$1" | cut -d: -f1)
    TXNUM=$(echo "$1" | cut -d: -f2)
fi

if [ "$BLOCK" = "$1" ] && [ "$TXNUM" = "$1" ]
then
    echo The provided shortchannelid is invalid. Valid examples: 532046x1702x0 or 532046:1702:0 >&2
    exit 1
fi

bitcoin-cli getblock "$(bitcoin-cli getblockhash "$BLOCK")" true | grep '^    "' | head -n "$((TXNUM + 1))" | tail -n 1 | tr -dc '0-9a-f\n'