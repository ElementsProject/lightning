#!/usr/bin/env bash

: "${EXPOSE_TCP:=false}"

networkdatadir="${LIGHTNINGD_DATA}/${LIGHTNINGD_NETWORK}"

set -m
lightningd --network="${LIGHTNINGD_NETWORK}" "$@" &

echo "Core-Lightning starting"
while read -r i; do if [ "$i" = "lightning-rpc" ]; then break; fi; done \
    < <(inotifywait -e create,open --format '%f' --quiet "${networkdatadir}" --monitor)

if [ "$EXPOSE_TCP" == "true" ]; then
    echo "Core-Lightning started, RPC available on port $LIGHTNINGD_RPC_PORT"

    socat "TCP4-listen:$LIGHTNINGD_RPC_PORT,fork,reuseaddr" "UNIX-CONNECT:${networkdatadir}/lightning-rpc" &
fi

# Now run any scripts which exist in the lightning-poststart.d directory
if [ -d "$LIGHTNINGD_DATA"/lightning-poststart.d ]; then
    for f in "$LIGHTNINGD_DATA"/lightning-poststart.d/*; do
	"$f"
    done
fi

fg %-
