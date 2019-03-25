#!/usr/bin/env bash

: "${EXPOSE_TCP:=false}"

# SIGTERM-handler this function gets called on Ctrl+C or if docker trys to stop the container
term_handler(){
   echo "*** Stopping C-Lightning Node ***"
   lightning-cli stop # this will gracefully shutdown the node and then exit
   exit 0
}

# Setup signal handlers
trap 'term_handler' SIGTERM SIGINT

if [ "$EXPOSE_TCP" == "true" ]; then
    set -m
    lightningd "$@" &
    pid="$!"
    echo "C-Lightning starting"
    while read -r i; do if [ "$i" = "lightning-rpc" ]; then break; fi; done \
    < <(inotifywait  -e create,open --format '%f' --quiet "$LIGHTNINGD_DATA" --monitor)
    echo "C-Lightning started"
    echo "C-Lightning started, RPC available on port $LIGHTNINGD_RPC_PORT"

    socat "TCP4-listen:$LIGHTNINGD_RPC_PORT,fork,reuseaddr" "UNIX-CONNECT:$LIGHTNINGD_DATA/lightning-rpc" &
else
    exec lightningd "$@" &
    pid="$!"
fi

# the node got started in background, so we can react on shutdown requests in this script
# wait for the node to shutdown, so that the container stays alive
wait $pid
