#!/usr/bin/env bash

: "${EXPOSE_TCP:=false}"

cat <<-EOF > "$LIGHTNINGD_DATA/config"
${LIGHTNINGD_OPT}
bind-addr=0.0.0.0:${LIGHTNINGD_PORT}
EOF

LIGHTNINGD_NETWORK_NAME=""

if [ "$LIGHTNINGD_CHAIN" == "btc" ] && [ "$LIGHTNINGD_NETWORK" == "mainnet" ]; then
    LIGHTNINGD_NETWORK_NAME="bitcoin"
elif [ "$LIGHTNINGD_CHAIN" == "btc" ] && [ "$LIGHTNINGD_NETWORK" == "testnet" ]; then
    LIGHTNINGD_NETWORK_NAME="testnet"
elif [ "$LIGHTNINGD_CHAIN" == "btc" ] && [ "$LIGHTNINGD_NETWORK" == "regtest" ]; then
    LIGHTNINGD_NETWORK_NAME="regtest"
elif [ "$LIGHTNINGD_CHAIN" == "ltc" ] && [ "$LIGHTNINGD_NETWORK" == "mainnet" ]; then
    LIGHTNINGD_NETWORK_NAME="litecoin"
elif [ "$LIGHTNINGD_CHAIN" == "ltc" ] && [ "$LIGHTNINGD_NETWORK" == "testnet" ]; then
    LIGHTNINGD_NETWORK_NAME="litecoin-testnet"
else
    echo "Invalid combinaion of LIGHTNINGD_NETWORK and LIGHTNINGD_CHAIN. LIGHTNINGD_CHAIN should be btc or ltc. LIGHTNINGD_NETWORK should be mainnet, testnet or regtest."
    echo "ltc regtest is not supported"
    exit
fi

echo "network=$LIGHTNINGD_NETWORK_NAME" >> "$LIGHTNINGD_DATA/config"
echo "network=$LIGHTNINGD_NETWORK_NAME added in $LIGHTNINGD_DATA/config"

if [[ "${LIGHTNINGD_ANNOUNCEADDR}" ]]; then
    echo "announce-addr=$LIGHTNINGD_ANNOUNCEADDR:${LIGHTNINGD_PORT}" >> "$LIGHTNINGD_DATA/config"
fi

if [[ "${LIGHTNINGD_ALIAS}" ]]; then
    # This allow to strip this parameter if LND_ALIGHTNINGD_ALIASLIAS is empty or null, and truncate it
    LIGHTNINGD_ALIAS="$(echo "$LIGHTNINGD_ALIAS" | cut -c -32)"
    echo "alias=$LIGHTNINGD_ALIAS" >> "$LIGHTNINGD_DATA/config"
    echo "alias=$LIGHTNINGD_ALIAS added to $LIGHTNINGD_DATA/config"
fi

if [[ "${LIGHTNINGD_READY_FILE}" ]]; then
    echo "Waiting $LIGHTNINGD_READY_FILE to be created..."
    while [ ! -f "$LIGHTNINGD_READY_FILE" ]; do sleep 1; done
    echo "The chain is fully synched"
fi

if [[ "${LIGHTNINGD_HIDDENSERVICE_HOSTNAME_FILE}" ]]; then
    echo "Waiting $LIGHTNINGD_HIDDENSERVICE_HOSTNAME_FILE to be created by tor..."
    while [ ! -f "$LIGHTNINGD_HIDDENSERVICE_HOSTNAME_FILE" ]; do sleep 1; done
    HIDDENSERVICE_ONION="$(head -n 1 "$LIGHTNINGD_HIDDENSERVICE_HOSTNAME_FILE"):${LIGHTNINGD_PORT}"
    echo "announce-addr=$HIDDENSERVICE_ONION" >> "$LIGHTNINGD_DATA/config"
    echo "announce-addr=$HIDDENSERVICE_ONION added to $LIGHTNINGD_DATA/config"
fi

if ! grep -q "^rpc-file=" "$LIGHTNINGD_DATA/config"; then
    echo "rpc-file=$LIGHTNINGD_DATA/lightning-rpc" >> "$LIGHTNINGD_DATA/config"
    echo "rpc-file=$LIGHTNINGD_DATA/lightning-rpc added to $LIGHTNINGD_DATA/config"
fi

echo "Installing bundled plugins"
mkdir -p "$LIGHTNINGD_DATA/plugins"
cp -u /etc/bundledplugins/* $LIGHTNINGD_DATA/plugins/

set -m
lightningd "$@" &

echo "Core-Lightning starting"
while read -r i; do if [ "$i" = "lightning-rpc" ]; then break; fi; done \
    < <(inotifywait -e create,open --format '%f' --quiet "$LIGHTNINGD_DATA" --monitor)

if [ "$EXPOSE_TCP" == "true" ]; then
    echo "Core-Lightning started, RPC available on port $LIGHTNINGD_RPC_PORT"

    socat "TCP4-listen:$LIGHTNINGD_RPC_PORT,fork,reuseaddr" "UNIX-CONNECT:$LIGHTNINGD_DATA/lightning-rpc" &
fi

# Now run any scripts which exist in the lightning-poststart.d directory
if [ -d "$LIGHTNINGD_DATA"/lightning-poststart.d ]; then
    for f in "$LIGHTNINGD_DATA"/lightning-poststart.d/*; do
	"$f"
    done
fi

RUNE_PATH="$LIGHTNINGD_DATA/rune.env"
if [ -f "$RUNE_PATH" ]; then
    source "$RUNE_PATH"
    matches=$(lightning-cli showrunes | jq --arg rune "$LIGHTNING_RUNE" --arg unique_id "$UNIQUE_ID" \
        '.runes[] | select(.rune == $rune and .unique_id == $unique_id)')
    if [[ -n $matches ]]; then
        echo "Rune already created"
    else
        LIGHTNING_RUNE=""
        UNIQUE_ID=""
        echo "Rune not found, re-creating..."
    fi
fi

if ! [[ "$LIGHTNING_RUNE" ]]; then
    echo "Creating rune..."
    RUNE_RESPONSE=$(lightning-cli createrune 'restrictions=[["For Applications#"]]')
    LIGHTNING_RUNE=$(echo "$RUNE_RESPONSE" | jq -r '.rune')
    UNIQUE_ID=$(echo "$RUNE_RESPONSE" | jq -r '.unique_id')
    if [[ "$LIGHTNING_RUNE" ]]; then
        echo "LIGHTNING_RUNE=\"${LIGHTNING_RUNE}\"" > "$RUNE_PATH"
        echo "UNIQUE_ID=${UNIQUE_ID}" >> "$RUNE_PATH"
        echo "Rune created"
        source "$RUNE_PATH"
    fi
fi

if ! [[ "$LIGHTNING_RUNE" ]]; then
    echo "Error while creating a rune..."
    echo "$RUNE_RESPONSE"
fi

fg %-
