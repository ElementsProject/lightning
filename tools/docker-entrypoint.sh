#!/usr/bin/env bash

: "${EXPOSE_TCP:=false}"

networkdatadir="${LIGHTNINGD_DATA}/${LIGHTNINGD_NETWORK}"

# -vls image: run the VLS signer proxy as the hsmd subdaemon
# unless the user already chose one.
if [ "${VLS_ENABLED:-false}" = "true" ]; then
    case " $* " in
        *" --subdaemon=hsmd:"* | *" --subdaemon hsmd:"*) ;;
        *) set -- --subdaemon=hsmd:/var/lib/vls/bin/remote_hsmd_socket "$@" ;;
    esac
    # The signer reads three things from the environment and *panics* if any is
    # missing (vls-proxy/src/util/env_var.rs: BITCOIND_RPC_URL, VLS_NETWORK,
    # VLS_CLN_VERSION).  lightningd sees only an hsmd that never answers and
    # then waits forever with no error of its own, so each one is either
    # supplied here or refused here.
    #
    # The network is not a separate choice: it follows lightningd's.
    export VLS_NETWORK="${VLS_NETWORK:-$LIGHTNINGD_NETWORK}"
    # The bitcoind URL cannot be guessed -- the signer validates on chain and
    # needs its own connection, which may not be the node's.  Refuse with an
    # explanation rather than starting something that will hang.
    if [ -z "${BITCOIND_RPC_URL:-}" ]; then
        echo "VLS_ENABLED=true but BITCOIND_RPC_URL is not set." >&2
        echo "The signer validates against the chain itself and needs a bitcoind RPC URL," >&2
        echo "e.g. -e BITCOIND_RPC_URL=http://user:pass@bitcoind:8332" >&2
        exit 1
    fi
fi

set -m
lightningd --network="${LIGHTNINGD_NETWORK}" "$@" &
LIGHTNINGD_PID=$!
trap 'kill -TERM "$LIGHTNINGD_PID" 2>/dev/null' TERM INT

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

wait "$LIGHTNINGD_PID"
trap - TERM INT
wait "$LIGHTNINGD_PID"
exit $?
