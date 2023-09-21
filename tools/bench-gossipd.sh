#! /bin/sh
# Needs bitcoind -regtest running.

set -e

DIR=""
TARGETS=""
DEFAULT_TARGETS=" store_load_msec vsz_kb store_rewrite_sec listnodes_sec listchannels_sec routing_sec peer_write_all_sec peer_read_all_sec "
MCP_DIR=../million-channels-project/data/1M/gossip/
CSV=false

wait_for_start()
{
    i=0
    ID=""
    while [ -z "$ID" ]; do
	ID="$($LCLI1 -H getinfo 2>/dev/null | grep '^id=' | cut -d= -f2)"
	sleep 1
	i=$((i + 1))
	# If it has to upgrade the gossip store, that can take a while!
	if [ $i = 120 ]; then
	    echo "lightningd didn't start?" >&2
	    cat "$DIR"/log
	    exit 1
	fi
    done
    # Wait for it to catch up with bitcoind.
    while [ "$($LCLI1 -H getinfo | grep '^blockheight=' | cut -d= -f2)" != "$(bitcoin-cli -regtest getblockcount)" ]; do sleep 1; done
    echo "$ID"
}

print_stat()
{
    if $CSV; then
	sed -e 's/^ *//' -e 's/ *$//' | tr \\012 ,
    else
	echo "$1": | tr -d \\n
	sed -e 's/^ *//' -e 's/ *$//'
    fi
}

for arg; do
    case "$arg" in
	--dir=*)
	    DIR="${arg#*=}"
	    ;;
	--mcp-dir=*)
	    MCP_DIR="${arg#*=}"
	    ;;
	--csv)
	    CSV=true
	    ;;
	--help)
	    echo "Usage: tools/bench-gossipd.sh [--dir=<directory>] [--mcp-dir=<directory>] [--csv] [TARGETS]"
	    echo "Default targets:$DEFAULT_TARGETS"
	    exit 0
	    ;;
	-*)
	    echo "Unknown arg $arg" >&2
	    exit 1
	    ;;
	*)
	    TARGETS="$TARGETS $arg"
	    ;;
    esac
done

# Targets must be space-separated for ## trick.
if [ -z "$TARGETS" ]; then
    TARGETS="$DEFAULT_TARGETS"
else
    TARGETS="$TARGETS "
fi

if ! bitcoin-cli -regtest ping >/dev/null 2>&1; then
    bitcoind -regtest > "$DIR"/bitcoind.log &

    while ! bitcoin-cli -regtest ping >/dev/null 2>&1; do sleep 1; done
fi

LIGHTNINGD="./lightningd/lightningd --developer --network=regtest --dev-gossip-time=1550513768"
LCLI1="./cli/lightning-cli --lightning-dir=$DIR -R"

if [ -z "$DIR" ]; then
    trap 'rm -rf "$DIR"' 0

    DIR="$(mktemp -d)"
    ./devtools/create-gossipstore --csv "$MCP_DIR"/scidSatoshis.csv -i "$MCP_DIR"/1M.gossip -o "$DIR"/gossip_store
fi

# shellcheck disable=SC2086
if $CSV; then echo $TARGETS | tr ' ' ,; fi

# First, measure load time.
rm -f "$DIR"/peer
[ ! -f "$DIR"/log ] || mv "$DIR"/log  "$DIR"/log.old.$$
$LIGHTNINGD --lightning-dir="$DIR" --log-file="$DIR"/log --log-level=debug --bind-addr="$DIR"/peer &

rm -f "$DIR"/stats
ID=$(wait_for_start)

while ! grep -q 'gossipd.*: total store load time' "$DIR"/log 2>/dev/null; do
    sleep 1
done
if [ -z "${TARGETS##* store_load_msec *}" ]; then
    grep 'gossipd.*: total store load time' "$DIR"/log | cut -d\  -f7 | print_stat store_load_msec
fi

# How big is gossipd?
if [ -z "${TARGETS##* vsz_kb *}" ]; then
    ps -o vsz= -p "$(pidof lightning_gossipd)" | print_stat vsz_kb
fi

# How long does rewriting the store take?
if [ -z "${TARGETS##* store_rewrite_sec *}" ]; then
    # shellcheck disable=SC2086
    /usr/bin/time --append -f %e $LCLI1 dev-compact-gossip-store 2>&1 > /dev/null | print_stat store_rewrite_sec
fi

# Now, how long does listnodes take?
if [ -z "${TARGETS##* listnodes_sec *}" ]; then
    # shellcheck disable=SC2086
    /usr/bin/time --append -f %e $LCLI1 listnodes 2>&1 > "$DIR"/listnodes.json | print_stat listnodes_sec
fi

# Now, how long does listchannels take?
if [ -z "${TARGETS##* listchannels_sec *}" ]; then
    # shellcheck disable=SC2086
    /usr/bin/time --append -f %e $LCLI1 listchannels 2>&1 > "$DIR"/listchannels.json | print_stat listchannels_sec
fi

# Now, try routing between first and last points.
if [ -z "${TARGETS##* routing_sec *}" ]; then
    echo "$DIV" | tr -d \\n; DIV=","
    # shellcheck disable=SC2046
    # shellcheck disable=SC2005
    echo $(tr '{}' '\n' < "$DIR"/listnodes.json | grep nodeid | cut -d'"' -f4 | sort | head -n2) | while read -r from to; do
	# Channels have htlc_min of 10000 msat.
	# shellcheck disable=SC2086
	/usr/bin/time --quiet --append -f %e $LCLI1 getroute $from 10000 1 6 $to 2>&1 > /dev/null | print_stat routing_sec
    done
fi

# Try getting all from the peer.
if [ -z "${TARGETS##* peer_write_all_sec *}" ]; then
    ENTRIES=$(grep 'Read .* cannounce/cupdate/nannounce/cdelete' "$DIR"/log | cut -d\  -f5 | tr / + | bc)
    if [ "$ENTRIES" = 0 ]; then echo "Bad store?"; exit 1; fi
    /usr/bin/time --quiet --append -f %e devtools/gossipwith --initial-sync --max-messages=$((ENTRIES - 5)) "$ID"@"$DIR"/peer 2>&1 > /dev/null | print_stat peer_write_all_sec
fi

if [ -z "${TARGETS##* peer_read_all_sec *}" ]; then
    # shellcheck disable=SC2086
    $LCLI1 stop > /dev/null
    sleep 5
    # In case they specified dir, don't blow away store.
    mv "$DIR"/gossip_store "$DIR"/gossip_store.bak
    rm -f "$DIR"/peer

    $LIGHTNINGD --lightning-dir="$DIR" --log-file="$DIR"/log --bind-addr="$DIR"/peer --log-level=debug &
    ID=$(wait_for_start)

    # FIXME: Measure this better.
    EXPECTED=$(find "$DIR"/gossip_store.bak -printf %s)

    START_TIME=$(date +%s)
    # We send a bad msg at the end, so lightningd hangs up
    xzcat ../million-channels-project/data/1M/gossip/xa*.xz | devtools/gossipwith --max-messages=1 --stdin "$ID"@"$DIR"/peer 0011 > /dev/null

    while [ "$(find "$DIR"/gossip_store -printf %s)" -lt "$EXPECTED" ]; do
	sleep 1
	i=$((i + 1))
    done
    END_TIME=$(date +%s)

    echo $((END_TIME - START_TIME)) | print_stat peer_read_all_sec
    mv "$DIR"/gossip_store.bak "$DIR"/gossip_store
fi

# shellcheck disable=SC2086
$LCLI1 stop > /dev/null
