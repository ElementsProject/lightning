#! /bin/sh
# The CLN-VLS pair, on regtest (research 14; runs it every
# release).  This is the one test that exercises the *pair* rather than either
# binary alone, and it is why the driver builds a test-only `vlsd`:
# `remote_hsmd_socket` is CLN's hsmd replacement and does nothing by itself but
# listen on port 7701 for a signer to connect.
#
#   contrib/reprobuild/vls-regtest.sh --tarball=<clightning-...-amd64.tar.xz> \
#       --signer=<remote_hsmd_socket-...-amd64> --vlsd=<dir>/bin/vlsd \
#       --bitcoin=<dir>/bin
#
# It is deliberately outside the derivation: it needs bitcoind, a
# writable directory and several minutes, none of which belong in a build.
# `tools/reprobuild` supplies the paths -- vlsd and bitcoind from the certified
# nixpkgs, so the test does not depend on what the host happens to have
# installed.
#
# Native row only.  The released lightningd for a cross row runs under the
# host's binfmt in the portability harness; asking a qemu-emulated node and
# signer to complete a channel open would be testing the emulator.
#
# What it asserts, in order of what it would catch:
#   * lightningd comes up *at all* with the signer as hsmd -- the version
#     handshake (`VLS_CLN_VERSION`) is checked by VLS itself, and research 14
#     recorded v0.14.0 against CLN 25.12+/26.x as untested upstream;
#   * `getinfo` returns a node id: the node key came from the signer;
#   * `newaddr` and `signmessage` succeed: two more signer round trips;
#   * the signer logged no policy failure.
set -eu

TARBALL=
SIGNER=
VLSD=
BITCOIN_BIN=
KEEP=0
TIMEOUT=300
for arg; do
    case "$arg" in
    --tarball=*) TARBALL=${arg#*=} ;;
    --signer=*) SIGNER=${arg#*=} ;;
    --vlsd=*) VLSD=${arg#*=} ;;
    --bitcoin=*) BITCOIN_BIN=${arg#*=} ;;
    --keep) KEEP=1 ;;
    --timeout=*) TIMEOUT=${arg#*=} ;;
    *) echo "unknown arg $arg" >&2; exit 1 ;;
    esac
done
for v in TARBALL SIGNER VLSD BITCOIN_BIN; do
    eval "val=\$$v"
    [ -n "$val" ] || { echo "vls-regtest: --$(echo "$v" | tr 'A-Z_' 'a-z-') is required" >&2; exit 1; }
done
[ -f "$TARBALL" ] || { echo "vls-regtest: no $TARBALL" >&2; exit 1; }
[ -x "$SIGNER" ] || { echo "vls-regtest: no $SIGNER" >&2; exit 1; }
[ -x "$VLSD" ] || { echo "vls-regtest: no $VLSD" >&2; exit 1; }

tmp=$(mktemp -d)
# Ports are derived from the pid rather than fixed: bitcoind is started
# detached, so a run that dies before its cleanup (the first one here did,
# on a vlsd panic) leaves a daemon holding the port and every later run
# fails at startup with nothing but "Error during initialization".
RPCPORT=$((18000 + $$ % 1000))
LNPORT=$((19000 + $$ % 1000))
VLS_PORT=$((7700 + $$ % 100))
# The signer panics unless BITCOIND_RPC_URL, VLS_NETWORK and VLS_CLN_VERSION
# are all set (vls-proxy/src/util/env_var.rs), and lightningd -- which only
# sees an hsmd that never answers -- then hangs with no error of its own.  The
# released -vls image was missing two of the three.
VLS_NETWORK=regtest
export VLS_PORT VLS_NETWORK
# Set once the RPC port is known, below.
BITCOIND_RPC_URL=
export BITCOIND_RPC_URL

cleanup() {
    [ -n "${LN_PID:-}" ] && kill "$LN_PID" 2>/dev/null
    [ -n "${VLSD_PID:-}" ] && kill "$VLSD_PID" 2>/dev/null
    # bitcoind is detached, so ask it to stop rather than killing a pid that
    # is not ours; fall back to the pid if the RPC is already gone.
    "$BITCOIN_BIN/bitcoin-cli" -datadir="$tmp/btc" stop >/dev/null 2>&1 ||
        { [ -n "${BTC_PID:-}" ] && kill "$BTC_PID" 2>/dev/null; }
    sleep 2
    if [ "$KEEP" = 1 ]; then
        echo "vls-regtest: kept $tmp"
        return
    fi
    chmod -R u+w "$tmp" 2>/dev/null
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

echo "vls-regtest: $(basename "$TARBALL") + $(basename "$SIGNER")"
# `--integration-test` makes vlsd keep its own hsm_secret (in VLS deployments
# the signer holds the key, and CLN's hsmd only proxies), at
# <datadir>/../<network>/hsm_secret -- a sibling of the datadir that it does
# not create itself.
mkdir -p "$tmp/tree" "$tmp/ln" "$tmp/vls" "$tmp/btc" "$tmp/regtest"
tar -xf "$TARBALL" -C "$tmp/tree"
# Located, not spelled out: the install prefix belongs to the release
# derivation, not to this harness.
LIGHTNINGD=$(find "$tmp/tree" -type f -name lightningd | head -1)
CLI=$(find "$tmp/tree" -type f -name lightning-cli | head -1)
if [ -z "$LIGHTNINGD" ] || [ -z "$CLI" ]; then
    echo "vls-regtest: no lightningd/lightning-cli in the tarball" >&2
    exit 1
fi
[ -x "$LIGHTNINGD" ] || { echo "vls-regtest: the tarball has no usr/bin/lightningd" >&2; exit 1; }

# --- bitcoind ---------------------------------------------------------------
cat > "$tmp/btc/bitcoin.conf" <<EOF
regtest=1
server=1
# No P2P at all: this node talks to nobody, and the regtest default port
# (18445) is what actually collided between runs -- the RPC port was never
# the problem.  bitcoind refuses to start if it cannot bind, so turning
# listening off removes a whole class of "Error during initialization".
# (No backticks in this heredoc: it is unquoted, so they would run.)
listen=0
rpcuser=repro
rpcpassword=repro
fallbackfee=0.0002
[regtest]
rpcport=$RPCPORT
EOF
"$BITCOIN_BIN/bitcoind" -datadir="$tmp/btc" -daemonwait >/dev/null
BTC_PID=$(pgrep -n -f "bitcoind -datadir=$tmp/btc" || true)
BITCOIND_RPC_URL="http://repro:repro@127.0.0.1:$RPCPORT"
echo "vls-regtest: bitcoind rpc $RPCPORT, signer port $VLS_PORT"
btccli() { "$BITCOIN_BIN/bitcoin-cli" -datadir="$tmp/btc" -rpcwait "$@"; }
btccli createwallet repro >/dev/null 2>&1 || btccli loadwallet repro >/dev/null 2>&1 || true
addr=$(btccli getnewaddress)
btccli generatetoaddress 101 "$addr" >/dev/null
echo "vls-regtest: bitcoind at height $(btccli getblockcount)"

# --- the signer -------------------------------------------------------------
#
# VLS refuses to sign for a node whose version it was not told about, so
# VLS_CLN_VERSION must equal exactly what this lightningd reports (research
# 14; the -vls image bakes the same value).  Reading it off the binary under
# test is the point: a stale constant would pass while the pair was wrong.
CLN_VERSION=$("$LIGHTNINGD" --version)
echo "vls-regtest: lightningd $CLN_VERSION, signer $("$SIGNER" --git-desc)"

( cd "$tmp/vls" && VLS_CLN_VERSION="$CLN_VERSION" "$VLSD" \
    --connect "http://127.0.0.1:$VLS_PORT" --network regtest \
    --integration-test --datadir "$tmp/vls" --log-level info \
    > "$tmp/vlsd.log" 2>&1 ) &
VLSD_PID=$!

# --- lightningd, with the signer as hsmd ------------------------------------
VLS_CLN_VERSION="$CLN_VERSION" "$LIGHTNINGD" \
    --network=regtest --lightning-dir="$tmp/ln" \
    --bitcoin-rpcuser=repro --bitcoin-rpcpassword=repro \
    --bitcoin-rpcconnect=127.0.0.1 --bitcoin-rpcport="$RPCPORT" \
    --subdaemon=hsmd:"$SIGNER" \
    --log-level=debug --log-file="$tmp/ln/log" \
    --addr=127.0.0.1:"$LNPORT" &
LN_PID=$!

ok=0
waited=0
while [ "$waited" -lt "$TIMEOUT" ]; do
    waited=$((waited + 2))
    if "$CLI" --lightning-dir="$tmp/ln" --network=regtest getinfo > "$tmp/getinfo" 2>/dev/null; then
        ok=1
        break
    fi
    kill -0 "$LN_PID" 2>/dev/null || break
    sleep 2
done

fail=0
if [ "$ok" != 1 ]; then
    echo "FAIL lightningd never answered getinfo with the VLS signer as hsmd"
    echo "--- lightningd log (tail)"; tail -n 40 "$tmp/ln/log" 2>/dev/null
    echo "--- vlsd log (tail)"; tail -n 40 "$tmp/vlsd.log" 2>/dev/null
    exit 1
fi

nodeid=$(sed -n 's/.*"id"[ ]*:[ ]*"\([0-9a-f]\{66\}\)".*/\1/p' "$tmp/getinfo" | head -1)
if [ -n "$nodeid" ]; then
    echo "ok   node id from the signer: $nodeid"
else
    echo "FAIL getinfo returned no node id"; fail=1
fi

if "$CLI" --lightning-dir="$tmp/ln" --network=regtest newaddr >/dev/null 2>&1; then
    echo "ok   newaddr (signer derived a key)"
else
    echo "FAIL newaddr"; fail=1
fi

if "$CLI" --lightning-dir="$tmp/ln" --network=regtest \
    signmessage "reprobuild" > "$tmp/signmessage" 2>/dev/null; then
    echo "ok   signmessage (signer signed): $(sed -n 's/.*"zbase"[ ]*:[ ]*"\([^"]*\)".*/\1/p' "$tmp/signmessage" | cut -c1-24)..."
else
    echo "FAIL signmessage"; fail=1
fi

# A policy violation is how VLS refuses; it is not an lightningd error and
# would otherwise pass unnoticed.
if grep -qiE "policy failure|VLS_.*mismatch|refus" "$tmp/vlsd.log"; then
    echo "FAIL the signer logged a refusal:"
    grep -iE "policy failure|VLS_.*mismatch|refus" "$tmp/vlsd.log" | head -5 | sed 's/^/       /'
    fail=1
fi

echo "---"
if [ "$fail" != 0 ]; then
    echo "vls-regtest: FAILED ($fail problem(s))" >&2
    exit 1
fi
echo "vls-regtest: OK (the released signer signed for the released node)"
