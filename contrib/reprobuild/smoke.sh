#!/bin/sh
# Runtime smoke test of a static tarball on a foreign distro (16, 22), run by
# portability.sh:
#   docker run --rm -v <extracted-tree>:/cln:ro \
#       -v $PWD/contrib/reprobuild/smoke.sh:/smoke.sh:ro debian:bookworm-slim sh /smoke.sh
# Runs inside a bare debian:bookworm-slim with the extracted tree at /cln.
set -u
cp -a /cln/. / || exit 1
# Found on PATH, not at a fixed path: the install prefix is the release's
# business, and this script should not be a second place that has to know it.
lightningd_bin=$(command -v lightningd) || { echo "lightningd not on PATH after unpacking" >&2; exit 1; }
echo "=== ldd (expect: not a dynamic executable / static-pie)"
ldd "$lightningd_bin" 2>&1 | head -2
echo "=== --version"
lightningd --version
lightning-cli --version
echo "=== regtest start without bitcoind (expect: bcli fails to reach bitcoin-cli, lightningd exits)"
mkdir -p /tmp/ln
# Through a file, not a pipe: `cmd | tail` would make $? tail's status, so
# the exit code reported here would always be tail's 0 and this check would
# pass however lightningd died.  POSIX sh has no PIPESTATUS.
timeout 60 lightningd --network=regtest --lightning-dir=/tmp/ln --log-level=info --disable-plugin=clnrest > /tmp/ln/start.log 2>&1
rc=$?
tail -25 /tmp/ln/start.log
echo "lightningd exit=$rc"
echo "=== plugin manifest handshake: every plugin must answer getmanifest (static Rust included)"
plugin_dir=$(dirname "$(dirname "$lightningd_bin")")/libexec/c-lightning/plugins
req='{"jsonrpc":"2.0","id":"cln:getmanifest#0","method":"getmanifest","params":{"allow-deprecated-apis":false}}'
# All plugins at once.  stdin stays open until the reply is in (a plugin that
# sees EOF right after the request exits 0 without answering), and closes as
# soon as it is: under qemu every plugin answers in about a second, so a fixed
# wait per plugin was nearly all of this test's run time.
handshake() {
    out=/tmp/manifest.$(basename "$1")
    : > "$out"
    # The feeder polls the file the plugin writes, on purpose.
    # shellcheck disable=SC2094
    {
        printf '%s\n\n' "$req"
        i=0
        while [ $i -lt 200 ] && ! grep -q '"result"' "$out"; do
            sleep 0.1
            i=$((i + 1))
        done
    } | timeout 25 "$1" > "$out" 2>/dev/null
}
for p in "$plugin_dir"/*; do handshake "$p" & done
wait
for p in "$plugin_dir"/*; do
    out=/tmp/manifest.$(basename "$p")
    if grep -q '"result"' "$out"; then
        echo "ok   $(basename "$p")"
    else
        got=$(head -c 200 "$out" | tr -d '\n')
        echo "FAIL $(basename "$p"): ${got:-no output}"
    fi
done
