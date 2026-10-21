#!/bin/sh
# Runtime smoke test of a static tarball on a foreign distro (16, 22), run by
# portability.sh:
#   docker run --rm -v <extracted-tree>:/cln:ro \
#       -v $PWD/contrib/reprobuild/smoke.sh:/smoke.sh:ro debian:bookworm-slim sh /smoke.sh
# Runs inside a bare debian:bookworm-slim with the extracted tree at /cln.
set -u
cp -a /cln/. / || exit 1
echo "=== ldd (expect: not a dynamic executable / static-pie)"
ldd /usr/bin/lightningd 2>&1 | head -2
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
for p in /usr/libexec/c-lightning/plugins/*; do
    # keep stdin open: a plugin that sees EOF right after the request exits 0 before answering
    out=$( { printf '{"jsonrpc":"2.0","id":"cln:getmanifest#0","method":"getmanifest","params":{"allow-deprecated-apis":false}}\n\n'; sleep 3; } | timeout 20 "$p" 2>/dev/null | head -c 200)
    case "$out" in
        *'"result"'*) echo "ok   $(basename "$p")";;
        *) echo "FAIL $(basename "$p"): ${out:-no output}";;
    esac
done
