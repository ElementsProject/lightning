#!/bin/sh
# What `tools/reprobuild fetch` runs: download Bitcoin Core's release tarballs for every arch in the matrix plus
# SHA256SUMS(.asc), verify on the host (gpg against contrib/keys/bitcoin/,
# then sha256sum), and extract bin/bitcoin-cli per triplet into the cache
# that `docker` hands the Dockerfile as the `bitcoin` build context.
#
#   contrib/reprobuild/fetch-bitcoin.sh [--cache=DIR]
#
# Downloads land in release/cache/dl (never a build context).
# Result: $CACHE/<triplet>/bin/bitcoin-cli for x86_64-linux-gnu,
# aarch64-linux-gnu, arm-linux-gnueabihf.  Idempotent: existing downloads are
# kept, verification always re-runs.
set -eu

top=$(cd "$(dirname "$0")/../.." && pwd)
pins=$top/contrib/reprobuild/pins
BITCOIN_VERSION=$(sed -n 's/^BITCOIN_VERSION=//p' "$pins")
BITCOIN_URL=$(sed -n 's/^BITCOIN_URL=//p' "$pins")
MIN_SIGS=$(sed -n 's/^BITCOIN_MIN_SIGS=//p' "$pins")
CACHE=$top/release/cache/bitcoin-$BITCOIN_VERSION
for arg; do
    case "$arg" in
    --cache=*) CACHE=${arg#*=} ;;
    *) echo "unknown arg $arg" >&2; exit 1 ;;
    esac
done
# arch -> Bitcoin Core release triplet (the matrix's three arches)
TRIPLETS="x86_64-linux-gnu aarch64-linux-gnu arm-linux-gnueabihf"

DL=$(dirname "$CACHE")/dl
mkdir -p "$DL" "$CACHE"
cd "$DL"
# shellcheck disable=SC2086
for f in SHA256SUMS SHA256SUMS.asc $(for t in $TRIPLETS; do echo "bitcoin-$BITCOIN_VERSION-$t.tar.gz"; done); do
    [ -s "$f" ] && { echo "fetch: have $f"; continue; }
    echo "fetch: $BITCOIN_URL/$f"
    curl -fsSL -o "$f.part" "$BITCOIN_URL/$f" && mv "$f.part" "$f"
done

# gpg: throwaway keyring holding only the vendored keys; count good sigs
# rather than trusting gpg's exit status (SHA256SUMS.asc carries many
# signatures, most from keys we do not vendor).
GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT
gpg --batch --quiet --import "$top"/contrib/keys/bitcoin/* 2>/dev/null
status=$(gpg --batch --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null || true)
# Distinct *keys*, not signature lines: the point of a minimum is that several
# independent maintainers vouched for these bytes, and two signatures from one
# key -- or one key imported twice -- would otherwise count as two vouches.
good=$(printf '%s\n' "$status" | sed -n 's/^\[GNUPG:\] VALIDSIG \([0-9A-F]*\) .*/\1/p' | sort -u | grep -c . || true)
bad=$(printf '%s\n' "$status" | grep -c '^\[GNUPG:\] BADSIG ' || true)
printf '%s\n' "$status" | sed -n 's/^\[GNUPG:\] GOODSIG [0-9A-F]* /fetch: good signature: /p'
echo "fetch: $good distinct key(s) with a good signature, $bad bad (minimum $MIN_SIGS)"
[ "$bad" -eq 0 ] || { echo "fetch: BAD signature on SHA256SUMS.asc" >&2; exit 1; }
[ "$good" -ge "$MIN_SIGS" ] || { echo "fetch: too few good signatures" >&2; exit 1; }

# sha256: only our three tarballs are present; make sure all three were checked
checked=$(sha256sum -c --ignore-missing SHA256SUMS | tee /dev/stderr | grep -c ': OK$')
[ "$checked" -eq 3 ] || { echo "fetch: expected 3 verified tarballs, got $checked" >&2; exit 1; }

for t in $TRIPLETS; do
    rm -rf "${CACHE:?}/$t"
    mkdir -p "$CACHE/$t/bin"
    tar -xzf "bitcoin-$BITCOIN_VERSION-$t.tar.gz" -C "$CACHE/$t/bin" --strip-components=2 \
        "bitcoin-$BITCOIN_VERSION/bin/bitcoin-cli"
    echo "fetch: $CACHE/$t/bin/bitcoin-cli ($(file -b "$CACHE/$t/bin/bitcoin-cli" | cut -d, -f1-3))"
done
