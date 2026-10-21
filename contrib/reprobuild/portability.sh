#!/bin/sh
# The portability matrix, run against a release tarball.
#
#   contrib/reprobuild/portability.sh release/clightning-...tar.xz
#
# One tarball per architecture replaced one per distribution, and the whole
# bet is that a static binary runs anywhere.  That is a claim about other
# people's systems, so it is measured every time rather than assumed -- and
# measured again whenever the toolchain moves, because a result obtained with
# a different libc does not transfer.
#
# The arch is read off the tarball name, and picks both the set of distro
# images and the `--platform` the foreign rows run under.
#
# Each row unpacks the tarball over / in a bare distro container and runs
# smoke.sh: --version, a regtest start, and a getmanifest
# handshake with every plugin -- the pass mark is every plugin the tarball
# actually ships, counted at run time.
set -eu

tarball=${1:?usage: portability.sh <tarball> [--images="ubuntu:26.04 ..."]}
shift
IMAGES_OVERRIDE=
for arg; do
    case "$arg" in
    --images=*) IMAGES_OVERRIDE=${arg#*=} ;;
    *) echo "unknown arg $arg" >&2; exit 1 ;;
    esac
done
top=$(cd "$(dirname "$0")/../.." && pwd)
smoke=$top/contrib/reprobuild/smoke.sh
tarball=$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")

# The matrix rows, which are the runtime promise.  Fedora has no
# armhf row (no such image); everything else is the full three-Ubuntu set.
case "$tarball" in
*-amd64*) ARCH=amd64; PLATFORM=linux/amd64;   IMAGES="ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 fedora:43" ;;
*-arm64*) ARCH=arm64; PLATFORM=linux/arm64;   IMAGES="ubuntu:22.04 ubuntu:24.04 ubuntu:26.04 fedora:43" ;;
*-armhf*) ARCH=armhf; PLATFORM=linux/arm/v7;  IMAGES="ubuntu:22.04 ubuntu:24.04 ubuntu:26.04" ;;
*) echo "cannot tell the arch from $tarball" >&2; exit 1 ;;
esac
# A release run checks the newest distro only -- enough to catch "the tarball
# does not run" -- and the full matrix is kept for the acceptance suite.
[ -n "$IMAGES_OVERRIDE" ] && IMAGES=$IMAGES_OVERRIDE
echo "portability: $ARCH ($PLATFORM) <- $(basename "$tarball")"
echo "portability: images: $IMAGES"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/tree"
tar -xf "$tarball" -C "$tmp/tree"

# How many plugins must answer getmanifest: counted from the tarball, not
# written down.  A hardcoded number stops meaning anything the moment a plugin
# is added or removed -- it would either keep passing against a stale floor or
# fail a release for a deliberate removal.  The path is globbed rather than
# spelled out so the install prefix is not baked in here too.
plugins=$(find "$tmp/tree" -path '*/libexec/c-lightning/plugins/*' -type f | grep -c . || true)
[ "$plugins" -gt 0 ] || { echo "portability: no plugins found in the tarball" >&2; exit 1; }
echo "portability: $plugins plugins in the tarball; every one must answer getmanifest"

pass=0 fail=0
for img in $IMAGES; do
    echo "################ $img ($PLATFORM)"
    if docker run --rm --platform "$PLATFORM" \
        -v "$tmp/tree:/cln:ro" -v "$smoke:/smoke.sh:ro" \
        "$img" sh /smoke.sh > "$tmp/out.$$" 2>&1; then
        :
    fi
    ok=$(grep -c '^ok   ' "$tmp/out.$$" || true)
    bad=$(grep -c '^FAIL ' "$tmp/out.$$" || true)
    ver=$(grep -m1 -A1 '=== --version' "$tmp/out.$$" | tail -1 || true)
    echo "  version line: $ver"
    echo "  plugins: $ok ok, $bad FAIL (of $plugins in the tarball)"
    if [ "$bad" = 0 ] && [ "$ok" -eq "$plugins" ]; then
        echo "  => PASS"
        pass=$((pass + 1))
    else
        echo "  => FAIL"
        sed -n '1,40p' "$tmp/out.$$"
        fail=$((fail + 1))
    fi
done

echo "================ portability $ARCH: $pass pass, $fail fail"
[ "$fail" = 0 ]
