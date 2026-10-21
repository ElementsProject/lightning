#! /bin/sh
# The two-tree probe, for one row.
#
#   contrib/reprobuild/two-tree-probe.sh [--arch=amd64] [--jobs=N] [--host-nix]
#
# Build the same row from two trees that differ **only** by one tracked file
# that is never compiled and never shipped, and require identical bytes.
#
# Why this and not a string check: the first proposal was "zero /nix/store
# references" as the invariant, and 40 retired it as both unreachable
# (lightningd keeps 8 OpenSSL store-path strings deliberately) and insufficient
# -- a variant whose bytes tracked the tree carried no offending string at all,
# because the path reached the bytes through gcc's `-frandom-seed` and
# `DW_AT_producer`, which `--strip-all` then deletes while keeping the
# consequence.  Only rebuilding from a second tree can see that.
#
# This runs on **every** row rather than one: an amd64-only probe
# was amd64-only, and the armhf Rust binaries were separately carrying a
# DT_RUNPATH naming their output path -- invisible on the row that was checked.
#
# It costs two builds of one row, so it belongs in `certify`'s acceptance suite
# rather than in every release.  The probe commits are made on a throwaway
# branch and removed afterwards; the tree is left as it was found.
set -eu

top=$(cd "$(dirname "$0")/../.." && pwd)
ARCH=amd64
JOBS=$(nproc 2>/dev/null || echo 4)
HOST_NIX=
for arg; do
    case "$arg" in
    --arch=*) ARCH=${arg#*=} ;;
    --jobs=*) JOBS=${arg#*=} ;;
    --host-nix) HOST_NIX=--host-nix ;;
    *) echo "unknown arg $arg" >&2; exit 1 ;;
    esac
done

[ -z "$(git -C "$top" status --porcelain --untracked-files=no)" ] ||
    { echo "two-tree-probe: commit first; this makes commits of its own" >&2; exit 1; }

start_branch=$(git -C "$top" rev-parse --abbrev-ref HEAD)
start_rev=$(git -C "$top" rev-parse HEAD)
probe=probe/two-tree-$$
out=${TMPDIR:-/tmp}/two-tree-probe.$$
mkdir -p "$out"

# Invoked by the trap below, which shellcheck does not count as a use (SC2329
# in 0.11, SC2317 in 0.9/0.10).
# shellcheck disable=SC2329,SC2317
cleanup() {
    git -C "$top" checkout -q "$start_branch" 2>/dev/null ||
        git -C "$top" checkout -q "$start_rev" 2>/dev/null
    git -C "$top" branch -qD "$probe" 2>/dev/null
    rm -f "$top/TWO-TREE-PROBE.md"
    rm -rf "$out"
}
trap cleanup EXIT INT TERM

echo "two-tree-probe: $ARCH, from $start_rev on a throwaway branch"
git -C "$top" checkout -q -b "$probe"

build() {
    label=$1
    "$top/tools/reprobuild" $HOST_NIX --jobs="$JOBS" \
        --version=probe --mtime=2020-01-01 --out="$out/$label" build "$ARCH" \
        > "$out/$label.log" 2>&1 || {
        echo "two-tree-probe: build $label FAILED" >&2
        tail -n 20 "$out/$label.log" >&2
        exit 1
    }
    sha256sum "$out/$label/clightning-probe-static-$ARCH.tar.xz" | cut -d' ' -f1
}

# Tree A: the commit under test, plus the probe file with one value.  Both
# builds carry the file, so what differs between them is only its *contents* --
# a file that no compiler reads and no artifact contains.
printf 'probe A\n' > "$top/TWO-TREE-PROBE.md"
git -C "$top" add TWO-TREE-PROBE.md
git -C "$top" -c user.name=probe -c user.email=probe@localhost \
    commit -q -m "probe A"
a=$(build A)
echo "two-tree-probe: A $a"

printf 'probe B -- one tracked, unshipped, uncompiled file, different bytes\n' \
    > "$top/TWO-TREE-PROBE.md"
git -C "$top" add TWO-TREE-PROBE.md
git -C "$top" -c user.name=probe -c user.email=probe@localhost \
    commit -q -m "probe B"
b=$(build B)
echo "two-tree-probe: B $b"

echo "---"
if [ "$a" = "$b" ]; then
    echo "two-tree-probe: OK ($ARCH) -- the release bytes do not track the tree"
    exit 0
fi
echo "two-tree-probe: FAILED ($ARCH) -- the bytes track the tree" >&2
echo "  A $a" >&2
echo "  B $b" >&2
echo "  Something in the build reads a path that moves with the source: check" >&2
echo "  build-ids first (nixpkgs seeds -frandom-seed from \$out), then rpaths," >&2
echo "  then panic-location strings in the Rust artifacts (40, 47)." >&2
exit 1
