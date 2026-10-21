#!/bin/sh
# What the driver's `check` runs on a finished tarball.
#
#   contrib/reprobuild/check.sh release/clightning-...tar.xz
#
# These are properties a release must have and the build could lose silently,
# so they are asserted on the shipped bytes rather than trusted, and `sign`
# refuses a tarball that fails:
#
#   * stripped -- no .symtab or .debug_* in any shipped ELF;
#   * static-pie -- pkgsStatic's stdenv appends `-static`, which quietly
#     yields a non-PIE static binary and loses ASLR;
#   * a build-id -- nixpkgs' toolchain emits none by default, and without one
#     a crash report from a stripped binary cannot be resolved at all.
set -eu

tarball=${1:?usage: check.sh <tarball>}
tmp=$(mktemp -d)
# chmod first: a tarball built straight out of a Nix store path carries
# read-only directories, which makes the cleanup fail.
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
tar -xf "$tarball" -C "$tmp"

# Located rather than spelled out: which prefix the tarball installs under is
# the release derivation's business, not a second fact this script has to keep
# in step with it.
lightningd=$(find "$tmp" -type f -name lightningd | head -1)
[ -n "$lightningd" ] || { echo "check: no lightningd in $tarball" >&2; exit 1; }

elfs=0 bad=0 nonpie=0 nobuildid=0 stripped_bad=0
# shellcheck disable=SC2044
for fp in $(find "$tmp" -type f); do
    [ "$(head -c 4 "$fp" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] || continue
    elfs=$((elfs + 1))
    rel=${fp#"$tmp"}

    sections=$(readelf -SW "$fp" 2>/dev/null || true)
    hdr=$(readelf -hW "$fp" 2>/dev/null || true)
    notes=$(readelf -nW "$fp" 2>/dev/null || true)

    if printf '%s' "$sections" | grep -qE '\.symtab|\.debug_'; then
        echo "FAIL  $rel: carries .symtab/.debug_*"
        stripped_bad=$((stripped_bad + 1)); bad=$((bad + 1))
    fi
    if ! printf '%s' "$hdr" | grep -q 'Type:[[:space:]]*DYN'; then
        echo "FAIL  $rel: not position-independent"
        nonpie=$((nonpie + 1)); bad=$((bad + 1))
    fi
    if ! printf '%s' "$notes" | grep -q 'Build ID'; then
        echo "FAIL  $rel: no build-id"
        nobuildid=$((nobuildid + 1)); bad=$((bad + 1))
    fi
    # A truly static binary has no INTERP and no NEEDED entries.
    if readelf -lW "$fp" 2>/dev/null | grep -q 'INTERP'; then
        echo "FAIL  $rel: has a PT_INTERP (dynamically linked)"
        bad=$((bad + 1))
    fi
done

# On the armhf row the *ABI* is the thing
# that has to be right, and it is invisible in the checks above.  Debian
# armhf is ARMv7 hard-float, and -mfpu=vfpv3-d16 had to be stated by hand
# because clang defaults armv7-a to NEON, and Alpine's
# "armhf" is ARMv6 entirely.  readelf -A is where the answer actually lands.
if readelf -hW "$lightningd" 2>/dev/null | grep -q 'Machine:.*ARM'; then
    echo "--- ARM build attributes ($(basename "$lightningd"))"
    readelf -A "$lightningd" 2>/dev/null |
        grep -E 'Tag_CPU_arch|Tag_FP_arch|Tag_ABI_VFP_args|Tag_Advanced_SIMD|Tag_CPU_name' || true
fi

echo "---"
echo "ELFs checked:        $elfs"
echo "unstripped:          $stripped_bad"
echo "non-PIE:             $nonpie"
echo "missing build-id:    $nobuildid"
if [ "$elfs" = 0 ]; then
    echo "CHECK FAILED: no ELF files found in $tarball" >&2
    exit 1
fi
if [ "$bad" != 0 ]; then
    echo "CHECK FAILED: $bad problem(s)" >&2
    exit 1
fi
echo "check: OK ($elfs ELFs, all static-pie, stripped, with build-id)"
