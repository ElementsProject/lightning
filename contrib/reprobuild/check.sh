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

# The arm tarballs are for the Raspberry Pi (nix/release-rows): armhf must
# run on a Pi 2 (Cortex-A7: ARMv7, VFPv4, NEON), arm64 on a Pi 3
# (Cortex-A53: ARMv8.0).  Neither shows in the checks above.
machine=$(readelf -hW "$lightningd" | sed -n 's/^ *Machine: *//p')
case "$machine" in
*AArch64*) qemu=qemu-aarch64 cpu=cortex-a53 ;;
*ARM*) qemu=qemu-arm cpu=cortex-a7 ;;
*) qemu='' cpu='' ;;
esac

# armhf: what each binary was compiled for.  A tag above the Pi 2, or a
# soft-float ABI, fails.
armattr_bad=0
if [ "$qemu" = qemu-arm ]; then
    # shellcheck disable=SC2044
    for fp in $(find "$tmp" -type f); do
        [ "$(head -c 4 "$fp" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] || continue
        rel=${fp#"$tmp"}
        attrs=$(readelf -A "$fp" 2>/dev/null || true)
        tag() { printf '%s\n' "$attrs" | sed -n "s/^ *$1: //p"; }
        why=
        [ "$(tag Tag_CPU_arch)" = v7 ] || why="$why CPU_arch=$(tag Tag_CPU_arch)"
        case "$(tag Tag_FP_arch)" in
        VFPv3 | VFPv3-D16 | VFPv4 | VFPv4-D16) ;;
        *) why="$why FP_arch=$(tag Tag_FP_arch)" ;;
        esac
        case "$(tag Tag_Advanced_SIMD_arch)" in
        "" | NEONv1 | "NEONv1 with Fused-MAC") ;;
        *) why="$why Advanced_SIMD=$(tag Tag_Advanced_SIMD_arch)" ;;
        esac
        [ "$(tag Tag_ABI_VFP_args)" = "VFP registers" ] || why="$why not hard-float"
        if [ -n "$why" ]; then
            echo "FAIL  $rel: not for a Raspberry Pi 2:$why"
            armattr_bad=$((armattr_bad + 1)); bad=$((bad + 1))
        fi
    done
fi

# Both arm rows: run every binary on the oldest Pi's CPU.  This catches
# code the attributes do not declare (rustc's armv7 target used D16-D31
# under a VFPv3 tag).  The plugins exit with no lightningd on stdin, which
# is fine; a signal is not.  qemu is the pinned one, not the host's.
cpu_bad=0
if [ -n "$qemu" ]; then
    top=$(cd "$(dirname "$0")/../.." && pwd)
    qemudir=$(nix --extra-experimental-features 'nix-command flakes' build --impure \
        --no-link --print-out-paths --expr \
        "(import (builtins.getFlake \"git+file://$top?submodules=1\").inputs.nixpkgs { system = \"x86_64-linux\"; }).qemu-user" |
        head -1)
    [ -x "$qemudir/bin/$qemu" ] || { echo "CHECK FAILED: no $qemu in $qemudir" >&2; exit 1; }
    echo "--- running every ELF on $cpu"
    # shellcheck disable=SC2044
    for fp in $(find "$tmp" -type f); do
        [ "$(head -c 4 "$fp" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] || continue
        rc=0
        timeout 120 "$qemudir/bin/$qemu" -cpu "$cpu" "$fp" --version </dev/null >/dev/null 2>&1 || rc=$?
        if [ "$rc" -ge 124 ]; then
            echo "FAIL  ${fp#"$tmp"}: died on $cpu (exit $rc)"
            cpu_bad=$((cpu_bad + 1)); bad=$((bad + 1))
        fi
    done
fi

echo "---"
echo "ELFs checked:        $elfs"
echo "unstripped:          $stripped_bad"
echo "non-PIE:             $nonpie"
echo "missing build-id:    $nobuildid"
if [ -n "$qemu" ]; then
    [ "$qemu" = qemu-arm ] && echo "above Pi 2 ABI:      $armattr_bad"
    echo "crashed on $cpu: $cpu_bad"
fi
if [ "$elfs" = 0 ]; then
    echo "CHECK FAILED: no ELF files found in $tarball" >&2
    exit 1
fi
if [ "$bad" != 0 ]; then
    echo "CHECK FAILED: $bad problem(s)" >&2
    exit 1
fi
echo "check: OK ($elfs ELFs, all static-pie, stripped, with build-id)"
