#!/bin/sh
# check.sh's assertions for the VLS signer binary.  VLS is deferred from the
# release (51), so this runs only when the `vls` verb is used directly, and it
# is part of the gate for bringing VLS back.
#
#   contrib/reprobuild/vls-check.sh release/remote_hsmd_socket-v0.14.0-<arch>
#
# Same three assertions as the tarball check -- the strip, static-pie and
# the build-id -- plus the two
# things that are specific to this artifact:
#
#   * it is *run*, under the closure's own qemu on a cross row, so the claim
#     is "this binary works on that arch" and not "it links".  The smoke
#     test lives outside the derivation so it can be run here.
#     smoke test outside the derivation precisely so it could be run here.
#   * `--git-desc` has to name the pinned commit.  vls-util/build.rs bakes
#     `git describe` into the binary, and a fixed-output source fetch has no
#     `.git`; without the shim in nix/pkgs/vls.nix every VLS we ship would
#     report the literal `git-desc-failed`.  This is the assertion that the
#     shim is still doing its job.
set -eu

bin=${1:?usage: vls-check.sh <remote_hsmd_socket-...>}
top=$(cd "$(dirname "$0")/../.." && pwd)

[ "$(head -c 4 "$bin" | od -An -tx1 | tr -d ' \n')" = "7f454c46" ] ||
    { echo "CHECK FAILED: $bin is not an ELF" >&2; exit 1; }

bad=0
sections=$(readelf -SW "$bin")
hdr=$(readelf -hW "$bin")
notes=$(readelf -nW "$bin")

if printf '%s' "$sections" | grep -qE '\.symtab|\.debug_'; then
    echo "FAIL  carries .symtab/.debug_*"; bad=$((bad + 1))
fi
if ! printf '%s' "$hdr" | grep -q 'Type:[[:space:]]*DYN'; then
    echo "FAIL  not position-independent"; bad=$((bad + 1))
fi
if ! printf '%s' "$notes" | grep -q 'Build ID'; then
    echo "FAIL  no build-id"; bad=$((bad + 1))
fi
if readelf -lW "$bin" | grep -q 'INTERP'; then
    echo "FAIL  has a PT_INTERP (dynamically linked)"; bad=$((bad + 1))
fi

machine=$(printf '%s' "$hdr" | sed -n 's/^ *Machine: *//p')
case "$machine" in
*X86-64*) emu=; qemu= ;;
*AArch64*) qemu="qemu-aarch64" ;;
*ARM*)
    qemu="qemu-arm"
    echo "--- ARM build attributes"
    readelf -A "$bin" |
        grep -E 'Tag_CPU_arch|Tag_FP_arch|Tag_ABI_VFP_args|Tag_Advanced_SIMD|Tag_CPU_name' || true
    ;;
*) echo "FAIL  unexpected machine: $machine"; bad=$((bad + 1)); qemu= ;;
esac

if [ -n "${qemu:-}" ]; then
    # The emulator comes from the *pinned* nixpkgs, not the host: 
    # made the same choice inside the derivation, because a build (or a
    # check) must not depend on how the captain's kernel registered binfmt.
    qemudir=$(nix --extra-experimental-features 'nix-command flakes' build --impure \
        --no-link --print-out-paths --expr \
        "(import (builtins.getFlake \"git+file://$top?submodules=1\").inputs.nixpkgs { system = \"x86_64-linux\"; }).qemu" |
        head -1)
    emu="$qemudir/bin/$qemu"
    [ -x "$emu" ] || { echo "CHECK FAILED: no $qemu in $qemudir" >&2; exit 1; }
fi

echo "--- run"
desc=$($emu "$bin" --git-desc 2>&1) || {
    echo "FAIL  could not run $bin${emu:+ under $emu}: $desc"
    bad=$((bad + 1))
    desc=
}
echo "  $desc"
case "$desc" in
*git-desc-failed* | *git-desc-error* | *git-desc-badstr*)
    echo "FAIL  GIT_DESC is the build.rs fallback -- the git shim is not working"
    bad=$((bad + 1))
    ;;
"remote_hsmd_socket git_desc=v"*)
    rev=$(sed -n 's/^ *rev = "\([0-9a-f]*\)";.*/\1/p' "$top/nix/pkgs/vls.nix")
    short=$(printf '%s' "$rev" | cut -c1-12)
    case "$desc" in
    *"-g$short") ;;
    *) echo "FAIL  GIT_DESC does not name the pinned rev $short"; bad=$((bad + 1)) ;;
    esac
    ;;
"") ;;
*) echo "FAIL  unexpected --git-desc output"; bad=$((bad + 1)) ;;
esac

echo "---"
echo "size:      $(stat -c %s "$bin") bytes"
echo "sha256:    $(sha256sum "$bin" | cut -c1-64)"
echo "build-id:  $(printf '%s' "$notes" | sed -n 's/.*Build ID: //p')"
if [ "$bad" != 0 ]; then
    echo "CHECK FAILED: $bad problem(s)" >&2
    exit 1
fi
echo "check: OK (static-pie, stripped, build-id, runs, names the pinned rev)"
