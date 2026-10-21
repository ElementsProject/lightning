# the row's static-pie link recipe.
#
# Extracted verbatim from `default.nix`'s let block by so the VLS
# derivation can link the same way CLN does.  38 is a *third-party*
# repository, but it is the same rustc, the same musl targets and the same
# armv7 gcc gap, so a second copy of this reasoning would be a second thing
# to keep in step.  Nothing here changed in the move: the wrapper
# derivations' store paths were compared before and after
# (`s03iqdph...-armv7l-unknown-linux-musleabihf-rust-cc.drv` and friends).
#
# `pkgs` is the *row's* package set -- pkgsStatic, or pkgsCross.<t>.pkgsStatic.
{ pkgs, lib }:
let
  inherit (pkgs) stdenv;
  bp = pkgs.buildPackages;
in
rec {
  # the armhf row's static-pie problem.
  #
  # nixpkgs' gcc 14.3.0 cannot link static-pie for 32-bit arm, and fails
  # *quietly*: `-static-pie` produces a **dynamically** linked PIE asking for
  # /lib/ld-musl-armhf.so.1, and `-static -pie` produces a static ET_EXEC.
  # The same wrapper on aarch64 gives a real static-pie, so this is gcc's ARM
  # spec dropping the PIE in a static link, not nixpkgs.  ld is perfectly
  # able: the recipe below (`-Wl,-pie` straight to the linker, no dynamic
  # linker, and the PIE crt objects named explicitly, since `-static` makes
  # gcc choose the non-PIE crt1.o/crtbeginT.o pair) yields ET_DYN, no INTERP,
  # and runs under qemu-arm.  Verified on a one-line program before being
  # committed to a build.
  #
  #  (static-pie everywhere) is what this preserves; the human
  # chose it on 2026-09-12 over dropping armhf or shipping it without ASLR.
  arm32 = stdenv.hostPlatform.isAarch32;
  gccLibDir = "${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.config}/${stdenv.cc.cc.version}";
  muslLibDir = "${stdenv.cc.libc}/lib";
  # How "link this statically, as a PIE" is spelled for this row.
  staticPieFlags = if arm32 then "-static -Wl,-pie -Wl,--no-dynamic-linker" else "-static-pie";
  # On arm32 the crt objects must also be named, and *in order* -- crtendS.o
  # and crtn.o belong after the user's objects, which a flag string cannot
  # express.  Hence a wrapper, used as CC only on that row: the other two
  # rows keep `cc -static-pie` verbatim, so their proven bytes do not move.
  staticPieCc = bp.writeShellScriptBin "${stdenv.cc.targetPrefix}static-pie-cc" ''
    # Only a *link* gets this treatment.  A compile-only or -shared
    # invocation passes straight through -- CLN's Makefile uses $(CC) for
    # both, and the crt objects would break a `-c`.
    for a in "$@"; do
      case "$a" in
        -c | -E | -S | -M | -MM | -MD | -shared)
          exec ${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc "$@"
          ;;
      esac
    done
    exec ${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc \
      ${staticPieFlags} -nostartfiles \
      ${muslLibDir}/rcrt1.o ${muslLibDir}/crti.o ${gccLibDir}/crtbeginS.o \
      "$@" \
      ${gccLibDir}/crtendS.o ${muslLibDir}/crtn.o
  '';
  # What configure is handed as the compiler for the release link.
  releaseCc =
    if arm32 then
      "${staticPieCc}/bin/${stdenv.cc.targetPrefix}static-pie-cc"
    else
      "${stdenv.cc.targetPrefix}cc ${staticPieFlags}";
  # rustc's static-pie gap, which is
  # The same gap the Alpine builder's `<triple>-rust-clang` wrapper closed.  nixpkgs
  # supplies rustc 1.89.0 rather than the 1.85, and the gap is unchanged:
  # rustc links a crt-static musl target with plain `-static` unless the
  # target spec claims static-pie support, which x86_64-unknown-linux-musl
  # does and the aarch64/armv7 musl targets still do not.  The arm64
  # artifact says it plainly -- 33 C binaries DYN, the seven Rust plugins
  # EXEC -- and the release wants static-pie on everything.  `-static` also
  # wins gcc's crt selection, so it has to be *removed*, not overridden.
  # no rpath on the arm32 row.
  #
  # nixpkgs' link wrapper classifies a link as `static-pie` only if it sees
  # the literal `-static-pie` flag, and only then does it filter rpaths.
  # The arm32 spelling above (`-static -Wl,-pie`) is classified `static`, so
  # the wrapper kept stdenv's self-rpath (`-rpath $out/lib`, from
  # NIX_LDFLAGS) and added one for the musl lib dir -- a DT_RUNPATH naming
  # the *output store path* in every Rust plugin and in VLS.  Harmless at
  # run time (static), but it made those bytes a function of $out, and so of
  # the tree: the exact class closed, which its amd64-only two-tree
  # probe could not see.  These go in the derivation's env, arm32 only, so
  # the other rows' derivations are not touched by it.
  noRpathEnv = lib.optionalAttrs arm32 {
    NIX_NO_SELF_RPATH = "1";
    "NIX_DONT_SET_RPATH_${stdenv.cc.suffixSalt}" = "1";
  };

  rustStaticPieCc = bp.writeShellScriptBin "${stdenv.cc.targetPrefix}rust-cc" ''
    # A `-shared` link passes through untouched: cargo links proc macros
    # and cdylibs through a linker too, and lost a build to a
    # wrapper that forced a static link onto those.  The name matters as
    # well -- a wrapper whose name ends in `-ld` makes rustc switch to its
    # raw-ld flavour and emit a different link line entirely.
    for a in "$@"; do
      if [ "$a" = -shared ]; then
        exec ${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc "$@"
      fi
    done
    # Dropping `-static` is not enough, as the first arm64 artifact showed:
    # rustc links a musl target *self-contained*, passing the crt objects
    # from its own `rustlib/<target>/lib/self-contained` dir by path.  Those
    # are the non-PIE pair, so the link stays ET_EXEC however the driver is
    # invoked.  The objects themselves are PIC, so the fix is the one ticket
    # 22 arrived at: rewrite the link into the static-pie one --
    # crt1.o -> rcrt1.o, crtbegin.o -> crtbeginS.o, `-static`/`-no-pie`
    # dropped, `-static-pie` added.  (Both replacement objects ship in
    # nixpkgs' cross rustc, checked before relying on them.)
    args=()
    for a in "$@"; do
      case "$a" in
        -static | -no-pie) ;;
        */crt1.o) args+=("''${a%crt1.o}rcrt1.o") ;;
        */crtbegin.o) args+=("''${a%crtbegin.o}crtbeginS.o") ;;
        *) args+=("$a") ;;
      esac
    done
    exec ${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc ${staticPieFlags} "''${args[@]}"
  '';
}
