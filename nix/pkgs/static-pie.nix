# How a release binary is linked: statically, as position-independent code.
#
# This is the shared half of one recipe, not a layer or an abstraction.  It is
# its own file for exactly one reason: both `default.nix` (Core Lightning) and
# `vls.nix` (the VLS signer) import it, and the two must link identically.  VLS
# is a separate upstream project, but it is the same rustc, the same musl
# targets and the same 32-bit ARM gcc gap, so a second copy of what follows
# would be a second thing to keep in step.
#
# Everything here is a workaround for one of two upstream gaps:
#
#   * nixpkgs' gcc cannot link static-pie for 32-bit ARM, and fails quietly;
#   * rustc will not emit static-pie for the ARM musl targets at all.
#
# Each is closed by a generated wrapper script that rewrites the compiler's
# arguments, because what has to change is argument *order*, which a flag
# cannot express.  Both are commented where they are defined.
#
# `pkgs` is the row's package set -- pkgsStatic, or
# pkgsCross.<target>.pkgsStatic -- so every value below is per-row.
#
# Exports: arm32, extraObjsManifest, staticPieFlags, staticPieCc, releaseCc,
# rustStaticPieCc and noRpathEnv, all consumed by default.nix and vls.nix.
{ pkgs, lib }:
let
  inherit (pkgs) stdenv;
  bp = pkgs.buildPackages;
in
rec {
  # The first of the two gaps: gcc on the 32-bit ARM row.
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
  # Static-pie on every row is what this preserves.  The alternatives were to
  # drop the 32-bit ARM row, or to ship it without ASLR.
  arm32 = stdenv.hostPlatform.isAarch32;
  # musl's malloc made the static lightningd 16% slower than a glibc build,
  # most of it in sqlite3_expanded_sql's alloc/copy churn.  The object, not
  # libmimalloc.a: an archive member is only pulled for an undefined symbol,
  # so libc.a could win the race and musl's malloc would ship silently.
  mimalloc = pkgs.mimalloc;
  # musl's x86_64 memcpy is `rep movsq` with byte loops either side, ~5x
  # slower than LLVM libc's for the short copies sqlite's string building
  # makes.  The arm rows' musl memcpy is already an optimised one.  memmove
  # must come too: musl's calls `__memcpy_fwd`, which would pull in musl's
  # memcpy.o and clash with ours.  Built by clang, not the row's gcc: gcc's
  # memmove came out 3-4x slower on large copies.  Baseline x86-64 (SSE2),
  # since a static binary has no ifunc to pick a wider one at run time.
  llvmLibc = bp.llvmPackages.libc;
  llvmMem = bp.runCommand "llvm-libc-memcpy-${llvmLibc.version}" { } ''
    clang=${bp.llvmPackages.clang-unwrapped}/bin/clang++
    mkdir -p $out
    for f in memcpy memmove; do
      $clang --target=${stdenv.hostPlatform.config} -march=x86-64 -std=c++17 -O2 \
        -fPIC -ffreestanding -fno-builtin -fno-exceptions -fno-rtti -fno-stack-protector \
        -nostdinc -isystem "$($clang -print-resource-dir)/include" \
        -DLIBC_NAMESPACE=__llvm_libc_cln -DLIBC_COPT_PUBLIC_PACKAGING \
        -I${llvmLibc.src}/libc -c ${llvmLibc.src}/libc/src/string/$f.cpp -o $out/$f.o
    done
    install -m644 ${llvmLibc.src}/libc/LICENSE.TXT $out/
  '';
  extraObjs = [
    "${mimalloc}/lib/mimalloc.o"
  ]
  ++ lib.optionals stdenv.hostPlatform.isx86_64 [
    "${llvmMem}/memcpy.o"
    "${llvmMem}/memmove.o"
  ];
  extraObjsArgs = lib.concatStringsSep " " extraObjs;
  # Listed in the input manifests next to the toolchain.
  extraObjsManifest = [
    "mimalloc ${mimalloc.version}"
  ]
  ++ lib.optional stdenv.hostPlatform.isx86_64 "llvm-libc memcpy+memmove ${llvmLibc.version}";
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
      ${extraObjsArgs} "$@" \
      ${gccLibDir}/crtendS.o ${muslLibDir}/crtn.o
  '';
  # What configure is handed as the compiler for the release link.
  releaseCc =
    if arm32 then
      "${staticPieCc}/bin/${stdenv.cc.targetPrefix}static-pie-cc"
    else
      # -Wl, so a compile-only invocation ignores the objects instead of warning.
      "${stdenv.cc.targetPrefix}cc ${staticPieFlags} ${
        lib.concatMapStringsSep " " (o: "-Wl,${o}") extraObjs
      }";
  # The second gap: rustc.
  #
  # rustc links a crt-static musl target with plain `-static` unless the
  # target spec claims static-pie support, which x86_64-unknown-linux-musl
  # does and the aarch64/armv7 musl targets still do not.  The first arm64
  # artifact said it plainly: 33 C binaries ET_DYN, the seven Rust plugins
  # ET_EXEC, where the release wants static-pie on all of them.  `-static`
  # also wins gcc's crt selection, so it has to be *removed* from the link
  # rather than overridden.
  #
  # nixpkgs' link wrapper classifies a link as `static-pie` only if it sees
  # the literal `-static-pie` flag, and only then does it filter rpaths.
  # The arm32 spelling above (`-static -Wl,-pie`) is classified `static`, so
  # the wrapper kept stdenv's self-rpath (`-rpath $out/lib`, from
  # NIX_LDFLAGS) and added one for the musl lib dir -- a DT_RUNPATH naming
  # the *output store path* in every Rust plugin and in VLS.  Harmless at
  # run time, since the binary is static, but it made those bytes a function
  # of $out and so of the tree -- exactly the class of difference the two-tree
  # probe exists to catch, and one an amd64-only probe cannot see.  These go
  # in the derivation's env on the 32-bit ARM row only, so the other rows'
  # derivations are untouched.
  noRpathEnv = lib.optionalAttrs arm32 {
    NIX_NO_SELF_RPATH = "1";
    "NIX_DONT_SET_RPATH_${stdenv.cc.suffixSalt}" = "1";
  };

  rustStaticPieCc = bp.writeShellScriptBin "${stdenv.cc.targetPrefix}rust-cc" ''
    # A `-shared` link passes through untouched: cargo links proc macros
    # and cdylibs through a linker too, and a wrapper that forced a static
    # link onto those cost a whole build.  The name matters as
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
    # invoked.  The objects themselves are PIC, so the fix is to rewrite the
    # link into the static-pie one --
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
    # Rust's default System allocator calls malloc, so this covers it too.
    exec ${stdenv.cc}/bin/${stdenv.cc.targetPrefix}cc ${staticPieFlags} ${extraObjsArgs} "''${args[@]}"
  '';
}
