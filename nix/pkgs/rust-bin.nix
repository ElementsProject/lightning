# The release's Rust toolchain: the Rust project's own release binaries.
#
# nixpkgs builds rustc from source for any package set Hydra does not
# cover, and `pkgsCross.<t>.pkgsStatic` is one of them: every arm64 and
# armhf build compiled a full rustc first.  The upstream dist tarballs are
# the same compiler for all three rows (one host rustc/cargo, one rust-std
# per target), fixed-output, and are what nixpkgs' own rustc bootstraps
# from anyway, so they add no trust the release did not already extend.
#
# Bumping: take the sha256s from
#   https://static.rust-lang.org/dist/channel-rust-<version>.toml
# after checking its .asc against the Rust release key.
{ lib, pkgs }:
let
  inherit (pkgs) stdenv;
  bp = pkgs.buildPackages;

  version = "1.98.1";
  date = "2026-09-03";
  commit = "48a229ceaefd4985c50990b14116b6d856af0985";
  sha256 = {
    "rustc-x86_64-unknown-linux-gnu" =
      "e974f036b28565f37c0f3bd92ddefa809bee16c04f9dcf07b9ed96e05aaaf7c4";
    "cargo-x86_64-unknown-linux-gnu" =
      "ea1de9f9e23107d97ee2b41a72c552f34064a593da503789218387aee59f3ba4";
    "rust-std-x86_64-unknown-linux-gnu" =
      "fa3ff450172a16c026944030230c5069947af93c728d9179971d44e5e0cfb561";
    "rust-std-x86_64-unknown-linux-musl" =
      "bd9f35880de21dab0e387e84009c00001ae7836a4ba565cb16823f13f75f325f";
    "rust-std-aarch64-unknown-linux-musl" =
      "7e0ad2e67817f224b7a6331e48d6397303fc050edaccf81784ed786ffddc884a";
    "rust-std-armv7-unknown-linux-musleabihf" =
      "dd0efa4210a6da6350a6b05d8ffa43eae4baecf2397cc00a3b028bdf56cdb1ce";
  };

  buildTarget = stdenv.buildPlatform.rust.rustcTarget;
  target = stdenv.hostPlatform.rust.rustcTarget;

  component =
    name: t:
    let
      key = "${name}-${t}";
    in
    bp.fetchurl {
      url = "https://static.rust-lang.org/dist/${date}/${name}-${version}-${t}.tar.xz";
      sha256 = sha256.${key} or (throw "nix/pkgs/rust-bin.nix: no sha256 for ${key}");
    };

  componentKeys = lib.unique [
    [
      "rustc"
      buildTarget
    ]
    [
      "cargo"
      buildTarget
    ]
    [
      "rust-std"
      buildTarget
    ]
    [
      "rust-std"
      target
    ]
  ];
  components = map (k: component (builtins.elemAt k 0) (builtins.elemAt k 1)) componentKeys;

  # The musl objects rustc links self-contained are swapped for the row's
  # own, as nixpkgs' static rustc does: the C code and the Rust plugins then
  # link one libc, and upstream's (an older musl) never reaches a binary.
  # crtbegin/crtend and libunwind stay upstream's; the row's musl has none.
  musl = stdenv.cc.libc;
  muslObjects = [
    "crt1.o"
    "crti.o"
    "crtn.o"
    "libc.a"
    "rcrt1.o"
    "Scrt1.o"
  ];
in
bp.stdenv.mkDerivation {
  pname = "rust-bin-${target}";
  inherit version;
  srcs = components;
  sourceRoot = ".";

  nativeBuildInputs = [ bp.autoPatchelfHook ];
  buildInputs = [
    bp.stdenv.cc.cc.lib
    bp.zlib
  ];

  dontConfigure = true;
  dontBuild = true;
  # Stripping damages the .rmeta sections inside rlibs.
  dontStrip = true;

  installPhase = ''
    runHook preInstall
    for d in */; do
      bash "$d/install.sh" --prefix=$out --disable-ldconfig
    done
    rm -f $out/lib/rustlib/install.log $out/lib/rustlib/uninstall.sh

    sc=$out/lib/rustlib/${target}/lib/self-contained
    if [ -d "$sc" ]; then
      for o in ${lib.concatStringsSep " " muslObjects}; do
        [ -e "$sc/$o" ] || { echo "rust-bin: upstream has no $sc/$o" >&2; exit 1; }
        install -m 0444 ${musl}/lib/$o "$sc/$o"
      done
    fi
    runHook postInstall
  '';

  passthru = {
    inherit date commit;
    # For the input manifests: every fetched component, by hash.
    manifestLines = [
      "rust-dist ${version} ${date} ${commit}"
    ]
    ++ map (
      k:
      let
        key = "${builtins.elemAt k 0}-${builtins.elemAt k 1}";
      in
      "rust-dist ${key} ${sha256.${key}}"
    ) componentKeys
    ++ [ "rust-dist musl-objects ${lib.getName musl} ${lib.getVersion musl}" ];
  };

  meta = {
    description = "Rust ${version} upstream release binaries for ${target}";
    homepage = "https://www.rust-lang.org/";
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = [ "x86_64-linux" ];
  };
}
